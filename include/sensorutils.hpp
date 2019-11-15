/*
// Copyright (c) 2017 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#pragma once
#include <cmath>
#include <iostream>

namespace ipmi
{
static constexpr int16_t maxInt10 = 0x1FF;
static constexpr int16_t minInt10 = -0x200;
static constexpr int8_t maxInt4 = 7;
static constexpr int8_t minInt4 = -8;

// Scales down floating-point number and provides exponent
// Returns true if successful, modifies values in-place
static inline bool scaleFloatExp(double& base, int8_t& exp)
{
    auto min10 = static_cast<double>(minInt10);
    auto max10 = static_cast<double>(maxInt10);

    // The provided exponent must not already be scaled
    if (exp != 0)
    {
        std::cerr << "IPMI scaling failed, value was already scaled\n";
        return false;
    }

    // Comparing with zero should be OK, zero is special in floating-point
    // If base is exactly zero, no adjustment of the exponent is necessary
    if (base == 0.0)
    {
        return true;
    }

    // As long as value is within base range, expand precision
    // This will help to avoid loss when later rounding to integer
    while ((base > min10) && (base < max10))
    {
        // Expand for maximum precision
        base *= 10.0;
        --exp;

        // It is OK for exp to equal (minInt4 - 1), another test is below
        // This is allowed here only because the shrinking step comes next
        if (exp < (minInt4 - 1))
        {
            std::cerr << "IPMI scaling failed, exponent is too small\n";
            return false;
        }
    }

    // As long as value is *not* within range, shrink precision
    // This should eventually pull the value closer to zero, thus within range
    while (!((base > min10) && (base < max10)))
    {
        // Back it down until it falls within bounds again
        base /= 10.0;
        ++exp;

        if (exp > maxInt4)
        {
            std::cerr << "IPMI scaling failed, exponent is too large\n";
            return false;
        }
    }

    // This is the "another test", as promised above
    if (exp < minInt4)
    {
        std::cerr << "IPMI scaling failed, exponent is too small\n";
        return false;
    }

    return true;
}

// Normalize integer (base,exponent) tuples
// For exact powers of 10, this provides more consistent results
// Example (100,-2) --> divide by 100 but add 2 to exp --> (1,0)
// Example (-1000,-5) --> divide by 1000 but add 3 to exp --> (-1,-2)
// Always successful, modifies values in-place
static inline void normalizeIntExp(int16_t& ibase, int8_t& exp, double& dbase)
{
    for (;;)
    {
        // If zero, already normalized, ensure exponent also zero
        if (ibase == 0)
        {
            exp = 0;
            break;
        }

        // If not cleanly divisible by 10, already normalized
        if ((ibase % 10) != 0)
        {
            break;
        }

        // If exponent already at max, already normalized
        if (!(exp < maxInt4))
        {
            break;
        }

        // Bring values closer to zero, correspondingly shift exponent
        // The floating-point base must be kept in sync with the integer base,
        // as both floating-point and integer share the same exponent.
        ibase /= 10;
        dbase /= 10.0;
        ++exp;
    }
}

// The IPMI equation:
// y = (Mx + (B * 10^(bExp))) * 10^(rExp)
// Section 36.3 of this document:
// https://www.intel.com/content/dam/www/public/us/en/documents/product-briefs/ipmi-second-gen-interface-spec-v2-rev1-1.pdf
//
// The goal is to exactly match the math done by the ipmitool command,
// at the other side of the interface:
// https://github.com/ipmitool/ipmitool/blob/42a023ff0726c80e8cc7d30315b987fe568a981d/lib/ipmi_sdr.c#L360
//
// To use with Wolfram Alpha, make all variables single letters
// bExp becomes E, rExp becomes R
// https://www.wolframalpha.com/input/?i=y%3D%28%28M*x%29%2B%28B*%2810%5EE%29%29%29*%2810%5ER%29
static inline bool getSensorAttributes(const double max, const double min,
                                       int16_t& mValue, int8_t& rExp,
                                       int16_t& bValue, int8_t& bExp,
                                       bool& bSigned)
{
    // Given min and max, we must solve for M, B, bExp, rExp
    // y comes in from D-Bus (the actual sensor reading)
    // x is calculated from y by scaleIPMIValueFromDouble() below
    // If y is min, x should equal = 0 (or -128 if signed)
    // If y is max, x should equal 255 (or 127 if signed)
    if (!(min < max))
    {
        std::cerr << "getSensorAttributes: Max must be greater than min\n";
        return false;
    }

    double fullRange = max - min;
    double lowestX;

    rExp = 0;
    bExp = 0;

    // FUTURE: The IPMI document is ambiguous, as to whether
    // the resulting byte should be signed or unsigned,
    // essentially leaving it up to the caller.
    // The document just refers to it as "raw reading",
    // or "byte of reading", without giving further details.
    // Previous code set it signed if min was less than zero,
    // so I'm sticking with that, until I learn otherwise.
    if (min < 0.0)
    {
        // FUTURE: It would be worth experimenting with the range (-127,127),
        // instead of the range (-128,127), because this
        // would give good symmetry around zero, and make results look better.
        // Divide by 254 instead of 255, and change -128 to -127 elsewhere.
        bSigned = true;
        lowestX = -128.0;
    }
    else
    {
        bSigned = false;
        lowestX = 0.0;
    }

    // Step 1: Set y to (max - min), set x to 255, set B to 0, solve for M
    // This works, regardless of signed or unsigned, because total range same
    double dM = fullRange / 255.0;

    // Step 2: Constrain M, and set rExp accordingly
    if (!(scaleFloatExp(dM, rExp)))
    {
        std::cerr << "IPMI scaling failed, range is out of bounds\n";
        return false;
    }

    mValue = static_cast<int16_t>(std::round(dM));

    normalizeIntExp(mValue, rExp, dM);

    // Step 3: set y to min, set x to min, keep M and rExp, solve for B
    // If negative, x will be -128 (the most negative possible byte), not 0

    // Solve the IPMI equation for B, instead of y
    // https://www.wolframalpha.com/input/?i=solve+y%3D%28%28M*x%29%2B%28B*%2810%5EE%29%29%29*%2810%5ER%29+for+B
    // B = 10^(-rExp - bExp) (y - M 10^rExp x)
    double dB = std::pow(10.0, ((0 - rExp) - bExp)) *
                (min - ((dM * std::pow(10.0, rExp) * lowestX)));

    // Step 4: Constrain B, and set bExp accordingly
    if (!(scaleFloatExp(dB, bExp)))
    {
        std::cerr << "IPMI scaling failed, offset is out of bounds\n";
        return false;
    }

    bValue = static_cast<int16_t>(std::round(dB));

    normalizeIntExp(bValue, bExp, dB);

    return true;
}

static inline uint8_t
    scaleIPMIValueFromDouble(const double value, const int16_t mValue,
                             const int8_t rExp, const int16_t bValue,
                             const int8_t bExp, const bool bSigned)
{
    // Avoid division by zero below
    if (mValue == 0)
    {
        std::cerr << "IPMI multiplier must not be zero\n";
        throw std::out_of_range("IPMI scaling error");
    }

    auto dM = static_cast<double>(mValue);
    auto dB = static_cast<double>(bValue);

    // Solve the IPMI equation for x, instead of y
    // https://www.wolframalpha.com/input/?i=solve+y%3D%28%28M*x%29%2B%28B*%2810%5EE%29%29%29*%2810%5ER%29+for+x
    // x = (10^(-rExp) (y - B 10^(rExp + bExp)))/M and M 10^rExp!=0
    double dX = (std::pow(10.0, 0 - rExp) *
                 (value - (dB * std::pow(10.0, rExp + bExp)))) /
                dM;

    // Discard wild values early, before running into int truncation issues
    if ((dX < -1000.0) || (dX > 1000.0))
    {
        std::cerr << "IPMI scaling corrupt\n";
        throw std::out_of_range("IPMI scaling corrupt");
    }

    auto scaledValue = static_cast<int32_t>(std::round(dX));

    int32_t minClamp;
    int32_t maxClamp;

    // Because of rounding and integer truncation of scaling factors,
    // sometimes the resulting byte is slightly out of range.
    // Still allow this, but clamp the values to range.
    if (bSigned)
    {
        minClamp = std::numeric_limits<int8_t>::lowest();
        maxClamp = std::numeric_limits<int8_t>::max();
    }
    else
    {
        minClamp = std::numeric_limits<uint8_t>::lowest();
        maxClamp = std::numeric_limits<uint8_t>::max();
    }

    auto clampedValue = scaledValue;

    if (clampedValue < minClamp)
    {
        clampedValue = minClamp;
    }
    if (clampedValue > maxClamp)
    {
        clampedValue = maxClamp;
    }

    uint8_t byteValue;

    // Although the resulting byte is the same storage,
    // the signed flag changes the interpretation, and thus the casting.
    if (bSigned)
    {
        byteValue = static_cast<int8_t>(clampedValue);
    }
    else
    {
        byteValue = static_cast<uint8_t>(clampedValue);
    }

    return byteValue;
}

static inline uint8_t getScaledIPMIValue(const double value, const double max,
                                         const double min)
{
    int16_t mValue = 0;
    int8_t rExp = 0;
    int16_t bValue = 0;
    int8_t bExp = 0;
    bool bSigned = false;

    bool result =
        getSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned);
    if (!result)
    {
        std::cerr << "IPMI scaling error, unable to get value\n";
        throw std::runtime_error("IPMI scaling failure");
    }

    uint8_t scaledValue =
        scaleIPMIValueFromDouble(value, mValue, rExp, bValue, bExp, bSigned);
    return scaledValue;
}

} // namespace ipmi

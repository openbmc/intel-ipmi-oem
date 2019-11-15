#include <cmath>
#include <sensorutils.hpp>

#include "gtest/gtest.h"

// There is a surprising amount of slop in the math,
// thanks to all the rounding and conversion.
// The byte value can drift by up to 2 away, I have seen.
#define EXPECTED_SLOP (2)

// The algorithm here was copied from ipmitool
// sdr_convert_sensor_reading() function
// https://github.com/ipmitool/ipmitool/blob/42a023ff0726c80e8cc7d30315b987fe568a981d/lib/ipmi_sdr.c#L360
double ipmitool_y_from_x(uint8_t x, int m, int k2_rExp, int b, int k1_bExp,
                         bool bSigned)
{
    double result;

    // Rename to exactly match names and types (except analog) from ipmitool
    uint8_t val = x;
    double k1 = k1_bExp;
    double k2 = k2_rExp;
    int analog = bSigned ? 2 : 0;

    // Begin paste here
    // Only change is to comment out complicated structure in switch statement

    switch (/*sensor->cmn.unit.*/ analog)
    {
        case 0:
            result = (double)(((m * val) + (b * pow(10, k1))) * pow(10, k2));
            break;
        case 1:
            if (val & 0x80)
                val++;
            /* Deliberately fall through to case 2. */
        case 2:
            result =
                (double)(((m * (int8_t)val) + (b * pow(10, k1))) * pow(10, k2));
            break;
        default:
            /* Oops! This isn't an analog sensor. */
            return 0.0;
    }

    // End paste here
    // Ignoring linearization curves and postprocessing that follows,
    // assuming all sensors are perfectly linear
    return result;
}

void testValue(int x, double y, int16_t M, int8_t rExp, int16_t B, int8_t bExp,
               bool bSigned)
{
    double yRoundtrip;
    int result;

    if (bSigned)
    {
        int8_t expect = x;
        int8_t actual =
            ipmi::scaleIPMIValueFromDouble(y, M, rExp, B, bExp, bSigned);

        result = actual;
        yRoundtrip = ipmitool_y_from_x(actual, M, rExp, B, bExp, bSigned);

        EXPECT_NEAR(actual, expect, EXPECTED_SLOP);
    }
    else
    {
        uint8_t expect = x;
        uint8_t actual =
            ipmi::scaleIPMIValueFromDouble(y, M, rExp, B, bExp, bSigned);

        result = actual;
        yRoundtrip = ipmitool_y_from_x(actual, M, rExp, B, bExp, bSigned);

        EXPECT_NEAR(actual, expect, EXPECTED_SLOP);
    }

    // Scale the amount of allowed slop based on M, so the ratio stays similar
    EXPECT_NEAR(y, yRoundtrip, M * EXPECTED_SLOP);

    char szFormat[1024];
    sprintf(szFormat,
            "Value | xExpect %4d | xResult %4d | y %9.3f"
            "| yRoundtrip %9.3f | M %5d | rExp %3d"
            "| B %5d | bExp %3d | bSigned %1d\n",
            x, result, y, yRoundtrip, M, (int)rExp, B, (int)bExp, (int)bSigned);
    std::cout << szFormat;
}

void testBounds(double yMin, double yMax, bool bExpectedOutcome = true)
{
    int16_t mValue;
    int8_t rExp;
    int16_t bValue;
    int8_t bExp;
    bool bSigned;
    bool result;

    result = ipmi::getSensorAttributes(yMax, yMin, mValue, rExp, bValue, bExp,
                                       bSigned);
    EXPECT_EQ(result, bExpectedOutcome);

    if (!result)
    {
        return;
    }

    char szFormat[1024];
    sprintf(szFormat,
            "Bounds | yMin %9.3f | yMax %9.3f | M %5d"
            " | rExp %3d | B %5d | bExp %3d | bSigned %1d\n",
            yMin, yMax, mValue, (int)rExp, bValue, (int)bExp, (int)bSigned);
    std::cout << szFormat;

    double y50p = (yMin + yMax) / 2.0;

    // Average the average
    double y25p = (yMin + y50p) / 2.0;
    double y75p = (y50p + yMax) / 2.0;

    if (bSigned)
    {
        int8_t xMin = -128;
        int8_t x25p = -64;
        int8_t x50p = 0;
        int8_t x75p = 64;
        int8_t xMax = 127;

        testValue(xMin, yMin, mValue, rExp, bValue, bExp, bSigned);
        testValue(x25p, y25p, mValue, rExp, bValue, bExp, bSigned);
        testValue(x50p, y50p, mValue, rExp, bValue, bExp, bSigned);
        testValue(x75p, y75p, mValue, rExp, bValue, bExp, bSigned);
        testValue(xMax, yMax, mValue, rExp, bValue, bExp, bSigned);
    }
    else
    {
        uint8_t xMin = 0;
        uint8_t x25p = 64;
        uint8_t x50p = 128;
        uint8_t x75p = 192;
        uint8_t xMax = 255;

        testValue(xMin, yMin, mValue, rExp, bValue, bExp, bSigned);
        testValue(x25p, y25p, mValue, rExp, bValue, bExp, bSigned);
        testValue(x50p, y50p, mValue, rExp, bValue, bExp, bSigned);
        testValue(x75p, y75p, mValue, rExp, bValue, bExp, bSigned);
        testValue(xMax, yMax, mValue, rExp, bValue, bExp, bSigned);
    }
}

void testRanges(void)
{
    // The ranges from the main TEST function
    testBounds(0x0, 0xFF);
    testBounds(-128, 127);
    testBounds(0, 16000);
    testBounds(0, 20);
    testBounds(8000, 16000);
    testBounds(-10, 10);
    testBounds(0, 277);
    testBounds(0, 0, false);
    testBounds(10, 12);

    // Additional test cases recommended to me by hardware people
    testBounds(-40, 150);
    testBounds(0, 1);
    testBounds(0, 2);
    testBounds(0, 4);
    testBounds(0, 8);
    testBounds(35, 65);
    testBounds(0, 18);
    testBounds(0, 25);
    testBounds(0, 80);
    testBounds(0, 500);
}

TEST(sensorutils, TranslateToIPMI)
{
    /*bool getSensorAttributes(double maxValue, double minValue, int16_t
       &mValue, int8_t &rExp, int16_t &bValue, int8_t &bExp, bool &bSigned); */
    // normal unsigned sensor
    double maxValue = 0xFF;
    double minValue = 0x0;
    int16_t mValue;
    int8_t rExp;
    int16_t bValue;
    int8_t bExp;
    bool bSigned;
    bool result;

    uint8_t scaledVal;

    result = ipmi::getSensorAttributes(maxValue, minValue, mValue, rExp, bValue,
                                       bExp, bSigned);
    EXPECT_EQ(result, true);
    if (result)
    {
        EXPECT_EQ(bSigned, false);
        EXPECT_EQ(mValue, 1);
        EXPECT_EQ(rExp, 0);
        EXPECT_EQ(bValue, 0);
        EXPECT_EQ(bExp, 0);
    }
    double expected = 0x50;
    scaledVal = ipmi::scaleIPMIValueFromDouble(0x50, mValue, rExp, bValue, bExp,
                                               bSigned);
    EXPECT_NEAR(scaledVal, expected, expected * 0.01);

    // normal signed sensor
    maxValue = 127;
    minValue = -128;

    result = ipmi::getSensorAttributes(maxValue, minValue, mValue, rExp, bValue,
                                       bExp, bSigned);
    EXPECT_EQ(result, true);

    if (result)
    {
        EXPECT_EQ(bSigned, true);
        EXPECT_EQ(mValue, 1);
        EXPECT_EQ(rExp, 0);
        EXPECT_EQ(bValue, 0);
        EXPECT_EQ(bExp, 0);
    }

    // check negative values
    expected = 236; // 2s compliment -20
    scaledVal = ipmi::scaleIPMIValueFromDouble(-20, mValue, rExp, bValue, bExp,
                                               bSigned);
    EXPECT_NEAR(scaledVal, expected, expected * 0.01);

    // fan example
    maxValue = 16000;
    minValue = 0;

    result = ipmi::getSensorAttributes(maxValue, minValue, mValue, rExp, bValue,
                                       bExp, bSigned);
    EXPECT_EQ(result, true);
    if (result)
    {
        EXPECT_EQ(bSigned, false);
        EXPECT_EQ(mValue, floor((16000.0 / 0xFF) + 0.5));
        EXPECT_EQ(rExp, 0);
        EXPECT_EQ(bValue, 0);
        EXPECT_EQ(bExp, 0);
    }

    // voltage sensor example
    maxValue = 20;
    minValue = 0;

    result = ipmi::getSensorAttributes(maxValue, minValue, mValue, rExp, bValue,
                                       bExp, bSigned);
    EXPECT_EQ(result, true);
    if (result)
    {
        EXPECT_EQ(bSigned, false);
        EXPECT_EQ(mValue, floor(((20.0 / 0xFF) / std::pow(10, rExp)) + 0.5));
        EXPECT_EQ(rExp, -3);
        EXPECT_EQ(bValue, 0);
        EXPECT_EQ(bExp, 0);
    }
    scaledVal = ipmi::scaleIPMIValueFromDouble(12.2, mValue, rExp, bValue, bExp,
                                               bSigned);

    expected = 12.2 / (mValue * std::pow(10, rExp));
    EXPECT_NEAR(scaledVal, expected, expected * 0.01);

    // shifted fan example
    maxValue = 16000;
    minValue = 8000;

    result = ipmi::getSensorAttributes(maxValue, minValue, mValue, rExp, bValue,
                                       bExp, bSigned);
    EXPECT_EQ(result, true);

    if (result)
    {
        EXPECT_EQ(bSigned, false);
        EXPECT_EQ(mValue, floor(((8000.0 / 0xFF) / std::pow(10, rExp)) + 0.5));
        EXPECT_EQ(rExp, -1);
        EXPECT_EQ(bValue, 8);
        EXPECT_EQ(bExp, 4);
    }

    // signed voltage sensor example
    maxValue = 10;
    minValue = -10;

    result = ipmi::getSensorAttributes(maxValue, minValue, mValue, rExp, bValue,
                                       bExp, bSigned);
    EXPECT_EQ(result, true);
    if (result)
    {
        EXPECT_EQ(bSigned, true);
        EXPECT_EQ(mValue, floor(((20.0 / 0xFF) / std::pow(10, rExp)) + 0.5));
        EXPECT_EQ(rExp, -3);
        // Although this seems like a weird magic number,
        // it is because the range (-128,127) is not symmetrical about zero,
        // unlike the range (-10,10), so this introduces some distortion.
        EXPECT_EQ(bValue, 392);
        EXPECT_EQ(bExp, -1);
    }

    scaledVal =
        ipmi::scaleIPMIValueFromDouble(5, mValue, rExp, bValue, bExp, bSigned);

    expected = 5 / (mValue * std::pow(10, rExp));
    EXPECT_NEAR(scaledVal, expected, expected * 0.01);

    // reading = max example
    maxValue = 277;
    minValue = 0;

    result = ipmi::getSensorAttributes(maxValue, minValue, mValue, rExp, bValue,
                                       bExp, bSigned);
    EXPECT_EQ(result, true);
    if (result)
    {
        EXPECT_EQ(bSigned, false);
    }

    scaledVal = ipmi::scaleIPMIValueFromDouble(maxValue, mValue, rExp, bValue,
                                               bExp, bSigned);

    expected = 0xFF;
    EXPECT_NEAR(scaledVal, expected, expected * 0.01);

    // 0, 0 failure
    maxValue = 0;
    minValue = 0;
    result = ipmi::getSensorAttributes(maxValue, minValue, mValue, rExp, bValue,
                                       bExp, bSigned);
    EXPECT_EQ(result, false);

    // too close *success* (was previously failure!)
    maxValue = 12;
    minValue = 10;
    result = ipmi::getSensorAttributes(maxValue, minValue, mValue, rExp, bValue,
                                       bExp, bSigned);
    EXPECT_EQ(result, true);
    if (result)
    {
        EXPECT_EQ(bSigned, false);
        EXPECT_EQ(mValue, floor(((2.0 / 0xFF) / std::pow(10, rExp)) + 0.5));
        EXPECT_EQ(rExp, -4);
        EXPECT_EQ(bValue, 1);
        EXPECT_EQ(bExp, 5);
    }

    // Additional test conditions added separately
    testRanges();
}

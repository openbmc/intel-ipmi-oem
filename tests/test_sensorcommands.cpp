#include <cmath>
#include <sensorutils.hpp>

#include "gtest/gtest.h"

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

    // fan example
    maxValue = 16000;
    minValue = 0;

    result = ipmi::getSensorAttributes(maxValue, minValue, mValue, rExp, bValue,
                                       bExp, bSigned);
    EXPECT_EQ(result, true);
    if (result)
    {
        EXPECT_EQ(bSigned, false);
        EXPECT_EQ(mValue, floor(16000.0 / 0xFF));
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
        EXPECT_EQ(mValue, floor(((20.0 / 0xFF) / std::pow(10, rExp))));
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
        EXPECT_EQ(mValue, floor(8000.0 / 0xFF));
        EXPECT_EQ(rExp, 0);
        EXPECT_EQ(bValue, 80);
        EXPECT_EQ(bExp, 2);
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
        EXPECT_EQ(mValue, floor(((20.0 / 0xFF) / std::pow(10, rExp))));
        EXPECT_EQ(rExp, -3);
        EXPECT_EQ(bValue, 0);
        EXPECT_EQ(bExp, 0);
    }

    scaledVal =
        ipmi::scaleIPMIValueFromDouble(5, mValue, rExp, bValue, bExp, bSigned);

    expected = 5 / (mValue * std::pow(10, rExp));
    EXPECT_NEAR(scaledVal, expected, expected * 0.01);

    // 0, 0 failure
    maxValue = 0;
    minValue = 0;
    result = ipmi::getSensorAttributes(maxValue, minValue, mValue, rExp, bValue,
                                       bExp, bSigned);
    EXPECT_EQ(result, false);

    // too close failure
    maxValue = 12;
    minValue = 10;
    result = ipmi::getSensorAttributes(maxValue, minValue, mValue, rExp, bValue,
                                       bExp, bSigned);
    EXPECT_EQ(result, false);
}

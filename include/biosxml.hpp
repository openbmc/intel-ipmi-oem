#pragma once

#include "tinyxml2.h"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <types.hpp>

#include <map>
#include <sstream>
#include <stack>
#include <string>
#include <variant>
#include <vector>

namespace bios
{
/* Can hold one 'option'
 * For example
 *  <option text="TIS" value="0x0"/>
 */
using OptionType = std::tuple<std::string, ipmi::DbusVariant>;

/* Can hold one 'options'
 * For example
 *  <options>
 *		<option text="TIS" value="0x0"/>
 *		<option text="PTP FIFO" value="0x1"/>
 *		<option text="PTP CRB" value="0x2"/>
 *	</options>
 */
using OptionTypeVector = std::vector<OptionType>;

/* Can hold one 'knob'
 * For example
 *  <knob  type="scalar" setupType="oneof" name="TpmDeviceInterfaceAttempt"
 *  varstoreIndex="14" prompt="Attempt PTP TPM Device Interface"
 *  description="Attempt PTP TPM Device Interface: PTP FIFO, PTP CRB" size="1"
 *  offset="0x0005" depex="Sif( _LIST_ TpmDevice _EQU_ 0 1 ) _AND_ Sif(
 *  TpmDeviceInterfacePtpFifoSupported _EQU_ 0 OR
 *  TpmDeviceInterfacePtpCrbSupported _EQU_ 0 )" default="0x00"
 *CurrentVal="0x00"> <options> <option text="TIS" value="0x0"/> <option
 *text="PTP FIFO" value="0x1"/> <option text="PTP CRB" value="0x2"/>
 *		</options>
 *	</knob>
 */
using BiosBaseTableTypeEntry =
    std::tuple<std::string, bool, std::string, std::string, std::string,
               ipmi::DbusVariant, ipmi::DbusVariant, OptionTypeVector>;

/* Can hold one 'biosknobs'
 * biosknobs has array of 'knob' */
using BiosBaseTableType = std::map<std::string, BiosBaseTableTypeEntry>;

namespace knob
{
/* These are the operators we support in a 'depex' expression
 * Note: We also support '_LIST_', 'Sif', 'Gif', 'Dif', and 'NOT'. But they are
 * handeled sepeartely. */
enum class DepexOperators
{
    unknown = 0,
    OR,
    AND,
    GT,
    GTE,
    LTE,
    LT,
    EQU,
    NEQ,
    MODULO
};

namespace option
{
/* Can hold one 'option' */
struct option
{
    option(std::string text, std::string value) :
        text(std::move(text)), value(std::move(value))
    {}

    std::string text;
    std::string value;
};
} // namespace option

/* Can hold one 'knob' */
struct knob
{
    knob(std::string nameStr, std::string currentValStr, int currentVal,
         std::string descriptionStr, std::string defaultStr,
         std::string promptStr, std::string depexStr,
         std::string& setupTypeStr) :
        nameStr(std::move(nameStr)),
        currentValStr(std::move(currentValStr)), currentVal(currentVal),
        descriptionStr(std::move(descriptionStr)),
        defaultStr(std::move(defaultStr)), promptStr(std::move(promptStr)),
        depexStr(std::move(depexStr)), depex(false),
        readOnly(("ReadOnly" == setupTypeStr) ? true : false)
    {}

    bool depex;
    bool readOnly;
    int currentVal;

    std::string nameStr;
    std::string currentValStr;
    std::string descriptionStr;
    std::string defaultStr;
    std::string promptStr;
    std::string depexStr;

    /* Can hold one 'options' */
    std::vector<option::option> options;
};
} // namespace knob

/* Class capable of computing 'depex' expression. */
class Depex
{
  public:
    Depex(std::vector<knob::knob>& knobs) : mKnobs(knobs)
    {}

    /* Compute 'depex' expression of all knobs in 'biosknobs'. */
    void compute()
    {
        mError.clear();

        for (auto& knob : mKnobs)
        {
            /* if 'depex' == "TRUE" no need to execute expression. */
            if ("TRUE" == knob.depexStr)
            {
                knob.depex = true;
            }
            else if (!knob.readOnly)
            {
                int value = 0;

                if (!evaluateExpression(knob.depexStr, value))
                {
                    mError.emplace_back("bad depex: " + knob.depexStr +
                                        " in knob: " + knob.nameStr);
                }
                else
                {
                    if (value)
                    {
                        knob.depex = true;
                    }
                }
            }
        }
    }

    /* Returns the number of 'knob's which have a bad 'depex' expression. */
    size_t getErrorCount()
    {
        return mError.size();
    }

    /* Prints all the 'knob's which have a bad 'depex' expression. */
    void printError()
    {
        for (auto& error : mError)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                error.c_str());
        }
    }

  private:
    /* Returns 'true' if the argument string is a number. */
    bool isNumber(const std::string& s)
    {
        return !s.empty() &&
               std::find_if(s.begin(), s.end(), [](unsigned char c) {
                   return !std::isdigit(c);
               }) == s.end();
    }

    /* Returns 'true' if the argument string is hex representation of a number.
     */
    bool isHexNotation(std::string const& s)
    {
        return s.compare(0, 2, "0x") == 0 && s.size() > 2 &&
               s.find_first_not_of("0123456789abcdefABCDEF", 2) ==
                   std::string::npos;
    }

    /* Function to find current value of a 'knob'
     * search is done using 'knob' attribute 'name' */
    bool getValue(std::string& variableName, int& value)
    {
        for (auto& knob : mKnobs)
        {
            if (knob.nameStr == variableName)
            {
                value = knob.currentVal;
                return true;
            }
        }

        std::string error =
            "Unable to find knob: " + variableName + " in knob list\n";
        phosphor::logging::log<phosphor::logging::level::ERR>(error.c_str());

        return false;
    }

    /* Get the expression enclosed within brackets, i.e., between '(' and ')' */
    bool getSubExpression(const std::string& expression,
                          std::string& subExpression, size_t& i)
    {
        int level = 1;
        subExpression.clear();

        for (; i < expression.length(); i++)
        {
            if (expression[i] == '(')
            {
                ++level;
            }
            else if (expression[i] == ')')
            {
                --level;
                if (level == 0)
                {
                    break;
                }
            }

            subExpression.push_back(expression[i]);
        }

        if (!subExpression.empty())
        {
            return true;
        }

        return false;
    }

    /* Function to handle operator '_LIST_'
     * Convert a '_LIST_' expression to a normal expression
     * Example "_LIST_ VariableA _EQU_ 0 1" is converted to "VariableA _EQU_ 0
     * OR VariableA _EQU_ 1" */
    bool getListExpression(const std::string& expression,
                           std::string& subExpression, size_t& i)
    {
        subExpression.clear();

        int cnt = 0;
        std::string variableStr;
        std::string operatorStr;

        for (; i < expression.length(); i++)
        {
            if (expression[i] == '(')
            {
                return false;
            }
            else if (expression[i] == ')')
            {
                break;
            }
            else if (expression[i] == ' ')
            {
                /* whitespace */
                continue;
            }
            else
            {
                std::string word;

                /* Get the next word in expression string */
                while ((i < expression.length()) && (expression[i] != ' '))
                {
                    word.push_back(expression[i++]);
                }

                if (word == "_OR_" || word == "OR" || word == "_AND_" ||
                    word == "AND" || word == "NOT")
                {
                    i = i - word.length();
                    break;
                }

                ++cnt;

                if (cnt == 1)
                {
                    variableStr = word;
                }
                else if (cnt == 2)
                {
                    operatorStr = word;
                }
                else
                {
                    if (cnt > 3)
                    {
                        subExpression += " OR ";
                    }

                    subExpression += "( ";
                    subExpression += variableStr;
                    subExpression += " ";
                    subExpression += operatorStr;
                    subExpression += " ";
                    subExpression += word;
                    subExpression += " )";
                }
            }
        }

        if (!subExpression.empty())
        {
            return true;
        }

        return false;
    }

    /* Function to handle operator 'NOT'
     * 1) Find the variable
     * 2) apply NOT on the variable */
    bool getNotValue(const std::string& expression, size_t& i, int& value)
    {
        std::string word;

        for (; i < expression.length(); i++)
        {
            if (expression[i] == ' ')
            {
                /* whitespace */
                continue;
            }
            else
            {
                /* Get the next word in expression string */
                while ((i < expression.length()) && (expression[i] != ' '))
                {
                    word.push_back(expression[i++]);
                }

                break;
            }
        }

        if (!word.empty())
        {
            if (getValue(word, value))
            {
                value = !value;
                return true;
            }
        }

        return false;
    }

    /* 1) Pop one operator from operator stack, example 'OR'
     * 2) Pop two variable from variable stack, example VarA and VarB
     * 3) Push back result of 'VarA OR VarB' to variable stack
     * 4) Repeat till operator stack is empty
     *
     * The last variable in variable stack is the output of the expression. */
    bool evaluateExprStack(std::stack<int>& values,
                           std::stack<knob::DepexOperators>& operators,
                           int& output)
    {
        if (values.size() != (operators.size() + 1))
        {
            return false;
        }

        while (!operators.empty())
        {
            int b = values.top();
            values.pop();

            int a = values.top();
            values.pop();

            switch (operators.top())
            {
                case knob::DepexOperators::OR:
                    values.emplace(a | b);
                    break;

                case knob::DepexOperators::AND:
                    values.emplace(a & b);
                    break;

                case knob::DepexOperators::EQU:
                    if (a == b)
                    {
                        values.emplace(1);
                        break;
                    }

                    values.emplace(0);
                    break;

                case knob::DepexOperators::NEQ:
                    if (a != b)
                    {
                        values.emplace(1);
                        break;
                    }

                    values.emplace(0);
                    break;

                case knob::DepexOperators::LTE:
                    if (a <= b)
                    {
                        values.emplace(1);
                        break;
                    }

                    values.emplace(0);
                    break;

                case knob::DepexOperators::LT:
                    if (a < b)
                    {
                        values.emplace(1);
                        break;
                    }

                    values.emplace(0);
                    break;

                case knob::DepexOperators::GTE:
                    if (a >= b)
                    {
                        values.emplace(1);
                        break;
                    }

                    values.emplace(0);
                    break;

                case knob::DepexOperators::GT:
                    if (a > b)
                    {
                        values.emplace(1);
                        break;
                    }

                    values.emplace(0);
                    break;

                case knob::DepexOperators::MODULO:
                    if (b == 0)
                    {
                        return false;
                    }
                    values.emplace(a % b);
                    break;

                default:
                    return false;
            }

            operators.pop();
        }

        if (values.size() == 1)
        {
            output = values.top();
            values.pop();

            return true;
        }

        return false;
    }

    /* Evaluvate one 'depex' expression
     * 1) Find a word in expression string
     * 2) If word is a variable push to variable stack
     * 3) If word is a operator push to operator stack
     *
     * Execute the stack at end to get the result of expression. */
    bool evaluateExpression(const std::string& expression, int& output)
    {
        if (expression.empty())
        {
            return false;
        }

        size_t i;
        int value;
        std::stack<int> values;
        std::stack<knob::DepexOperators> operators;
        std::string subExpression;

        for (i = 0; i < expression.length(); i++)
        {
            if (expression[i] == ' ')
            {
                /* whitespace */
                continue;
            }
            else
            {
                std::string word;

                /* Get the next word in expression string */
                while ((i < expression.length()) && (expression[i] != ' '))
                {
                    word.push_back(expression[i++]);
                }

                if (word == "_OR_" || word == "OR")
                {
                    /* OR and AND has more precedence than other operators
                     * To handle statements like "a != b or c != d"
                     * we need to execute, for above example, both '!=' before
                     * 'or' */
                    if (!operators.empty())
                    {
                        if (!evaluateExprStack(values, operators, value))
                        {
                            return false;
                        }

                        values.emplace(value);
                    }

                    operators.emplace(knob::DepexOperators::OR);
                }
                else if (word == "_AND_" || word == "AND")
                {
                    /* OR and AND has more precedence than other operators
                     * To handle statements like "a == b and c == d"
                     * we need to execute, for above example, both '==' before
                     * 'and' */
                    if (!operators.empty())
                    {
                        if (!evaluateExprStack(values, operators, value))
                        {
                            return false;
                        }

                        values.emplace(value);
                    }

                    operators.emplace(knob::DepexOperators::AND);
                }
                else if (word == "_LTE_")
                {
                    operators.emplace(knob::DepexOperators::LTE);
                }
                else if (word == "_LT_")
                {
                    operators.emplace(knob::DepexOperators::LT);
                }
                else if (word == "_GTE_")
                {
                    operators.emplace(knob::DepexOperators::GTE);
                }
                else if (word == "_GT_")
                {
                    operators.emplace(knob::DepexOperators::GT);
                }
                else if (word == "_NEQ_")
                {
                    operators.emplace(knob::DepexOperators::NEQ);
                }
                else if (word == "_EQU_")
                {
                    operators.emplace(knob::DepexOperators::EQU);
                }
                else if (word == "%")
                {
                    operators.emplace(knob::DepexOperators::MODULO);
                }
                else
                {
                    /* Handle 'Sif(', 'Gif(', 'Dif(' and '('
                     * by taking the inner/sub expression and evaluating it */
                    if (word.back() == '(')
                    {
                        if (!getSubExpression(expression, subExpression, i))
                            break;

                        if (!evaluateExpression(subExpression, value))
                            break;
                    }
                    else if (word == "_LIST_")
                    {
                        if (!getListExpression(expression, subExpression, i))
                            break;

                        --i;

                        if (!evaluateExpression(subExpression, value))
                            break;
                    }
                    else if (word == "NOT")
                    {
                        if (!getNotValue(expression, i, value))
                            break;
                    }
                    else if (isNumber(word) || isHexNotation(word))
                    {
                        try
                        {
                            value = std::stoi(word);
                        }
                        catch (const std::exception& ex)
                        {
                            phosphor::logging::log<
                                phosphor::logging::level::ERR>(ex.what());
                            return false;
                        }
                    }
                    else
                    {
                        if (!getValue(word, value))
                            break;
                    }

                    values.emplace(value);
                }
            }
        }

        if (i == expression.length())
        {
            if (evaluateExprStack(values, operators, output))
            {
                return true;
            }
        }

        return false;
    }

  private:
    /* To store all 'knob's in 'biosknobs' */
    std::vector<knob::knob>& mKnobs;

    /* To store all bad 'depex' expression */
    std::vector<std::string> mError;
};

class Xml
{
  public:
    Xml(const char* filePath) : mDepex(std::make_unique<Depex>(mKnobs))
    {
        if (!getKnobs(filePath))
        {
            std::string error =
                "Unable to get knobs in file: " + std::string(filePath);
            throw std::runtime_error(error);
        }
    }

    /* Fill Bios table with all 'knob's which have output of 'depex' expression
     * as 'true' */
    bool getBaseTable(bios::BiosBaseTableType& baseTable)
    {
        baseTable.clear();

        for (auto& knob : mKnobs)
        {
            if (knob.depex)
            {
                std::string text =
                    "xyz.openbmc_project.BIOSConfig.Manager.BoundType.OneOf";
                bios::OptionTypeVector options;

                for (auto& option : knob.options)
                {
                    options.emplace_back(text, option.value);
                }

                bios::BiosBaseTableTypeEntry baseTableEntry = std::make_tuple(
                    "xyz.openbmc_project.BIOSConfig.Manager.AttributeType."
                    "Enumeration",
                    false, knob.nameStr, knob.descriptionStr, "./",
                    knob.currentValStr, knob.defaultStr, options);

                baseTable.emplace(knob.nameStr, baseTableEntry);
            }
        }

        if (!baseTable.empty())
        {
            return true;
        }

        return false;
    }

    /* Execute all 'depex' expression */
    bool doDepexCompute()
    {
        mDepex->compute();

        if (mDepex->getErrorCount())
        {
            mDepex->printError();
            return false;
        }

        return true;
    }

  private:
    /* Get 'option' */
    void getOption(tinyxml2::XMLElement* pOption)
    {
        if (pOption)
        {
            std::string valueStr;
            std::string textStr;

            if (pOption->Attribute("text"))
                valueStr = pOption->Attribute("text");

            if (pOption->Attribute("value"))
                textStr = pOption->Attribute("value");

            mKnobs.back().options.emplace_back(pOption->Attribute("text"),
                                               pOption->Attribute("value"));
        }
    }

    /* Get 'options' */
    void getOptions(tinyxml2::XMLElement* pKnob)
    {
        uint16_t reserveCnt = 0;

        /* Get node options inside knob */
        tinyxml2::XMLElement* pOptions = pKnob->FirstChildElement("options");

        if (pOptions)
        {
            for (tinyxml2::XMLElement* pOption =
                     pOptions->FirstChildElement("option");
                 pOption; pOption = pOption->NextSiblingElement("option"))
            {
                ++reserveCnt;
            }

            mKnobs.back().options.reserve(reserveCnt);

            /* Loop through all option inside options */
            for (tinyxml2::XMLElement* pOption =
                     pOptions->FirstChildElement("option");
                 pOption; pOption = pOption->NextSiblingElement("option"))
            {
                getOption(pOption);
            }
        }
    }

    /* Get 'knob' */
    void getKnob(tinyxml2::XMLElement* pKnob)
    {
        if (pKnob)
        {
            int currentVal = 0;
            std::string nameStr;
            std::string currentValStr;
            std::string descriptionStr;
            std::string defaultStr;
            std::string depexStr;
            std::string promptStr;
            std::string setupTypeStr;

            if (!pKnob->Attribute("name") || !pKnob->Attribute("CurrentVal"))
            {
                return;
            }

            nameStr = pKnob->Attribute("name");
            currentValStr = pKnob->Attribute("CurrentVal");
            std::stringstream ss;
            ss << std::hex << currentValStr;
            if (ss.good())
            {
                ss >> currentVal;
            }
            else
            {
                std::string error = "Invalid hex value input " + currentValStr +
                                    " for " + nameStr + "\n";
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    error.c_str());
                return;
            }
            if (pKnob->Attribute("description"))
                descriptionStr = pKnob->Attribute("description");

            if (pKnob->Attribute("default"))
                defaultStr = pKnob->Attribute("default");

            if (pKnob->Attribute("depex"))
                depexStr = pKnob->Attribute("depex");

            if (pKnob->Attribute("prompt"))
                promptStr = pKnob->Attribute("prompt");

            if (pKnob->Attribute("setupType"))
                setupTypeStr = pKnob->Attribute("setupType");

            mKnobs.emplace_back(nameStr, currentValStr, currentVal,
                                descriptionStr, defaultStr, promptStr, depexStr,
                                setupTypeStr);

            getOptions(pKnob);
        }
    }

    /* Get 'biosknobs' */
    bool getKnobs(const char* biosXmlFilePath)
    {
        uint16_t reserveCnt = 0;

        mKnobs.clear();

        tinyxml2::XMLDocument biosXml;

        /* Load the XML file into the Doc instance */
        biosXml.LoadFile(biosXmlFilePath);

        /* Get 'SYSTEM' */
        tinyxml2::XMLElement* pRootElement = biosXml.RootElement();
        if (pRootElement)
        {
            /* Get 'biosknobs' inside 'SYSTEM' */
            tinyxml2::XMLElement* pBiosknobs =
                pRootElement->FirstChildElement("biosknobs");
            if (pBiosknobs)
            {
                for (tinyxml2::XMLElement* pKnob =
                         pBiosknobs->FirstChildElement("knob");
                     pKnob; pKnob = pKnob->NextSiblingElement("knob"))
                {
                    ++reserveCnt;
                }

                /* reserve before emplace_back will avoids realloc(s) */
                mKnobs.reserve(reserveCnt);

                for (tinyxml2::XMLElement* pKnob =
                         pBiosknobs->FirstChildElement("knob");
                     pKnob; pKnob = pKnob->NextSiblingElement("knob"))
                {
                    getKnob(pKnob);
                }
            }
        }

        if (!mKnobs.empty())
        {
            return true;
        }

        return false;
    }

  private:
    /* To store all 'knob's in 'biosknobs' */
    std::vector<knob::knob> mKnobs;

    /* Object of Depex class to compute 'depex' expression */
    std::unique_ptr<Depex> mDepex;
};
} // namespace bios

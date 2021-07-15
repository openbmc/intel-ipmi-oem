#pragma once

#include "tinyxml2.h"

#include <map>
#include <sstream>
#include <stack>
#include <string>
#include <variant>
#include <vector>

/* Can hold one 'option'
 * For example
 *  <option text="TIS" value="0x0"/>
 */
using OptionType = std::tuple<std::string, std::variant<int64_t, std::string>>;

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
 *  TpmDeviceInterfacePtpCrbSupported _EQU_ 0 )" default="0x00" CurrentVal="0x00">
 *		<options>
 *			<option text="TIS" value="0x0"/>
 *			<option text="PTP FIFO" value="0x1"/>
 *			<option text="PTP CRB" value="0x2"/>
 *		</options>
 *	</knob>
 */
using BiosBaseTableTypeEntry =
    std::tuple<std::string, bool, std::string, std::string, std::string,
               std::variant<int64_t, std::string>,
               std::variant<int64_t, std::string>, OptionTypeVector>;

/* Can hold one 'biosknobs'
 * biosknobs has array of 'knob' */
using BiosBaseTableType = std::map<std::string, BiosBaseTableTypeEntry>;

namespace bios
{
namespace knob
{
/* These are the operators we support in a 'depex' expression
 * Note: We also support '_LIST_', 'Sif', 'Gif', 'Dif', and 'NOT'. But they are
 * handeled sepeartely. */
enum class dupex_operators
{
    unknown = 0,
    OR,
    AND,
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
    knob(std::string nameStr, std::string currentValStr,
         std::string descriptionStr, std::string defaultStr,
         std::string promptStr, std::string depexStr,
         std::string& setupTypeStr) :
        nameStr(std::move(nameStr)),
        currentValStr(std::move(currentValStr)),
        descriptionStr(std::move(descriptionStr)),
        defaultStr(std::move(defaultStr)), promptStr(std::move(promptStr)),
        depexStr(std::move(depexStr)), depex(false), readOnly(false)
    {
        currentVal = std::stoi(this->currentValStr);
        depex = false;

        if ("ReadOnly" == setupTypeStr)
        {
            readOnly = true;
        }
    }

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
    Depex(std::vector<knob::knob>& knobs) : m_knobs(knobs)
    {}

    /* Compute 'depex' expression of all knobs in 'biosknobs'. */
    void compute()
    {
        m_error.clear();

        for (auto& knob : m_knobs)
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
                    m_error.emplace_back("bad depex: " + knob.depexStr +
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
    size_t getError()
    {
        return m_error.size();
    }

    /* Prints all the 'knob's which have a bad 'depex' expression. */
    void printError()
    {
        for (auto& error : m_error)
        {
            std::cerr << error << "\n";
        }
    }

  private:
    /* Returns 'true' if the argument string is a number. */
    bool is_number(const std::string& s)
    {
        return !s.empty() &&
               std::find_if(s.begin(), s.end(), [](unsigned char c) {
                   return !std::isdigit(c);
               }) == s.end();
    }

    /* Returns 'true' if the argument string is hex representation of a number.
     */
    bool is_hex_notation(std::string const& s)
    {
        return s.compare(0, 2, "0x") == 0 && s.size() > 2 &&
               s.find_first_not_of("0123456789abcdefABCDEF", 2) ==
                   std::string::npos;
    }

    /* Function to find current value of a 'knob'
     * search is done using 'knob' attribute 'name' */
    bool getValue(std::string& variableName, int& value)
    {
        for (auto& knob : m_knobs)
        {
            if (knob.nameStr == variableName)
            {
                value = knob.currentVal;
                return true;
            }
        }

        std::string error =
            "Unable to find knob: " + variableName + " in knob list\n";
        std::cerr << error;

        return false;
    }

    /* Get the expression enclosed within brackets, i.e., between '(' and ')' */
    bool getSubExpression(std::string& expression, std::string& subExpression,
                          size_t& i)
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
    bool getListExpression(std::string& expression, std::string& subExpression,
                           size_t& i)
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
    bool getNotValue(std::string& expression, size_t& i, int& value)
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
                           std::stack<knob::dupex_operators>& operators,
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
                case knob::dupex_operators::OR:
                    values.emplace(a | b);
                    break;

                case knob::dupex_operators::AND:
                    values.emplace(a & b);
                    break;

                case knob::dupex_operators::EQU:
                    if (a == b)
                    {
                        values.emplace(1);
                        break;
                    }

                    values.emplace(0);
                    break;

                case knob::dupex_operators::NEQ:
                    if (a != b)
                    {
                        values.emplace(1);
                        break;
                    }

                    values.emplace(0);
                    break;

                case knob::dupex_operators::LTE:
                    if (a <= b)
                    {
                        values.emplace(1);
                        break;
                    }

                    values.emplace(0);
                    break;

                case knob::dupex_operators::LT:
                    if (a < b)
                    {
                        values.emplace(1);
                        break;
                    }

                    values.emplace(0);
                    break;

                case knob::dupex_operators::MODULO:
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
    bool evaluateExpression(std::string& expression, int& output)
    {
        if (expression.empty())
        {
            return false;
        }

        size_t i;
        int value;
        std::stack<int> values;
        std::stack<knob::dupex_operators> operators;
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

                    operators.emplace(knob::dupex_operators::OR);
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

                    operators.emplace(knob::dupex_operators::AND);
                }
                else if (word == "_LTE_")
                {
                    operators.emplace(knob::dupex_operators::LTE);
                }
                else if (word == "_LT_")
                {
                    operators.emplace(knob::dupex_operators::LT);
                }
                else if (word == "_NEQ_")
                {
                    operators.emplace(knob::dupex_operators::NEQ);
                }
                else if (word == "_EQU_")
                {
                    operators.emplace(knob::dupex_operators::EQU);
                }
                else if (word == "%")
                {
                    operators.emplace(knob::dupex_operators::MODULO);
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
                    else if (is_number(word) || is_hex_notation(word))
                    {
                        value = std::stoi(word);
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
    std::vector<knob::knob>& m_knobs;

    /* To store all bad 'depex' expression */
    std::vector<std::string> m_error;
};

class Xml
{
  public:
    Xml(const char* filePath) :
        m_filePath(filePath), m_depex(std::make_unique<Depex>(m_knobs))
    {
        if (!getKnobs(m_filePath))
        {
            std::string error =
                "Unable to get knobs in file: " + std::string(m_filePath);
            throw std::runtime_error(error);
        }
    }

    /* Fill Bios table with all 'knob's which have output of 'depex' expression
     * as 'true' */
    bool getBaseTable(BiosBaseTableType& baseTable)
    {
        baseTable.clear();

        for (auto& knob : m_knobs)
        {
            if (knob.depex)
            {
                std::string text =
                    "xyz.openbmc_project.BIOSConfig.Manager.BoundType.OneOf";
                OptionTypeVector options;

                for (auto& option : knob.options)
                {
                    options.emplace_back(text, option.value);
                }

                BiosBaseTableTypeEntry baseTableEntry = std::make_tuple(
                    "xyz.openbmc_project.BIOSConfig.Manager.AttributeType."
                    "String",
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
        m_depex->compute();

        if (m_depex->getError())
        {
            m_depex->printError();
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

            m_knobs.back().options.emplace_back(pOption->Attribute("text"),
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

            m_knobs.back().options.reserve(reserveCnt);

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
            std::string nameStr;
            std::string CurrentValStr;
            std::string descriptionStr;
            std::string defaultStr;
            std::string depexStr;
            std::string promptStr;
            std::string setupTypeStr;

            if (pKnob->Attribute("name"))
                nameStr = pKnob->Attribute("name");

            if (pKnob->Attribute("CurrentVal"))
                CurrentValStr = pKnob->Attribute("CurrentVal");

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

            m_knobs.emplace_back(nameStr, CurrentValStr, descriptionStr,
                                 defaultStr, promptStr, depexStr, setupTypeStr);

            getOptions(pKnob);
        }
    }

    /* Get 'biosknobs' */
    bool getKnobs(const char* biosXmlFilePath)
    {
        uint16_t reserveCnt = 0;

        m_knobs.clear();

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
                m_knobs.reserve(reserveCnt);

                for (tinyxml2::XMLElement* pKnob =
                         pBiosknobs->FirstChildElement("knob");
                     pKnob; pKnob = pKnob->NextSiblingElement("knob"))
                {
                    getKnob(pKnob);
                }
            }
        }

        if (!m_knobs.empty())
        {
            return true;
        }

        return false;
    }

  private:
    /* To store all 'knob's in 'biosknobs' */
    std::vector<knob::knob> m_knobs;

    /* bios.xml path */
    const char* m_filePath;

    /* Object of Depex class to compute 'depex' expression */
    std::unique_ptr<Depex> m_depex;
};
} // namespace bios

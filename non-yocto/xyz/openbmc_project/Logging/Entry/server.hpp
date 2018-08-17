#pragma once
#include <tuple>
#include <systemd/sd-bus.h>
#include <sdbusplus/sdbus.hpp>
#include <sdbusplus/server.hpp>

namespace sdbusplus
{
namespace xyz
{
namespace openbmc_project
{
namespace Logging
{
namespace server
{

class Entry
{
    public:
        /* Define all of the basic class operations:
         *     Not allowed:
         *         - Default constructor to avoid nullptrs.
         *         - Copy operations due to internal unique_ptr.
         *         - Move operations due to 'this' being registered as the
         *           'context' with sdbus.
         *     Allowed:
         *         - Destructor.
         */
        Entry() = delete;
        Entry(const Entry&) = delete;
        Entry& operator=(const Entry&) = delete;
        Entry(Entry&&) = delete;
        Entry& operator=(Entry&&) = delete;
        virtual ~Entry() = default;

        /** @brief Constructor to put object onto bus at a dbus path.
         *  @param[in] bus - Bus to attach to.
         *  @param[in] path - Path to attach at.
         */
        Entry(bus::bus& bus, const char* path);

        enum class Level
        {
            Emergency,
            Alert,
            Critical,
            Error,
            Warning,
            Notice,
            Informational,
            Debug,
        };

        using PropertiesVariant = sdbusplus::message::variant<
                std::string,
                Level,
                bool,
                uint32_t,
                std::vector<std::string>,
                uint64_t>;

        /** @brief Constructor to initialize the object from a map of
         *         properties.
         *
         *  @param[in] bus - Bus to attach to.
         *  @param[in] path - Path to attach at.
         *  @param[in] vals - Map of property name to value for initialization.
         */
        Entry(bus::bus& bus, const char* path,
                     const std::map<std::string, PropertiesVariant>& vals,
                     bool skipSignal = false);



        /** Get value of Id */
        virtual uint32_t id() const;
        /** Set value of Id with option to skip sending signal */
        virtual uint32_t id(uint32_t value,
               bool skipSignal);
        /** Set value of Id */
        virtual uint32_t id(uint32_t value);
        /** Get value of Timestamp */
        virtual uint64_t timestamp() const;
        /** Set value of Timestamp with option to skip sending signal */
        virtual uint64_t timestamp(uint64_t value,
               bool skipSignal);
        /** Set value of Timestamp */
        virtual uint64_t timestamp(uint64_t value);
        /** Get value of Severity */
        virtual Level severity() const;
        /** Set value of Severity with option to skip sending signal */
        virtual Level severity(Level value,
               bool skipSignal);
        /** Set value of Severity */
        virtual Level severity(Level value);
        /** Get value of Message */
        virtual std::string message() const;
        /** Set value of Message with option to skip sending signal */
        virtual std::string message(std::string value,
               bool skipSignal);
        /** Set value of Message */
        virtual std::string message(std::string value);
        /** Get value of AdditionalData */
        virtual std::vector<std::string> additionalData() const;
        /** Set value of AdditionalData with option to skip sending signal */
        virtual std::vector<std::string> additionalData(std::vector<std::string> value,
               bool skipSignal);
        /** Set value of AdditionalData */
        virtual std::vector<std::string> additionalData(std::vector<std::string> value);
        /** Get value of Resolved */
        virtual bool resolved() const;
        /** Set value of Resolved with option to skip sending signal */
        virtual bool resolved(bool value,
               bool skipSignal);
        /** Set value of Resolved */
        virtual bool resolved(bool value);

        /** @brief Sets a property by name.
         *  @param[in] _name - A string representation of the property name.
         *  @param[in] val - A variant containing the value to set.
         */
        void setPropertyByName(const std::string& _name,
                               const PropertiesVariant& val,
                               bool skipSignal = false);

        /** @brief Gets a property by name.
         *  @param[in] _name - A string representation of the property name.
         *  @return - A variant containing the value of the property.
         */
        PropertiesVariant getPropertyByName(const std::string& _name);

    /** @brief Convert a string to an appropriate enum value.
     *  @param[in] s - The string to convert in the form of
     *                 "xyz.openbmc_project.Logging.Entry.<value name>"
     *  @return - The enum value.
     */
    static Level convertLevelFromString(const std::string& s);

    private:

        /** @brief sd-bus callback for get-property 'Id' */
        static int _callback_get_Id(
            sd_bus*, const char*, const char*, const char*,
            sd_bus_message*, void*, sd_bus_error*);
        /** @brief sd-bus callback for set-property 'Id' */
        static int _callback_set_Id(
            sd_bus*, const char*, const char*, const char*,
            sd_bus_message*, void*, sd_bus_error*);

        /** @brief sd-bus callback for get-property 'Timestamp' */
        static int _callback_get_Timestamp(
            sd_bus*, const char*, const char*, const char*,
            sd_bus_message*, void*, sd_bus_error*);
        /** @brief sd-bus callback for set-property 'Timestamp' */
        static int _callback_set_Timestamp(
            sd_bus*, const char*, const char*, const char*,
            sd_bus_message*, void*, sd_bus_error*);

        /** @brief sd-bus callback for get-property 'Severity' */
        static int _callback_get_Severity(
            sd_bus*, const char*, const char*, const char*,
            sd_bus_message*, void*, sd_bus_error*);
        /** @brief sd-bus callback for set-property 'Severity' */
        static int _callback_set_Severity(
            sd_bus*, const char*, const char*, const char*,
            sd_bus_message*, void*, sd_bus_error*);

        /** @brief sd-bus callback for get-property 'Message' */
        static int _callback_get_Message(
            sd_bus*, const char*, const char*, const char*,
            sd_bus_message*, void*, sd_bus_error*);
        /** @brief sd-bus callback for set-property 'Message' */
        static int _callback_set_Message(
            sd_bus*, const char*, const char*, const char*,
            sd_bus_message*, void*, sd_bus_error*);

        /** @brief sd-bus callback for get-property 'AdditionalData' */
        static int _callback_get_AdditionalData(
            sd_bus*, const char*, const char*, const char*,
            sd_bus_message*, void*, sd_bus_error*);
        /** @brief sd-bus callback for set-property 'AdditionalData' */
        static int _callback_set_AdditionalData(
            sd_bus*, const char*, const char*, const char*,
            sd_bus_message*, void*, sd_bus_error*);

        /** @brief sd-bus callback for get-property 'Resolved' */
        static int _callback_get_Resolved(
            sd_bus*, const char*, const char*, const char*,
            sd_bus_message*, void*, sd_bus_error*);
        /** @brief sd-bus callback for set-property 'Resolved' */
        static int _callback_set_Resolved(
            sd_bus*, const char*, const char*, const char*,
            sd_bus_message*, void*, sd_bus_error*);


        static constexpr auto _interface = "xyz.openbmc_project.Logging.Entry";
        static const vtable::vtable_t _vtable[];
        sdbusplus::server::interface::interface
                _xyz_openbmc_project_Logging_Entry_interface;
        sdbusplus::SdBusInterface *_intf;

        uint32_t _id{};
        uint64_t _timestamp{};
        Level _severity{};
        std::string _message{};
        std::vector<std::string> _additionalData{};
        bool _resolved{};

};

/* Specialization of sdbusplus::server::bindings::details::convertForMessage
 * for enum-type Entry::Level.
 *
 * This converts from the enum to a constant c-string representing the enum.
 *
 * @param[in] e - Enum value to convert.
 * @return C-string representing the name for the enum value.
 */
std::string convertForMessage(Entry::Level e);

} // namespace server
} // namespace Logging
} // namespace openbmc_project
} // namespace xyz
} // namespace sdbusplus


#include <ipmid/api.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/process/child.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <chrono>
#include <commandutils.hpp>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <ipmid/api.hpp>
#include <map>
#include <random>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/server/object.hpp>
#include <sdbusplus/timer.hpp>
#include <sstream>

static void register_netfn_firmware_functions() __attribute__((constructor));

// oem return code for firmware update control
constexpr ipmi_ret_t IPMI_CC_REQ_INVALID_PHASE = 0xd5;
constexpr ipmi_ret_t IPMI_CC_USB_ATTACH_FAIL = 0x80;

static sdbusplus::bus::bus _bus(ipmid_get_sd_bus_connection());

static constexpr bool DEBUG = false;

static constexpr char FW_UPDATE_SERVER_DBUS_NAME[] =
    "xyz.openbmc_project.fwupdate1.server";

static constexpr char FW_UPDATE_SERVER_PATH[] =
    "/xyz/openbmc_project/fwupdate1";
static constexpr char FW_UPDATE_SERVER_INFO_PATH[] =
    "/xyz/openbmc_project/fwupdate1/info";
static constexpr char FW_UPDATE_ACTIVE_INFO_PATH[] =
    "/xyz/openbmc_project/fwupdate1/info/bmc_active";
static constexpr char FW_UPDATE_BACKUP_INFO_PATH[] =
    "/xyz/openbmc_project/fwupdate1/info/bmc_backup";

static constexpr char FW_UPDATE_INTERFACE[] = "xyz.openbmc_project.fwupdate1";
static constexpr char FW_UPDATE_INFO_INTERFACE[] =
    "xyz.openbmc_project.fwupdate1.fwinfo";
static constexpr char FW_UPDATE_SECURITY_INTERFACE[] =
    "xyz.openbmc_project.fwupdate1.security";

constexpr std::size_t operator""_MB(unsigned long long v)
{
    return 1024u * 1024u * v;
}
static constexpr int FIRMWARE_BUFFER_MAX_SIZE = 32_MB;

static constexpr char FIRMWARE_BUFFER_FILE[] = "/tmp/fw-download.bin";
static bool local_download_is_active(void)
{
    struct stat sb;
    if (stat(FIRMWARE_BUFFER_FILE, &sb) < 0)
        return false;
    return true;
}

class fw_update_status_cache
{
  public:
    enum
    {
        FW_STATE_INIT = 0,
        FW_STATE_IDLE,
        FW_STATE_DOWNLOAD,
        FW_STATE_VERIFY,
        FW_STATE_WRITE,
        FW_STATE_READY,
        FW_STATE_ERROR = 0x0f,
        FW_STATE_AC_CYCLE_REQUIRED = 0x83,
    };
    fw_update_status_cache()
    {
        _match = std::make_shared<sdbusplus::bus::match::match>(
            _bus,
            sdbusplus::bus::match::rules::propertiesChanged(
                FW_UPDATE_SERVER_PATH, FW_UPDATE_INTERFACE),
            [&](sdbusplus::message::message &msg) {
                if (DEBUG)
                    std::cerr << "propertiesChanged lambda\n";
                std::map<std::string, ipmi::DbusVariant> props;
                std::vector<std::string> inval;
                std::string iface;
                msg.read(iface, props, inval);
                _parse_props(props);
            });
        _initial_fetch();
    }

    uint8_t state()
    {
        if (DEBUG)
            std::cerr << "fw-state: 0x" << std::hex << (int)_state << '\n';
        if ((_state == FW_STATE_IDLE || _state == FW_STATE_INIT) &&
            local_download_is_active())
        {
            _state = FW_STATE_DOWNLOAD;
            _percent = 0;
        }
        return _state;
    }
    uint8_t percent()
    {
        return _percent;
    }
    std::string msg()
    {
        return _msg;
    }
#ifdef UPDATER_ENABLED
    std::string get_software_obj_path()
    {
        return _software_obj_path;
    }
    void set_software_obj_path(std::string &obj_path)
    {
        _software_obj_path = obj_path;
        _state = FW_STATE_WRITE;
        _percent = 0;
        _match = std::make_shared<sdbusplus::bus::match::match>(
            _bus,
            sdbusplus::bus::match::rules::propertiesChanged(
                _software_obj_path,
                "xyz.openbmc_project.Software.ActivationProgress"),
            [&](sdbusplus::message::message &msg) {
                if (DEBUG)
                    std::cerr << "propertiesChanged lambda\n";
                std::map<std::string, ipmi::DbusVariant> props;
                std::vector<std::string> inval;
                std::string iface;
                msg.read(iface, props, inval);
                _parse_props(props);
            });
    }
    uint8_t activation_timer_timeout()
    {
        std::cerr << "activation_timer_timout(): increase percentage...\n";
        _percent = _percent + 5;
        std::cerr << "_percent = " << std::string((char *)&_percent) << "\n";
        return _percent;
    }
#endif
  protected:
    void _parse_props(std::map<std::string, ipmi::DbusVariant> &properties)
    {
        if (DEBUG)
            std::cerr << "propertiesChanged (" << properties.size()
                      << " elements)";
        for (const auto &t : properties)
        {
            auto key = t.first;
            auto value = t.second;
            if (key == "state")
            {
                auto state =
                    sdbusplus::message::variant_ns::get<std::string>(value);
                if (DEBUG)
                    std::cerr << ", state=" << state;
                if (state == "INIT")
                    _state = FW_STATE_INIT;
                else if (state == "IDLE")
                    _state = FW_STATE_IDLE;
                else if (state == "DOWNLOAD")
                    _state = FW_STATE_DOWNLOAD;
                else if (state == "VERIFY")
                    _state = FW_STATE_VERIFY;
                else if (state == "WRITE")
                    _state = FW_STATE_WRITE;
                else if (state == "READY")
                    _state = FW_STATE_READY;
                else if (state == "ERROR")
                    _state = FW_STATE_ERROR;
                else if (state == "AC_CYCLE_REQUIRED")
                    _state = FW_STATE_AC_CYCLE_REQUIRED;
                else
                {
                    _state = FW_STATE_ERROR;
                    _msg = "internal error";
                }
            }
            else if (key == "percent")
            {
                _percent = sdbusplus::message::variant_ns::get<int32_t>(value);
                if (DEBUG)
                    std::cerr << ", pct=" << (int)_percent;
            }
            else if (key == "msg")
            {
                _msg = sdbusplus::message::variant_ns::get<std::string>(value);
                if (DEBUG)
                    std::cerr << ", msg='" << _msg << '\'';
            }
            else if (key == "Progress")
            {
                _percent = sdbusplus::message::variant_ns::get<uint8_t>(value);
                ;
                if (_percent == 100)
                    _state = FW_STATE_READY;
            }
        }
        if ((_state == FW_STATE_IDLE || _state == FW_STATE_INIT) &&
            local_download_is_active())
        {
            _state = FW_STATE_DOWNLOAD;
            _percent = 0;
        }
        if (DEBUG)
            std::cerr << '\n';
    }
    void _initial_fetch()
    {
#ifndef UPDATER_ENABLED
        auto method = _bus.new_method_call(
            FW_UPDATE_SERVER_DBUS_NAME, FW_UPDATE_SERVER_PATH,
            "org.freedesktop.DBus.Properties", "GetAll");
        method.append(FW_UPDATE_INTERFACE);
        if (DEBUG)
            std::cerr << "fetch fw status via dbus...\n";
        try
        {
            auto reply = _bus.call(method);

            std::map<std::string, ipmi::DbusVariant> properties;
            reply.read(properties);
            _parse_props(properties);
        }
        catch (sdbusplus::exception::SdBusError &e)
        {
            std::cerr << "Failed in _initial_fetch(): SDBus Error: " << e.what()
                      << "\n";
            return;
        }
#endif
    }

    std::shared_ptr<sdbusplus::bus::match::match> _match;
    uint8_t _state = 0;
    uint8_t _percent = 0;
    std::string _msg;

  private:
    std::string _software_obj_path;
};

static fw_update_status_cache fw_update_status;

static std::chrono::steady_clock::time_point fw_random_number_timestamp;
static constexpr int FW_RANDOM_NUMBER_LENGTH = 8;
static constexpr auto FW_RANDOM_NUMBER_TTL = std::chrono::seconds(30);
static uint8_t fw_random_number[FW_RANDOM_NUMBER_LENGTH];

static ipmi_ret_t ipmi_firmware_get_fw_random_number(
    ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_request_t request,
    ipmi_response_t response, ipmi_data_len_t data_len, ipmi_context_t context)
{
    std::random_device rd;
    std::default_random_engine gen(rd());
    std::uniform_int_distribution<> dist{0, 255};

    if (*data_len != 0)
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    fw_random_number_timestamp = std::chrono::steady_clock::now();

    uint8_t *msg_reply = static_cast<uint8_t *>(response);
    for (int i = 0; i < FW_RANDOM_NUMBER_LENGTH; i++)
        fw_random_number[i] = msg_reply[i] = dist(gen);

    if (DEBUG)
        std::cerr << "FW Rand Num: 0x" << std::hex << (int)msg_reply[0] << " 0x"
                  << (int)msg_reply[1] << " 0x" << (int)msg_reply[2] << " 0x"
                  << (int)msg_reply[3] << " 0x" << (int)msg_reply[4] << " 0x"
                  << (int)msg_reply[5] << " 0x" << (int)msg_reply[6] << " 0x"
                  << (int)msg_reply[7] << '\n';

    *data_len = FW_RANDOM_NUMBER_LENGTH;

    return IPMI_CC_OK;
}

static ipmi_ret_t ipmi_firmware_enter_fw_transfer_mode(
    ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_request_t request,
    ipmi_response_t response, ipmi_data_len_t data_len, ipmi_context_t context)
{
    if (DEBUG)
        std::cerr << "Enter FW transfer mode requested, data_len = "
                  << *data_len << '\n';

    if (*data_len != FW_RANDOM_NUMBER_LENGTH)
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    *data_len = 0;

    auto rq_time = std::chrono::steady_clock::now();
    if (DEBUG)
        std::cerr << "now - fwts = "
                  << std::chrono::duration_cast<std::chrono::microseconds>(
                         rq_time - fw_random_number_timestamp)
                         .count()
                  << " us\n";
    if (std::chrono::duration_cast<std::chrono::microseconds>(
            rq_time - fw_random_number_timestamp)
            .count() > std::chrono::duration_cast<std::chrono::microseconds>(
                           FW_RANDOM_NUMBER_TTL)
                           .count())
    {
        if (DEBUG)
            std::cerr << "key timeout\n";
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    uint8_t *msg_request = static_cast<uint8_t *>(request);
    for (int i = 0; i < FW_RANDOM_NUMBER_LENGTH; i++)
    {
        if (fw_random_number[i] != msg_request[i])
        {
            if (DEBUG)
                std::cerr << "key error" << (int)fw_random_number[i]
                          << "!=" << (int)msg_request[i] << "\n";
            return IPMI_CC_INVALID_FIELD_REQUEST;
        }
    }

    if (fw_update_status.state() != fw_update_status_cache::FW_STATE_IDLE
        // TODO: Allowing FW_STATE_INIT here to let image activation available
        // without being in FW_STATE_IDLE, need to fix/adjust the state machine
        // to match xyz.openbmc_project.Software.BMC.Updater service activation
        // mechanism at finer grain
        && fw_update_status.state() != fw_update_status_cache::FW_STATE_INIT)
    {
        if (DEBUG)
            std::cerr << "not in INIT or IDLE\n";
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    // FIXME? c++ doesn't off an option for exclusive file creation
    FILE *fp = fopen(FIRMWARE_BUFFER_FILE, "wx");
    if (!fp)
    {
        if (DEBUG)
            std::cerr << "failed to create buffer file\n";
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    fclose(fp);

    return IPMI_CC_OK;
}

/** @brief implements exit firmware update mode command
 *  @param None
 *
 *  @returns IPMI completion code
 */
ipmi::RspType<> ipmiFirmwareExitFwUpdateMode()
{

    if (DEBUG)
    {
        std::cerr << "Exit FW update mode \n";
    }

    switch (fw_update_status.state())
    {
        case fw_update_status_cache::FW_STATE_INIT:
        case fw_update_status_cache::FW_STATE_IDLE:
            return ipmi::responseInvalidFieldRequest();
            break;
        case fw_update_status_cache::FW_STATE_DOWNLOAD:
            unlink(FIRMWARE_BUFFER_FILE);
        case fw_update_status_cache::FW_STATE_VERIFY:
            break;
        case fw_update_status_cache::FW_STATE_WRITE:
            return ipmi::responseInvalidFieldRequest();
            break;
        case fw_update_status_cache::FW_STATE_READY:
        case fw_update_status_cache::FW_STATE_ERROR:
            unlink(FIRMWARE_BUFFER_FILE);
            break;
        case fw_update_status_cache::FW_STATE_AC_CYCLE_REQUIRED:
            return ipmi::responseInvalidFieldRequest();
            break;
    }
    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
    // attempt to reset the state machine -- this may fail
    auto method =
        bus->new_method_call(FW_UPDATE_SERVER_DBUS_NAME, FW_UPDATE_SERVER_PATH,
                             "org.freedesktop.DBus.Properties", "Abort");
    try
    {
        auto reply = bus->call(method);
        ipmi::DbusVariant retval;
        reply.read(retval);
        if (std::get<int>(retval) != 0)
        {
            return ipmi::responseInvalidFieldRequest();
        }
    }
    catch (sdbusplus::exception::SdBusError &e)
    {
        std::cerr << "SDBus Error: " << e.what() << "\n";
        return ipmi::responseUnspecifiedError();
    }
    return ipmi::responseSuccess();
}

static void post_transfer_complete_handler(
    std::unique_ptr<sdbusplus::bus::match::match> &fw_update_matcher);
static bool request_start_firmware_update(const std::string &uri)
{
    if (DEBUG)
        std::cerr << "request start firmware update()\n";

#ifdef UPDATER_ENABLED
    // fwupdate URIs start with file:// or usb:// or tftp:// etc. By the time
    // the code gets to this point, the file should be transferred start the
    // request (creating a new file in /tmp/images causes the update manager to
    // check if it is ready for activation)
    static std::unique_ptr<sdbusplus::bus::match::match> fw_update_matcher;
    post_transfer_complete_handler(fw_update_matcher);
    std::filesystem::rename(
        uri, "/tmp/images/" +
                 boost::uuids::to_string(boost::uuids::random_generator()()));
#else
    auto method =
        _bus.new_method_call(FW_UPDATE_SERVER_DBUS_NAME, FW_UPDATE_SERVER_PATH,
                             FW_UPDATE_INTERFACE, "start");
    if (DEBUG)
        std::cerr << "fwupdate1.start: " << uri << '\n';
    method.append(uri);
    try
    {
        auto reply = _bus.call(method);

        uint32_t retval;
        reply.read(retval);
        if (retval != 0)
        {
            if (DEBUG)
                std::cerr << "method returned non-zero: " << retval << "\n";
            return false;
        }
        return true;
    }
    catch (sdbusplus::exception::SdBusError &e)
    {
        std::cerr << "SDBus Error: " << e.what();
        return false;
    }
#endif
    return true;
}

static bool request_abort_firmware_update()
{
    auto method =
        _bus.new_method_call(FW_UPDATE_SERVER_DBUS_NAME, FW_UPDATE_SERVER_PATH,
                             FW_UPDATE_INTERFACE, "abort");
    try
    {
        auto reply = _bus.call(method);

        unlink(FIRMWARE_BUFFER_FILE);
        uint32_t retval;
        reply.read(retval);
        if (retval != 0)
            return false;
    }
    catch (sdbusplus::exception::SdBusError &e)
    {
        std::cerr << "SDBus Error: " << e.what() << "\n";
        unlink(FIRMWARE_BUFFER_FILE);
        return false;
    }
    return true;
}

class transfer_hash_check
{
  public:
    enum hash_check
    {
        CHECK_NOT_REQUESTED = 0,
        CHECK_REQUESTED,
        CHECK_PASSED_SHA2,
        CHECK_RESVD1,
        CHECK_FAILED_SHA2 = 0xe2,
        CHECK_RESVD2 = 0xe3,
    };

  protected:
    EVP_MD_CTX *_ctx;
    std::vector<uint8_t> _expected;
    enum hash_check _check;
    bool _started;

  public:
    transfer_hash_check() : _check(CHECK_NOT_REQUESTED), _started(false)
    {
    }
    ~transfer_hash_check()
    {
        if (_ctx)
        {
            EVP_MD_CTX_destroy(_ctx);
            _ctx = NULL;
        }
    }
    void init(const std::vector<uint8_t> &expected)
    {
        _expected = expected;
        _check = CHECK_REQUESTED;
        _ctx = EVP_MD_CTX_create();
        EVP_DigestInit(_ctx, EVP_sha256());
    }
    void hash(const std::vector<uint8_t> &data)
    {
        if (!_started)
            _started = true;
        EVP_DigestUpdate(_ctx, data.data(), data.size());
    }
    void clear()
    {
        // if not started, nothing to clear
        if (_started)
        {
            if (_ctx)
                EVP_MD_CTX_destroy(_ctx);
            if (_check != CHECK_NOT_REQUESTED)
                _check = CHECK_REQUESTED;
            _ctx = EVP_MD_CTX_create();
            EVP_DigestInit(_ctx, EVP_sha256());
        }
    }
    enum hash_check check()
    {
        if (_check == CHECK_REQUESTED)
        {
            unsigned int len;
            std::vector<uint8_t> digest(EVP_MD_size(EVP_sha256()));
            EVP_DigestFinal(_ctx, digest.data(), &len);
            if (digest == _expected)
            {
                if (DEBUG)
                    std::cerr << "transfer sha2 check passed\n";
                _check = CHECK_PASSED_SHA2;
            }
            else
            {
                if (DEBUG)
                    std::cerr << "transfer sha2 check failed\n";
                _check = CHECK_FAILED_SHA2;
            }
        }
        return _check;
    }
    uint8_t status() const
    {
        return static_cast<uint8_t>(_check);
    }
};

std::shared_ptr<transfer_hash_check> xfer_hash_check;

#ifdef UPDATER_ENABLED
static void activate_image(const char *obj_path)
{
    if (DEBUG)
    {
        std::cerr << "activateImage()...\n";
        std::cerr << "obj_path = " << obj_path << "\n";
    }
    auto method_call = _bus.new_method_call(
        "xyz.openbmc_project.Software.BMC.Updater", obj_path,
        "org.freedesktop.DBus.Properties", "Set");
    method_call.append("xyz.openbmc_project.Software.Activation",
                       "RequestedActivation",
                       sdbusplus::message::variant<std::string>(
                           "xyz.openbmc_project.Software.Activation."
                           "RequestedActivations.Active"));

    try
    {
        auto method_call_reply = _bus.call(method_call);
    }
    catch (sdbusplus::exception::SdBusError &e)
    {
        std::cerr << "Failed in activate_image(): SDBus Error: " << e.what()
                  << "\n";
        return;
    }
}

static void post_transfer_complete_handler(
    std::unique_ptr<sdbusplus::bus::match::match> &fw_update_matcher)
{
    // Setup timer for watching signal
    static phosphor::Timer timer(
        [&fw_update_matcher]() { fw_update_matcher = nullptr; });

    static phosphor::Timer activation_status_timer([]() {
        if (fw_update_status.activation_timer_timeout() >= 95)
        {
            activation_status_timer.stop();
        }
    });

    timer.start(std::chrono::microseconds(5000000), false);

    // callback function for capturing signal
    auto callback = [&fw_update_matcher](sdbusplus::message::message &m) {
        if (DEBUG)
            std::cerr << "[complete] Match fired\n";
        bool flag = false;

        std::vector<std::pair<
            std::string,
            std::vector<std::pair<std::string,
                                  sdbusplus::message::variant<std::string>>>>>
            interfaces_properties;

        sdbusplus::message::object_path obj_path;

        try
        {
            m.read(obj_path, interfaces_properties); // Read in the object path
                                                     // that was just created
        }
        catch (std::exception &e)
        {
            std::cerr
                << "[complete] Failed at post_transfer_complete-handler : "
                << e.what() << "\n";
        }
        // constructing response message
        if (DEBUG)
            std::cerr << "[complete] obj path = " << obj_path.str << "\n";
        for (auto &interface : interfaces_properties)
        {
            if (DEBUG)
                std::cerr << "[complete] interface = " << interface.first
                          << "\n";

            if (interface.first == "xyz.openbmc_project.Software.Activation")
            {
                // cancel timer only when
                // xyz.openbmc_project.Software.Activation interface is
                // added

                if (DEBUG)
                    std::cerr << "[complete] Attempt to cancel timer...\n";
                try
                {
                    timer.stop();
                    activation_status_timer.start(
                        std::chrono::microseconds(3000000), true);
                }
                catch (std::exception &e)
                {
                    std::cerr << "[complete] cancel timer error: " << e.what()
                              << "\n";
                }

                fw_update_status.set_software_obj_path(obj_path.str);
                activate_image(obj_path.str.c_str());
                if (DEBUG)
                    std::cerr << "[complete] returned from activeImage()\n";

                fw_update_matcher = nullptr;
            }
        }
    };

    // Adding matcher
    fw_update_matcher = std::make_unique<sdbusplus::bus::match::match>(
        _bus,
        "interface='org.freedesktop.DBus.ObjectManager',type='signal',"
        "member='InterfacesAdded',path='/xyz/openbmc_project/software'",
        callback);
}
#endif

class MappedFile
{
  public:
    MappedFile(const std::string &fname) : addr(nullptr), fsize(0)
    {
        std::error_code ec;
        size_t sz = std::filesystem::file_size(fname, ec);
        int fd = open(fname.c_str(), O_RDONLY);
        if (!ec || fd < 0)
        {
            return;
        }
        void *tmp = mmap(NULL, sz, PROT_READ, MAP_SHARED, fd, 0);
        close(fd);
        if (tmp == MAP_FAILED)
        {
            return;
        }
        addr = tmp;
        fsize = sz;
    }

    ~MappedFile()
    {
        if (addr)
        {
            munmap(addr, fsize);
        }
    }
    const uint8_t *data() const
    {
        return static_cast<const uint8_t *>(addr);
    }
    size_t size() const
    {
        return fsize;
    }

  private:
    size_t fsize;
    void *addr;
};

static int transfer_from_file(const std::string &uri, bool move = true)
{
    std::error_code ec;
    if (DEBUG)
        std::cerr << "transfer_from_file(" << uri << ")\n";
    if (move)
    {
        std::filesystem::rename(uri, FIRMWARE_BUFFER_FILE, ec);
    }
    else
    {
        std::filesystem::copy(uri, FIRMWARE_BUFFER_FILE,
                              std::filesystem::copy_options::overwrite_existing,
                              ec);
    }
    if (xfer_hash_check)
    {
        MappedFile mappedfw(uri);
        xfer_hash_check->hash(
            {mappedfw.data(), mappedfw.data() + mappedfw.size()});
    }
    if (ec.value())
    {
        std::cerr << "cp/mv returns: " << ec.message() << "(" << ec.value()
                  << ")\n";
    }
    return ec.value();
}

template <typename... ArgTypes>
static int executeCmd(const char *path, ArgTypes &&... tArgs)
{
    boost::process::child execProg(path, const_cast<char *>(tArgs)...);
    execProg.wait();
    return execProg.exit_code();
}

constexpr char USB_CTRL_PATH[] = "/usr/bin/usb-ctrl";
constexpr char FWUPDATE_MOUNT_POINT[] = "/tmp/usb-fwupd.mnt";
constexpr char FWUPDATE_USB_VOL_IMG[] = "/tmp/usb-fwupd.img";
constexpr char FWUPDATE_USB_DEV_NAME[] = "fw-usb-mass-storage-dev";
constexpr size_t fwPathMaxLength = 255;
static int transfer_from_usb(const std::string &uri)
{
    int ret, sysret;
    char fwpath[fwPathMaxLength];
    if (DEBUG)
        std::cerr << "transfer_from_usb(" << uri << ")\n";
    ret = executeCmd(USB_CTRL_PATH, "mount", FWUPDATE_USB_VOL_IMG,
                     FWUPDATE_MOUNT_POINT);
    if (ret)
    {
        return ret;
    }

    std::string usb_path = std::string(FWUPDATE_MOUNT_POINT) + "/" + uri;
    ret = transfer_from_file(usb_path, false);

    executeCmd(USB_CTRL_PATH, "cleanup", FWUPDATE_USB_VOL_IMG,
               FWUPDATE_MOUNT_POINT);
    return ret;
}

static bool transfer_firmware_from_uri(const std::string &uri)
{
    static constexpr char FW_URI_FILE[] = "file://";
    static constexpr char FW_URI_USB[] = "usb://";
    if (DEBUG)
        std::cerr << "transfer_firmware_from_uri(" << uri << ")\n";
    if (boost::algorithm::starts_with(uri, FW_URI_FILE))
    {
        std::string fname = uri.substr(sizeof(FW_URI_FILE) - 1);
        if (fname != FIRMWARE_BUFFER_FILE)
        {
            return 0 == transfer_from_file(fname);
        }
        return true;
    }
    if (boost::algorithm::starts_with(uri, FW_URI_USB))
    {
        std::string fname = uri.substr(sizeof(FW_URI_USB) - 1);
        return 0 == transfer_from_usb(fname);
    }
    return false;
}

/* Get USB-mass-storage device status: inserted => true, ejected => false */
static int usb_get_status()
{
    static constexpr char usb_gadget_base[] = "/sys/kernel/config/usb_gadget/";
    auto usb_device =
        std::filesystem::path(usb_gadget_base) / FWUPDATE_USB_DEV_NAME;
    std::error_code ec;
    return std::filesystem::exists(usb_device, ec) && !ec;
}

/* Insert the USB-mass-storage device status: success => 0, failure => non-0 */
static int usb_attach_device()
{
    if (usb_get_status())
    {
        return 1;
    }
    int ret =
        executeCmd(USB_CTRL_PATH, "setup", FWUPDATE_USB_VOL_IMG,
                   std::to_string(FIRMWARE_BUFFER_MAX_SIZE / 1_MB).c_str());
    if (!ret)
    {
        ret = executeCmd(USB_CTRL_PATH, "insert", FWUPDATE_USB_DEV_NAME,
                         FWUPDATE_USB_VOL_IMG);
    }
    return ret;
}

/* Eject the USB-mass-storage device status: success => 0, failure => non-0 */
static int usb_detach_device()
{
    if (!usb_get_status())
    {
        return 1;
    }
    return executeCmd(USB_CTRL_PATH, "eject", FWUPDATE_USB_DEV_NAME);
}

constexpr uint8_t controls_init = 0x00;
constexpr uint8_t controls_transfer_started = 0x01;
constexpr uint8_t controls_transfer_completed = 0x02;
constexpr uint8_t controls_transfer_aborted = 0x04;
constexpr uint8_t controls_usb_attached = 0x08;

struct fw_update_control_request
{
    enum knob
    {
        CTRL_GET = 0,
        CTRL_XFER_START,
        CTRL_XFER_COMPLETE,
        CTRL_XFER_ABORT,
        CTRL_SET_FILENAME,
        CTRL_USB_ATTACH,
        CTRL_USB_DETACH,
    } __attribute__((packed));
    enum knob control;
    uint8_t nlen;
    char filename[fwPathMaxLength];
} __attribute__((packed));

static ipmi_ret_t ipmi_firmware_control(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                        ipmi_request_t request,
                                        ipmi_response_t response,
                                        ipmi_data_len_t data_len,
                                        ipmi_context_t context)
{
    static std::string fw_xfer_uri;

    if (DEBUG)
        std::cerr << "FW update control\n";
    *data_len = 0;

    static uint8_t controls = controls_init;
    ipmi_ret_t rc = IPMI_CC_OK;
    auto ctrl_req = reinterpret_cast<fw_update_control_request *>(request);
    auto ctrl_resp = reinterpret_cast<uint8_t *>(response);

    if (usb_get_status())
    {
        controls |= controls_usb_attached;
    }
    else
    {
        controls &= ~controls_usb_attached;
    }

    switch (ctrl_req->control)
    {
        case fw_update_control_request::CTRL_GET:
            break;
        case fw_update_control_request::CTRL_XFER_START:
        {
            controls |= controls_transfer_started;
            // reset buffer to empty (truncate file)
            std::ofstream out(FIRMWARE_BUFFER_FILE,
                              std::ofstream::binary | std::ofstream::trunc);
            fw_xfer_uri = std::string("file://") + FIRMWARE_BUFFER_FILE;
            if (xfer_hash_check)
            {
                xfer_hash_check->clear();
            }
            if (DEBUG)
                std::cerr << "transfer start\n";
        }
        break;
        case fw_update_control_request::CTRL_XFER_COMPLETE:
        {
            if (usb_get_status())
            {
                rc = IPMI_CC_REQ_INVALID_PHASE;
            }
            // finish transfer based on URI
            if (!transfer_firmware_from_uri(fw_xfer_uri))
            {
                rc = IPMI_CC_UNSPECIFIED_ERROR;
                break;
            }
            // transfer complete
            if (xfer_hash_check)
            {
                if (transfer_hash_check::CHECK_PASSED_SHA2 !=
                    xfer_hash_check->check())
                {
                    if (DEBUG)
                        std::cerr << "xfer_hash_check returns not "
                                     "CHECK_PASSED_SHA2\n";
                    rc = IPMI_CC_UNSPECIFIED_ERROR;
                    break;
                }
            }
            // start the request
            if (!request_start_firmware_update(FIRMWARE_BUFFER_FILE))
            {
                if (DEBUG)
                    std::cerr
                        << "request_start_firmware_update returns failure\n";
                rc = IPMI_CC_UNSPECIFIED_ERROR;
            }
            if (rc == IPMI_CC_OK)
            {
                controls |= controls_transfer_completed;
            }
        }
        break;
        case fw_update_control_request::CTRL_XFER_ABORT:
            if (DEBUG)
                std::cerr << "send abort request\n";
            if (usb_get_status())
            {
                if (0 != usb_detach_device())
                {
                    rc = IPMI_CC_USB_ATTACH_FAIL;
                }
            }
            if (!request_abort_firmware_update())
            {
                if (DEBUG)
                    std::cerr
                        << "abort_start_firmware_update returns failure\n";
                rc = IPMI_CC_UNSPECIFIED_ERROR;
            }
            controls |= controls_transfer_aborted;
            break;
        case fw_update_control_request::CTRL_SET_FILENAME:
            fw_xfer_uri.clear();
            fw_xfer_uri.insert(0, ctrl_req->filename, ctrl_req->nlen);
            break;
        case fw_update_control_request::CTRL_USB_ATTACH:
            if (usb_get_status())
            {
                rc = IPMI_CC_INVALID_FIELD_REQUEST;
            }
            else if (0 != usb_attach_device())
            {
                rc = IPMI_CC_USB_ATTACH_FAIL;
            }
            else
            {
                rc = IPMI_CC_OK;
            }
            break;
        case fw_update_control_request::CTRL_USB_DETACH:
            if (!usb_get_status())
            {
                rc = IPMI_CC_INVALID_FIELD_REQUEST;
            }
            if (0 != usb_detach_device())
            {
                rc = IPMI_CC_USB_ATTACH_FAIL;
            }
            else
            {
                rc = IPMI_CC_OK;
            }
            break;
        default:
            if (DEBUG)
                std::cerr << "control byte " << std::hex << ctrl_req->control
                          << " unknown\n";
            rc = IPMI_CC_INVALID_FIELD_REQUEST;
            break;
    }

    if (rc == IPMI_CC_OK)
    {
        *ctrl_resp = controls;
        *data_len = sizeof(*ctrl_resp);
    }

    return rc;
}

struct fw_version_info
{
    uint8_t id_tag;
    uint8_t major;
    uint8_t minor;
    uint32_t build;
    uint32_t build_time;
    uint32_t update_time;
} __attribute__((packed));

static ipmi_ret_t ipmi_firmware_get_fw_version_info(
    ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_request_t request,
    ipmi_response_t response, ipmi_data_len_t data_len, ipmi_context_t context)
{
    if (DEBUG)
        std::cerr << "Get FW Version Info\n";

    // Byte 1 - Count (N) Number of devices data is being returned for.
    // Byte 2 - ID Tag 00 – reserved 01 – BMC Active Image 02 – BBU Active Image
    //                 03 – BMC Backup Image 04 – BBU Backup Image 05 – BBR
    //                 Image
    // Byte 3 - Major Version Number
    // Byte 4 - Minor Version Number
    // Bytes 5:8 - Build Number
    // Bytes 9:12 - Build Timestamp Format: LSB first, same format as SEL
    // timestamp
    // Bytes 13:16 - Update Timestamp
    // Bytes - 17:(15xN) - Repeat of 2 through 16

    uint8_t count = 0;
    auto ret_count = reinterpret_cast<uint8_t *>(response);
    auto info = reinterpret_cast<struct fw_version_info *>(ret_count + 1);

    for (uint8_t id_tag = 1; id_tag < 6; id_tag++)
    {
        const char *fw_path;
        switch (id_tag)
        {
            case 1:
                fw_path = FW_UPDATE_ACTIVE_INFO_PATH;
                break;
            case 2:
                fw_path = FW_UPDATE_BACKUP_INFO_PATH;
                break;
            case 3:
            case 4:
            case 5:
                continue; // skip for now
                break;
        }
        auto method =
            _bus.new_method_call(FW_UPDATE_SERVER_DBUS_NAME, fw_path,
                                 "org.freedesktop.DBus.Properties", "GetAll");
        method.append(FW_UPDATE_INFO_INTERFACE);
        std::vector<std::pair<std::string, ipmi::DbusVariant>> properties;
        try
        {
            auto reply = _bus.call(method);

            if (reply.is_method_error())
                continue;

            reply.read(properties);
        }
        catch (sdbusplus::exception::SdBusError &e)
        {
            std::cerr << "SDBus Error: " << e.what();
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
        uint8_t major = 0;
        uint8_t minor = 0;
        uint32_t build = 0;
        int32_t build_time = 0;
        int32_t update_time = 0;
        for (const auto &t : properties)
        {
            auto key = t.first;
            auto value = t.second;
            if (key == "version")
            {
                auto strver =
                    sdbusplus::message::variant_ns::get<std::string>(value);
                std::stringstream ss;
                ss << std::hex << strver;
                uint32_t t;
                ss >> t;
                major = t;
                ss.ignore();
                ss >> t;
                minor = t;
                ss.ignore();
                ss >> build;
            }
            else if (key == "build_time")
            {
                build_time =
                    sdbusplus::message::variant_ns::get<int32_t>(value);
            }
            else if (key == "update_time")
            {
                update_time =
                    sdbusplus::message::variant_ns::get<int32_t>(value);
            }
        }

        info->id_tag = id_tag;
        info->major = major;
        info->minor = minor;
        info->build = build;
        info->build_time = build_time;
        info->update_time = update_time;
        count++;
        info++;
    }
    *ret_count = count;

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = sizeof(count) + count * sizeof(*info);

    return rc;
}

struct fw_security_revision_info
{
    uint8_t id_tag;
    uint16_t sec_rev;
} __attribute__((packed));

static ipmi_ret_t ipmi_firmware_get_fw_security_revision(
    ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_request_t request,
    ipmi_response_t response, ipmi_data_len_t data_len, ipmi_context_t context)
{
    if (DEBUG)
        std::cerr << "Get FW security revision info\n";

    // Byte 1 - Count (N) Number of devices data is being returned for.
    // Byte 2 - ID Tag 00 – reserved 01 – BMC Active Image 02 – BBU Active Image
    //                 03 – BMC Backup Image 04 – BBU Backup Image 05 – BBR
    //                 Image
    // Byte 3 - Major Version Number
    // Byte 4 - Minor Version Number
    // Bytes 5:8 - Build Number
    // Bytes 9:12 - Build Timestamp Format: LSB first, same format as SEL
    // timestamp
    // Bytes 13:16 - Update Timestamp
    // Bytes - 17:(15xN) - Repeat of 2 through 16

    uint8_t count = 0;
    auto ret_count = reinterpret_cast<uint8_t *>(response);
    auto info =
        reinterpret_cast<struct fw_security_revision_info *>(ret_count + 1);

    for (uint8_t id_tag = 1; id_tag < 6; id_tag++)
    {
        const char *fw_path;
        switch (id_tag)
        {
            case 1:
                fw_path = FW_UPDATE_ACTIVE_INFO_PATH;
                break;
            case 2:
                fw_path = FW_UPDATE_BACKUP_INFO_PATH;
                break;
            case 3:
            case 4:
            case 5:
                continue; // skip for now
                break;
        }
        auto method =
            _bus.new_method_call(FW_UPDATE_SERVER_DBUS_NAME, fw_path,
                                 "org.freedesktop.DBus.Properties", "GetAll");
        method.append(FW_UPDATE_INFO_INTERFACE, "security_version");
        ipmi::DbusVariant sec_rev;
        try
        {
            auto reply = _bus.call(method);

            if (reply.is_method_error())
                continue;

            reply.read(sec_rev);
        }
        catch (sdbusplus::exception::SdBusError &e)
        {
            std::cerr << "SDBus Error: " << e.what();
            return IPMI_CC_UNSPECIFIED_ERROR;
        }

        info->id_tag = id_tag;
        info->sec_rev = sdbusplus::message::variant_ns::get<int>(sec_rev);
        count++;
        info++;
    }
    *ret_count = count;

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = sizeof(count) + count * sizeof(*info);

    return rc;
}

struct fw_channel_size
{
    uint8_t channel_id;
    uint32_t channel_size;
} __attribute__((packed));

enum
{
    CHANNEL_RESVD = 0,
    CHANNEL_KCS,
    CHANNEL_RMCP_PLUS,
    CHANNEL_USB_DATA,
    CHANNEL_USB_MASS_STORAGE,
} channel_transfer_type;

static ipmi_ret_t ipmi_firmware_max_transfer_size(
    ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_request_t request,
    ipmi_response_t response, ipmi_data_len_t data_len, ipmi_context_t context)
{
    if (DEBUG)
        std::cerr << "Get FW max transfer size\n";

    // Byte 1 - Count (N) Number of devices data is being returned for.
    // Byte 2 - ID Tag 00 – reserved 01 – kcs 02 – rmcp+,
    //                 03 – usb data, 04 – usb mass storage
    // Byte 3-6 - transfer size (little endian)
    // Bytes - 7:(5xN) - Repeat of 2 through 6

    uint8_t count = 0;
    auto ret_count = reinterpret_cast<uint8_t *>(response);
    auto info = reinterpret_cast<struct fw_channel_size *>(ret_count + 1);

    info->channel_id = CHANNEL_KCS;
    info->channel_size = 128;
    info++;
    count++;

    info->channel_id = CHANNEL_RMCP_PLUS;
    info->channel_size = 50 * 1024;
    info++;
    count++;

    /*
    info->channel_id = CHANNEL_USB_MASS_STORAGE;
    info->channel_size = 128;
    info++;
    count++;
    */

    *ret_count = count;

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = sizeof(count) + count * sizeof(*info);

    return rc;
}

enum
{
    EXEC_CTX_RESVD = 0,
    EXEC_CTX_FULL_LINUX = 0x10,
    EXEC_CTX_SAFE_MODE_LINUX = 0x11,
} bmc_execution_context;

struct fw_execution_context
{
    uint8_t context;
    uint8_t image_selection;
} __attribute__((packed));

static ipmi_ret_t ipmi_firmware_get_fw_execution_context(
    ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_request_t request,
    ipmi_response_t response, ipmi_data_len_t data_len, ipmi_context_t context)
{
    if (DEBUG)
        std::cerr << "Get FW execution context\n";

    // Byte 1 - execution context
    //          0x10 - full linux stack, 0x11 - safe-mode linux stack
    // Byte 2 - current image selection
    //          1 - primary, 2 - secondary

    auto info = reinterpret_cast<struct fw_execution_context *>(response);
    auto method =
        _bus.new_method_call(FW_UPDATE_SERVER_DBUS_NAME, FW_UPDATE_SERVER_PATH,
                             "org.freedesktop.DBus.Properties", "GetAll");
    method.append(FW_UPDATE_SECURITY_INTERFACE);
    int active_img;
    bool safe_mode;
    std::string cert;
    try
    {
        auto reply = _bus.call(method);

        if (!reply.is_method_error())
        {
            std::vector<std::pair<std::string, ipmi::DbusVariant>> properties;
            reply.read(properties);

            for (const auto &t : properties)
            {
                auto key = t.first;
                auto value = t.second;
                if (key == "active_partition")
                {
                    active_img =
                        sdbusplus::message::variant_ns::get<int>(value);
                }
                else if (key == "safe_mode")
                {
                    safe_mode =
                        sdbusplus::message::variant_ns::get<bool>(value);
                }
            }
        }
    }
    catch (sdbusplus::exception::SdBusError &e)
    {
        std::cerr << "SDBus Error: " << e.what();
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    if (safe_mode)
        info->context = EXEC_CTX_SAFE_MODE_LINUX;
    else
        info->context = EXEC_CTX_FULL_LINUX;

    info->image_selection = active_img;

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = sizeof(*info);

    return rc;
}

struct fw_update_status_response
{
    uint8_t status;
    uint8_t percent;
    uint8_t check;
} __attribute__((packed));

static ipmi_ret_t ipmi_firmware_get_status(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                           ipmi_request_t request,
                                           ipmi_response_t response,
                                           ipmi_data_len_t data_len,
                                           ipmi_context_t context)
{
    if (DEBUG)
        std::cerr << "Get FW update status\n";

    // Byte 1 - status (0=init, 1=idle, 2=download, 3=validate, 4=write,
    //                  5=ready, f=error, 83=ac cycle required)
    // Byte 2 - percent
    // Byte 3 - integrity check status (0=none, 1=req, 2=sha2ok, e2=sha2fail)

    auto fw_status =
        reinterpret_cast<struct fw_update_status_response *>(response);

    fw_status->status = fw_update_status.state();
    fw_status->percent = fw_update_status.percent();
    fw_status->check = xfer_hash_check ? xfer_hash_check->status() : 0;

    // Status code.
    *data_len = sizeof(*fw_status);
    return IPMI_CC_OK;
}

static constexpr uint8_t FW_UPDATE_OPTIONS_NO_DOWNREV = (1 << 0);
static constexpr uint8_t FW_UPDATE_OPTIONS_DEFER_RESTART = (1 << 1);
static constexpr uint8_t FW_UPDATE_OPTIONS_SHA2_CHECK = (1 << 2);
static constexpr uint8_t FW_UPDATE_OPTIONS_RESVD1 = (1 << 3);
struct fw_update_options_request
{
    uint8_t mask;
    uint8_t options;
} __attribute__((packed));

bool fw_update_set_dbus_property(const std::string &path,
                                 const std::string &iface,
                                 const std::string &name,
                                 ipmi::DbusVariant value)
{
    auto method =
        _bus.new_method_call(FW_UPDATE_SERVER_DBUS_NAME, path.c_str(),
                             "org.freedesktop.DBus.Properties", "Set");
    method.append(iface, name, value);
    try
    {
        auto reply = _bus.call(method);
        auto err = reply.is_method_error();
        if (err)
            if (DEBUG)
                std::cerr << "failed to set prop " << path << '/' << iface
                          << '.' << name << '\n';
        return err;
    }
    catch (sdbusplus::exception::SdBusError &e)
    {
        std::cerr << "SDBus Error: " << e.what();
        return false;
    }
}

uint32_t fw_update_options = 0;
static ipmi_ret_t ipmi_firmware_update_options(
    ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_request_t request,
    ipmi_response_t response, ipmi_data_len_t data_len, ipmi_context_t context)
{
    if (DEBUG)
        std::cerr << "Get/set FW update options\n";

    // request:
    // Byte 1 - mask
    // Byte 2 - options
    // Byte 3-34 - optional integrity check expected value
    // response:
    // Byte 1 - set options

    auto fw_options =
        reinterpret_cast<struct fw_update_options_request *>(request);

    const char *path = FW_UPDATE_SERVER_INFO_PATH;
    const char *iface = FW_UPDATE_SECURITY_INTERFACE;
    if ((fw_options->mask & FW_UPDATE_OPTIONS_NO_DOWNREV) &&
        (fw_options->options & FW_UPDATE_OPTIONS_NO_DOWNREV) !=
            (fw_update_options & FW_UPDATE_OPTIONS_NO_DOWNREV))
    {
        if (fw_options->options & FW_UPDATE_OPTIONS_NO_DOWNREV)
        {
            fw_update_options |= FW_UPDATE_OPTIONS_NO_DOWNREV;
        }
        else
        {
            fw_update_options &= ~FW_UPDATE_OPTIONS_NO_DOWNREV;
            // send dbus
        }
        const char *name = "inhibit_downgrade";
        fw_update_set_dbus_property(
            path, iface, name,
            (bool)(!!(fw_update_options & FW_UPDATE_OPTIONS_NO_DOWNREV)));
    }
    if ((fw_options->mask & FW_UPDATE_OPTIONS_DEFER_RESTART) &&
        (fw_options->options & FW_UPDATE_OPTIONS_DEFER_RESTART) !=
            (fw_update_options & FW_UPDATE_OPTIONS_DEFER_RESTART))
    {
        if (fw_options->options & FW_UPDATE_OPTIONS_DEFER_RESTART)
        {
            fw_update_options |= FW_UPDATE_OPTIONS_DEFER_RESTART;
        }
        else
        {
            fw_update_options &= ~FW_UPDATE_OPTIONS_DEFER_RESTART;
        }
        const char *name = "defer_restart";
        fw_update_set_dbus_property(
            path, iface, name,
            (bool)(!!(fw_update_options & FW_UPDATE_OPTIONS_DEFER_RESTART)));
    }
    if (fw_options->mask & FW_UPDATE_OPTIONS_SHA2_CHECK)
    {
        auto hash_size = EVP_MD_size(EVP_sha256());
        if (fw_options->options & FW_UPDATE_OPTIONS_SHA2_CHECK)
        {
            if (*data_len != (sizeof(*fw_options) + hash_size))
            {
                *data_len = 0;
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }
            xfer_hash_check = std::make_shared<transfer_hash_check>();
            auto exp_hash = reinterpret_cast<uint8_t *>(fw_options + 1);
            xfer_hash_check->init({exp_hash, exp_hash + hash_size});
            fw_update_options |= FW_UPDATE_OPTIONS_SHA2_CHECK;
        }
        else
        {
            fw_update_options &= ~FW_UPDATE_OPTIONS_SHA2_CHECK;
            // delete the xfer_hash_check object
            xfer_hash_check.reset();
        }
    }
    auto options_rsp = reinterpret_cast<uint8_t *>(response);
    *options_rsp = fw_update_options;

    if (DEBUG)
        std::cerr << "current fw_update_options = " << std::hex
                  << fw_update_options << '\n';
    // Status code.
    *data_len = sizeof(*options_rsp);
    return IPMI_CC_OK;
}

struct fw_cert_info
{
    uint16_t cert_len;
    uint64_t serial;
    uint8_t subject_len;
    char subject[255];
} __attribute__((packed));

static ipmi_ret_t ipmi_firmware_get_root_cert_info(
    ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_request_t request,
    ipmi_response_t response, ipmi_data_len_t data_len, ipmi_context_t context)
{
    if (DEBUG)
        std::cerr << "Get FW root cert info\n";

    // request:
    // Byte 1 - certificate ID: request which certificate (ignored)

    // response:
    // Byte 1-2  - certificate length (little endian)
    // Byte 3-10 - serial number (little endian)
    // Byte 11   - subject length
    // Byte 12-N - subject data

    auto cert_info = reinterpret_cast<struct fw_cert_info *>(response);
    auto method = _bus.new_method_call(
        FW_UPDATE_SERVER_DBUS_NAME, FW_UPDATE_SERVER_INFO_PATH,
        "org.freedesktop.DBus.Properties", "GetAll");
    method.append(FW_UPDATE_SECURITY_INTERFACE);
    std::string subject;
    uint64_t serial;
    std::string cert;
    try
    {
        auto reply = _bus.call(method);

        std::vector<std::pair<std::string, ipmi::DbusVariant>> properties;
        reply.read(properties);

        for (const auto &t : properties)
        {
            auto key = t.first;
            auto value = t.second;
            if (key == "certificate_subject")
            {
                subject =
                    sdbusplus::message::variant_ns::get<std::string>(value);
            }
            else if (key == "cetificate_serial")
            {
                serial = sdbusplus::message::variant_ns::get<uint64_t>(value);
            }
            else if (key == "certificate")
            {
                cert = sdbusplus::message::variant_ns::get<std::string>(value);
            }
        }
    }
    catch (sdbusplus::exception::SdBusError &e)
    {
        std::cerr << "SDBus Error: " << e.what();
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    cert_info->cert_len = cert.size();
    cert_info->serial = serial;
    // truncate subject so it fits in the 255-byte array (if necessary)
    if (subject.size() > sizeof(cert_info->subject))
        subject.resize(sizeof(cert_info->subject));
    cert_info->subject_len = subject.size();
    std::copy(subject.begin(), subject.end(), cert_info->subject);

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    // make sure to account for the *actual* size of the subject
    *data_len = sizeof(*cert_info) - sizeof(cert_info->subject) +
                cert_info->subject_len;

    return rc;
}

struct fw_cert_data_req
{
    uint8_t cert_id;
    uint16_t offset;
    uint16_t count;
} __attribute__((packed));

static ipmi_ret_t ipmi_firmware_get_root_cert_data(
    ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_request_t request,
    ipmi_response_t response, ipmi_data_len_t data_len, ipmi_context_t context)
{
    if (DEBUG)
        std::cerr << "Get FW root cert data\n";

    // request:
    // Byte 1 - certificate ID: request which certificate (ignored)
    // Byte 2-3 - offset within cert to start at
    // Byte 4-5 - number of bytes to return

    // response:
    // Byte 1-N  - certificate data

    if (*data_len != sizeof(fw_cert_data_req))
        return IPMI_CC_REQ_DATA_LEN_INVALID;

    auto cert_data_req = reinterpret_cast<struct fw_cert_data_req *>(request);
    auto method = _bus.new_method_call(
        FW_UPDATE_SERVER_DBUS_NAME, FW_UPDATE_SERVER_INFO_PATH,
        "org.freedesktop.DBus.Properties", "Get");
    method.append(FW_UPDATE_SECURITY_INTERFACE, "certificate");
    ipmi::DbusVariant cert;
    try
    {
        auto reply = _bus.call(method);
        reply.read(cert);
    }
    catch (sdbusplus::exception::SdBusError &e)
    {
        std::cerr << "SDBus Error: " << e.what();
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    auto cert_data = sdbusplus::message::variant_ns::get<std::string>(cert);

    if (cert_data_req->offset >= cert_data.size())
    {
        *data_len = 0;
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    auto first = cert_data.begin() + cert_data_req->offset;
    auto last = first + cert_data_req->count;
    if (last > cert_data.end())
        last = cert_data.end();

    auto data_out = reinterpret_cast<char *>(response);
    std::copy(first, last, data_out);

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = (last - first);

    return rc;
}

static ipmi_ret_t ipmi_firmware_write_data(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                           ipmi_request_t request,
                                           ipmi_response_t response,
                                           ipmi_data_len_t data_len,
                                           ipmi_context_t context)
{
    if (DEBUG)
        std::cerr << "write fw data (" << *data_len << " bytes)\n";

    auto bytes_in = *data_len;
    *data_len = 0;
    if (fw_update_status.state() != fw_update_status_cache::FW_STATE_DOWNLOAD)
        return IPMI_CC_INVALID;

    std::ofstream out(FIRMWARE_BUFFER_FILE,
                      std::ofstream::binary | std::ofstream::app);
    if (!out)
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    if (out.tellp() > FIRMWARE_BUFFER_MAX_SIZE)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    auto data = reinterpret_cast<uint8_t *>(request);
    out.write(reinterpret_cast<char *>(data), bytes_in);
    out.close();
    if (xfer_hash_check)
    {
        xfer_hash_check->hash({data, data + bytes_in});
    }

    // Status code.
    return IPMI_CC_OK;
}

static constexpr char NOT_IMPLEMENTED[] = "NOT IMPLEMENTED";

static ipmi_ret_t ipmi_firmware_wildcard_handler(
    ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_request_t request,
    ipmi_response_t response, ipmi_data_len_t data_len, ipmi_context_t context)
{
    if (DEBUG)
        std::cerr << "Handling stubbed Netfn:[0x" << std::hex << +netfn
                  << "], Cmd:[0x" << std::hex << +cmd << "]\n";

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;

    *data_len = sizeof(NOT_IMPLEMENTED);

    // Now pack actual response
    char *msg_reply = static_cast<char *>(response);
    std::copy(std::begin(NOT_IMPLEMENTED), std::end(NOT_IMPLEMENTED),
              msg_reply);

    return rc;
}

struct intc_app_get_buffer_size_resp
{
    uint8_t kcs_size;
    uint8_t ipmb_size;
} __attribute__((packed));

static constexpr int KCS_MAX_BUFFER_SIZE = 63;
static constexpr int IPMB_MAX_BUFFER_SIZE = 128;
static ipmi_ret_t ipmi_intel_app_get_buffer_size(
    ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_request_t request,
    ipmi_response_t response, ipmi_data_len_t data_len, ipmi_context_t context)
{
    auto msg_reply =
        reinterpret_cast<intc_app_get_buffer_size_resp *>(response);
    // for now this is hard coded; really this number is dependent on
    // the BMC kcs driver as well as the host kcs driver....
    // we can't know the latter.
    msg_reply->kcs_size = KCS_MAX_BUFFER_SIZE / 4;
    msg_reply->ipmb_size = IPMB_MAX_BUFFER_SIZE / 4;
    *data_len = sizeof(*msg_reply);

    return IPMI_CC_OK;
}

static constexpr ipmi_cmd_t IPMI_CMD_FW_GET_FW_VERSION_INFO = 0x20;
static constexpr ipmi_cmd_t IPMI_CMD_FW_GET_FW_SEC_VERSION_INFO = 0x21;
static constexpr ipmi_cmd_t IPMI_CMD_FW_GET_FW_UPD_CHAN_INFO = 0x22;
static constexpr ipmi_cmd_t IPMI_CMD_FW_GET_BMC_EXEC_CTX = 0x23;
static constexpr ipmi_cmd_t IPMI_CMD_FW_GET_ROOT_CERT_INFO = 0x24;
static constexpr ipmi_cmd_t IPMI_CMD_FW_GET_ROOT_CERT_DATA = 0x25;
static constexpr ipmi_cmd_t IPMI_CMD_FW_GET_FW_UPDATE_RAND_NUM = 0x26;
static constexpr ipmi_cmd_t IPMI_CMD_FW_SET_FW_UPDATE_MODE = 0x27;
static constexpr ipmi_cmd_t IPMI_CMD_FW_EXIT_FW_UPDATE_MODE = 0x28;
static constexpr ipmi_cmd_t IPMI_CMD_FW_UPDATE_CONTROL = 0x29;
static constexpr ipmi_cmd_t IPMI_CMD_FW_GET_STATUS = 0x2a;
static constexpr ipmi_cmd_t IPMI_CMD_FW_SET_FW_UPDATE_OPTIONS = 0x2b;
static constexpr ipmi_cmd_t IPMI_CMD_FW_IMAGE_WRITE = 0x2c;
static constexpr ipmi_cmd_t IPMI_CMD_FW_GET_TIMESTAMP = 0x2d;
static constexpr ipmi_cmd_t IPMI_CMD_FW_GET_UPDATE_ERR_MSG = 0xe0;
static constexpr ipmi_cmd_t IPMI_CMD_FW_GET_REMOTE_FW_INFO = 0xf0;

static constexpr ipmi_netfn_t NETFUN_INTC_APP = 0x30;
static constexpr ipmi_cmd_t IPMI_CMD_INTC_GET_BUFFER_SIZE = 0x66;

static void register_netfn_firmware_functions()
{
    // guarantee that we start with an already timed out timestamp
    fw_random_number_timestamp =
        std::chrono::steady_clock::now() - FW_RANDOM_NUMBER_TTL;

    unlink(FIRMWARE_BUFFER_FILE);

    // <Get BT Interface Capabilities>
    if (DEBUG)
        std::cerr << "Registering firmware update commands\n";

    // get firmware version information
    ipmi_register_callback(NETFUN_FIRMWARE, IPMI_CMD_FW_GET_FW_VERSION_INFO,
                           NULL, ipmi_firmware_get_fw_version_info,
                           PRIVILEGE_ADMIN);

    // get firmware security version information
    ipmi_register_callback(NETFUN_FIRMWARE, IPMI_CMD_FW_GET_FW_SEC_VERSION_INFO,
                           NULL, ipmi_firmware_get_fw_security_revision,
                           PRIVILEGE_ADMIN);

    // get channel information (max transfer sizes)
    ipmi_register_callback(NETFUN_FIRMWARE, IPMI_CMD_FW_GET_FW_UPD_CHAN_INFO,
                           NULL, ipmi_firmware_max_transfer_size,
                           PRIVILEGE_ADMIN);

    // get bmc execution context
    ipmi_register_callback(NETFUN_FIRMWARE, IPMI_CMD_FW_GET_BMC_EXEC_CTX, NULL,
                           ipmi_firmware_get_fw_execution_context,
                           PRIVILEGE_ADMIN);

    // get root certificate information
    ipmi_register_callback(NETFUN_FIRMWARE, IPMI_CMD_FW_GET_ROOT_CERT_INFO,
                           NULL, ipmi_firmware_get_root_cert_info,
                           PRIVILEGE_ADMIN);

    // get root certificate data
    ipmi_register_callback(NETFUN_FIRMWARE, IPMI_CMD_FW_GET_ROOT_CERT_DATA,
                           NULL, ipmi_firmware_get_root_cert_data,
                           PRIVILEGE_ADMIN);

    // generate bmc fw update random number (for enter fw tranfer mode)
    ipmi_register_callback(NETFUN_FIRMWARE, IPMI_CMD_FW_GET_FW_UPDATE_RAND_NUM,
                           NULL, ipmi_firmware_get_fw_random_number,
                           PRIVILEGE_ADMIN);

    // enter firmware update mode
    ipmi_register_callback(NETFUN_FIRMWARE, IPMI_CMD_FW_SET_FW_UPDATE_MODE,
                           NULL, ipmi_firmware_enter_fw_transfer_mode,
                           PRIVILEGE_ADMIN);

    // exit firmware update mode
    ipmi::registerHandler(ipmi::prioOemBase, NETFUN_FIRMWARE,
                          IPMI_CMD_FW_EXIT_FW_UPDATE_MODE,
                          ipmi::Privilege::Admin, ipmiFirmwareExitFwUpdateMode);

    // firmware control mechanism (set filename, usb, etc.)
    ipmi_register_callback(NETFUN_FIRMWARE, IPMI_CMD_FW_UPDATE_CONTROL, NULL,
                           ipmi_firmware_control, PRIVILEGE_ADMIN);

    // get firmware update status
    ipmi_register_callback(NETFUN_FIRMWARE, IPMI_CMD_FW_GET_STATUS, NULL,
                           ipmi_firmware_get_status, PRIVILEGE_ADMIN);

    // set firmware update options (no downgrade, etc.)
    ipmi_register_callback(NETFUN_FIRMWARE, IPMI_CMD_FW_SET_FW_UPDATE_OPTIONS,
                           NULL, ipmi_firmware_update_options, PRIVILEGE_ADMIN);

    // write image data
    ipmi_register_callback(NETFUN_FIRMWARE, IPMI_CMD_FW_IMAGE_WRITE, NULL,
                           ipmi_firmware_write_data, PRIVILEGE_ADMIN);

    // get update timestamps
    ipmi_register_callback(NETFUN_FIRMWARE, IPMI_CMD_FW_GET_TIMESTAMP, NULL,
                           ipmi_firmware_wildcard_handler, PRIVILEGE_ADMIN);

    // get error message (when in error state)
    ipmi_register_callback(NETFUN_FIRMWARE, IPMI_CMD_FW_GET_UPDATE_ERR_MSG,
                           NULL, ipmi_firmware_wildcard_handler,
                           PRIVILEGE_ADMIN);

    // get remote firmware information (PSU, HSBP, etc.)
    ipmi_register_callback(NETFUN_FIRMWARE, IPMI_CMD_FW_GET_REMOTE_FW_INFO,
                           NULL, ipmi_firmware_wildcard_handler,
                           PRIVILEGE_ADMIN);

    // <Wildcard Command>
    ipmi_register_callback(NETFUN_FIRMWARE, IPMI_CMD_WILDCARD, NULL,
                           ipmi_firmware_wildcard_handler, PRIVILEGE_ADMIN);

    // get buffer size is used by fw update (exclusively?)
    ipmi_register_callback(NETFUN_INTC_APP, IPMI_CMD_INTC_GET_BUFFER_SIZE, NULL,
                           ipmi_intel_app_get_buffer_size, PRIVILEGE_USER);
    return;
}

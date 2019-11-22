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
#include <ipmid/utils.hpp>
#include <map>
#include <random>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/server/object.hpp>
#include <sdbusplus/timer.hpp>
#include <sstream>
#ifdef INTEL_PFR_ENABLED
#include <spiDev.hpp>
#endif

namespace ipmi
{
namespace firmware
{
constexpr Cmd cmdGetFwVersionInfo = 0x20;
constexpr Cmd cmdFwGetRootCertData = 0x25;
constexpr Cmd cmdFwImageWriteData = 0x2c;
} // namespace firmware
} // namespace ipmi

#ifdef INTEL_PFR_ENABLED
uint32_t imgLength = 0;
uint32_t imgType = 0;
bool block0Mapped = false;
static constexpr uint32_t perBlock0MagicNum = 0xB6EAFD19;

static constexpr const char *versionIntf =
    "xyz.openbmc_project.Software.Version";

enum class FWDeviceIDTag : uint8_t
{
    bmcActiveImage = 1,
    bmcRecoveryImage,
};

const static boost::container::flat_map<FWDeviceIDTag, const char *>
    fwVersionIdMap{{FWDeviceIDTag::bmcActiveImage,
                    "/xyz/openbmc_project/software/bmc_active"},
                   {FWDeviceIDTag::bmcRecoveryImage,
                    "/xyz/openbmc_project/software/bmc_recovery"}};

#endif

static constexpr const char *bmcStateIntf = "xyz.openbmc_project.State.BMC";
static constexpr const char *bmcStatePath = "/xyz/openbmc_project/state/bmc0";
static constexpr const char *bmcStateReady =
    "xyz.openbmc_project.State.BMC.BMCState.Ready";
static constexpr const char *bmcStateUpdateInProgress =
    "xyz.openbmc_project.State.BMC.BMCState.UpdateInProgress";

static constexpr const char *secondaryFitImageStartAddr = "22480000";
static uint8_t getActiveBootImage(void);
static void register_netfn_firmware_functions() __attribute__((constructor));

// oem return code for firmware update control
constexpr ipmi_ret_t IPMI_CC_REQ_INVALID_PHASE = 0xd5;
constexpr ipmi_ret_t IPMI_CC_USB_ATTACH_FAIL = 0x80;

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
            *_bus,
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
        if (_percent >= 95)
        {
            /*changing the state to ready to update firmware utility */
            _state = FW_STATE_READY;
        }
        std::cerr << " _percent = " << (int)_percent << "\n";
        return _percent;
    }
    /* API for changing state to ERROR  */
    void firmwareUpdateAbortState()
    {
        unlink(FIRMWARE_BUFFER_FILE);
        // changing the state to error
        _state = FW_STATE_ERROR;
    }
    void setDeferRestart(bool deferRestart)
    {
        _deferRestart = deferRestart;
    }
    void setInhibitDowngrade(bool inhibitDowngrade)
    {
        _inhibitDowngrade = inhibitDowngrade;
    }
    bool getDeferRestart()
    {
        return _deferRestart;
    }
    bool getInhibitDowngrade()
    {
        return _inhibitDowngrade;
    }

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
                auto state = std::get<std::string>(value);
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
                _percent = std::get<int32_t>(value);
                if (DEBUG)
                    std::cerr << ", pct=" << (int)_percent;
            }
            else if (key == "msg")
            {
                _msg = std::get<std::string>(value);
                if (DEBUG)
                    std::cerr << ", msg='" << _msg << '\'';
            }
            else if (key == "Progress")
            {
                _percent = std::get<uint8_t>(value);
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

    std::shared_ptr<sdbusplus::asio::connection> _bus;
    std::shared_ptr<sdbusplus::bus::match::match> _match;
    uint8_t _state = 0;
    uint8_t _percent = 0;
    bool _deferRestart = false;
    bool _inhibitDowngrade = false;
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

static bool getFirmwareUpdateMode()
{
    std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();
    try
    {
        auto service = ipmi::getService(*busp, bmcStateIntf, bmcStatePath);
        ipmi::Value state = ipmi::getDbusProperty(
            *busp, service, bmcStatePath, bmcStateIntf, "CurrentBMCState");
        std::string bmcState = std::get<std::string>(state);
        return (bmcState == bmcStateUpdateInProgress);
    }
    catch (const std::exception &e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Exception caught while getting BMC state.",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        throw;
    }
}

static void setFirmwareUpdateMode(const bool mode)
{

    std::string bmcState(bmcStateReady);
    if (mode)
    {
        bmcState = bmcStateUpdateInProgress;
    }

    std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();
    try
    {
        auto service = ipmi::getService(*busp, bmcStateIntf, bmcStatePath);
        ipmi::setDbusProperty(*busp, service, bmcStatePath, bmcStateIntf,
                              "CurrentBMCState", bmcState);
    }
    catch (const std::exception &e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Exception caught while setting BMC state.",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        throw;
    }
}

/** @brief Set Firmware Update Mode
 *
 *  This function sets BMC into firmware update mode
 *  after validating Random number obtained from the Get
 *  Firmware Update Random Number command
 *
 *  @parameter
 *   -  randNum - Random number(token)
 *  @returns IPMI completion code
 **/
ipmi::RspType<> ipmiSetFirmwareUpdateMode(
    std::array<uint8_t, FW_RANDOM_NUMBER_LENGTH> &randNum)
{
    /* Firmware Update Random number is valid for 30 seconds only */
    auto timeElapsed =
        (std::chrono::steady_clock::now() - fw_random_number_timestamp);
    if (std::chrono::duration_cast<std::chrono::microseconds>(timeElapsed)
            .count() > std::chrono::duration_cast<std::chrono::microseconds>(
                           FW_RANDOM_NUMBER_TTL)
                           .count())
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Firmware update random number expired.");
        return ipmi::responseInvalidFieldRequest();
    }

    /* Validate random number */
    for (int i = 0; i < FW_RANDOM_NUMBER_LENGTH; i++)
    {
        if (fw_random_number[i] != randNum[i])
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "Invalid random number specified.");
            return ipmi::responseInvalidFieldRequest();
        }
    }

    try
    {
        if (getFirmwareUpdateMode())
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "Already firmware update is in progress.");
            return ipmi::responseBusy();
        }
    }
    catch (const std::exception &e)
    {
        return ipmi::responseUnspecifiedError();
    }

    // FIXME? c++ doesn't off an option for exclusive file creation
    FILE *fp = fopen(FIRMWARE_BUFFER_FILE, "wx");
    if (!fp)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Unable to open file.");
        return ipmi::responseUnspecifiedError();
    }
    fclose(fp);

    try
    {
        setFirmwareUpdateMode(true);
    }
    catch (const std::exception &e)
    {
        unlink(FIRMWARE_BUFFER_FILE);
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess();
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
        case fw_update_status_cache::FW_STATE_VERIFY:
            break;
        case fw_update_status_cache::FW_STATE_WRITE:
            break;
        case fw_update_status_cache::FW_STATE_READY:
        case fw_update_status_cache::FW_STATE_ERROR:
            break;
        case fw_update_status_cache::FW_STATE_AC_CYCLE_REQUIRED:
            return ipmi::responseInvalidFieldRequest();
            break;
    }
    fw_update_status.firmwareUpdateAbortState();

    try
    {
        setFirmwareUpdateMode(false);
    }
    catch (const std::exception &e)
    {
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

    // fwupdate URIs start with file:// or usb:// or tftp:// etc. By the time
    // the code gets to this point, the file should be transferred start the
    // request (creating a new file in /tmp/images causes the update manager to
    // check if it is ready for activation)
    static std::unique_ptr<sdbusplus::bus::match::match> fw_update_matcher;
    post_transfer_complete_handler(fw_update_matcher);
    std::filesystem::rename(
        uri, "/tmp/images/" +
                 boost::uuids::to_string(boost::uuids::random_generator()()));
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

static void activate_image(const char *obj_path)
{
    // If flag is false  means to reboot
    if (fw_update_status.getDeferRestart() == false)
    {

        if (DEBUG)
        {
            std::cerr << "activateImage()...\n";
            std::cerr << "obj_path = " << obj_path << "\n";
        }
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "activating Image: ",
            phosphor::logging::entry("OBJPATH =%s", obj_path));
        std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
        bus->async_method_call(
            [](const boost::system::error_code ec) {
                if (ec)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "async_method_call error: activate_image failed");
                    return;
                }
            },
            "xyz.openbmc_project.Software.BMC.Updater", obj_path,
            "org.freedesktop.DBus.Properties", "Set",
            "xyz.openbmc_project.Software.Activation", "RequestedActivation",
            std::variant<std::string>("xyz.openbmc_project.Software.Activation."
                                      "RequestedActivations.Active"));
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Firmware image activation is deferred.");
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
            std::vector<std::pair<std::string, std::variant<std::string>>>>>
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
        *getSdBus(),
        "interface='org.freedesktop.DBus.ObjectManager',type='signal',"
        "member='InterfacesAdded',path='/xyz/openbmc_project/software'",
        callback);
}

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
#ifdef INTEL_PFR_ENABLED
            imgLength = 0;
            imgType = 0;
            block0Mapped = false;
#endif
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
            fw_update_status.firmwareUpdateAbortState();
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

#ifdef INTEL_PFR_ENABLED
using fwVersionInfoType = std::tuple<uint8_t,   // ID Tag
                                     uint8_t,   // Major Version Number
                                     uint8_t,   // Minor Version Number
                                     uint32_t,  // Build Number
                                     uint32_t,  // Build Timestamp
                                     uint32_t>; // Update Timestamp
ipmi::RspType<uint8_t, std::vector<fwVersionInfoType>> ipmiGetFwVersionInfo()
{
    // Byte 1 - Count (N) Number of devices data is being returned for.
    // Bytes  2:16 - Device firmare information(fwVersionInfoType)
    // Bytes - 17:(15xN) - Repeat of 2 through 16

    std::vector<fwVersionInfoType> fwVerInfoList;
    std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();
    for (const auto &fwDev : fwVersionIdMap)
    {
        std::string verStr;
        try
        {
            auto service = ipmi::getService(*busp, versionIntf, fwDev.second);

            ipmi::Value result = ipmi::getDbusProperty(
                *busp, service, fwDev.second, versionIntf, "Version");
            verStr = std::get<std::string>(result);
        }
        catch (const std::exception &e)
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "Failed to fetch Version property",
                phosphor::logging::entry("ERROR=%s", e.what()),
                phosphor::logging::entry("PATH=%s", fwDev.second),
                phosphor::logging::entry("INTERFACE=%s", versionIntf));
            continue;
        }

        if (verStr.empty())
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "Version is empty.",
                phosphor::logging::entry("PATH=%s", fwDev.second),
                phosphor::logging::entry("INTERFACE=%s", versionIntf));
            continue;
        }

        // BMC Version format: <major>.<minor>-<build bum>-<build hash>
        std::vector<std::string> splitVer;
        boost::split(splitVer, verStr, boost::is_any_of(".-"));
        if (splitVer.size() < 3)
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "Invalid Version format.",
                phosphor::logging::entry("Version=%s", verStr.c_str()),
                phosphor::logging::entry("PATH=%s", fwDev.second));
            continue;
        }

        uint8_t majorNum = 0;
        uint8_t minorNum = 0;
        uint32_t buildNum = 0;
        try
        {
            majorNum = std::stoul(splitVer[0], nullptr, 16);
            minorNum = std::stoul(splitVer[1], nullptr, 16);
            buildNum = std::stoul(splitVer[2], nullptr, 16);
        }
        catch (const std::exception &e)
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "Failed to convert stoul.",
                phosphor::logging::entry("ERROR=%s", e.what()));
            continue;
        }

        // Build Timestamp - Not supported.
        // Update Timestamp - TODO: Need to check with CPLD team.
        fwVerInfoList.emplace_back(
            fwVersionInfoType(static_cast<uint8_t>(fwDev.first), majorNum,
                              minorNum, buildNum, 0, 0));
    }

    return ipmi::responseSuccess(fwVerInfoList.size(), fwVerInfoList);
}
#endif

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

    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
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
            bus->new_method_call(FW_UPDATE_SERVER_DBUS_NAME, fw_path,
                                 "org.freedesktop.DBus.Properties", "GetAll");
        method.append(FW_UPDATE_INFO_INTERFACE, "security_version");
        ipmi::DbusVariant sec_rev;
        try
        {
            auto reply = bus->call(method);

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
        info->sec_rev = std::get<int>(sec_rev);
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

static constexpr uint8_t channelListSize = 2;
/** @brief implements Maximum Firmware Transfer size command
 *  @parameter
 *   -  none
 *  @returns IPMI completion code plus response data
 *   - count - channel count
 *   - channelList - channel list information
 */
ipmi::RspType<uint8_t, // channel count
              std::array<std::tuple<uint8_t, uint32_t>,
                         channelListSize> // channel
                                          // list
              >
    ipmiFirmwareMaxTransferSize()
{
    constexpr uint8_t KCSMaxBufSize = 128;
    constexpr uint32_t RMCPPLUSMaxBufSize = 50 * 1024;
    if (DEBUG)
        std::cerr << "Get FW max transfer size\n";
    // Byte 1 - Count (N) Number of devices data is being returned for.
    // Byte 2 - ID Tag 00 – reserved 01 – kcs 02 – rmcp+,
    //                 03 – usb data, 04 – usb mass storage
    // Byte 3-6 - transfer size (little endian)
    // Bytes - 7:(5xN) - Repeat of 2 through 6
    constexpr std::array<std::tuple<uint8_t, uint32_t>, channelListSize>
        channelList = {{{CHANNEL_KCS, KCSMaxBufSize},
                        {CHANNEL_RMCP_PLUS, RMCPPLUSMaxBufSize}}};
    return ipmi::responseSuccess(channelListSize, channelList);
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
    info->context = EXEC_CTX_FULL_LINUX;

    info->image_selection = getActiveBootImage();

    // Status code.
    ipmi_ret_t rc = IPMI_CC_OK;
    *data_len = sizeof(*info);

    return rc;
}

uint8_t getActiveBootImage(void)
{
    // 0x01 -  primaryImage
    constexpr uint8_t primaryImage = 0x01;
    // 0x02 -  secondaryImage
    constexpr uint8_t secondaryImage = 0x02;
    uint8_t bootImage = primaryImage;

    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
    auto method = bus->new_method_call(
        "xyz.openbmc_project.U_Boot.Environment.Manager",
        "/xyz/openbmc_project/u_boot/environment/mgr",
        "xyz.openbmc_project.U_Boot.Environment.Manager", "Read");
    method.append("bootcmd");
    std::string value;
    try
    {
        auto reply = bus->call(method);
        reply.read(value);
    }
    catch (sdbusplus::exception::SdBusError &e)
    {
        std::cerr << "SDBus Error: " << e.what();
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    /* cheking for secondary FitImage Address 22480000  */
    if (value.find(secondaryFitImageStartAddr) != std::string::npos)
    {
        bootImage = secondaryImage;
    }
    else
    {
        bootImage = primaryImage;
    }

    return bootImage;
}
/** @brief implements firmware get status command
 *  @parameter
 *   -  none
 *  @returns IPMI completion code plus response data
 *   - status     -  processing status
 *   - percentage -  percentage completion
 *   - check      -  channel integrity check status
 **/
ipmi::RspType<uint8_t, // status
              uint8_t, // percentage
              uint8_t  // check
              >
    ipmiFrmwareGetStatus()

{
    if (DEBUG)
        std::cerr << "Get FW update status\n";
    // Byte 1 - status (0=init, 1=idle, 2=download, 3=validate, 4=write,
    //                  5=ready, f=error, 83=ac cycle required)
    // Byte 2 - percent
    // Byte 3 - integrity check status (0=none, 1=req, 2=sha2ok, e2=sha2fail)
    uint8_t status = fw_update_status.state();
    uint8_t percent = fw_update_status.percent();
    uint8_t check = xfer_hash_check ? xfer_hash_check->status() : 0;

    // Status code.
    return ipmi::responseSuccess(status, percent, check);
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
            /*setting flag to flase for deferring downgrade support*/
            fw_update_status.setInhibitDowngrade(true);
        }
        else
        {
            fw_update_options &= ~FW_UPDATE_OPTIONS_NO_DOWNREV;
            /*setting flag to true for downgrade support*/
            fw_update_status.setInhibitDowngrade(false);
        }
    }
    if ((fw_options->mask & FW_UPDATE_OPTIONS_DEFER_RESTART) &&
        (fw_options->options & FW_UPDATE_OPTIONS_DEFER_RESTART) !=
            (fw_update_options & FW_UPDATE_OPTIONS_DEFER_RESTART))
    {
        if (fw_options->options & FW_UPDATE_OPTIONS_DEFER_RESTART)
        {
            fw_update_options |= FW_UPDATE_OPTIONS_DEFER_RESTART;
            /* setting flag to true to stop image activation */
            fw_update_status.setDeferRestart(true);
        }
        else
        {
            /* setting flag to false for image activation */
            fw_update_options &= ~FW_UPDATE_OPTIONS_DEFER_RESTART;
            fw_update_status.setDeferRestart(false);
        }
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
    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
    auto method = bus->new_method_call(
        FW_UPDATE_SERVER_DBUS_NAME, FW_UPDATE_SERVER_INFO_PATH,
        "org.freedesktop.DBus.Properties", "GetAll");
    method.append(FW_UPDATE_SECURITY_INTERFACE);
    std::string subject;
    uint64_t serial;
    std::string cert;
    try
    {
        auto reply = bus->call(method);

        std::vector<std::pair<std::string, ipmi::DbusVariant>> properties;
        reply.read(properties);

        for (const auto &t : properties)
        {
            auto key = t.first;
            auto value = t.second;
            if (key == "certificate_subject")
            {
                subject = std::get<std::string>(value);
            }
            else if (key == "cetificate_serial")
            {
                serial = std::get<uint64_t>(value);
            }
            else if (key == "certificate")
            {
                cert = std::get<std::string>(value);
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

#ifdef INTEL_PFR_ENABLED
enum class FwGetRootCertDataTag : uint8_t
{
    activeRootKey = 1,
    recoveryRootKey,
    activeCSK,
    recoveryCSK,
};

static constexpr char *bmcActivePfmMTDDev = "/dev/mtd/pfm";
static constexpr char *bmcRecoveryImgMTDDev = "/dev/mtd/rc-image";
static constexpr size_t pfmBaseOffsetInImage = 0x400;
static constexpr size_t rootkeyOffsetInPfm = 0xA0;
static constexpr size_t cskKeyOffsetInPfm = 0x124;
static constexpr size_t cskSignatureOffsetInPfm = 0x19c;
static constexpr size_t certKeyLen = 96;
static constexpr size_t cskSignatureLen = 96;

ipmi::RspType<std::array<uint8_t, certKeyLen>,
              std::optional<std::array<uint8_t, cskSignatureLen>>>
    ipmiGetFwRootCertData(uint8_t certId)
{
    size_t certKeyOffset = 0;
    size_t cskSigOffset = 0;
    std::string mtdDev;

    switch (static_cast<FwGetRootCertDataTag>(certId))
    {
        case FwGetRootCertDataTag::activeRootKey:
        {
            mtdDev = bmcActivePfmMTDDev;
            certKeyOffset = rootkeyOffsetInPfm;
            break;
        }
        case FwGetRootCertDataTag::recoveryRootKey:
        {
            mtdDev = bmcRecoveryImgMTDDev;
            certKeyOffset = pfmBaseOffsetInImage + rootkeyOffsetInPfm;
            break;
        }
        case FwGetRootCertDataTag::activeCSK:
        {
            mtdDev = bmcActivePfmMTDDev;
            certKeyOffset = cskKeyOffsetInPfm;
            cskSigOffset = cskSignatureOffsetInPfm;
            break;
        }
        case FwGetRootCertDataTag::recoveryCSK:
        {
            mtdDev = bmcRecoveryImgMTDDev;
            certKeyOffset = pfmBaseOffsetInImage + cskKeyOffsetInPfm;
            cskSigOffset = pfmBaseOffsetInImage + cskSignatureOffsetInPfm;
            break;
        }
        default:
        {
            return ipmi::responseInvalidFieldRequest();
        }
    }

    std::array<uint8_t, certKeyLen> certKey = {0};

    try
    {
        SPIDev spiDev(mtdDev);
        spiDev.spiReadData(certKeyOffset, certKeyLen, certKey.data());

        if (cskSigOffset)
        {
            std::array<uint8_t, cskSignatureLen> cskSignature = {0};
            spiDev.spiReadData(cskSigOffset, cskSignatureLen,
                               cskSignature.data());
            return ipmi::responseSuccess(certKey, cskSignature);
        }
    }
    catch (const std::exception &e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Exception caught in ipmiGetFwRootCertData",
            phosphor::logging::entry("MSG=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(certKey, std::nullopt);
}
#endif

ipmi::RspType<uint32_t>
    ipmiFwImageWriteData(const std::vector<uint8_t> &writeData)
{
    const uint8_t ccCmdNotSupportedInPresentState = 0xD5;
    size_t writeDataLen = writeData.size();

    if (!writeDataLen)
    {
        return ipmi::responseReqDataLenInvalid();
    }

    if (fw_update_status.state() != fw_update_status_cache::FW_STATE_DOWNLOAD)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Invalid firmware update state.");
        return ipmi::response(ccCmdNotSupportedInPresentState);
    }

    std::ofstream out(FIRMWARE_BUFFER_FILE,
                      std::ofstream::binary | std::ofstream::app);
    if (!out)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Error while opening file.");
        return ipmi::responseUnspecifiedError();
    }

    uint64_t fileDataLen = out.tellp();

    if ((fileDataLen + writeDataLen) > FIRMWARE_BUFFER_MAX_SIZE)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "Firmware image size exceeds the limit");
        return ipmi::responseInvalidFieldRequest();
    }

    const char *data = reinterpret_cast<const char *>(writeData.data());
    out.write(data, writeDataLen);
    out.close();

    if (xfer_hash_check)
    {
        xfer_hash_check->hash(writeData);
    }

#ifdef INTEL_PFR_ENABLED
    /* PFR image block 0 - As defined in HAS */
    struct PFRImageBlock0
    {
        uint32_t tag;
        uint32_t pcLength;
        uint32_t pcType;
        uint32_t reserved1;
        uint8_t hash256[32];
        uint8_t hash384[48];
        uint8_t reserved2[32];
    } __attribute__((packed));

    /* Get the PFR block 0 data and read the uploaded image
     * information( Image type, length etc) */
    if (((fileDataLen + writeDataLen) >= sizeof(PFRImageBlock0)) &&
        (!block0Mapped))
    {
        struct PFRImageBlock0 block0Data = {0};

        std::ifstream inFile(FIRMWARE_BUFFER_FILE,
                             std::ios::binary | std::ios::in);
        inFile.read(reinterpret_cast<char *>(&block0Data), sizeof(block0Data));
        inFile.close();

        uint32_t magicNum = block0Data.tag;

        /* Validate the magic number */
        if (magicNum != perBlock0MagicNum)
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "PFR image magic number not matched");
            return ipmi::responseInvalidFieldRequest();
        }
        // Note:imgLength, imgType and block0Mapped are in global scope, as
        // these are used in cascaded updates.
        imgLength = block0Data.pcLength;
        imgType = block0Data.pcType;
        block0Mapped = true;
    }
#endif // end of INTEL_PFR_ENABLED
    return ipmi::responseSuccess(writeDataLen);
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
static constexpr ipmi_cmd_t IPMI_CMD_FW_GET_FW_UPDATE_RAND_NUM = 0x26;
static constexpr ipmi_cmd_t IPMI_CMD_FW_SET_FW_UPDATE_MODE = 0x27;
static constexpr ipmi_cmd_t cmdFirmwareExitFirmwareUpdateMode = 0x28;
static constexpr ipmi_cmd_t IPMI_CMD_FW_UPDATE_CONTROL = 0x29;
static constexpr ipmi_cmd_t IPMI_CMD_FW_GET_STATUS = 0x2a;
static constexpr ipmi_cmd_t IPMI_CMD_FW_SET_FW_UPDATE_OPTIONS = 0x2b;
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

#ifdef INTEL_PFR_ENABLED
    // Following commands are supported only for PFR enabled platforms
    // CMD:0x20 - Get Firmware Version Information

    // get firmware version information
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnFirmware,
                          ipmi::firmware::cmdGetFwVersionInfo,
                          ipmi::Privilege::Admin, ipmiGetFwVersionInfo);
#endif
    // get firmware security version information
    ipmi_register_callback(NETFUN_FIRMWARE, IPMI_CMD_FW_GET_FW_SEC_VERSION_INFO,
                           NULL, ipmi_firmware_get_fw_security_revision,
                           PRIVILEGE_ADMIN);

    // get channel information (max transfer sizes)
    ipmi::registerHandler(ipmi::prioOemBase, NETFUN_FIRMWARE,
                          IPMI_CMD_FW_GET_FW_UPD_CHAN_INFO,
                          ipmi::Privilege::Admin, ipmiFirmwareMaxTransferSize);

    // get bmc execution context
    ipmi_register_callback(NETFUN_FIRMWARE, IPMI_CMD_FW_GET_BMC_EXEC_CTX, NULL,
                           ipmi_firmware_get_fw_execution_context,
                           PRIVILEGE_ADMIN);

    // get root certificate information
    ipmi_register_callback(NETFUN_FIRMWARE, IPMI_CMD_FW_GET_ROOT_CERT_INFO,
                           NULL, ipmi_firmware_get_root_cert_info,
                           PRIVILEGE_ADMIN);
#ifdef INTEL_PFR_ENABLED
    // get root certificate data
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnFirmware,
                          ipmi::firmware::cmdFwGetRootCertData,
                          ipmi::Privilege::Admin, ipmiGetFwRootCertData);
#endif

    // generate bmc fw update random number (for enter fw tranfer mode)
    ipmi_register_callback(NETFUN_FIRMWARE, IPMI_CMD_FW_GET_FW_UPDATE_RAND_NUM,
                           NULL, ipmi_firmware_get_fw_random_number,
                           PRIVILEGE_ADMIN);

    // Set Firmware Update Mode(0x27)
    ipmi::registerHandler(ipmi::prioOemBase, NETFUN_FIRMWARE,
                          IPMI_CMD_FW_SET_FW_UPDATE_MODE,
                          ipmi::Privilege::Admin, ipmiSetFirmwareUpdateMode);

    // exit firmware update mode
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnFirmware,
                          cmdFirmwareExitFirmwareUpdateMode,
                          ipmi::Privilege::Admin, ipmiFirmwareExitFwUpdateMode);

    // firmware control mechanism (set filename, usb, etc.)
    ipmi_register_callback(NETFUN_FIRMWARE, IPMI_CMD_FW_UPDATE_CONTROL, NULL,
                           ipmi_firmware_control, PRIVILEGE_ADMIN);

    // get firmware update status
    ipmi::registerHandler(ipmi::prioOemBase, NETFUN_FIRMWARE,
                          IPMI_CMD_FW_GET_STATUS, ipmi::Privilege::Admin,
                          ipmiFrmwareGetStatus);
    // set firmware update options (no downgrade, etc.)
    ipmi_register_callback(NETFUN_FIRMWARE, IPMI_CMD_FW_SET_FW_UPDATE_OPTIONS,
                           NULL, ipmi_firmware_update_options, PRIVILEGE_ADMIN);

    // write image data
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnFirmware,
                          ipmi::firmware::cmdFwImageWriteData,
                          ipmi::Privilege::Admin, ipmiFwImageWriteData);

    // get buffer size is used by fw update (exclusively?)
    ipmi_register_callback(NETFUN_INTC_APP, IPMI_CMD_INTC_GET_BUFFER_SIZE, NULL,
                           ipmi_intel_app_get_buffer_size, PRIVILEGE_USER);
    return;
}

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

#include <ipmid/api.h>

#include <boost/container/flat_map.hpp>
#include <boost/process.hpp>
#include <commandutils.hpp>
#include <iostream>
#include <phosphor-ipmi-host/selutility.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>
#include <sdbusplus/timer.hpp>
#include <sdrutils.hpp>
#include <stdexcept>
#include <storagecommands.hpp>
#include <string_view>

namespace intel_oem::ipmi::sel::erase_time
{
static constexpr const char* selEraseTimestamp = "/var/lib/ipmi/sel_erase_time";

void save()
{
    // open the file, creating it if necessary
    int fd = open(selEraseTimestamp, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0)
    {
        std::cerr << "Failed to open file\n";
        return;
    }

    // update the file timestamp to the current time
    if (futimens(fd, NULL) < 0)
    {
        std::cerr << "Failed to update timestamp: "
                  << std::string(strerror(errno));
    }
    close(fd);
}

int get()
{
    struct stat st;
    // default to an invalid timestamp
    int timestamp = ::ipmi::sel::invalidTimeStamp;

    int fd = open(selEraseTimestamp, O_RDWR | O_CLOEXEC, 0644);
    if (fd < 0)
    {
        return timestamp;
    }

    if (fstat(fd, &st) >= 0)
    {
        timestamp = st.st_mtime;
    }

    return timestamp;
}
} // namespace intel_oem::ipmi::sel::erase_time

namespace ipmi
{

namespace storage
{

constexpr static const size_t maxMessageSize = 64;
constexpr static const size_t maxFruSdrNameSize = 16;
using ManagedObjectType = boost::container::flat_map<
    sdbusplus::message::object_path,
    boost::container::flat_map<
        std::string, boost::container::flat_map<std::string, DbusVariant>>>;
using ManagedEntry = std::pair<
    sdbusplus::message::object_path,
    boost::container::flat_map<
        std::string, boost::container::flat_map<std::string, DbusVariant>>>;

constexpr static const char* fruDeviceServiceName =
    "xyz.openbmc_project.FruDevice";
constexpr static const size_t cacheTimeoutSeconds = 10;

constexpr static const uint8_t deassertionEvent = 1;

static std::vector<uint8_t> fruCache;
static uint8_t cacheBus = 0xFF;
static uint8_t cacheAddr = 0XFF;

std::unique_ptr<phosphor::Timer> cacheTimer = nullptr;

// we unfortunately have to build a map of hashes in case there is a
// collision to verify our dev-id
boost::container::flat_map<uint8_t, std::pair<uint8_t, uint8_t>> deviceHashes;

void registerStorageFunctions() __attribute__((constructor));
static sdbusplus::bus::bus dbus(ipmid_get_sd_bus_connection());

bool writeFru()
{
    sdbusplus::message::message writeFru = dbus.new_method_call(
        fruDeviceServiceName, "/xyz/openbmc_project/FruDevice",
        "xyz.openbmc_project.FruDeviceManager", "WriteFru");
    writeFru.append(cacheBus, cacheAddr, fruCache);
    try
    {
        sdbusplus::message::message writeFruResp = dbus.call(writeFru);
    }
    catch (sdbusplus::exception_t&)
    {
        // todo: log sel?
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "error writing fru");
        return false;
    }
    return true;
}

void createTimer()
{
    if (cacheTimer == nullptr)
    {
        cacheTimer = std::make_unique<phosphor::Timer>(writeFru);
    }
}

ipmi_ret_t replaceCacheFru(uint8_t devId)
{
    static uint8_t lastDevId = 0xFF;

    bool timerRunning = (cacheTimer != nullptr) && !cacheTimer->isExpired();
    if (lastDevId == devId && timerRunning)
    {
        return IPMI_CC_OK; // cache already up to date
    }
    // if timer is running, stop it and writeFru manually
    else if (timerRunning)
    {
        cacheTimer->stop();
        writeFru();
    }

    sdbusplus::message::message getObjects = dbus.new_method_call(
        fruDeviceServiceName, "/", "org.freedesktop.DBus.ObjectManager",
        "GetManagedObjects");
    ManagedObjectType frus;
    try
    {
        sdbusplus::message::message resp = dbus.call(getObjects);
        resp.read(frus);
    }
    catch (sdbusplus::exception_t&)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "replaceCacheFru: error getting managed objects");
        return IPMI_CC_RESPONSE_ERROR;
    }

    deviceHashes.clear();

    // hash the object paths to create unique device id's. increment on
    // collision
    std::hash<std::string> hasher;
    for (const auto& fru : frus)
    {
        auto fruIface = fru.second.find("xyz.openbmc_project.FruDevice");
        if (fruIface == fru.second.end())
        {
            continue;
        }

        auto busFind = fruIface->second.find("BUS");
        auto addrFind = fruIface->second.find("ADDRESS");
        if (busFind == fruIface->second.end() ||
            addrFind == fruIface->second.end())
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "fru device missing Bus or Address",
                phosphor::logging::entry("FRU=%s", fru.first.str.c_str()));
            continue;
        }

        uint8_t fruBus =
            sdbusplus::message::variant_ns::get<uint32_t>(busFind->second);
        uint8_t fruAddr =
            sdbusplus::message::variant_ns::get<uint32_t>(addrFind->second);

        uint8_t fruHash = 0;
        if (fruBus != 0 || fruAddr != 0)
        {
            fruHash = hasher(fru.first.str);
            // can't be 0xFF based on spec, and 0 is reserved for baseboard
            if (fruHash == 0 || fruHash == 0xFF)
            {
                fruHash = 1;
            }
        }
        std::pair<uint8_t, uint8_t> newDev(fruBus, fruAddr);

        bool emplacePassed = false;
        while (!emplacePassed)
        {
            auto resp = deviceHashes.emplace(fruHash, newDev);
            emplacePassed = resp.second;
            if (!emplacePassed)
            {
                fruHash++;
                // can't be 0xFF based on spec, and 0 is reserved for
                // baseboard
                if (fruHash == 0XFF)
                {
                    fruHash = 0x1;
                }
            }
        }
    }
    auto deviceFind = deviceHashes.find(devId);
    if (deviceFind == deviceHashes.end())
    {
        return IPMI_CC_SENSOR_INVALID;
    }

    fruCache.clear();
    sdbusplus::message::message getRawFru = dbus.new_method_call(
        fruDeviceServiceName, "/xyz/openbmc_project/FruDevice",
        "xyz.openbmc_project.FruDeviceManager", "GetRawFru");
    cacheBus = deviceFind->second.first;
    cacheAddr = deviceFind->second.second;
    getRawFru.append(cacheBus, cacheAddr);
    try
    {
        sdbusplus::message::message getRawResp = dbus.call(getRawFru);
        getRawResp.read(fruCache);
    }
    catch (sdbusplus::exception_t&)
    {
        lastDevId = 0xFF;
        cacheBus = 0xFF;
        cacheAddr = 0xFF;
        return IPMI_CC_RESPONSE_ERROR;
    }

    lastDevId = devId;
    return IPMI_CC_OK;
}

ipmi_ret_t ipmiStorageReadFRUData(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t dataLen,
                                  ipmi_context_t context)
{
    if (*dataLen != 4)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    *dataLen = 0; // default to 0 in case of an error

    auto req = static_cast<GetFRUAreaReq*>(request);

    if (req->countToRead > maxMessageSize - 1)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    ipmi_ret_t status = replaceCacheFru(req->fruDeviceID);

    if (status != IPMI_CC_OK)
    {
        return status;
    }

    size_t fromFRUByteLen = 0;
    if (req->countToRead + req->fruInventoryOffset < fruCache.size())
    {
        fromFRUByteLen = req->countToRead;
    }
    else if (fruCache.size() > req->fruInventoryOffset)
    {
        fromFRUByteLen = fruCache.size() - req->fruInventoryOffset;
    }
    size_t padByteLen = req->countToRead - fromFRUByteLen;
    uint8_t* respPtr = static_cast<uint8_t*>(response);
    *respPtr = req->countToRead;
    std::copy(fruCache.begin() + req->fruInventoryOffset,
              fruCache.begin() + req->fruInventoryOffset + fromFRUByteLen,
              ++respPtr);
    // if longer than the fru is requested, fill with 0xFF
    if (padByteLen)
    {
        respPtr += fromFRUByteLen;
        std::fill(respPtr, respPtr + padByteLen, 0xFF);
    }
    *dataLen = fromFRUByteLen + 1;

    return IPMI_CC_OK;
}

ipmi_ret_t ipmiStorageWriteFRUData(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t dataLen,
                                   ipmi_context_t context)
{
    if (*dataLen < 4 ||
        *dataLen >=
            0xFF + 3) // count written return is one byte, so limit to one byte
                      // of data after the three request data bytes
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    auto req = static_cast<WriteFRUDataReq*>(request);
    size_t writeLen = *dataLen - 3;
    *dataLen = 0; // default to 0 in case of an error

    ipmi_ret_t status = replaceCacheFru(req->fruDeviceID);
    if (status != IPMI_CC_OK)
    {
        return status;
    }
    int lastWriteAddr = req->fruInventoryOffset + writeLen;
    if (fruCache.size() < lastWriteAddr)
    {
        fruCache.resize(req->fruInventoryOffset + writeLen);
    }

    std::copy(req->data, req->data + writeLen,
              fruCache.begin() + req->fruInventoryOffset);

    bool atEnd = false;

    if (fruCache.size() >= sizeof(FRUHeader))
    {

        FRUHeader* header = reinterpret_cast<FRUHeader*>(fruCache.data());

        int lastRecordStart = std::max(
            header->internalOffset,
            std::max(header->chassisOffset,
                     std::max(header->boardOffset, header->productOffset)));
        // TODO: Handle Multi-Record FRUs?

        lastRecordStart *= 8; // header starts in are multiples of 8 bytes

        // get the length of the area in multiples of 8 bytes
        if (lastWriteAddr > (lastRecordStart + 1))
        {
            // second byte in record area is the length
            int areaLength(fruCache[lastRecordStart + 1]);
            areaLength *= 8; // it is in multiples of 8 bytes

            if (lastWriteAddr >= (areaLength + lastRecordStart))
            {
                atEnd = true;
            }
        }
    }
    uint8_t* respPtr = static_cast<uint8_t*>(response);
    if (atEnd)
    {
        // cancel timer, we're at the end so might as well send it
        cacheTimer->stop();
        if (!writeFru())
        {
            return IPMI_CC_INVALID_FIELD_REQUEST;
        }
        *respPtr = std::min(fruCache.size(), static_cast<size_t>(0xFF));
    }
    else
    {
        // start a timer, if no further data is sent in cacheTimeoutSeconds
        // seconds, check to see if it is valid
        createTimer();
        cacheTimer->start(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::seconds(cacheTimeoutSeconds)));
        *respPtr = 0;
    }

    *dataLen = 1;

    return IPMI_CC_OK;
}

ipmi_ret_t ipmiStorageGetFRUInvAreaInfo(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                        ipmi_request_t request,
                                        ipmi_response_t response,
                                        ipmi_data_len_t dataLen,
                                        ipmi_context_t context)
{
    if (*dataLen != 1)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    *dataLen = 0; // default to 0 in case of an error

    uint8_t reqDev = *(static_cast<uint8_t*>(request));
    if (reqDev == 0xFF)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    ipmi_ret_t status = replaceCacheFru(reqDev);

    if (status != IPMI_CC_OK)
    {
        return status;
    }

    GetFRUAreaResp* respPtr = static_cast<GetFRUAreaResp*>(response);
    respPtr->inventorySizeLSB = fruCache.size() & 0xFF;
    respPtr->inventorySizeMSB = fruCache.size() >> 8;
    respPtr->accessType = static_cast<uint8_t>(GetFRUAreaAccessType::byte);

    *dataLen = sizeof(GetFRUAreaResp);
    return IPMI_CC_OK;
}

ipmi_ret_t getFruSdrCount(size_t& count)
{
    ipmi_ret_t ret = replaceCacheFru(0);
    if (ret != IPMI_CC_OK)
    {
        return ret;
    }
    count = deviceHashes.size();
    return IPMI_CC_OK;
}

ipmi_ret_t getFruSdrs(size_t index, get_sdr::SensorDataFruRecord& resp)
{
    ipmi_ret_t ret = replaceCacheFru(0); // this will update the hash list
    if (ret != IPMI_CC_OK)
    {
        return ret;
    }
    if (deviceHashes.size() < index)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    auto device = deviceHashes.begin() + index;
    uint8_t& bus = device->second.first;
    uint8_t& address = device->second.second;

    ManagedObjectType frus;

    sdbusplus::message::message getObjects = dbus.new_method_call(
        fruDeviceServiceName, "/", "org.freedesktop.DBus.ObjectManager",
        "GetManagedObjects");
    try
    {
        sdbusplus::message::message resp = dbus.call(getObjects);
        resp.read(frus);
    }
    catch (sdbusplus::exception_t&)
    {
        return IPMI_CC_RESPONSE_ERROR;
    }
    boost::container::flat_map<std::string, DbusVariant>* fruData = nullptr;
    auto fru =
        std::find_if(frus.begin(), frus.end(),
                     [bus, address, &fruData](ManagedEntry& entry) {
                         auto findFruDevice =
                             entry.second.find("xyz.openbmc_project.FruDevice");
                         if (findFruDevice == entry.second.end())
                         {
                             return false;
                         }
                         fruData = &(findFruDevice->second);
                         auto findBus = findFruDevice->second.find("BUS");
                         auto findAddress =
                             findFruDevice->second.find("ADDRESS");
                         if (findBus == findFruDevice->second.end() ||
                             findAddress == findFruDevice->second.end())
                         {
                             return false;
                         }
                         if (sdbusplus::message::variant_ns::get<uint32_t>(
                                 findBus->second) != bus)
                         {
                             return false;
                         }
                         if (sdbusplus::message::variant_ns::get<uint32_t>(
                                 findAddress->second) != address)
                         {
                             return false;
                         }
                         return true;
                     });
    if (fru == frus.end())
    {
        return IPMI_CC_RESPONSE_ERROR;
    }
    std::string name;
    auto findProductName = fruData->find("BOARD_PRODUCT_NAME");
    auto findBoardName = fruData->find("PRODUCT_PRODUCT_NAME");
    if (findProductName != fruData->end())
    {
        name = sdbusplus::message::variant_ns::get<std::string>(
            findProductName->second);
    }
    else if (findBoardName != fruData->end())
    {
        name = sdbusplus::message::variant_ns::get<std::string>(
            findBoardName->second);
    }
    else
    {
        name = "UNKNOWN";
    }
    if (name.size() > maxFruSdrNameSize)
    {
        name = name.substr(0, maxFruSdrNameSize);
    }
    size_t sizeDiff = maxFruSdrNameSize - name.size();

    resp.header.record_id_lsb = 0x0; // calling code is to implement these
    resp.header.record_id_msb = 0x0;
    resp.header.sdr_version = ipmiSdrVersion;
    resp.header.record_type = 0x11; // FRU Device Locator
    resp.header.record_length = sizeof(resp.body) + sizeof(resp.key) - sizeDiff;
    resp.key.deviceAddress = 0x20;
    resp.key.fruID = device->first;
    resp.key.accessLun = 0x80; // logical / physical fru device
    resp.key.channelNumber = 0x0;
    resp.body.reserved = 0x0;
    resp.body.deviceType = 0x10;
    resp.body.deviceTypeModifier = 0x0;
    resp.body.entityID = 0x0;
    resp.body.entityInstance = 0x1;
    resp.body.oem = 0x0;
    resp.body.deviceIDLen = name.size();
    name.copy(resp.body.deviceID, name.size());

    return IPMI_CC_OK;
}

ipmi_ret_t ipmiStorageGetSELInfo(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                 ipmi_request_t request,
                                 ipmi_response_t response,
                                 ipmi_data_len_t data_len,
                                 ipmi_context_t context)
{
    if (*data_len != 0)
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    ipmi::sel::GetSELInfoResponse* responseData =
        static_cast<ipmi::sel::GetSELInfoResponse*>(response);

    responseData->selVersion = ipmi::sel::selVersion;
    responseData->addTimeStamp = ipmi::sel::invalidTimeStamp;
    responseData->operationSupport = intel_oem::ipmi::sel::selOperationSupport;
    responseData->entries = 0;

    // Fill in the last erase time
    responseData->eraseTimeStamp = intel_oem::ipmi::sel::erase_time::get();

    // Open the journal
    sd_journal* journalTmp = nullptr;
    if (int ret = sd_journal_open(&journalTmp, SD_JOURNAL_LOCAL_ONLY); ret < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to open journal: ",
            phosphor::logging::entry("ERRNO=%s", strerror(-ret)));
        return IPMI_CC_RESPONSE_ERROR;
    }
    std::unique_ptr<sd_journal, decltype(&sd_journal_close)> journal(
        journalTmp, sd_journal_close);
    journalTmp = nullptr;

    // Filter the journal based on the SEL MESSAGE_ID
    std::string match =
        "MESSAGE_ID=" + std::string(intel_oem::ipmi::sel::selMessageId);
    sd_journal_add_match(journal.get(), match.c_str(), 0);

    // Count the number of SEL Entries in the journal and get the timestamp of
    // the newest entry
    bool timestampRecorded = false;
    SD_JOURNAL_FOREACH_BACKWARDS(journal.get())
    {
        if (!timestampRecorded)
        {
            uint64_t timestamp;
            if (int ret =
                    sd_journal_get_realtime_usec(journal.get(), &timestamp);
                ret < 0)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Failed to read timestamp: ",
                    phosphor::logging::entry("ERRNO=%s", strerror(-ret)));
                return IPMI_CC_RESPONSE_ERROR;
            }
            timestamp /= (1000 * 1000); // convert from us to s
            responseData->addTimeStamp = static_cast<uint32_t>(timestamp);
            timestampRecorded = true;
        }
        responseData->entries++;
    }

    *data_len = sizeof(ipmi::sel::GetSELInfoResponse);
    return IPMI_CC_OK;
}

static int fromHexStr(const std::string hexStr, std::vector<uint8_t>& data)
{
    for (unsigned int i = 0; i < hexStr.size(); i += 2)
    {
        try
        {
            data.push_back(static_cast<uint8_t>(
                std::stoul(hexStr.substr(i, 2), nullptr, 16)));
        }
        catch (std::invalid_argument& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
            return -1;
        }
        catch (std::out_of_range& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
            return -1;
        }
    }
    return 0;
}

static int getJournalMetadata(sd_journal* journal,
                              const std::string_view& field,
                              std::string& contents)
{
    const char* data = nullptr;
    size_t length = 0;

    // Get the metadata from the requested field of the journal entry
    if (int ret = sd_journal_get_data(journal, field.data(),
                                      (const void**)&data, &length);
        ret < 0)
    {
        return ret;
    }
    std::string_view metadata(data, length);
    // Only use the content after the "=" character.
    metadata.remove_prefix(std::min(metadata.find("=") + 1, metadata.size()));
    contents = std::string(metadata);
    return 0;
}

static int getJournalMetadata(sd_journal* journal,
                              const std::string_view& field, const int& base,
                              int& contents)
{
    std::string metadata;
    // Get the metadata from the requested field of the journal entry
    if (int ret = getJournalMetadata(journal, field, metadata); ret < 0)
    {
        return ret;
    }
    try
    {
        contents = static_cast<int>(std::stoul(metadata, nullptr, base));
    }
    catch (std::invalid_argument& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return -1;
    }
    catch (std::out_of_range& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return -1;
    }
    return 0;
}

static int getJournalSelData(sd_journal* journal, std::vector<uint8_t>& evtData)
{
    std::string evtDataStr;
    // Get the OEM data from the IPMI_SEL_DATA field
    if (int ret = getJournalMetadata(journal, "IPMI_SEL_DATA", evtDataStr);
        ret < 0)
    {
        return ret;
    }
    return fromHexStr(evtDataStr, evtData);
}

ipmi_ret_t ipmiStorageGetSELEntry(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t data_len,
                                  ipmi_context_t context)
{
    if (*data_len != sizeof(ipmi::sel::GetSELEntryRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    *data_len = 0; // Default to 0 in case of errors
    auto requestData =
        static_cast<const ipmi::sel::GetSELEntryRequest*>(request);

    if (requestData->reservationID != 0 || requestData->offset != 0)
    {
        if (!checkSELReservation(requestData->reservationID))
        {
            return IPMI_CC_INVALID_RESERVATION_ID;
        }
    }

    GetSELEntryResponse record{};
    // Default as the last entry
    record.nextRecordID = ipmi::sel::lastEntry;

    // Check for the requested SEL Entry.
    sd_journal* journalTmp;
    if (int ret = sd_journal_open(&journalTmp, SD_JOURNAL_LOCAL_ONLY); ret < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to open journal: ",
            phosphor::logging::entry("ERRNO=%s", strerror(-ret)));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    std::unique_ptr<sd_journal, decltype(&sd_journal_close)> journal(
        journalTmp, sd_journal_close);
    journalTmp = nullptr;

    std::string match =
        "MESSAGE_ID=" + std::string(intel_oem::ipmi::sel::selMessageId);
    sd_journal_add_match(journal.get(), match.c_str(), 0);

    // Get the requested target SEL record ID if first or last is requested.
    int targetID = requestData->selRecordID;
    if (targetID == ipmi::sel::firstEntry)
    {
        SD_JOURNAL_FOREACH(journal.get())
        {
            // Get the record ID from the IPMI_SEL_RECORD_ID field of the first
            // entry
            if (getJournalMetadata(journal.get(), "IPMI_SEL_RECORD_ID", 10,
                                   targetID) < 0)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            break;
        }
    }
    else if (targetID == ipmi::sel::lastEntry)
    {
        SD_JOURNAL_FOREACH_BACKWARDS(journal.get())
        {
            // Get the record ID from the IPMI_SEL_RECORD_ID field of the first
            // entry
            if (getJournalMetadata(journal.get(), "IPMI_SEL_RECORD_ID", 10,
                                   targetID) < 0)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            break;
        }
    }
    // Find the requested ID
    match = "IPMI_SEL_RECORD_ID=" + std::to_string(targetID);
    sd_journal_add_match(journal.get(), match.c_str(), 0);
    // And find the next ID (wrapping to Record ID 1 when necessary)
    int nextID = targetID + 1;
    if (nextID == ipmi::sel::lastEntry)
    {
        nextID = 1;
    }
    match = "IPMI_SEL_RECORD_ID=" + std::to_string(nextID);
    sd_journal_add_match(journal.get(), match.c_str(), 0);
    SD_JOURNAL_FOREACH(journal.get())
    {
        // Get the record ID from the IPMI_SEL_RECORD_ID field
        int id = 0;
        if (getJournalMetadata(journal.get(), "IPMI_SEL_RECORD_ID", 10, id) < 0)
        {
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
        if (id == targetID)
        {
            // Found the desired record, so fill in the data
            record.recordID = id;

            int recordType = 0;
            // Get the record type from the IPMI_SEL_RECORD_TYPE field
            if (getJournalMetadata(journal.get(), "IPMI_SEL_RECORD_TYPE", 16,
                                   recordType) < 0)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            record.recordType = recordType;
            // The rest of the record depends on the record type
            if (record.recordType == intel_oem::ipmi::sel::systemEvent)
            {
                // Get the timestamp
                uint64_t ts = 0;
                if (sd_journal_get_realtime_usec(journal.get(), &ts) < 0)
                {
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                record.record.system.timestamp = static_cast<uint32_t>(
                    ts / 1000 / 1000); // Convert from us to s

                int generatorID = 0;
                // Get the generator ID from the IPMI_SEL_GENERATOR_ID field
                if (getJournalMetadata(journal.get(), "IPMI_SEL_GENERATOR_ID",
                                       16, generatorID) < 0)
                {
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                record.record.system.generatorID = generatorID;

                // Set the event message revision
                record.record.system.eventMsgRevision =
                    intel_oem::ipmi::sel::eventMsgRev;

                std::string path;
                // Get the IPMI_SEL_SENSOR_PATH field
                if (getJournalMetadata(journal.get(), "IPMI_SEL_SENSOR_PATH",
                                       path) < 0)
                {
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                record.record.system.sensorType = getSensorTypeFromPath(path);
                record.record.system.sensorNum = getSensorNumberFromPath(path);
                record.record.system.eventType =
                    getSensorEventTypeFromPath(path);

                int eventDir = 0;
                // Get the event direction from the IPMI_SEL_EVENT_DIR field
                if (getJournalMetadata(journal.get(), "IPMI_SEL_EVENT_DIR", 16,
                                       eventDir) < 0)
                {
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                // Set the event direction
                if (eventDir == 0)
                {
                    record.record.system.eventDir = deassertionEvent;
                }

                std::vector<uint8_t> evtData;
                // Get the event data from the IPMI_SEL_DATA field
                if (getJournalSelData(journal.get(), evtData) < 0)
                {
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                record.record.system.eventData[0] = evtData[0];
                record.record.system.eventData[1] = evtData[1];
                record.record.system.eventData[2] = evtData[2];
            }
            else if (record.recordType >=
                         intel_oem::ipmi::sel::oemTsEventFirst &&
                     record.recordType <= intel_oem::ipmi::sel::oemTsEventLast)
            {
                // Get the timestamp
                uint64_t timestamp = 0;
                if (sd_journal_get_realtime_usec(journal.get(), &timestamp) < 0)
                {
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                record.record.oemTs.timestamp = static_cast<uint32_t>(
                    timestamp / 1000 / 1000); // Convert from us to s

                std::vector<uint8_t> evtData;
                // Get the OEM data from the IPMI_SEL_DATA field
                if (getJournalSelData(journal.get(), evtData) < 0)
                {
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                // Only keep the bytes that fit in the record
                std::copy_n(evtData.begin(),
                            std::min(evtData.size(),
                                     intel_oem::ipmi::sel::oemTsEventSize),
                            record.record.oemTs.eventData);
            }
            else if (record.recordType >= intel_oem::ipmi::sel::oemEventFirst &&
                     record.recordType <= intel_oem::ipmi::sel::oemEventLast)
            {
                std::vector<uint8_t> evtData;
                // Get the OEM data from the IPMI_SEL_DATA field
                if (getJournalSelData(journal.get(), evtData) < 0)
                {
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                // Only keep the bytes that fit in the record
                std::copy_n(evtData.begin(),
                            std::min(evtData.size(),
                                     intel_oem::ipmi::sel::oemEventSize),
                            record.record.oem.eventData);
            }
        }
        else if (id == nextID)
        {
            record.nextRecordID = id;
        }
    }

    // If we didn't find the requested record, return an error
    if (record.recordID == 0)
    {
        return IPMI_CC_SENSOR_INVALID;
    }

    if (requestData->readLength == ipmi::sel::entireRecord)
    {
        std::copy(&record, &record + 1,
                  static_cast<GetSELEntryResponse*>(response));
        *data_len = sizeof(record);
    }
    else
    {
        if (requestData->offset >= ipmi::sel::selRecordSize ||
            requestData->readLength > ipmi::sel::selRecordSize)
        {
            return IPMI_CC_PARM_OUT_OF_RANGE;
        }

        auto diff = ipmi::sel::selRecordSize - requestData->offset;
        auto readLength =
            std::min(diff, static_cast<int>(requestData->readLength));

        *static_cast<uint16_t*>(response) = record.nextRecordID;
        std::copy_n(
            reinterpret_cast<uint8_t*>(&record.recordID) + requestData->offset,
            readLength,
            static_cast<uint8_t*>(response) + sizeof(record.nextRecordID));
        *data_len = sizeof(record.nextRecordID) + readLength;
    }

    return IPMI_CC_OK;
}

ipmi_ret_t ipmiStorageAddSELEntry(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t data_len,
                                  ipmi_context_t context)
{
    static constexpr char const* ipmiSELObject =
        "xyz.openbmc_project.Logging.IPMI";
    static constexpr char const* ipmiSELPath =
        "/xyz/openbmc_project/Logging/IPMI";
    static constexpr char const* ipmiSELAddInterface =
        "xyz.openbmc_project.Logging.IPMI";
    static const std::string ipmiSELAddMessage =
        "IPMI SEL entry logged using IPMI Add SEL Entry command.";
    uint16_t recordID = 0;
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};

    if (*data_len != sizeof(AddSELRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    AddSELRequest* req = static_cast<AddSELRequest*>(request);

    // Per the IPMI spec, need to cancel any reservation when a SEL entry is
    // added
    cancelSELReservation();

    if (req->recordType == intel_oem::ipmi::sel::systemEvent)
    {
        std::string sensorPath =
            getPathFromSensorNumber(req->record.system.sensorNum);
        std::vector<uint8_t> eventData(
            req->record.system.eventData,
            req->record.system.eventData +
                intel_oem::ipmi::sel::systemEventSize);
        bool assert = req->record.system.eventDir ? false : true;
        uint16_t genId = req->record.system.generatorID;
        sdbusplus::message::message writeSEL = bus.new_method_call(
            ipmiSELObject, ipmiSELPath, ipmiSELAddInterface, "IpmiSelAdd");
        writeSEL.append(ipmiSELAddMessage, sensorPath, eventData, assert,
                        genId);
        try
        {
            sdbusplus::message::message writeSELResp = bus.call(writeSEL);
            writeSELResp.read(recordID);
        }
        catch (sdbusplus::exception_t& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
            *data_len = 0;
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }
    else if (req->recordType >= intel_oem::ipmi::sel::oemTsEventFirst &&
             req->recordType <= intel_oem::ipmi::sel::oemEventLast)
    {
        std::vector<uint8_t> eventData;
        if (req->recordType <= intel_oem::ipmi::sel::oemTsEventLast)
        {
            eventData =
                std::vector<uint8_t>(req->record.oemTs.eventData,
                                     req->record.oemTs.eventData +
                                         intel_oem::ipmi::sel::oemTsEventSize);
        }
        else
        {
            eventData = std::vector<uint8_t>(
                req->record.oem.eventData,
                req->record.oem.eventData + intel_oem::ipmi::sel::oemEventSize);
        }
        sdbusplus::message::message writeSEL = bus.new_method_call(
            ipmiSELObject, ipmiSELPath, ipmiSELAddInterface, "IpmiSelAddOem");
        writeSEL.append(ipmiSELAddMessage, eventData, req->recordType);
        try
        {
            sdbusplus::message::message writeSELResp = bus.call(writeSEL);
            writeSELResp.read(recordID);
        }
        catch (sdbusplus::exception_t& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
            *data_len = 0;
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }
    else
    {
        *data_len = 0;
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    *static_cast<uint16_t*>(response) = recordID;
    *data_len = sizeof(recordID);
    return IPMI_CC_OK;
}

ipmi_ret_t ipmiStorageClearSEL(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                               ipmi_request_t request, ipmi_response_t response,
                               ipmi_data_len_t data_len, ipmi_context_t context)
{
    if (*data_len != sizeof(ipmi::sel::ClearSELRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    auto requestData = static_cast<const ipmi::sel::ClearSELRequest*>(request);

    if (!checkSELReservation(requestData->reservationID))
    {
        *data_len = 0;
        return IPMI_CC_INVALID_RESERVATION_ID;
    }

    if (requestData->charC != 'C' || requestData->charL != 'L' ||
        requestData->charR != 'R')
    {
        *data_len = 0;
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    uint8_t eraseProgress = ipmi::sel::eraseComplete;

    /*
     * Erasure status cannot be fetched from DBUS, so always return erasure
     * status as `erase completed`.
     */
    if (requestData->eraseOperation == ipmi::sel::getEraseStatus)
    {
        *static_cast<uint8_t*>(response) = eraseProgress;
        *data_len = sizeof(eraseProgress);
        return IPMI_CC_OK;
    }

    // Per the IPMI spec, need to cancel any reservation when the SEL is cleared
    cancelSELReservation();

    // Save the erase time
    intel_oem::ipmi::sel::erase_time::save();

    // Clear the SEL by by rotating the journal to start a new file then
    // vacuuming to keep only the new file
    if (boost::process::system("/bin/journalctl", "--rotate") != 0)
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    if (boost::process::system("/bin/journalctl", "--vacuum-files=1") != 0)
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    *static_cast<uint8_t*>(response) = eraseProgress;
    *data_len = sizeof(eraseProgress);
    return IPMI_CC_OK;
}

ipmi_ret_t ipmiStorageSetSELTime(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                 ipmi_request_t request,
                                 ipmi_response_t response,
                                 ipmi_data_len_t data_len,
                                 ipmi_context_t context)
{
    // Set SEL Time is not supported
    *data_len = 0;
    return IPMI_CC_INVALID;
}

void registerStorageFunctions()
{
    // <Get FRU Inventory Area Info>
    ipmiPrintAndRegister(
        NETFUN_STORAGE,
        static_cast<ipmi_cmd_t>(IPMINetfnStorageCmds::ipmiCmdGetFRUInvAreaInfo),
        NULL, ipmiStorageGetFRUInvAreaInfo, PRIVILEGE_OPERATOR);

    // <READ FRU Data>
    ipmiPrintAndRegister(
        NETFUN_STORAGE,
        static_cast<ipmi_cmd_t>(IPMINetfnStorageCmds::ipmiCmdReadFRUData), NULL,
        ipmiStorageReadFRUData, PRIVILEGE_OPERATOR);

    // <WRITE FRU Data>
    ipmiPrintAndRegister(
        NETFUN_STORAGE,
        static_cast<ipmi_cmd_t>(IPMINetfnStorageCmds::ipmiCmdWriteFRUData),
        NULL, ipmiStorageWriteFRUData, PRIVILEGE_OPERATOR);

    // <Get SEL Info>
    ipmiPrintAndRegister(
        NETFUN_STORAGE,
        static_cast<ipmi_cmd_t>(IPMINetfnStorageCmds::ipmiCmdGetSELInfo), NULL,
        ipmiStorageGetSELInfo, PRIVILEGE_OPERATOR);

    // <Get SEL Entry>
    ipmiPrintAndRegister(
        NETFUN_STORAGE,
        static_cast<ipmi_cmd_t>(IPMINetfnStorageCmds::ipmiCmdGetSELEntry), NULL,
        ipmiStorageGetSELEntry, PRIVILEGE_OPERATOR);

    // <Add SEL Entry>
    ipmiPrintAndRegister(
        NETFUN_STORAGE,
        static_cast<ipmi_cmd_t>(IPMINetfnStorageCmds::ipmiCmdAddSEL), NULL,
        ipmiStorageAddSELEntry, PRIVILEGE_OPERATOR);

    // <Clear SEL>
    ipmiPrintAndRegister(
        NETFUN_STORAGE,
        static_cast<ipmi_cmd_t>(IPMINetfnStorageCmds::ipmiCmdClearSEL), NULL,
        ipmiStorageClearSEL, PRIVILEGE_OPERATOR);

    // <Set SEL Time>
    ipmiPrintAndRegister(
        NETFUN_STORAGE,
        static_cast<ipmi_cmd_t>(IPMINetfnStorageCmds::ipmiCmdSetSELTime), NULL,
        ipmiStorageSetSELTime, PRIVILEGE_OPERATOR);
}
} // namespace storage
} // namespace ipmi

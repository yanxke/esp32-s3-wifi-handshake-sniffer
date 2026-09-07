#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include <Arduino.h>

namespace Capture {

constexpr size_t MAX_TARGETS = 8;

struct TargetNetwork {
    uint8_t bssid[6] = {0};
    uint8_t channel = 1;
    char    ssid[33] = "";
};

extern bool     isRunning;
extern bool     handshakeFound;
extern bool     pmkidFound;
extern uint32_t frameCount;
extern uint32_t eapolCount;
extern uint32_t pmkidCount;
extern uint8_t  captureChannel;

void setup();
void start(uint8_t channel, const uint8_t* targetBSSID, bool fullChannel = false, const char* essid = nullptr);
void stop();
void loop();
void reset();
void startSaved(bool preserveSavedFiles = true);
void saveConfiguration(uint8_t channel, const uint8_t* targetBSSID, bool fullChannel, const char* essid = nullptr);
bool startTargets(const TargetNetwork* targets, size_t count);
bool saveTargetConfiguration(const TargetNetwork* targets, size_t count);
bool hasSavedConfig();
bool isAutoStartEnabled();
void setAutoStartEnabled(bool enabled);
uint8_t getSavedChannel();
bool usesSavedFullChannel();
const char* getSavedBssid();
size_t getSavedTargetCount();
bool getSavedTarget(size_t index, TargetNetwork& out);

bool usesFullChannel();
bool managementApActive();
const char* getLastError();
const char* getCaptureSummary();
uint32_t    getRawChannelFrames();
uint32_t    getTargetFrames();
bool        hasLatestCapture();
bool        hasLatestMetadata();
size_t      getLatestPcapSize();
size_t      getLatestPmkidSize();
size_t      getLatestMetaSize();
size_t      getFilesystemTotalBytes();
size_t      getFilesystemUsedBytes();
size_t      getFilesystemFreeBytes();

const uint8_t* getPcapData();
size_t         getPcapSize();
const char*    getPmkidData();
size_t         getPmkidSize();
bool           has22000Data();
bool           loadLatestPcap(std::vector<uint8_t>& out);
bool           loadLatestPmkid(String& out);
bool           loadLatestMeta(String& out);
bool           clearLatestSaved();
bool           clearAllFiles();

}  // namespace Capture

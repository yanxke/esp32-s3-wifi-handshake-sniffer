#include "capture.h"

#include <Arduino.h>
#include <LittleFS.h>
#include <Preferences.h>
#include <WiFi.h>
#include <esp_wifi.h>

#include <array>
#include <cstdio>
#include <cstring>
#include <vector>

namespace Capture {

bool     isRunning      = false;
bool     handshakeFound = false;
bool     pmkidFound     = false;
uint32_t frameCount     = 0;
uint32_t eapolCount     = 0;
uint32_t pmkidCount     = 0;
uint8_t  captureChannel = 1;

const char* getPmkidData();

namespace {

constexpr const char* kMgmtApSsid = "esp32-s3-whs";
constexpr const char* kMgmtApPassword = "changeme";
constexpr const char* kLatestPcapPath = "/latest_capture.pcap";
constexpr const char* kLatestPmkidPath = "/latest_capture.22000";
constexpr const char* kLatestMetaPath = "/latest_capture.json";
constexpr size_t PCAP_CHUNK = 8 * 1024;
constexpr size_t MAX_PMKID = 10;
constexpr size_t MAX_NETWORKS = 8;
constexpr size_t MAX_ESSID_LEN = 32;
constexpr uint32_t CHECKPOINT_INTERVAL_MS = 60000;
constexpr uint32_t CHANNEL_ROTATION_INTERVAL_MS = 10UL * 60UL * 1000UL;

bool     fullChannelMode  = false;
Preferences capturePreferences;
bool     savedConfigValid = false;
bool     savedFullChannel = true;
bool     resumeOnBoot = false;
uint8_t savedChannel = 1;
uint8_t savedBssid[6] = {0};
char    savedBssidText[18] = "";
String  savedEssid;
std::array<TargetNetwork, MAX_TARGETS> savedTargets;
size_t  savedTargetCount = 0;
bool     apActive         = true;
bool     fsReady          = false;
bool     latestPcapKnown  = false;
bool     latestPmkidKnown = false;
bool     latestMetaKnown  = false;
uint8_t  targetBssid[6]   = {0};
std::array<TargetNetwork, MAX_TARGETS> activeTargets;
size_t   activeTargetCount = 0;
std::array<uint8_t, MAX_TARGETS> activeChannels;
size_t   activeChannelCount = 0;
size_t   activeChannelIndex = 0;
uint32_t lastChannelSwitchMs = 0;
char     capSummary[160]  = "";
char     lastError[160]   = "";
size_t   pcapWritePos     = 0;
uint32_t startMs          = 0;
uint32_t lastDiagMs       = 0;
uint32_t lastCheckpointMs = 0;
size_t   lastCheckpointPcapPos = 0;
uint32_t lastCheckpointPmkidCount = 0;
bool     firstFrameSeen   = false;
bool     idleWarningShown = false;
uint32_t rawChannelFrames = 0;
uint16_t savedBeaconFrames = 0;
uint16_t savedProbeRespFrames = 0;
uint32_t pcapDroppedRecords = 0;
size_t   pcapActivePos = 0;
size_t   pcapFlushLen = 0;
bool     pcapFlushPending = false;
bool     pcapFileOpen = false;
bool     preserveSavedFilesOnStart = false;
bool     pmkidCheckpointPending = false;
uint32_t nextSessionId = 1;

File pcapFile;
std::array<uint8_t, PCAP_CHUNK> pcapActiveBuf;
std::array<uint8_t, PCAP_CHUNK> pcapFlushBuf;
String pmkidBuf;
String captureEssid;
std::array<std::array<uint8_t, 16>, MAX_PMKID> pmkidList;
std::array<std::array<uint8_t, 6>, MAX_PMKID>  pmkidApList;
std::array<std::array<uint8_t, 6>, MAX_PMKID>  pmkidStaList;
std::array<std::array<uint8_t, MAX_ESSID_LEN>, MAX_PMKID> pmkidEssidList;
std::array<uint8_t, MAX_PMKID> pmkidEssidLen;
int pmkidStored = 0;

String buildSessionMetaJson(uint32_t elapsedSec);

struct EapolCandidate {
    bool valid = false;
    uint64_t replay = 0;
    uint8_t mic[16] = {0};
    uint16_t len = 0;
    uint8_t nonce[32] = {0};
    uint8_t data[256] = {0};
};

struct NetworkEssid {
    bool used = false;
    uint8_t bssid[6] = {0};
    uint8_t len = 0;
    uint8_t data[MAX_ESSID_LEN] = {0};
};

struct HandshakeState {
    uint8_t ap[6] = {0};
    uint8_t sta[6] = {0};
    bool used = false;
    bool m1 = false;
    bool m2 = false;
    bool m3 = false;
    bool m4 = false;
    uint64_t lastReplay = 0;
    uint8_t lastLoggedMsg = 0;
    uint8_t anonce[32] = {0};
    uint64_t m1Replay = 0;
    uint8_t essidLen = 0;
    uint8_t essid[MAX_ESSID_LEN] = {0};
    EapolCandidate m2Data;
    EapolCandidate m3Data;
    EapolCandidate m4Data;
};

std::array<HandshakeState, 8> handshakes;
std::array<NetworkEssid, MAX_NETWORKS> networkEssids;

void storeEapolCandidate(EapolCandidate& candidate, const uint8_t* pkt, int off,
                         uint16_t frameLen, uint64_t replay) {
    candidate.valid = true;
    candidate.replay = replay;
    candidate.len = frameLen;
    memcpy(candidate.nonce, pkt + off + 17, sizeof(candidate.nonce));
    memcpy(candidate.data, pkt + off, frameLen);
    memcpy(candidate.mic, pkt + off + 81, sizeof(candidate.mic));
    memset(candidate.data + 81, 0, sizeof(candidate.mic));
}

const uint8_t PCAP_GHDR[] = {
    0xD4, 0xC3, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0x00, 0x00, 0x7F, 0x00, 0x00, 0x00
};

uint8_t rtTmpl[18] = {
    0x00, 0x00, 0x12, 0x00, 0x34, 0x00, 0x20, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00
};

uint16_t ch2freq(uint8_t ch) {
    if (ch == 14) return 2484;
    if (ch >= 1 && ch <= 13) return 2407 + ch * 5;
    return 2412;
}

uint16_t ch2flags(uint16_t f) {
    return (f >= 5000) ? 0x0140 : 0x00A0;
}

void startManagementAp() {
    WiFi.persistent(false);
    // esp_wifi_stop() is used by capture mode. Force a clean Arduino Wi-Fi
    // state before starting the management AP again.
    WiFi.mode(WIFI_MODE_NULL);
    delay(50);
    WiFi.mode(WIFI_MODE_APSTA);
    const bool started = WiFi.softAP(kMgmtApSsid, kMgmtApPassword, 1, 0, 4);
    apActive = started;
    Serial.printf("[Capture] Management AP %s, SSID=%s IP=%s\n",
                  started ? "restored" : "restart failed",
                  kMgmtApSsid,
                  WiFi.softAPIP().toString().c_str());
}

void stopManagementAp() {
    Serial.println("[Capture] Management AP stopping for passive sniff");
    WiFi.softAPdisconnect(true);
    apActive = false;
}

void resetHandshakeState() {
    for (auto& hs : handshakes) {
        hs = HandshakeState{};
    }
}

void copyMac(uint8_t* dst, const uint8_t* src) {
    memcpy(dst, src, 6);
}

bool sameMac(const uint8_t* a, const uint8_t* b) {
    return memcmp(a, b, 6) == 0;
}

NetworkEssid* getNetworkEssid(const uint8_t* bssid, bool create) {
    for (auto& network : networkEssids) {
        if (network.used && sameMac(network.bssid, bssid)) return &network;
    }
    if (!create) return nullptr;
    for (auto& network : networkEssids) {
        if (!network.used) {
            network.used = true;
            memcpy(network.bssid, bssid, 6);
            return &network;
        }
    }
    return nullptr;
}

bool extractSsidFromManagement(const uint8_t* pkt, uint16_t len,
                               uint8_t* ssid, uint8_t* ssidLen) {
    if (!pkt || !ssid || !ssidLen || len < 36) return false;

    const uint8_t subtype = (pkt[0] >> 4) & 0x0F;
    if (subtype != 0x08 && subtype != 0x05) return false;

    int pos = 36; // 24-byte MAC header + 12-byte beacon/probe fixed fields
    while (pos + 2 <= len) {
        const uint8_t id = pkt[pos];
        const uint8_t ieLen = pkt[pos + 1];
        pos += 2;
        if (pos + ieLen > len) return false;
        if (id == 0) {
            if (ieLen == 0 || ieLen > MAX_ESSID_LEN) return false;
            memcpy(ssid, pkt + pos, ieLen);
            *ssidLen = ieLen;
            return true;
        }
        pos += ieLen;
    }
    return false;
}

void rememberNetworkEssid(const uint8_t* bssid, const uint8_t* ssid, uint8_t ssidLen) {
    if (!bssid || !ssid || ssidLen == 0 || ssidLen > MAX_ESSID_LEN) return;
    NetworkEssid* network = getNetworkEssid(bssid, true);
    if (!network) return;
    memcpy(network->bssid, bssid, 6);
    memcpy(network->data, ssid, ssidLen);
    network->len = ssidLen;
}

bool matchesTarget(const uint8_t* pkt, uint16_t len) {
    if (fullChannelMode) return true;
    if (len < 24) return false;

    uint8_t fc = pkt[0];
    uint8_t type = (fc >> 2) & 0x03;

    for (size_t i = 0; i < activeTargetCount; ++i) {
        if (activeTargets[i].channel != captureChannel) continue;

        const uint8_t* bssid = activeTargets[i].bssid;
        if (type == 0 && sameMac(pkt + 16, bssid)) {
            return true;
        }

        if (type == 2 && (sameMac(pkt + 4, bssid) ||
                          sameMac(pkt + 10, bssid) ||
                          sameMac(pkt + 16, bssid))) {
            return true;
        }
    }

    return false;
}

void getAddrs(const uint8_t* pkt, uint8_t* sa, uint8_t* da) {
    uint8_t fc = pkt[0];
    bool toDs = fc & 1;
    bool fromDs = fc & 2;
    if (toDs && !fromDs) {
        if (da) memcpy(da, pkt + 4, 6);
        if (sa) memcpy(sa, pkt + 10, 6);
    } else if (fromDs && !toDs) {
        if (da) memcpy(da, pkt + 4, 6);
        if (sa) memcpy(sa, pkt + 16, 6);
    } else if (toDs && fromDs) {
        if (da) memcpy(da, pkt + 4, 6);
        if (sa) memcpy(sa, pkt + 24, 6);
    } else {
        if (da) memcpy(da, pkt + 4, 6);
        if (sa) memcpy(sa, pkt + 10, 6);
    }
}

int findEapol(const uint8_t* pkt, uint16_t len) {
    for (int i = 24; i < len - 7; ++i) {
        if (pkt[i] == 0xAA && pkt[i + 1] == 0xAA && pkt[i + 2] == 0x03 &&
            pkt[i + 6] == 0x88 && pkt[i + 7] == 0x8E) {
            return i + 8;
        }
    }
    return -1;
}

void macStr(const uint8_t* m, char* out) {
    snprintf(out, 18, "%02X%02X%02X%02X%02X%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
}

void appendHex(String& out, const uint8_t* data, size_t len) {
    static const char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < len; ++i) {
        out += hex[data[i] >> 4];
        out += hex[data[i] & 0x0F];
    }
}

bool isPmkidDuplicate(const uint8_t* pmkid) {
    for (int i = 0; i < pmkidStored; ++i) {
        if (memcmp(pmkidList[i].data(), pmkid, 16) == 0) return true;
    }
    return false;
}

void addPmkid(const uint8_t* pmkid, const uint8_t* ap, const uint8_t* sta,
              const uint8_t* essid, uint8_t essidLen) {
    if (pmkidStored >= (int)MAX_PMKID || isPmkidDuplicate(pmkid)) return;
    memcpy(pmkidList[pmkidStored].data(), pmkid, 16);
    if (ap) memcpy(pmkidApList[pmkidStored].data(), ap, 6);
    else memset(pmkidApList[pmkidStored].data(), 0xFF, 6);
    if (sta) memcpy(pmkidStaList[pmkidStored].data(), sta, 6);
    else memset(pmkidStaList[pmkidStored].data(), 0xFF, 6);
    pmkidEssidLen[pmkidStored] = (essid && essidLen <= MAX_ESSID_LEN) ? essidLen : 0;
    if (pmkidEssidLen[pmkidStored] > 0) {
        memcpy(pmkidEssidList[pmkidStored].data(), essid, pmkidEssidLen[pmkidStored]);
    }
    pmkidStored++;
    pmkidCount = pmkidStored;
    pmkidFound = true;
    pmkidCheckpointPending = true;
    char apStr[18], staStr[18];
    macStr(pmkidApList[pmkidStored - 1].data(), apStr);
    macStr(pmkidStaList[pmkidStored - 1].data(), staStr);
    Serial.printf("[Capture] PMKID captured #%u AP=%s STA=%s\n",
                  (unsigned)pmkidCount, apStr, staStr);
}

void extractPmkidFromM1(const uint8_t* pkt, uint16_t len, int off, const uint8_t* sta,
                        const uint8_t* ap, const uint8_t* essid, uint8_t essidLen) {
    if (off < 0 || off + 99 > len) return;
    const uint16_t keyDataLen = (uint16_t(pkt[off + 97]) << 8) | pkt[off + 98];
    const int kdStart = off + 99;
    const int searchEnd = kdStart + keyDataLen - 22;
    if (keyDataLen < 22 || searchEnd >= len) return;
    for (int i = kdStart; i <= searchEnd; ++i) {
        if (pkt[i] == 0xDD && pkt[i + 2] == 0x00 && pkt[i + 3] == 0x0F &&
            pkt[i + 4] == 0xAC && pkt[i + 5] == 0x04) {
            addPmkid(pkt + i + 6, ap, sta, essid, essidLen);
            return;
        }
    }
}

void extractPmkidFromBeacon(const uint8_t* pkt, uint16_t len, const uint8_t* bssid,
                            const uint8_t* essid, uint8_t essidLen) {
    for (int i = 24; i < len - 20; ++i) {
        if (pkt[i] == 0x30 && pkt[i + 2] == 0x00 && pkt[i + 3] == 0x0F && pkt[i + 4] == 0xAC) {
            int rsnLen = pkt[i + 1];
            int pos = i + 6;
            if (pos + 6 > i + 2 + rsnLen) return;
            pos += 4;
            uint16_t pairCnt = pkt[pos] | (pkt[pos + 1] << 8);
            pos += 2 + pairCnt * 4;
            if (pos + 2 > i + 2 + rsnLen) return;
            uint16_t akmCnt = pkt[pos] | (pkt[pos + 1] << 8);
            pos += 2 + akmCnt * 4 + 2;
            if (pos + 2 > i + 2 + rsnLen) return;
            uint16_t pmkidCnt = pkt[pos] | (pkt[pos + 1] << 8);
            pos += 2;
            for (int j = 0; j < pmkidCnt && pos + 16 <= i + 2 + rsnLen; ++j) {
                addPmkid(pkt + pos, bssid, nullptr, essid, essidLen);
                pos += 16;
            }
            return;
        }
    }
}

HandshakeState* getHandshakeState(const uint8_t* ap, const uint8_t* sta) {
    for (auto& hs : handshakes) {
        if (hs.used && sameMac(hs.ap, ap) && sameMac(hs.sta, sta)) {
            return &hs;
        }
    }
    for (auto& hs : handshakes) {
        if (!hs.used) {
            hs.used = true;
            copyMac(hs.ap, ap);
            copyMac(hs.sta, sta);
            return &hs;
        }
    }
    return &handshakes[0];
}

void updateSummary() {
    int n = 0;
    if (pmkidCount) n += snprintf(capSummary + n, sizeof(capSummary) - n, "PMKID=%lu ", (unsigned long)pmkidCount);
    if (eapolCount) n += snprintf(capSummary + n, sizeof(capSummary) - n, "EAPOL=%lu ", (unsigned long)eapolCount);
    if (handshakeFound) snprintf(capSummary + n, sizeof(capSummary) - n, "HS=complete");
}

String buildSessionMetaJson(uint32_t elapsedSec) {
    String out;
    out.reserve(320);
    out += "{\"channel\":";
    out += String(captureChannel);
    out += ",\"mode\":\"";
    out += fullChannelMode ? "full" : "target";
    out += "\",\"rawFrames\":";
    out += String(rawChannelFrames);
    out += ",\"targetFrames\":";
    out += String(frameCount);
    out += ",\"eapol\":";
    out += String(eapolCount);
    out += ",\"pmkidCount\":";
    out += String(pmkidCount);
    out += ",\"handshake\":";
    out += handshakeFound ? "true" : "false";
    out += ",\"elapsedSec\":";
    out += String(elapsedSec);
    out += ",\"pcapBytes\":";
    out += String((unsigned)pcapWritePos);
    out += ",\"pmkidBytes\":";
    out += String((unsigned)strlen(getPmkidData()));
    out += ",\"summary\":\"";
    out += getCaptureSummary();
    out += "\"}";
    return out;
}

bool findFileQuiet(const char* path, size_t* sizeOut = nullptr) {
    if (!fsReady) return false;
    File root = LittleFS.open("/");
    if (!root) return false;

    bool found = false;
    File file = root.openNextFile();
    while (file) {
        String name = file.name();
        if (!name.startsWith("/")) name = "/" + name;
        if (name == path) {
            if (sizeOut) *sizeOut = file.size();
            found = true;
            file.close();
            break;
        }
        file.close();
        file = root.openNextFile();
    }
    root.close();
    return found;
}

bool fileExistsNoisySafe(const char* path) {
    return findFileQuiet(path);
}

size_t fileSizeNoisySafe(const char* path) {
    size_t size = 0;
    findFileQuiet(path, &size);
    return size;
}

void analyzeKey(const uint8_t* pkt, uint16_t len, int off) {
    if (off < 0 || off + 99 > len) return;
    if (pkt[off + 1] != 0x03) return;

    const uint16_t bodyLen = (uint16_t(pkt[off + 2]) << 8) | pkt[off + 3];
    const uint16_t frameLen = uint16_t(bodyLen + 4);
    if (frameLen < 99 || frameLen > 256 || off + frameLen > len) return;

    const uint16_t ki = (uint16_t(pkt[off + 5]) << 8) | pkt[off + 6];
    const bool pairwise = ((ki >> 3) & 1) != 0;
    if (!pairwise) return;

    eapolCount++;

    // Hashcat 22000 and hcxtools do not support key-descriptor version 0.
    // Some captures advertise an AKM/RSN PMKID while still using KDV 0
    // (for example key-info 0x0088/0x13C8); exporting those as WPA*01/02
    // produces records that look valid but cannot be verified by hashcat.
    const uint8_t keyDescriptorVersion = ki & 0x07;
    if (keyDescriptorVersion == 0 || keyDescriptorVersion > 3) return;

    uint8_t sa[6], da[6];
    getAddrs(pkt, sa, da);

    const bool mic = ((ki >> 8) & 1) != 0;
    const bool ack = ((ki >> 7) & 1) != 0;
    // WPA Key Information: Install is bit 6 (Key Index occupies bits 4-5).
    // Bit 4 is not the Install flag and causes M3 (for example, 0x13CA) to
    // be missed entirely.
    const bool inst = ((ki >> 6) & 1) != 0;
    const bool sec = ((ki >> 9) & 1) != 0;
    uint64_t replay = 0;
    for (int i = 0; i < 8; ++i) {
        replay = (replay << 8) | pkt[off + 9 + i];
    }

    uint8_t ap[6], sta[6];
    if (ack) {
        copyMac(ap, sa);
        copyMac(sta, da);
    } else {
        copyMac(ap, da);
        copyMac(sta, sa);
    }

    HandshakeState* hs = getHandshakeState(ap, sta);
    NetworkEssid* network = getNetworkEssid(ap, false);
    if (network && network->len > 0) {
        hs->essidLen = network->len;
        memcpy(hs->essid, network->data, network->len);
    }
    const uint8_t* hsEssid = hs->essidLen > 0
                               ? hs->essid
                               : (const uint8_t*)captureEssid.c_str();
    const uint8_t hsEssidLen = hs->essidLen > 0
                                 ? hs->essidLen
                                 : uint8_t(captureEssid.length() > MAX_ESSID_LEN
                                             ? MAX_ESSID_LEN : captureEssid.length());
    uint8_t msgType = 0;

    if (ack && !mic && !inst && !sec && !hs->m1) {
        hs->m1 = true;
        hs->m1Replay = replay;
        memcpy(hs->anonce, pkt + off + 17, sizeof(hs->anonce));
        msgType = 1;
        char apStr[18], staStr[18];
        macStr(ap, apStr);
        macStr(sta, staStr);
        Serial.printf("[Capture] EAPOL M1 AP=%s STA=%s ki=0x%04X replay=%llu\n",
                      apStr, staStr, ki, replay);
        extractPmkidFromM1(pkt, len, off, sta, ap, hsEssid, hsEssidLen);
    } else if (!ack && mic && !inst && !sec && !hs->m2) {
        hs->m2 = true;
        storeEapolCandidate(hs->m2Data, pkt, off, frameLen, replay);
        msgType = 2;
        char apStr[18], staStr[18];
        macStr(ap, apStr);
        macStr(sta, staStr);
        Serial.printf("[Capture] EAPOL M2 AP=%s STA=%s ki=0x%04X replay=%llu\n",
                      apStr, staStr, ki, replay);
    } else if (ack && mic && inst && sec && !hs->m3) {
        hs->m3 = true;
        storeEapolCandidate(hs->m3Data, pkt, off, frameLen, replay);
        msgType = 3;
        char apStr[18], staStr[18];
        macStr(ap, apStr);
        macStr(sta, staStr);
        Serial.printf("[Capture] EAPOL M3 AP=%s STA=%s ki=0x%04X replay=%llu\n",
                      apStr, staStr, ki, replay);
    } else if (!ack && mic && !inst && sec && !hs->m4) {
        hs->m4 = true;
        storeEapolCandidate(hs->m4Data, pkt, off, frameLen, replay);
        msgType = 4;
        char apStr[18], staStr[18];
        macStr(ap, apStr);
        macStr(sta, staStr);
        Serial.printf("[Capture] EAPOL M4 AP=%s STA=%s ki=0x%04X replay=%llu\n",
                      apStr, staStr, ki, replay);
    } else if (hs->lastReplay != replay || hs->lastLoggedMsg == 0) {
        char apStr[18], staStr[18];
        macStr(ap, apStr);
        macStr(sta, staStr);
        Serial.printf("[Capture] EAPOL other AP=%s STA=%s ki=0x%04X ack=%u mic=%u inst=%u sec=%u replay=%llu\n",
                      apStr, staStr, ki, ack ? 1 : 0, mic ? 1 : 0, inst ? 1 : 0, sec ? 1 : 0, replay);
    }

    hs->lastReplay = replay;
    if (msgType != 0) hs->lastLoggedMsg = msgType;

    if (hs->m1 && hs->m2 && hs->m3 && hs->m4 && !handshakeFound) {
        handshakeFound = true;
        char apStr[18], staStr[18];
        macStr(ap, apStr);
        macStr(sta, staStr);
        Serial.printf("[Capture] Handshake complete AP=%s STA=%s\n", apStr, staStr);
    }

    updateSummary();
}

void writePcapRecord(const uint8_t* frame, uint16_t len, int8_t rssi) {
    const size_t recordSize = len + 34;
    if (!pcapFileOpen || recordSize > PCAP_CHUNK) return;

    uint32_t us = micros();
    uint32_t secs = us / 1000000;
    uint32_t usecs = us % 1000000;
    uint32_t packetLen = 18 + len;
    uint8_t hdr[16];
    hdr[0] = secs & 0xFF; hdr[1] = (secs >> 8) & 0xFF; hdr[2] = (secs >> 16) & 0xFF; hdr[3] = (secs >> 24) & 0xFF;
    hdr[4] = usecs & 0xFF; hdr[5] = (usecs >> 8) & 0xFF; hdr[6] = (usecs >> 16) & 0xFF; hdr[7] = (usecs >> 24) & 0xFF;
    hdr[8] = packetLen & 0xFF; hdr[9] = (packetLen >> 8) & 0xFF; hdr[10] = (packetLen >> 16) & 0xFF; hdr[11] = (packetLen >> 24) & 0xFF;
    hdr[12] = hdr[8]; hdr[13] = hdr[9]; hdr[14] = hdr[10]; hdr[15] = hdr[11];

    uint8_t rt[18];
    memcpy(rt, rtTmpl, sizeof(rt));
    uint16_t freq = ch2freq(captureChannel);
    uint16_t flags = ch2flags(freq);
    rt[10] = freq & 0xFF;
    rt[11] = (freq >> 8) & 0xFF;
    rt[12] = flags & 0xFF;
    rt[13] = (flags >> 8) & 0xFF;
    rt[14] = (uint8_t)rssi;

    noInterrupts();
    if (pcapActivePos + recordSize > PCAP_CHUNK) {
        if (pcapFlushPending) {
            pcapDroppedRecords++;
            interrupts();
            return;
        }
        memcpy(pcapFlushBuf.data(), pcapActiveBuf.data(), pcapActivePos);
        pcapFlushLen = pcapActivePos;
        pcapFlushPending = true;
        pcapActivePos = 0;
    }

    memcpy(pcapActiveBuf.data() + pcapActivePos, hdr, sizeof(hdr));
    pcapActivePos += sizeof(hdr);
    memcpy(pcapActiveBuf.data() + pcapActivePos, rt, sizeof(rt));
    pcapActivePos += sizeof(rt);
    memcpy(pcapActiveBuf.data() + pcapActivePos, frame, len);
    pcapActivePos += len;
    pcapWritePos += recordSize;
    interrupts();
}

void flushPendingPcapChunk() {
    if (!pcapFileOpen || !pcapFlushPending) return;

    size_t len = 0;
    noInterrupts();
    len = pcapFlushLen;
    interrupts();

    if (len > 0) {
        pcapFile.write(pcapFlushBuf.data(), len);
    }

    noInterrupts();
    pcapFlushLen = 0;
    pcapFlushPending = false;
    interrupts();
}

void flushActivePcapChunk() {
    if (!pcapFileOpen) return;

    noInterrupts();
    size_t len = pcapActivePos;
    pcapActivePos = 0;
    interrupts();

    if (len > 0) {
        pcapFile.write(pcapActiveBuf.data(), len);
    }
}

bool parseSavedBssid(const char* text, uint8_t out[6]) {
    if (!text || strlen(text) != 17) return false;
    unsigned values[6];
    int n = sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x",
                   &values[0], &values[1], &values[2],
                   &values[3], &values[4], &values[5]);
    if (n != 6) return false;
    for (int i = 0; i < 6; ++i) out[i] = (uint8_t)values[i];
    return true;
}

bool normalizeTargets(const TargetNetwork* targets, size_t count,
                      std::array<TargetNetwork, MAX_TARGETS>& out,
                      size_t& outCount) {
    outCount = 0;
    if (!targets || count == 0) return false;

    for (size_t i = 0; i < count && outCount < MAX_TARGETS; ++i) {
        if (targets[i].channel < 1 || targets[i].channel > 14) continue;

        bool duplicate = false;
        for (size_t j = 0; j < outCount; ++j) {
            if (sameMac(out[j].bssid, targets[i].bssid)) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) continue;

        out[outCount] = targets[i];
        out[outCount].ssid[sizeof(out[outCount].ssid) - 1] = '\0';
        ++outCount;
    }

    return outCount > 0;
}

void rebuildActiveChannels() {
    activeChannelCount = 0;
    activeChannelIndex = 0;
    for (size_t i = 0; i < activeTargetCount; ++i) {
        bool known = false;
        for (size_t j = 0; j < activeChannelCount; ++j) {
            if (activeChannels[j] == activeTargets[i].channel) {
                known = true;
                break;
            }
        }
        if (!known && activeChannelCount < activeChannels.size()) {
            activeChannels[activeChannelCount++] = activeTargets[i].channel;
        }
    }
}

bool saveTargetConfigurationInternal(const TargetNetwork* targets, size_t count) {
    std::array<TargetNetwork, MAX_TARGETS> normalized;
    size_t normalizedCount = 0;
    if (!normalizeTargets(targets, count, normalized, normalizedCount)) return false;

    savedTargets = normalized;
    savedTargetCount = normalizedCount;
    savedFullChannel = false;
    savedChannel = savedTargets[0].channel;
    memcpy(savedBssid, savedTargets[0].bssid, sizeof(savedBssid));
    snprintf(savedBssidText, sizeof(savedBssidText),
             "%02X:%02X:%02X:%02X:%02X:%02X",
             savedBssid[0], savedBssid[1], savedBssid[2],
             savedBssid[3], savedBssid[4], savedBssid[5]);
    savedEssid = savedTargets[0].ssid;

    const size_t targetBytes = normalizedCount * sizeof(TargetNetwork);
    const bool targetsWritten = capturePreferences.putBytes("targets", normalized.data(), targetBytes) == targetBytes;
    const bool countWritten = capturePreferences.putUChar("target_count", (uint8_t)normalizedCount) == sizeof(uint8_t);
    const bool channelWritten = capturePreferences.putUChar("channel", savedChannel) == sizeof(savedChannel);
    const bool modeWritten = capturePreferences.putBool("full", false) == sizeof(uint8_t);
    const bool bssidWritten = capturePreferences.putString("bssid", savedBssidText) == strlen(savedBssidText);
    const bool essidWritten = capturePreferences.putString("ssid", savedEssid) == savedEssid.length();

    const bool verified = targetsWritten && countWritten && channelWritten && modeWritten &&
                          bssidWritten && essidWritten &&
                          capturePreferences.getUChar("target_count", 0) == normalizedCount &&
                          capturePreferences.getBytesLength("targets") == targetBytes;
    savedConfigValid = verified;

    Serial.printf("[Capture] NVS config save: write=%s verify=%s mode=target targets=%u\n",
                  (targetsWritten && countWritten && channelWritten && modeWritten) ? "ok" : "FAIL",
                  verified ? "ok" : "FAIL",
                  (unsigned)normalizedCount);
    return verified;
}

void saveCaptureConfig(uint8_t channel, const uint8_t* bssid, bool fullChannel, const char* essid) {
    if (!fullChannel && !bssid) return;

    if (!fullChannel) {
        TargetNetwork target;
        memcpy(target.bssid, bssid, sizeof(target.bssid));
        target.channel = channel;
        if (essid) strncpy(target.ssid, essid, sizeof(target.ssid) - 1);
        target.ssid[sizeof(target.ssid) - 1] = '\0';
        saveTargetConfigurationInternal(&target, 1);
        return;
    }

    savedChannel = channel;
    savedFullChannel = true;
    savedTargetCount = 0;
    savedTargets = {};
    savedEssid = String();
    memset(savedBssid, 0, sizeof(savedBssid));
    savedBssidText[0] = '\0';
    const bool channelWritten = capturePreferences.putUChar("channel", channel) == sizeof(channel);
    const bool modeWritten = capturePreferences.putBool("full", true) == sizeof(uint8_t);
    const bool bssidWritten = !capturePreferences.isKey("bssid") || capturePreferences.remove("bssid");
    const bool targetsRemoved = !capturePreferences.isKey("targets") || capturePreferences.remove("targets");
    const bool countRemoved = !capturePreferences.isKey("target_count") || capturePreferences.remove("target_count");
    const bool essidWritten = capturePreferences.putString("ssid", "") == 0;
    savedConfigValid = channelWritten && modeWritten && bssidWritten && targetsRemoved &&
                       countRemoved && essidWritten &&
                       capturePreferences.getUChar("channel", 0) == channel &&
                       capturePreferences.getBool("full", false);

    Serial.printf("[Capture] NVS config save: write=%s verify=%s mode=full channel=%u\n",
                  (channelWritten && modeWritten) ? "ok" : "FAIL",
                  savedConfigValid ? "ok" : "FAIL",
                  channel);
}

void archiveExistingSession() {
    if (!fsReady) return;

    const size_t pcapSize = fileSizeNoisySafe(kLatestPcapPath);
    const size_t pmkidSize = fileSizeNoisySafe(kLatestPmkidPath);
    const size_t metaSize = fileSizeNoisySafe(kLatestMetaPath);
    const bool hasPcap = pcapSize > sizeof(PCAP_GHDR);
    const bool hasPmkid = pmkidSize > 0;
    const bool hasMeta = metaSize > 0;
    Serial.printf("[Capture] Archive check: %s=%u B %s=%u B %s=%u B\n",
                  kLatestPcapPath, (unsigned)pcapSize,
                  kLatestPmkidPath, (unsigned)pmkidSize,
                  kLatestMetaPath, (unsigned)metaSize);
    if (!hasPcap && !hasPmkid && !hasMeta) {
        Serial.println("[Capture] Archive check: no completed latest files found");
        return;
    }

    char id[12];
    snprintf(id, sizeof(id), "%06lu", (unsigned long)nextSessionId++);
    capturePreferences.putUInt("nextid", nextSessionId);

    char archivedPcap[40], archivedPmkid[40], archivedMeta[40];
    snprintf(archivedPcap, sizeof(archivedPcap), "/session_%s.pcap", id);
    snprintf(archivedPmkid, sizeof(archivedPmkid), "/session_%s.22000", id);
    snprintf(archivedMeta, sizeof(archivedMeta), "/session_%s.json", id);

    bool ok = true;
    if (hasPcap) {
        const bool renamed = LittleFS.rename(kLatestPcapPath, archivedPcap);
        Serial.printf("[Capture] Rename %s -> %s: %s\n", kLatestPcapPath, archivedPcap, renamed ? "ok" : "FAIL");
        ok = renamed && ok;
    }
    if (hasPmkid) {
        const bool renamed = LittleFS.rename(kLatestPmkidPath, archivedPmkid);
        Serial.printf("[Capture] Rename %s -> %s: %s\n", kLatestPmkidPath, archivedPmkid, renamed ? "ok" : "FAIL");
        ok = renamed && ok;
    }
    if (hasMeta) {
        const bool renamed = LittleFS.rename(kLatestMetaPath, archivedMeta);
        Serial.printf("[Capture] Rename %s -> %s: %s\n", kLatestMetaPath, archivedMeta, renamed ? "ok" : "FAIL");
        ok = renamed && ok;
    }
    Serial.printf("[Capture] Archived session %s: %s\n", id, ok ? "ok" : "partial/fail");
}

void logSavedFiles() {
    if (!fsReady) return;
    File root = LittleFS.open("/");
    if (!root) {
        Serial.println("[Capture] Filesystem listing failed");
        return;
    }
    uint16_t count = 0;
    File file = root.openNextFile();
    while (file) {
        Serial.printf("[Capture] File found: %s (%u B)\n", file.name(), (unsigned)file.size());
        count++;
        file.close();
        file = root.openNextFile();
    }
    root.close();
    Serial.printf("[Capture] Filesystem listing complete: %u file(s)\n", count);
}

void checkpointCapture(bool savePcap, bool savePmkid) {
    if (!fsReady) return;

    if (savePcap) {
        // Make all complete records currently buffered in RAM durable first.
        flushPendingPcapChunk();
        flushActivePcapChunk();
        if (pcapFileOpen) {
            pcapFile.flush();
            latestPcapKnown = fileSizeNoisySafe(kLatestPcapPath) > sizeof(PCAP_GHDR);
        }
    }

    size_t pmkidSize = 0;
    if (savePmkid) {
        const char* pmkidData = getPmkidData();
        pmkidSize = strlen(pmkidData);
        if (fileExistsNoisySafe(kLatestPmkidPath)) LittleFS.remove(kLatestPmkidPath);
        File pmkidFile = LittleFS.open(kLatestPmkidPath, FILE_WRITE, true);
        bool pmkidSaved = false;
        if (pmkidFile) {
            pmkidSaved = pmkidFile.write((const uint8_t*)pmkidData, pmkidSize) == pmkidSize;
            pmkidFile.flush();
            pmkidFile.close();
        }
        latestPmkidKnown = pmkidSaved && pmkidSize > 0;
    }

    String meta = buildSessionMetaJson((millis() - startMs) / 1000);
    if (fileExistsNoisySafe(kLatestMetaPath)) LittleFS.remove(kLatestMetaPath);
    File metaFile = LittleFS.open(kLatestMetaPath, FILE_WRITE, true);
    bool metaSaved = false;
    if (metaFile) {
        metaSaved = metaFile.print(meta) == meta.length();
        metaFile.flush();
        metaFile.close();
    }
    latestMetaKnown = metaSaved;

    Serial.printf("[Capture] Checkpoint: pcap=%u B pmkid=%u B meta=%s\n",
                  (unsigned)fileSizeNoisySafe(kLatestPcapPath),
                  (unsigned)pmkidSize,
                  metaSaved ? "ok" : "fail");

    lastCheckpointPcapPos = pcapWritePos;
    lastCheckpointPmkidCount = pmkidCount;
    pmkidCheckpointPending = false;
}

void closePcapFile() {
    if (!pcapFileOpen) return;
    flushPendingPcapChunk();
    flushActivePcapChunk();
    pcapFile.flush();
    pcapFile.close();
    pcapFileOpen = false;
}

bool shouldSaveFrame(uint8_t frameType, uint8_t subtype, bool hasEapol) {
    if (hasEapol) return true;
    if (frameType != 0) return false;

    switch (subtype) {
        case 0x00:  // Association request
        case 0x01:  // Association response
        case 0x02:  // Reassociation request
        case 0x03:  // Reassociation response
        case 0x0B:  // Authentication
            return true;
        case 0x05:  // Probe response
            if (savedProbeRespFrames < 3) {
                savedProbeRespFrames++;
                return true;
            }
            return false;
        case 0x08:  // Beacon
            if (savedBeaconFrames < 3) {
                savedBeaconFrames++;
                return true;
            }
            return false;
        default:
            return false;
    }
}

void rxCallback(void* buf, wifi_promiscuous_pkt_type_t) {
    if (!isRunning) return;

    auto* pkt = static_cast<wifi_promiscuous_pkt_t*>(buf);
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < 24 || len > 2500) return;
    rawChannelFrames++;

    const uint8_t* payload = pkt->payload;
    if (!matchesTarget(payload, len)) return;

    if (!firstFrameSeen) {
        firstFrameSeen = true;
        Serial.printf("[Capture] First matching frame seen after %lus\n",
                      (unsigned long)((millis() - startMs) / 1000));
    }
    frameCount++;
    if ((frameCount % 1000) == 0) {
        Serial.printf("[Capture] Matching frames=%lu EAPOL=%lu PMKID=%lu\n",
                      (unsigned long)frameCount,
                      (unsigned long)eapolCount,
                      (unsigned long)pmkidCount);
    }

    uint8_t fc = payload[0];
    uint8_t frameType = (fc >> 2) & 0x03;
    uint8_t subtype = (fc >> 4) & 0x0F;
    if (frameType == 0) {
        if (subtype == 0x08 || subtype == 0x05) {
            uint8_t bssid[6];
            memcpy(bssid, payload + 16, 6);
            uint8_t ssid[MAX_ESSID_LEN];
            uint8_t ssidLen = 0;
            const bool hasSsid = extractSsidFromManagement(payload, len, ssid, &ssidLen);
            if (hasSsid) rememberNetworkEssid(bssid, ssid, ssidLen);
            extractPmkidFromBeacon(payload, len, bssid,
                                   hasSsid ? ssid : nullptr,
                                   hasSsid ? ssidLen : 0);
        }
    }

    int eapolOffset = findEapol(payload, len);
    if (shouldSaveFrame(frameType, subtype, eapolOffset >= 0)) {
        writePcapRecord(payload, len, pkt->rx_ctrl.rssi);
    }
    if (eapolOffset >= 0) {
        analyzeKey(payload, len, eapolOffset);
    }
}

}  // namespace

void setup() {
    capturePreferences.begin("capturecfg", false);
    nextSessionId = capturePreferences.getUInt("nextid", 1);
    if (nextSessionId == 0) nextSessionId = 1;
    savedChannel = capturePreferences.getUChar("channel", 1);
    if (savedChannel < 1 || savedChannel > 14) savedChannel = 1;
    savedFullChannel = capturePreferences.getBool("full", true);
    resumeOnBoot = capturePreferences.getBool("resume", false);
    String savedBssidString = capturePreferences.isKey("bssid")
                                 ? capturePreferences.getString("bssid", "")
                                 : String();
    savedEssid = capturePreferences.getString("ssid", "");
    savedBssidString.toCharArray(savedBssidText, sizeof(savedBssidText));
    savedTargets = {};
    savedTargetCount = 0;
    if (!savedFullChannel) {
        const uint8_t storedCount = capturePreferences.getUChar("target_count", 0);
        const size_t targetBytes = size_t(storedCount) * sizeof(TargetNetwork);
        if (storedCount > 0 && storedCount <= MAX_TARGETS &&
            capturePreferences.getBytesLength("targets") == targetBytes &&
            capturePreferences.getBytes("targets", savedTargets.data(), targetBytes) == targetBytes) {
            savedTargetCount = storedCount;
        } else if (parseSavedBssid(savedBssidText, savedBssid)) {
            // Migrate the original single-target configuration in memory.
            savedTargetCount = 1;
            memcpy(savedTargets[0].bssid, savedBssid, sizeof(savedBssid));
            savedTargets[0].channel = savedChannel;
            savedEssid.toCharArray(savedTargets[0].ssid, sizeof(savedTargets[0].ssid));
        }
        if (savedTargetCount > 0) {
            savedChannel = savedTargets[0].channel;
            memcpy(savedBssid, savedTargets[0].bssid, sizeof(savedBssid));
            savedEssid = savedTargets[0].ssid;
            snprintf(savedBssidText, sizeof(savedBssidText),
                     "%02X:%02X:%02X:%02X:%02X:%02X",
                     savedBssid[0], savedBssid[1], savedBssid[2],
                     savedBssid[3], savedBssid[4], savedBssid[5]);
        }
    }
    savedConfigValid = capturePreferences.isKey("channel") &&
                       (savedFullChannel || savedTargetCount > 0);

    pmkidBuf.reserve(512);
    fsReady = LittleFS.begin(true);
    Serial.printf("[Capture] LittleFS %s\n", fsReady ? "ready" : "init failed");
    latestPcapKnown = fileSizeNoisySafe(kLatestPcapPath) > 24;
    latestPmkidKnown = fileSizeNoisySafe(kLatestPmkidPath) > 0;
    latestMetaKnown = fileSizeNoisySafe(kLatestMetaPath) > 0;
    if (fsReady) {
        Serial.printf("[Capture] Saved files on boot: pcap=%s pmkid=%s meta=%s\n",
                      latestPcapKnown ? "yes" : "no",
                      latestPmkidKnown ? "yes" : "no",
                      latestMetaKnown ? "yes" : "no");
        logSavedFiles();
    }
}

void startInternal(uint8_t channel, const TargetNetwork* targets, size_t targetCount,
                   bool fullChannel, const char* essid) {
    if (isRunning) stop();

    lastError[0] = '\0';
    std::array<TargetNetwork, MAX_TARGETS> normalizedTargets;
    size_t normalizedTargetCount = 0;
    if (!fullChannel && !normalizeTargets(targets, targetCount,
                                          normalizedTargets, normalizedTargetCount)) {
        strncpy(lastError, "missing target bssid", sizeof(lastError) - 1);
        return;
    }
    if (fullChannel && (channel < 1 || channel > 14)) {
        strncpy(lastError, "invalid channel", sizeof(lastError) - 1);
        return;
    }

    if (fullChannel) {
        saveCaptureConfig(channel, nullptr, true, nullptr);
        activeTargetCount = 0;
        activeChannelCount = 1;
        activeChannelIndex = 0;
        activeChannels[0] = channel;
    } else {
        saveTargetConfigurationInternal(normalizedTargets.data(), normalizedTargetCount);
        activeTargets = normalizedTargets;
        activeTargetCount = normalizedTargetCount;
        rebuildActiveChannels();
        channel = activeChannels[0];
        memcpy(targetBssid, activeTargets[0].bssid, sizeof(targetBssid));
    }

    captureEssid = (!fullChannel && normalizedTargetCount > 0)
                       ? String(normalizedTargets[0].ssid)
                       : String();
    if (!captureEssid.length() && essid && !fullChannel) captureEssid = String(essid);
    resumeOnBoot = true;
    const bool resumeWritten = capturePreferences.putBool("resume", true) == sizeof(uint8_t);
    Serial.printf("[Capture] Resume-on-boot state saved: %s\n", resumeWritten ? "running" : "FAILED");

    fullChannelMode = fullChannel;
    captureChannel = channel;
    if (fullChannel) memset(targetBssid, 0, sizeof(targetBssid));

    frameCount = 0;
    eapolCount = 0;
    pmkidCount = 0;
    handshakeFound = false;
    pmkidFound = false;
    pmkidStored = 0;
    for (auto& network : networkEssids) network = NetworkEssid{};
    capSummary[0] = '\0';
    pmkidBuf = "";
    resetHandshakeState();
    firstFrameSeen = false;
    idleWarningShown = false;
    startMs = millis();
    lastDiagMs = startMs;
    lastCheckpointMs = startMs;
    lastChannelSwitchMs = startMs;
    rawChannelFrames = 0;
    savedBeaconFrames = 0;
    savedProbeRespFrames = 0;
    pcapDroppedRecords = 0;
    pmkidCheckpointPending = false;
    pcapActivePos = 0;
    pcapFlushLen = 0;
    pcapFlushPending = false;

    stopManagementAp();
    WiFi.persistent(false);
    WiFi.mode(WIFI_MODE_STA);
    WiFi.disconnect(false, true);
    WiFi.setSleep(false);

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_channel(captureChannel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_ps(WIFI_PS_NONE);

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(rxCallback);
    esp_wifi_set_promiscuous(true);

    pcapWritePos = sizeof(PCAP_GHDR);
    latestPcapKnown = false;
    latestPmkidKnown = preserveSavedFilesOnStart ? latestPmkidKnown : false;
    latestMetaKnown = preserveSavedFilesOnStart ? latestMetaKnown : false;
    if (fsReady) {
        archiveExistingSession();
        latestPcapKnown = false;
        latestPmkidKnown = false;
        latestMetaKnown = false;
        if (fileExistsNoisySafe(kLatestPcapPath)) {
            LittleFS.remove(kLatestPcapPath);
        }
        if (!preserveSavedFilesOnStart && fileExistsNoisySafe(kLatestPmkidPath)) {
            LittleFS.remove(kLatestPmkidPath);
        }
        if (!preserveSavedFilesOnStart && fileExistsNoisySafe(kLatestMetaPath)) {
            LittleFS.remove(kLatestMetaPath);
        }
        pcapFile = LittleFS.open(kLatestPcapPath, FILE_WRITE, true);
        if (pcapFile) {
            pcapFileOpen = true;
            pcapFile.write(PCAP_GHDR, sizeof(PCAP_GHDR));
        } else {
            strncpy(lastError, "pcap file open failed", sizeof(lastError) - 1);
        }
    }
    lastCheckpointPcapPos = pcapWritePos;
    lastCheckpointPmkidCount = pmkidCount;
    isRunning = true;

    char bssidStr[18];
    macStr(targetBssid, bssidStr);
    Serial.printf("[Capture] Passive sniff start Ch=%u mode=%s target=%s essid=\"%s\"\n",
                  captureChannel, fullChannelMode ? "full" : "target",
                  fullChannelMode ? "<all>" : bssidStr,
                  captureEssid.length() ? captureEssid.c_str() : "<empty>");
    Serial.printf("[Capture] Targets=%u unique channels=%u rotation=%s\n",
                  (unsigned)activeTargetCount,
                  (unsigned)activeChannelCount,
                  activeChannelCount > 1 ? "10 minutes" : "disabled");
    Serial.println("[Capture] WiFi mode=STA promiscuous");
    Serial.println("[Capture] Waiting for matching traffic...");
}

void start(uint8_t channel, const uint8_t* bssid, bool fullChannel, const char* essid) {
    if (fullChannel) {
        startInternal(channel, nullptr, 0, true, nullptr);
        return;
    }
    if (!bssid) {
        strncpy(lastError, "missing target bssid", sizeof(lastError) - 1);
        return;
    }

    TargetNetwork target;
    memcpy(target.bssid, bssid, sizeof(target.bssid));
    target.channel = channel;
    if (essid) strncpy(target.ssid, essid, sizeof(target.ssid) - 1);
    target.ssid[sizeof(target.ssid) - 1] = '\0';
    startInternal(channel, &target, 1, false, essid);
}

bool startTargets(const TargetNetwork* targets, size_t count) {
    std::array<TargetNetwork, MAX_TARGETS> normalized;
    size_t normalizedCount = 0;
    if (!normalizeTargets(targets, count, normalized, normalizedCount)) return false;
    startInternal(normalized[0].channel, normalized.data(), normalizedCount, false, nullptr);
    return isRunning;
}

bool saveTargetConfiguration(const TargetNetwork* targets, size_t count) {
    return saveTargetConfigurationInternal(targets, count);
}

void saveConfiguration(uint8_t channel, const uint8_t* bssid, bool fullChannel, const char* essid) {
    if (channel < 1 || channel > 14) return;
    if (!fullChannel && !bssid) return;
    saveCaptureConfig(channel, bssid, fullChannel, essid);
}

void startSaved(bool preserveSavedFiles) {
    preserveSavedFilesOnStart = preserveSavedFiles;
    if (!savedConfigValid) {
        start(1, nullptr, true);
    } else if (savedFullChannel) {
        start(savedChannel, nullptr, true, nullptr);
    } else {
        startTargets(savedTargets.data(), savedTargetCount);
    }
    preserveSavedFilesOnStart = false;
}

bool hasSavedConfig() {
    return savedConfigValid;
}

bool isAutoStartEnabled() {
    return resumeOnBoot;
}

void setAutoStartEnabled(bool enabled) {
    // Kept for API compatibility; boot behavior is now based on the last
    // actual capture state rather than a web UI preference.
    resumeOnBoot = enabled;
    capturePreferences.putBool("resume", enabled);
}

uint8_t getSavedChannel() {
    return savedChannel;
}

bool usesSavedFullChannel() {
    return savedFullChannel;
}

const char* getSavedBssid() {
    return savedBssidText;
}

size_t getSavedTargetCount() {
    return savedTargetCount;
}

bool getSavedTarget(size_t index, TargetNetwork& out) {
    if (index >= savedTargetCount) return false;
    out = savedTargets[index];
    return true;
}

void stop() {
    if (isRunning) {
        resumeOnBoot = false;
        const bool resumeWritten = capturePreferences.putBool("resume", false) == sizeof(uint8_t);
        Serial.printf("[Capture] Resume-on-boot state saved: %s\n", resumeWritten ? "idle" : "FAILED");
        esp_wifi_set_promiscuous_rx_cb(nullptr);
        esp_wifi_set_promiscuous(false);
        esp_wifi_stop();
        isRunning = false;
        closePcapFile();
        Serial.printf("[Capture] Done: frames=%lu eapol=%lu hs=%s pmkid=%lu\n",
                      (unsigned long)frameCount,
                      (unsigned long)eapolCount,
                      handshakeFound ? "YES" : "no",
                      (unsigned long)pmkidCount);
        if (fsReady) {
            const uint32_t elapsedSec = (millis() - startMs) / 1000;
            size_t latestSize = fileSizeNoisySafe(kLatestPcapPath);
            bool pcapSaved = latestSize == pcapWritePos && latestSize > sizeof(PCAP_GHDR);
            latestPcapKnown = pcapSaved;

            const char* pmkidData = getPmkidData();
            size_t pmkidSize = strlen(pmkidData);
            if (fileExistsNoisySafe(kLatestPmkidPath)) {
                LittleFS.remove(kLatestPmkidPath);
            }
            File pmkidFile = LittleFS.open(kLatestPmkidPath, FILE_WRITE, true);
            bool pmkidSaved = false;
            if (pmkidFile) {
                pmkidSaved = (pmkidFile.write((const uint8_t*)pmkidData, pmkidSize) == pmkidSize);
                pmkidFile.close();
            }
            latestPmkidKnown = pmkidSaved && pmkidSize > 0;

            String meta = buildSessionMetaJson(elapsedSec);
            if (fileExistsNoisySafe(kLatestMetaPath)) {
                LittleFS.remove(kLatestMetaPath);
            }
            File metaFile = LittleFS.open(kLatestMetaPath, FILE_WRITE, true);
            bool metaSaved = false;
            if (metaFile) {
                metaSaved = (metaFile.print(meta) == meta.length());
                metaFile.close();
            }
            latestMetaKnown = metaSaved;

            Serial.printf("[Capture] Saved latest capture: pcap=%s (%u B, dropped=%lu), pmkid=%s (%u B), meta=%s\n",
                          pcapSaved ? "ok" : "fail",
                          (unsigned)latestSize,
                          (unsigned long)pcapDroppedRecords,
                          pmkidSaved ? "ok" : "fail",
                          (unsigned)pmkidSize,
                          metaSaved ? "ok" : "fail");
        }
    }

    startManagementAp();
}

void rotateChannelIfDue(uint32_t now) {
    if (fullChannelMode || activeChannelCount <= 1 ||
        now - lastChannelSwitchMs < CHANNEL_ROTATION_INTERVAL_MS) {
        return;
    }

    activeChannelIndex = (activeChannelIndex + 1) % activeChannelCount;
    const uint8_t nextChannel = activeChannels[activeChannelIndex];
    const esp_err_t result = esp_wifi_set_channel(nextChannel, WIFI_SECOND_CHAN_NONE);
    if (result == ESP_OK) {
        captureChannel = nextChannel;
        Serial.printf("[Capture] Rotating to channel %u after 10 minutes\n",
                      captureChannel);
    } else {
        Serial.printf("[Capture] Channel rotation to %u failed: %d\n",
                      nextChannel, (int)result);
    }
    lastChannelSwitchMs = now;
}

void loop() {
    if (!isRunning) return;
    const uint32_t now = millis();
    rotateChannelIfDue(now);
    flushPendingPcapChunk();

    const bool newPcapData = pcapWritePos != lastCheckpointPcapPos;
    const bool newPmkidData = pmkidCount != lastCheckpointPmkidCount;
    const bool checkpointDue = now - lastCheckpointMs >= CHECKPOINT_INTERVAL_MS;
    const bool immediatePmkidCheckpoint = pmkidCheckpointPending && newPmkidData;
    if ((checkpointDue || immediatePmkidCheckpoint) && (newPcapData || newPmkidData)) {
        lastCheckpointMs = now;
        checkpointCapture(newPcapData, newPmkidData);
    }
    if (now - lastDiagMs >= 10000) {
        lastDiagMs = now;
        if (!firstFrameSeen && !idleWarningShown) {
            idleWarningShown = true;
            Serial.printf("[Capture] No matching target frames after %lus. Raw channel frames=%lu. If raw>0, BSSID filter/target is wrong; if raw=0, radio is not seeing channel traffic.\n",
                          (unsigned long)((now - startMs) / 1000),
                          (unsigned long)rawChannelFrames);
            Serial.println("[Capture] Also verify the target network uses WPA/WPA2 and that a client is actually reconnecting.");
        } else {
            Serial.printf("[Capture] Listening... raw=%lu target=%lu eapol=%lu pmkid=%lu elapsed=%lus\n",
                          (unsigned long)rawChannelFrames,
                          (unsigned long)frameCount,
                          (unsigned long)eapolCount,
                          (unsigned long)pmkidCount,
                          (unsigned long)((now - startMs) / 1000));
        }
    }
}

void reset() {
    stop();
    pcapWritePos = 0;
    pmkidBuf = "";
    capSummary[0] = '\0';
    lastError[0] = '\0';
    frameCount = 0;
    eapolCount = 0;
    pmkidCount = 0;
    handshakeFound = false;
    pmkidFound = false;
    pmkidStored = 0;
    resetHandshakeState();
}

bool usesFullChannel() {
    return fullChannelMode;
}

bool managementApActive() {
    return apActive;
}

bool hasLatestCapture() {
    return fsReady && latestPcapKnown;
}

bool hasLatestMetadata() {
    return fsReady && latestMetaKnown;
}

size_t getLatestPcapSize() {
    if (!fsReady || !latestPcapKnown) return 0;
    if (!fileExistsNoisySafe(kLatestPcapPath)) {
        latestPcapKnown = false;
        return 0;
    }
    File f = LittleFS.open(kLatestPcapPath, FILE_READ);
    if (!f) return 0;
    size_t sz = f.size();
    f.close();
    return sz;
}

size_t getLatestPmkidSize() {
    if (!fsReady || !latestPmkidKnown) return 0;
    if (!fileExistsNoisySafe(kLatestPmkidPath)) {
        latestPmkidKnown = false;
        return 0;
    }
    File f = LittleFS.open(kLatestPmkidPath, FILE_READ);
    if (!f) return 0;
    size_t sz = f.size();
    f.close();
    return sz;
}

size_t getLatestMetaSize() {
    if (!fsReady || !latestMetaKnown) return 0;
    if (!fileExistsNoisySafe(kLatestMetaPath)) {
        latestMetaKnown = false;
        return 0;
    }
    File f = LittleFS.open(kLatestMetaPath, FILE_READ);
    if (!f) return 0;
    size_t sz = f.size();
    f.close();
    return sz;
}

constexpr uint64_t MAX_REPLAY_GAP = 8;

bool replayPairAcceptable(uint64_t a, uint64_t b) {
    const uint64_t gap = a >= b ? a - b : b - a;
    return gap <= MAX_REPLAY_GAP;
}

uint8_t replayPairMarker(uint8_t base, uint64_t a, uint64_t b) {
    return replayPairAcceptable(a, b) && a == b ? base : uint8_t(base | 0x80);
}

bool eapolPairAvailable(const EapolCandidate& candidate, uint64_t referenceReplay) {
    if (!candidate.valid || candidate.len == 0 ||
        !replayPairAcceptable(referenceReplay, candidate.replay)) {
        return false;
    }

    bool noncePresent = false;
    bool micPresent = false;
    for (size_t i = 0; i < sizeof(candidate.nonce); ++i) {
        noncePresent = noncePresent || candidate.nonce[i] != 0;
    }
    for (size_t i = 0; i < sizeof(candidate.mic); ++i) {
        micPresent = micPresent || candidate.mic[i] != 0;
    }
    return noncePresent && micPresent;
}

void appendEapolRecord(String& out, const HandshakeState& hs,
                       const EapolCandidate& candidate, const uint8_t* anonce,
                       uint64_t referenceReplay, uint8_t pairType) {
    if (!eapolPairAvailable(candidate, referenceReplay)) return;

    out += "WPA*02*";
    appendHex(out, candidate.mic, sizeof(candidate.mic));
    out += "*";
    char mac[18];
    macStr(hs.ap, mac);
    out += mac;
    out += "*";
    macStr(hs.sta, mac);
    out += mac;
    out += "*";
    const uint8_t* essid = hs.essidLen > 0
                             ? hs.essid
                             : (const uint8_t*)captureEssid.c_str();
    const size_t essidLen = hs.essidLen > 0
                              ? hs.essidLen
                              : (captureEssid.length() > MAX_ESSID_LEN
                                  ? MAX_ESSID_LEN : captureEssid.length());
    appendHex(out, essid, essidLen);
    out += "*";
    appendHex(out, anonce, 32);
    out += "*";
    appendHex(out, candidate.data, candidate.len);
    out += "*";
    // The message-pair field is a byte and must always be two hex digits.
    const uint8_t marker = replayPairMarker(pairType, referenceReplay, candidate.replay);
    static const char hex[] = "0123456789ABCDEF";
    out += hex[marker >> 4];
    out += hex[marker & 0x0F];
    out += "\n";
}

size_t getFilesystemTotalBytes() {
    return fsReady ? LittleFS.totalBytes() : 0;
}

size_t getFilesystemUsedBytes() {
    return fsReady ? LittleFS.usedBytes() : 0;
}

size_t getFilesystemFreeBytes() {
    const size_t total = getFilesystemTotalBytes();
    const size_t used = getFilesystemUsedBytes();
    return used < total ? total - used : 0;
}

const char* getLastError() {
    return lastError[0] ? lastError : "";
}

const uint8_t* getPcapData() {
    return nullptr;
}

size_t getPcapSize() {
    return pcapWritePos;
}

const char* getPmkidData() {
    pmkidBuf = "";
    pmkidBuf.reserve(pmkidStored * 64);
    for (int i = 0; i < pmkidStored; ++i) {
        char apStr[18], staStr[18], pmkidHex[33], essidHex[65];
        macStr(pmkidApList[i].data(), apStr);
        macStr(pmkidStaList[i].data(), staStr);
        for (int j = 0; j < 16; ++j) {
            snprintf(pmkidHex + j * 2, 3, "%02X", pmkidList[i][j]);
        }
        const uint8_t* recordEssid = pmkidEssidLen[i] > 0
                                       ? pmkidEssidList[i].data()
                                       : (const uint8_t*)captureEssid.c_str();
        const size_t essidLen = pmkidEssidLen[i] > 0
                                  ? pmkidEssidLen[i]
                                  : (captureEssid.length() > MAX_ESSID_LEN
                                      ? MAX_ESSID_LEN : captureEssid.length());
        for (size_t j = 0; j < essidLen; ++j) {
            snprintf(essidHex + j * 2, 3, "%02X", recordEssid[j]);
        }
        essidHex[essidLen * 2] = '\0';
        // PMKID records use signature 01 in hashcat's WPA 22000 format.
        // Signature 02 is for full EAPOL records (MIC, ESSID, nonce,
        // normalized EAPOL data, and message-pair metadata), which are not
        // represented by the PMKID buffers above.
        pmkidBuf += "WPA*01*";
        pmkidBuf += pmkidHex;
        pmkidBuf += "*";
        pmkidBuf += apStr;
        pmkidBuf += "*";
        pmkidBuf += staStr;
        pmkidBuf += "*";
        pmkidBuf += essidHex;
        pmkidBuf += "***\n";
    }

    // Export the same preferred EAPOL pairing as hcxtools' default output.
    // The MIC is preserved in field 2 and zeroed in the EAPOL field. M2 is
    // preferred because it contains the client SNonce and produces Hash 1.
    for (const auto& hs : handshakes) {
        if (!hs.used || !hs.m1) continue;
        if (hs.m3Data.valid && eapolPairAvailable(hs.m2Data, hs.m3Data.replay)) {
            // M2 EAPOL + M3 ANonce is hcxtools' preferred M32E2 pairing.
            // A replay mismatch is represented by the high bit, producing
            // the usual M32E2/0x82 form when needed.
            appendEapolRecord(pmkidBuf, hs, hs.m2Data, hs.m3Data.nonce, hs.m3Data.replay, 2);
        } else {
            // If M3 was not captured, M1+M2 is the usable fallback.
            appendEapolRecord(pmkidBuf, hs, hs.m2Data, hs.anonce, hs.m1Replay, 0);
        }
    }
    return pmkidBuf.c_str();
}

size_t getPmkidSize() {
    return strlen(getPmkidData());
}

bool has22000Data() {
    if (pmkidStored > 0) return true;

    for (const auto& hs : handshakes) {
        if (!hs.used || !hs.m1) continue;
        if (hs.m3Data.valid && eapolPairAvailable(hs.m2Data, hs.m3Data.replay)) return true;
        if (eapolPairAvailable(hs.m2Data, hs.m1Replay)) return true;
    }
    return false;
}

bool loadLatestPcap(std::vector<uint8_t>& out) {
    if (!fsReady || !latestPcapKnown) return false;
    if (!fileExistsNoisySafe(kLatestPcapPath)) {
        latestPcapKnown = false;
        return false;
    }
    File f = LittleFS.open(kLatestPcapPath, FILE_READ);
    if (!f) return false;
    out.resize(f.size());
    bool ok = (f.read(out.data(), out.size()) == (int)out.size());
    f.close();
    return ok;
}

bool loadLatestPmkid(String& out) {
    if (!fsReady || !latestPmkidKnown) return false;
    if (!fileExistsNoisySafe(kLatestPmkidPath)) {
        latestPmkidKnown = false;
        return false;
    }
    File f = LittleFS.open(kLatestPmkidPath, FILE_READ);
    if (!f) return false;
    out = f.readString();
    f.close();
    return true;
}

bool loadLatestMeta(String& out) {
    if (!fsReady || !latestMetaKnown) return false;
    if (!fileExistsNoisySafe(kLatestMetaPath)) {
        latestMetaKnown = false;
        return false;
    }
    File f = LittleFS.open(kLatestMetaPath, FILE_READ);
    if (!f) return false;
    out = f.readString();
    f.close();
    return true;
}

bool clearLatestSaved() {
    if (!fsReady) return false;
    bool ok = true;
    if (fileExistsNoisySafe(kLatestPcapPath)) ok = LittleFS.remove(kLatestPcapPath) && ok;
    if (fileExistsNoisySafe(kLatestPmkidPath)) ok = LittleFS.remove(kLatestPmkidPath) && ok;
    if (fileExistsNoisySafe(kLatestMetaPath)) ok = LittleFS.remove(kLatestMetaPath) && ok;

    File root = LittleFS.open("/");
    if (root) {
        File file = root.openNextFile();
        while (file) {
            String name = file.name();
            file.close();
            if (name.startsWith("/session_")) ok = LittleFS.remove(name.c_str()) && ok;
            file = root.openNextFile();
        }
        root.close();
    }
    latestPcapKnown = false;
    latestPmkidKnown = false;
    latestMetaKnown = false;
    return ok;
}

bool clearAllFiles() {
    if (!fsReady || isRunning) return false;

    std::vector<String> names;
    File root = LittleFS.open("/");
    if (!root) return false;

    File file = root.openNextFile();
    while (file) {
        if (!file.isDirectory()) {
            String name = file.name();
            if (!name.startsWith("/")) name = "/" + name;
            names.push_back(name);
        }
        file.close();
        file = root.openNextFile();
    }
    root.close();

    bool ok = true;
    for (const String& name : names) {
        ok = LittleFS.remove(name.c_str()) && ok;
    }

    latestPcapKnown = false;
    latestPmkidKnown = false;
    latestMetaKnown = false;
    Serial.printf("[Capture] LittleFS delete all files: %u file(s), %s\n",
                  (unsigned)names.size(), ok ? "ok" : "FAIL");
    return ok;
}

const char* getCaptureSummary() {
    if (!capSummary[0]) {
        updateSummary();
    }
    return capSummary[0] ? capSummary : "idle";
}

uint32_t getRawChannelFrames() {
    return rawChannelFrames;
}

uint32_t getTargetFrames() {
    return frameCount;
}

}  // namespace Capture

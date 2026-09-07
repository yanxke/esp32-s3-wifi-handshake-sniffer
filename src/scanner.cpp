#include "scanner.h"

namespace Scanner {

static void appendJsonEscaped(String& out, const String& value) {
    for (size_t i = 0; i < value.length(); ++i) {
        char c = value[i];
        switch (c) {
            case '\"': out += F("\\\""); break;
            case '\\': out += F("\\\\"); break;
            case '\b': out += F("\\b"); break;
            case '\f': out += F("\\f"); break;
            case '\n': out += F("\\n"); break;
            case '\r': out += F("\\r"); break;
            case '\t': out += F("\\t"); break;
            default:
                if ((uint8_t)c < 0x20) {
                    char buf[7];
                    snprintf(buf, sizeof(buf), "\\u%04x", (uint8_t)c);
                    out += buf;
                } else {
                    out += c;
                }
                break;
        }
    }
}

void setup() {
    // main.cpp 已设 WIFI_MODE_APSTA，这里无需触发额外状态切换
}

std::vector<APInfo> scanNetworks() {
    std::vector<APInfo> results;

    Serial.println("[Scanner] Starting scan...");
    WiFi.scanDelete();

    // 同步阻塞扫描（ESP32-S3 AP 模式下异步扫描会超时）
    // 参数: async=false(阻塞), show_hidden=true, passive=false(主动扫描), timeout=300ms/信道
    int16_t count = WiFi.scanNetworks(false, true, false, 300);

    if (count <= 0) {
        Serial.printf("[Scanner] Scan returned %d (no networks or failed)\n", count);
        WiFi.scanDelete();
        return results;
    }

    Serial.printf("[Scanner] Found %d networks\n", count);

    for (int16_t i = 0; i < count; i++) {
        APInfo info;

        info.ssid       = WiFi.SSID(i);
        info.bssid      = WiFi.BSSIDstr(i);
        info.rssi       = WiFi.RSSI(i);
        info.channel    = WiFi.channel(i);
        info.encryption = WiFi.encryptionType(i);

        if (info.encryption == WIFI_AUTH_WPA2_ENTERPRISE) {
            Serial.printf("[Scanner] Skipping WPA2 Enterprise AP SSID=\"%s\" BSSID=%s channel=%d\n",
                          info.ssid.c_str(), info.bssid.c_str(), info.channel);
            continue;
        }

        if (info.ssid.isEmpty()) {
            info.ssid = "<hidden>";
        }

        Serial.printf("[Scanner] AP[%d] SSID=\"%s\" BSSID=%s channel=%d RSSI=%d security=%d\n",
                      i, info.ssid.c_str(), info.bssid.c_str(),
                      info.channel, info.rssi, info.encryption);

        results.push_back(info);
    }

    WiFi.scanDelete();
    return results;
}

String scanToJson() {
    std::vector<APInfo> networks = scanNetworks();
    String json;

    json.reserve(networks.size() * 128);

    json += '[';

    for (size_t i = 0; i < networks.size(); i++) {
        const APInfo& ap = networks[i];

        json += F("{\"ssid\":\"");
        appendJsonEscaped(json, ap.ssid);
        json += F("\",\"bssid\":\"");
        appendJsonEscaped(json, ap.bssid);
        json += F("\",\"rssi\":");
        json += String(ap.rssi);
        json += F(",\"channel\":");
        json += String(ap.channel);
        json += F(",\"encryption\":");
        json += String(ap.encryption);
        json += '}';

        if (i + 1 < networks.size()) {
            json += ',';
        }
    }

    json += ']';

    return json;
}

} // namespace Scanner

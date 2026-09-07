#include <Arduino.h>
#include <WiFi.h>
#include "scanner.h"
#include "capture.h"
#include "web.h"

#ifndef RGB_LED_GPIO
#ifdef RGB_BUILTIN
#define RGB_LED_GPIO RGB_BUILTIN
#else
#define RGB_LED_GPIO 48
#endif
#endif

namespace {

constexpr const char* kProjectName = "ESP32-S3 WiFi Handshake Sniffer";
constexpr const char* kApSsid = "esp32-s3-whs";
constexpr const char* kApPassword = "changeme";
constexpr uint8_t kBootButtonPin = 0;
String gSerialLine;
uint32_t lastSerialStatusMs = 0;
bool lastBootButtonState = HIGH;
uint32_t lastBootButtonChangeMs = 0;
uint32_t lastLedUpdateMs = 0;
bool ledOn = true;
uint8_t ledRed = 0xFF;
uint8_t ledGreen = 0xFF;
uint8_t ledBlue = 0xFF;

void setStatusLed(uint8_t red, uint8_t green, uint8_t blue) {
    if (red == ledRed && green == ledGreen && blue == ledBlue) return;
    ledRed = red;
    ledGreen = green;
    ledBlue = blue;
#ifdef RGB_LED_ORDER_RGB
    // neopixelWrite() expects RGB values but sends them in GRB order. Swap
    // red and green here for LEDs whose physical order is RGB.
    neopixelWrite(RGB_LED_GPIO, green, red, blue);
#else
    neopixelWrite(RGB_LED_GPIO, red, green, blue);
#endif
}

void updateStatusLed() {
    const uint32_t now = millis();
    if (!Capture::isRunning) {
        setStatusLed(0, 64, 0);  // idle: green
        ledOn = true;
        return;
    }

    const uint32_t handshakePacketCount = Capture::eapolCount + Capture::pmkidCount;
    if (handshakePacketCount == 0) {
        setStatusLed(64, 64, 0);  // capturing, no packets yet: yellow
        ledOn = true;
        return;
    }

    // One EAPOL/PMKID packet starts at one complete blink every two seconds.
    // Each additional handshake packet shortens the cycle, capped at five
    // blinks/second. Ordinary matching frames do not affect the rate.
    const uint32_t packetCount = handshakePacketCount > 10 ? 10 : handshakePacketCount;
    const uint32_t cycleMs = 2000 / packetCount;
    if (now - lastLedUpdateMs >= cycleMs / 2) {
        lastLedUpdateMs = now;
        ledOn = !ledOn;
        const bool has22000 = Capture::has22000Data();
        // Any usable WPA*01 or WPA*02 record: orange; otherwise captured
        // handshake packets: yellow.
        const uint8_t red = has22000 ? 80 : 64;
        const uint8_t green = has22000 ? 24 : 64;
        setStatusLed(ledOn ? red : 0, ledOn ? green : 0, 0);
    }
}

void pollBootButton() {
    const bool state = digitalRead(kBootButtonPin);
    const uint32_t now = millis();
    if (state != lastBootButtonState && now - lastBootButtonChangeMs >= 50) {
        lastBootButtonChangeMs = now;
        lastBootButtonState = state;
        if (state == LOW) {
            if (Capture::isRunning) {
                Serial.println("[BOOT] Stopping capture...");
                Capture::stop();
            } else {
                Serial.println("[BOOT] Starting capture from saved configuration...");
                Capture::startSaved();
            }
        }
    }
}

void startManagementAp() {
    WiFi.mode(WIFI_MODE_APSTA);
    const bool started = WiFi.softAP(kApSsid, kApPassword, 1, 0, 4);
    Serial.printf("[WiFi] Management AP %s, SSID=%s IP=%s\n",
                  started ? "started" : "start failed",
                  kApSsid,
                  WiFi.softAPIP().toString().c_str());
}

void printSerialHelp() {
    Serial.println("[Serial] Commands:");
    Serial.println("[Serial]   help   - show commands");
    Serial.println("[Serial]   status - print capture status");
    Serial.println("[Serial]   stop   - stop capture, save to flash, restore AP");
    Serial.println("[Serial]   BOOT button - start/stop full-channel capture on channel 1");
}

void printCaptureStatus() {
    const char* mode = Capture::usesFullChannel() ? "full-channel" : "target-bssid";
    Serial.printf("[Status] running=%s mode=%s channel=%u target=%s\n",
                  Capture::isRunning ? "yes" : "no",
                  mode,
                  Capture::captureChannel,
                  Capture::usesFullChannel() ? "<all>" : Capture::getSavedBssid());
    Serial.printf("[Status] packets raw=%lu target=%lu eapol=%lu pmkid=%lu\n",
                  (unsigned long)Capture::getRawChannelFrames(),
                  (unsigned long)Capture::getTargetFrames(),
                  (unsigned long)Capture::eapolCount,
                  (unsigned long)Capture::pmkidCount);
    Serial.printf("[Status] current pcap=%u B 22000=%u B | saved pcap=%u B 22000=%u B json=%u B\n",
                  (unsigned)Capture::getPcapSize(),
                  (unsigned)Capture::getPmkidSize(),
                  (unsigned)Capture::getLatestPcapSize(),
                  (unsigned)Capture::getLatestPmkidSize(),
                  (unsigned)Capture::getLatestMetaSize());
    Serial.printf("[Status] LittleFS used=%u B free=%u B total=%u B\n",
                  (unsigned)Capture::getFilesystemUsedBytes(),
                  (unsigned)Capture::getFilesystemFreeBytes(),
                  (unsigned)Capture::getFilesystemTotalBytes());
}

void printPeriodicStatus() {
    const uint32_t now = millis();
    if (now - lastSerialStatusMs < 10000) return;
    lastSerialStatusMs = now;
    printCaptureStatus();
}

void handleSerialCommand(const String& line) {
    String cmd = line;
    cmd.trim();
    cmd.toLowerCase();
    if (!cmd.length()) return;

    if (cmd == "help" || cmd == "?") {
        printSerialHelp();
        return;
    }

    if (cmd == "status") {
        printCaptureStatus();
        return;
    }

    if (cmd == "stop") {
        if (!Capture::isRunning) {
            Serial.println("[Serial] Capture is not running");
            printCaptureStatus();
            return;
        }
        Serial.println("[Serial] Stopping capture, saving to flash, restoring AP...");
        Capture::stop();
        printCaptureStatus();
        Serial.printf("[Serial] Reconnect to %s and download from the web UI\n", kApSsid);
        return;
    }

    Serial.print("[Serial] Unknown command: ");
    Serial.println(cmd);
    printSerialHelp();
}

void pollSerialCommands() {
    while (Serial.available() > 0) {
        const char ch = static_cast<char>(Serial.read());
        if (ch == '\r') continue;
        if (ch == '\n') {
            handleSerialCommand(gSerialLine);
            gSerialLine = "";
            continue;
        }
        if (gSerialLine.length() < 64) {
            gSerialLine += ch;
        }
    }
}

}  // namespace

void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println();
    Serial.printf("[%s] Starting...\n", kProjectName);

    pinMode(kBootButtonPin, INPUT_PULLUP);
    setStatusLed(0, 64, 0);

    startManagementAp();

    Capture::setup();
    Scanner::setup();
    WebUI::setup();

    if (Capture::isAutoStartEnabled()) {
        Serial.println("[Boot] Previous state was capturing; resuming saved capture configuration...");
        Capture::startSaved();
    } else {
        Serial.println("[Boot] Previous state was idle; waiting for BOOT button or web start.");
    }

    Serial.printf("[%s] AP IP: ", kProjectName);
    Serial.println(WiFi.softAPIP());
    Serial.printf("[%s] Ready\n", kProjectName);
    Serial.print("  Connect to '");
    Serial.print(kApSsid);
    Serial.println("'");
    Serial.print("  Open http://");
    Serial.print(WiFi.softAPIP());
    Serial.println("/");
    printSerialHelp();
}

void loop() {
    pollBootButton();
    pollSerialCommands();
    Capture::loop();
    WebUI::loop();
    updateStatusLed();
    printPeriodicStatus();
}

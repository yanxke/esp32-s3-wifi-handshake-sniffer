# ESP32-S3 WiFi Handshake Sniffer

## 简介

ESP32-S3 WiFi Handshake Sniffer 是一个基于 ESP32-S3、PlatformIO 和 Arduino 框架的 WiFi 握手包 / PMKID 被动监听工具。设备启动后会创建本地管理热点，并提供一个中文 Web UI，用于扫描附近 AP、选择目标 BSSID 和信道、启动监听、查看抓取状态，并下载抓取结果。

本项目适合用于授权 WiFi 安全测试、实验室研究和学习 802.11 WPA/WPA2 握手流程。请仅在你拥有或明确获得授权的网络环境中使用。

## 功能特性

- 支持 ESP32-S3 DevKitC-1
- 使用 PlatformIO + Arduino 开发
- 启动本地管理 AP，并通过 Captive Portal 风格 Web UI 操作
- 扫描附近 WiFi，显示 SSID、BSSID、RSSI、信道和加密类型
- 支持目标 BSSID 过滤模式
- 支持同时选择最多 8 个目标 AP；同信道目标同时过滤，不同信道每 10 分钟轮换
- 支持整信道监听模式
- 被动监听 EAPOL 握手包
- 检测 WPA/WPA2 四次握手进度
- 提取 PMKID，并按 hashcat `.22000` 的 `WPA*01*` 格式导出
- 导出带 Radiotap 头的 `.pcap` 文件
- 将当前和历史会话的 PCAP、PMKID 和 JSON 元数据保存到 LittleFS
- 使用 NVS 保存语言、抓包配置和启动时自动抓包选项
- Web UI 支持中英文切换、保存配置、自动启动、历史文件列表和清除 LittleFS 文件
- 支持周期性串口状态报告，以及查看状态和停止抓包的串口命令

## 硬件与环境

- ESP32-S3 DevKitC-1
- Waveshare ESP32-S3 Zero（使用对应的 PlatformIO 环境）
- PlatformIO
- Arduino framework for ESP32

默认工程配置见 `platformio.ini`：

```ini
[env:esp32-s3-devkitc-1]
platform = espressif32
board = esp32-s3-devkitc-1
framework = arduino
monitor_speed = 115200
upload_speed = 921600
board_build.flash_mode = qio
```

Waveshare ESP32-S3 Zero 使用 `env:waveshare-esp32-s3-zero`，其 RGB 灯为 GPIO21；DevKitC-1 使用 GPIO48。

## 使用方法

1. 使用 PlatformIO 编译并烧录固件。
2. 打开串口监视器，等待设备启动。
3. 连接设备创建的 WiFi 热点：

```text
esp32-s3-whs
```

默认密码：`changeme`

抓包结果保存在设备的 LittleFS Flash 分区：

- `/latest_capture.pcap`
- `/latest_capture.22000`
- `/latest_capture.json`

开始新的抓包会将上一会话归档为 `/session_XXXXXX.pcap`、`.22000` 和 `.json` 文件；设备重启不会清除这些文件。抓包过程中每分钟会将新增数据检查点保存到 Flash，捕获 PMKID 或完整 EAPOL 握手后也会立即保存。Web UI 的“所有已保存会话”区域可分别下载各个文件；“清除已保存”会清除当前结果，“删除 LittleFS 全部文件”会清除所有抓包文件。

## BOOT 按钮与 RGB 指示灯

- BOOT 按钮（GPIO0）按下后会开始或停止抓包。
- 开始抓包时，设备使用 NVS 中保存的抓包配置；如果没有保存配置，则使用信道 1 的全信道模式。
- 在 Web UI 开启“启动时自动开始上次配置”后，设备重启时会自动恢复已保存配置；否则保持空闲。BOOT 按钮始终使用已保存的配置开始抓包。
- RGB 灯（DevKitC-1 为 GPIO48，Waveshare ESP32-S3 Zero 为 GPIO21）绿色常亮表示空闲。
- 黄色常亮表示正在抓包但尚未捕获数据包。
- 捕获数据包后黄色闪烁，初始为每 2 秒一个闪烁周期，随着数据包数量增加加快，最高 5 Hz。
- 生成可用 `.22000` 内容（PMKID 或 EAPOL）后，闪烁颜色变为橙色。

4. 打开设备管理页面，默认地址通常为：

```text
http://192.168.4.1/
```

5. 在 Web UI 中扫描附近 AP，选择目标网络，开始监听。
6. 抓包开始后管理热点会临时关闭，Web 页面可能断开。
7. 停止监听后重新连接管理热点，在 Web UI 中下载 `.pcap`、`.22000` 或 `.json` 报告。

## 串口命令

```text
help   - 显示命令列表
status - 输出当前抓包状态
stop   - 停止抓包，保存结果，并恢复管理热点
```

设备还会输出每次扫描的 SSID、BSSID、信道、RSSI 和加密类型，并周期性输出抓包数量、文件大小以及 LittleFS 空间使用情况。

## 输出文件

- `latest_capture.pcap`：最近一次抓包结果，可用于 Wireshark 等工具分析
- `latest_capture.22000`：PMKID/EAPOL hashcat 22000 格式输出
- `latest_capture.json`：抓包会话元数据，包括信道、帧数量、EAPOL/PMKID 数量和耗时等
- `session_XXXXXX.*`：历史会话归档文件

## 注意事项

- ESP32-S3 监听时需要固定在目标信道。
- 目标网络需要有客户端重连或产生握手相关流量，才能抓到 EAPOL 握手。
- 全信道监听模式实际是监听当前配置的单个信道上的全部匹配帧，不会自动跳频。
- 目标 BSSID 模式最多支持 8 个 AP；同一信道上的目标会同时监听，不同信道会每 10 分钟切换一次。
- 扫描结果中的 WPA2 Enterprise AP 会被过滤，不会出现在可选目标列表中。
- 抓包期间管理 AP 会关闭，停止抓包后才会恢复。
- 本项目不会主动发送解除认证帧，只做被动监听。

## Overview

ESP32-S3 WiFi Handshake Sniffer is a lightweight WiFi handshake and PMKID sniffer built for ESP32-S3 with PlatformIO and the Arduino framework. The device starts a local management access point with a browser-based Web UI for AP scanning, target selection, passive monitor-mode capture, status tracking, and result downloads.

This project is intended for authorized WiFi security testing, lab research, and learning 802.11 WPA/WPA2 handshake behavior. Use it only on networks you own or have explicit permission to test.

## Features

- ESP32-S3 DevKitC-1 support
- Waveshare ESP32-S3 Zero support through the `env:waveshare-esp32-s3-zero` PlatformIO environment
- PlatformIO + Arduino project
- Built-in management AP with captive-portal-style Web UI
- Nearby AP scanning with SSID, BSSID, RSSI, channel, and encryption info
- Target BSSID capture mode
- Up to eight target APs at once; same-channel targets are filtered together and different channels rotate every 10 minutes
- Full current-channel monitor mode
- Passive EAPOL handshake detection
- WPA/WPA2 four-way handshake progress tracking
- PMKID extraction with hashcat `.22000` `WPA*01*` export
- `.pcap` export with Radiotap headers
- Current and archived PCAP, PMKID, and JSON metadata saved to LittleFS
- NVS-persisted language, capture configuration, and last capture-running state
- Bilingual Web UI with persisted language, saved capture configuration, auto-start, and LittleFS file management
- Periodic serial status reporting and commands for status, stop, and help

## Hardware And Environment

- ESP32-S3 DevKitC-1
- PlatformIO
- Arduino framework for ESP32

The default project configuration is in `platformio.ini`:

```ini
[env:esp32-s3-devkitc-1]
platform = espressif32
board = esp32-s3-devkitc-1
framework = arduino
monitor_speed = 115200
upload_speed = 921600
board_build.flash_mode = qio
board_build.partitions = partitions_8MB_nota.csv
```

For the Waveshare ESP32-S3 Zero, use `pio run -e waveshare-esp32-s3-zero`; that environment sets the RGB LED to GPIO21 and uses RGB ordering. The DevKitC-1 environment uses GPIO48.

## Usage

1. Build and flash the firmware with PlatformIO.
2. Open the serial monitor and wait for the device to boot.
3. Connect to the management WiFi network:

```text
SSID:    esp32-s3-whs
Password: changeme
```

Capture files are stored in the device’s LittleFS flash partition:

- `/latest_capture.pcap`
- `/latest_capture.22000`
- `/latest_capture.json`

When a new capture starts, the previous session is archived as `/session_XXXXXX.pcap`, `.22000`, and `.json`. During capture, new data is checkpointed to flash every minute and immediately after a PMKID or complete EAPOL handshake is found. Reboots do not clear saved files. The Web UI lists all saved files for individual download; “Clear saved” removes the latest result, while “Delete all LittleFS files” removes all capture files.

Open the management page at `http://192.168.4.1/`. Scan nearby APs, select a target network, and start listening. The management AP temporarily closes during capture and returns after capture stops. Reconnect afterward to download the results.

## Serial Commands

```text
help   - show the command list
status - print detailed capture and LittleFS status
stop   - stop capture, save results, and restore the management AP
```

The device also prints each scanned SSID, BSSID, channel, RSSI, and security type, plus periodic capture statistics including packet counts, file sizes, and LittleFS space.

## Output Files

- `latest_capture.pcap`: latest capture, suitable for analysis with Wireshark and similar tools
- `latest_capture.22000`: PMKID/EAPOL output in Hashcat 22000 format
- `latest_capture.json`: capture metadata including channel, frame counts, EAPOL/PMKID counts, and elapsed time
- `session_XXXXXX.*`: archived files from previous sessions

## Notes

- Listening must be fixed to the target channel.
- The target network needs a client reconnect or other handshake-related traffic for EAPOL frames to be captured.
- Full-channel mode means all matching frames on the selected single channel; it does not hop channels automatically.
- Target mode supports up to eight APs; same-channel targets are captured together and different channels rotate every 10 minutes.
- WPA2 Enterprise APs are filtered out of the scan results and cannot be selected as targets.
- The management AP is disabled during capture and restored afterward.
- The project does not send deauthentication frames; it performs passive monitoring only.

## BOOT Button And RGB LED

- Press the BOOT button (GPIO0) to start or stop capture.
- Capture starts with the configuration saved in NVS. If no configuration has been saved, it uses full-channel mode on channel 1.
- Enable “Start the saved configuration at boot” in the Web UI to resume the saved configuration automatically after reboot; otherwise the device stays idle.
- Solid green RGB means idle (GPIO48 on DevKitC-1, GPIO21 on Waveshare ESP32-S3 Zero).
- Solid yellow means capture is running but no packets have been captured yet.
- After packets are captured, the LED blinks yellow, starting at one cycle every 2 seconds and increasing up to 5 Hz as the packet count grows.
- After usable `.22000` data is generated (PMKID or EAPOL), the blinking color changes to orange.

## Build And Flash

Install PlatformIO, connect your ESP32-S3 DevKitC-1, then build and upload:

```sh
pio run
pio run --target upload
pio device monitor
```

## Repository Topics

Suggested GitHub topics:

```text
esp32-s3
wifi
sniffer
handshake
pmkid
eapol
pcap
hashcat
platformio
arduino
littlefs
wifi-security
```
<!-- 
## License

No license has been selected yet. Add a license before publishing if you want to define how others may use this project. -->

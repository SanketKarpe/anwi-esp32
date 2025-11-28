#include "..\lib\global_vars.h"
#include <ArduinoJson.h>
#include <EEPROM.h>
#include <HTTPClient.h>
#include <WiFi.h>
#include <esp_wifi.h>

#include "alerts.h"
#include "config.h"
#include "debug_print.h"
#include "geofence.h"
#include "packet_capture.h"

uint8_t isConfiguredflag = -1;

/**
 * @brief Hops to the next WiFi channel.
 *
 * If channel hopping is enabled in the configuration, this function increments
 * the current channel. If the maximum channel is reached, it resets to the
 * initial channel.
 */
void hop_channel() {
  if (sensor_config.protection_config.is_hop_channel_enabled) {
    if (set_channel == MAX_CHANNEL) {
      set_channel = INIT_CHANNEL;
    } else {
      set_channel++;
    }
    if (DEBUG_PRINT) {
      Serial.print(" CHAN SET TO : ");
      Serial.println(set_channel);
    }

    esp_wifi_set_channel(set_channel, WIFI_SECOND_CHAN_NONE);
  }
}

/**
 * @brief Main execution loop.
 *
 * Handles the main logic of the application, including:
 * - Updating radio status (if in NRF mode).
 * - Sending heartbeats.
 * - Running detection logic (scanning for attacks).
 * - Running protection logic (geofencing).
 */
void loop() {
  if (sensor_config.alert_mode == ALERT_NRF) {
    radio_update();
  }

  heartbeat();

  if (sensor_config.operation_mode == OPERATION_DETECTION_MODE) {
    curTime = millis();
    if (curTime - prevTime >= SCAN_FREQ) {
      if (pkt_info.is_deauth_detected) {
        if (deauth_pkt_counter >= MAX_DEAUTH_PKT) {
          pkt_info.attack_type = IS_DEAUTH_ATTACK;
        }
        pkt_info.is_deauth_detected = false;
      }
      hop_channel();
    } else {
      prevTime = curTime;
      deauth_pkt_counter = 0;
    }

    if (pkt_info.attack_type == IS_EVILTWIN_ATTACK ||
        pkt_info.attack_type == IS_DEAUTH_ATTACK) {
      send_alert();
      pkt_info.attack_type = -1;
    }
  }

  else if (sensor_config.operation_mode == OPERATION_PROTECTION_MODE) {
    delay(5000);
    // recalibrate geofence after regular interval
    // recalibrate geofence after regular interval
    recalibrate_transmission_power();

    // set values for pkt_info variable
    unsigned char number_client;

    wifi_sta_list_t wifi_sta_list;
    esp_wifi_ap_get_sta_list(&wifi_sta_list);

    number_client = wifi_sta_list.num;

    if (DEBUG_PRINT) {
      Serial.print(" Total connected_client are = ");
      Serial.println(number_client);
    }

    // send alert for each connected client.. Currently no duplicate checked
    char bssid_mac[18];
    for (int i = 0; i < wifi_sta_list.num; i++) {
      wifi_sta_info_t station = wifi_sta_list.sta[i];

      pkt_info.attack_type = IS_GEOFENCE_ATTACK;
      WiFi.macAddress(pkt_info.frame_hdr.bssid_address);
      pkt_info.channel = 1;
      pkt_info.rssi = WiFi.RSSI(); // Note: RSSI might not be available for AP
                                   // clients easily in this mode
      WiFi.macAddress(pkt_info.frame_hdr.destination_address);
      MEMCPY(pkt_info.frame_hdr.source_address, station.mac, 6);
      pkt_info.frame_hdr.deauth.reason_code = 0;
      snprintf(bssid_mac, sizeof(bssid_mac), MACSTR,
               MAC2STR(pkt_info.frame_hdr.bssid_address));
      Serial.print("Attacker MAC : ");
      Serial.println(bssid_mac);
      send_alert();
      pkt_info.attack_type = -1;
    }
    pkt_info.attack_type = -1;
  }
}

/**
 * @brief Initializes the device.
 *
 * Sets up serial communication, checks configuration status, and initializes
 * the sensor based on the stored configuration (Detection or Protection mode).
 * If not configured, it enters configuration mode.
 */
void setup() {
  delay(5000);
  isConfiguredflag = get_configuration_status();
  Serial.begin(115200);
  Serial.println("\nANWI - All New Wireless IDS\n ");
  if (isConfiguredflag == 0) {
    Serial.println("NOT_CONFIGURED");
    while (get_configuration_status() == 0) {
      if (Serial) {
        config_sensor_json();
      }
    }
    Serial.println("JUST_CONFIGURED");
    delay(2000);
    ESP.restart();
  } else {
    Serial.println("ALREADY_CONFIGURED");
    get_config_settings();
    print_config();
    delay(5000);
    if (Serial.read() == 'd') {
      clear_configuration();
      Serial.println("CONFIGURATION_CLEARED");
      Serial.println("Rebooting Sensor");
      delay(1000);
      ESP.restart();
    }
    Serial.println("Using existing configuration");
  }

  if (sensor_config.alert_mode == ALERT_NRF) {
    init_radio();
    radio_update();
  }

  curr_channel = 1;
  // get_config_settings();
  if (sensor_config.operation_mode == OPERATION_DETECTION_MODE) {
    Serial.println("ANWI Attack Detection Mode Activated..");
    init_sniffing();
  } else if (sensor_config.operation_mode == OPERATION_PROTECTION_MODE) {
    Serial.println("ANWI Protection Mode Activated..");
    setup_geofence(sensor_config.protect_ap_info.SSID);
  }
}

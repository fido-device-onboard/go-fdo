// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package examples

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"
)

// LinuxSysConfig provides a Linux-specific implementation for setting system parameters.
// This is an EXAMPLE implementation for standard Linux systems.
// Adapt this for your specific environment (embedded systems, BSD, etc.).
type LinuxSysConfig struct {
	// SupportedParameters defines which parameters this implementation supports
	// If nil, all standard parameters are supported
	SupportedParameters map[string]bool
}

// SetParameter sets a system parameter on a Linux system.
// This example implementation supports:
// - hostname: Sets system hostname
// - timezone: Sets system timezone
// - ntp-server: Configures NTP server
// - locale: Sets system locale
// - language: Sets system language
// - wifi: Configures WiFi network credentials
func (l *LinuxSysConfig) SetParameter(parameter, value string) error {
	// Check if parameter is supported
	if l.SupportedParameters != nil {
		if !l.SupportedParameters[parameter] {
			return fmt.Errorf("parameter '%s' is not supported", parameter)
		}
	}

	switch parameter {
	case "hostname":
		return l.setHostname(value)
	case "timezone":
		return l.setTimezone(value)
	case "ntp-server":
		return l.setNTPServer(value)
	case "locale":
		return l.setLocale(value)
	case "language":
		return l.setLanguage(value)
	case "wifi":
		return l.setWiFi(value)
	default:
		// Unknown parameter - check if it's vendor-specific
		if strings.Contains(parameter, ".") {
			// Vendor-specific parameter - ignore gracefully
			return fmt.Errorf("vendor parameter '%s' is not supported", parameter)
		}
		return fmt.Errorf("unknown parameter '%s'", parameter)
	}
}

// setHostname sets the system hostname.
func (l *LinuxSysConfig) setHostname(hostname string) error {
	// Validate hostname format (basic validation)
	if hostname == "" {
		return fmt.Errorf("invalid hostname: empty string")
	}

	// Write to /etc/hostname
	if err := os.WriteFile("/etc/hostname", []byte(hostname+"\n"), 0600); err != nil {
		return fmt.Errorf("failed to write /etc/hostname: %w", err)
	}

	// Set hostname immediately using hostname command
	cmd := exec.Command("hostname", hostname)
	if err := cmd.Run(); err != nil {
		// Non-fatal - file is written, hostname will be set on reboot
		return fmt.Errorf("warning: failed to set hostname immediately: %w", err)
	}

	// Update /etc/hosts (optional, best-effort)
	_ = l.updateHostsFile(hostname)

	return nil
}

// updateHostsFile updates /etc/hosts with the new hostname.
func (l *LinuxSysConfig) updateHostsFile(hostname string) error {
	hostsPath := "/etc/hosts"

	// Read current hosts file
	data, err := os.ReadFile(hostsPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	var newLines []string
	updated := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Update 127.0.1.1 line if it exists
		if strings.HasPrefix(trimmed, "127.0.1.1") {
			newLines = append(newLines, fmt.Sprintf("127.0.1.1\t%s", hostname))
			updated = true
		} else {
			newLines = append(newLines, line)
		}
	}

	// If no 127.0.1.1 line existed, add one
	if !updated {
		newLines = append(newLines, fmt.Sprintf("127.0.1.1\t%s", hostname))
	}

	// Write back
	return os.WriteFile(hostsPath, []byte(strings.Join(newLines, "\n")), 0600)
}

// setTimezone sets the system timezone.
func (l *LinuxSysConfig) setTimezone(timezone string) error {
	// Validate timezone exists
	tzPath := filepath.Join("/usr/share/zoneinfo", timezone)
	if _, err := os.Stat(tzPath); os.IsNotExist(err) {
		return fmt.Errorf("invalid timezone: %s not found", timezone)
	}

	// Remove old symlink if it exists
	localtimePath := "/etc/localtime"
	_ = os.Remove(localtimePath)

	// Create symlink to timezone data
	if err := os.Symlink(tzPath, localtimePath); err != nil {
		return fmt.Errorf("failed to set timezone: %w", err)
	}

	// Write timezone name to /etc/timezone (Debian/Ubuntu)
	_ = os.WriteFile("/etc/timezone", []byte(timezone+"\n"), 0600)

	return nil
}

// setNTPServer configures the NTP server.
func (l *LinuxSysConfig) setNTPServer(server string) error {
	// Try systemd-timesyncd first (most common on modern systems)
	if err := l.setNTPServerSystemd(server); err == nil {
		return nil
	}

	// Try chrony
	if err := l.setNTPServerChrony(server); err == nil {
		return nil
	}

	// Try ntpd
	if err := l.setNTPServerNTPD(server); err == nil {
		return nil
	}

	return fmt.Errorf("no supported NTP client found (tried systemd-timesyncd, chrony, ntpd)")
}

// setNTPServerSystemd configures systemd-timesyncd.
func (l *LinuxSysConfig) setNTPServerSystemd(server string) error {
	configPath := "/etc/systemd/timesyncd.conf"

	// Check if systemd-timesyncd is available
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("systemd-timesyncd not available")
	}

	// Read existing config
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	var newLines []string
	updated := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Update NTP= line if it exists
		if strings.HasPrefix(trimmed, "NTP=") || strings.HasPrefix(trimmed, "#NTP=") {
			newLines = append(newLines, fmt.Sprintf("NTP=%s", server))
			updated = true
		} else {
			newLines = append(newLines, line)
		}
	}

	// If no NTP= line existed, add one under [Time] section
	if !updated {
		for i, line := range newLines {
			if strings.TrimSpace(line) == "[Time]" {
				// Insert after [Time] section
				newLines = append(newLines[:i+1], append([]string{fmt.Sprintf("NTP=%s", server)}, newLines[i+1:]...)...)
				updated = true
				break
			}
		}
	}

	// If still not updated, add [Time] section
	if !updated {
		newLines = append(newLines, "", "[Time]", fmt.Sprintf("NTP=%s", server))
	}

	// Write back
	if err := os.WriteFile(configPath, []byte(strings.Join(newLines, "\n")), 0600); err != nil {
		return err
	}

	// Restart systemd-timesyncd
	cmd := exec.Command("systemctl", "restart", "systemd-timesyncd")
	return cmd.Run()
}

// setNTPServerChrony configures chrony.
func (l *LinuxSysConfig) setNTPServerChrony(server string) error {
	configPath := "/etc/chrony/chrony.conf"

	// Try alternate path
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		configPath = "/etc/chrony.conf"
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			return fmt.Errorf("chrony not available")
		}
	}

	// Read existing config
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	var newLines []string

	// Comment out existing server/pool lines and add new one
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "server ") || strings.HasPrefix(trimmed, "pool ") {
			newLines = append(newLines, "#"+line)
		} else {
			newLines = append(newLines, line)
		}
	}

	// Add new server line
	newLines = append(newLines, fmt.Sprintf("server %s iburst", server))

	// Write back
	if err := os.WriteFile(configPath, []byte(strings.Join(newLines, "\n")), 0600); err != nil {
		return err
	}

	// Restart chronyd
	cmd := exec.Command("systemctl", "restart", "chronyd")
	return cmd.Run()
}

// setNTPServerNTPD configures ntpd.
func (l *LinuxSysConfig) setNTPServerNTPD(server string) error {
	configPath := "/etc/ntp.conf"

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("ntpd not available")
	}

	// Read existing config
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	var newLines []string

	// Comment out existing server lines and add new one
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "server ") {
			newLines = append(newLines, "#"+line)
		} else {
			newLines = append(newLines, line)
		}
	}

	// Add new server line
	newLines = append(newLines, fmt.Sprintf("server %s iburst", server))

	// Write back
	if err := os.WriteFile(configPath, []byte(strings.Join(newLines, "\n")), 0600); err != nil {
		return err
	}

	// Restart ntpd
	cmd := exec.Command("systemctl", "restart", "ntpd")
	if err := cmd.Run(); err != nil {
		// Try alternate service name
		cmd = exec.Command("systemctl", "restart", "ntp")
		return cmd.Run()
	}

	return nil
}

// setLocale sets the system locale.
func (l *LinuxSysConfig) setLocale(locale string) error {
	// Validate locale format (basic validation)
	if locale == "" {
		return fmt.Errorf("invalid locale: empty string")
	}

	// Check if locale is available (try to find it in locale -a output)
	// This is best-effort - some systems may not have locale command
	cmd := exec.Command("locale", "-a")
	output, err := cmd.Output()
	if err == nil {
		// Check if locale exists in available locales
		availableLocales := strings.Split(string(output), "\n")
		found := false
		for _, available := range availableLocales {
			if strings.TrimSpace(available) == locale {
				found = true
				break
			}
		}
		if !found {
			// Try to generate the locale
			if err := l.generateLocale(locale); err != nil {
				return fmt.Errorf("locale '%s' not available and generation failed: %w", locale, err)
			}
		}
	}

	// Try different locale configuration files based on distribution
	localeSet := false

	// Debian/Ubuntu: /etc/default/locale
	if err := l.updateLocaleFile("/etc/default/locale", locale); err == nil {
		localeSet = true
	}

	// RHEL/CentOS/Fedora: /etc/locale.conf
	if err := l.updateLocaleFile("/etc/locale.conf", locale); err == nil {
		localeSet = true
	}

	if !localeSet {
		return fmt.Errorf("failed to set locale on this system")
	}

	return nil
}

// updateLocaleFile updates a locale configuration file.
func (l *LinuxSysConfig) updateLocaleFile(path, locale string) error {
	// Read existing file if it exists
	var lines []string
	// Validate path is within expected bounds
	if !strings.HasPrefix(path, "/etc/") && !strings.HasPrefix(path, "/usr/") {
		return fmt.Errorf("invalid path: %s", path)
	}
	data, err := os.ReadFile(path)
	if err == nil {
		lines = strings.Split(string(data), "\n")
	}

	// Update or add LANG line
	updated := false
	var newLines []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "LANG=") {
			newLines = append(newLines, fmt.Sprintf("LANG=%s", locale))
			updated = true
		} else {
			newLines = append(newLines, line)
		}
	}

	// If LANG wasn't found, add it
	if !updated {
		newLines = append(newLines, fmt.Sprintf("LANG=%s", locale))
	}

	// Write back
	return os.WriteFile(path, []byte(strings.Join(newLines, "\n")), 0600)
}

// generateLocale attempts to generate a locale using locale-gen.
func (l *LinuxSysConfig) generateLocale(locale string) error {
	// Try locale-gen (Debian/Ubuntu)
	cmd := exec.Command("locale-gen", locale)
	if err := cmd.Run(); err == nil {
		return nil
	}

	// Try localedef (RHEL/CentOS)
	// Parse locale into parts (e.g., en_US.UTF-8 -> en_US and UTF-8)
	parts := strings.Split(locale, ".")
	// Validate input to prevent command injection
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("invalid locale format: %s", locale)
	}
	// Only allow alphanumeric and underscore in locale name
	for _, r := range parts[0] {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
			return fmt.Errorf("invalid locale name: %s", parts[0])
		}
	}
	cmd = exec.Command("localedef", "-i", parts[0], "-f", parts[1], locale)
	if err := cmd.Run(); err == nil {
		return nil
	}

	return fmt.Errorf("locale generation not supported on this system")
}

// setLanguage sets the system language (simplified locale setting).
func (l *LinuxSysConfig) setLanguage(language string) error {
	// Validate language format (basic validation)
	if language == "" {
		return fmt.Errorf("invalid language: empty string")
	}

	// Map simple language codes to full locales
	locale := l.mapLanguageToLocale(language)

	// Use setLocale to actually apply the setting
	return l.setLocale(locale)
}

// mapLanguageToLocale maps a language code to a full locale string.
func (l *LinuxSysConfig) mapLanguageToLocale(language string) string {
	// Common language mappings
	languageMap := map[string]string{
		"en":    "en_US.UTF-8",
		"en-US": "en_US.UTF-8",
		"en-GB": "en_GB.UTF-8",
		"de":    "de_DE.UTF-8",
		"de-DE": "de_DE.UTF-8",
		"fr":    "fr_FR.UTF-8",
		"fr-FR": "fr_FR.UTF-8",
		"es":    "es_ES.UTF-8",
		"es-ES": "es_ES.UTF-8",
		"it":    "it_IT.UTF-8",
		"it-IT": "it_IT.UTF-8",
		"ja":    "ja_JP.UTF-8",
		"ja-JP": "ja_JP.UTF-8",
		"zh":    "zh_CN.UTF-8",
		"zh-CN": "zh_CN.UTF-8",
		"zh-TW": "zh_TW.UTF-8",
		"ko":    "ko_KR.UTF-8",
		"ko-KR": "ko_KR.UTF-8",
		"ru":    "ru_RU.UTF-8",
		"ru-RU": "ru_RU.UTF-8",
		"pt":    "pt_PT.UTF-8",
		"pt-PT": "pt_PT.UTF-8",
		"pt-BR": "pt_BR.UTF-8",
		"nl":    "nl_NL.UTF-8",
		"nl-NL": "nl_NL.UTF-8",
		"pl":    "pl_PL.UTF-8",
		"pl-PL": "pl_PL.UTF-8",
		"tr":    "tr_TR.UTF-8",
		"tr-TR": "tr_TR.UTF-8",
	}

	// Check if we have a mapping
	if locale, ok := languageMap[language]; ok {
		return locale
	}

	// If language looks like a full locale already (contains underscore or dot), use as-is
	if strings.Contains(language, "_") || strings.Contains(language, ".") {
		return language
	}

	// Default: append .UTF-8 to language code
	// Convert language-COUNTRY to language_COUNTRY format
	locale := strings.ReplaceAll(language, "-", "_")
	if !strings.Contains(locale, ".") {
		locale += ".UTF-8"
	}

	return locale
}

// WiFiConfig represents WiFi network credentials.
type WiFiConfig struct {
	SSID     string `json:"ssid"`
	Password string `json:"password,omitempty"`
	Security string `json:"security,omitempty"`
	Hidden   bool   `json:"hidden,omitempty"`
	Priority int    `json:"priority,omitempty"`
}

// setWiFi configures WiFi network credentials.
func (l *LinuxSysConfig) setWiFi(value string) error {
	// Parse JSON value
	var config WiFiConfig
	if err := json.Unmarshal([]byte(value), &config); err != nil {
		return fmt.Errorf("invalid wifi JSON: %w", err)
	}

	// Validate required fields
	if config.SSID == "" {
		return fmt.Errorf("wifi SSID is required")
	}

	// Default security to auto
	if config.Security == "" {
		config.Security = "auto"
	}

	// Configure using wpa_supplicant
	return l.configureWpaSupplicant(config)
}

// configureWpaSupplicant adds a network to wpa_supplicant configuration.
func (l *LinuxSysConfig) configureWpaSupplicant(config WiFiConfig) error {
	// Common wpa_supplicant config paths
	configPaths := []string{
		"/etc/wpa_supplicant/wpa_supplicant.conf",
		"/etc/wpa_supplicant.conf",
	}

	var configPath string
	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			configPath = path
			break
		}
	}

	// If no config exists, create one
	if configPath == "" {
		configPath = "/etc/wpa_supplicant/wpa_supplicant.conf"
		if err := os.MkdirAll(filepath.Dir(configPath), 0750); err != nil {
			return fmt.Errorf("failed to create wpa_supplicant directory: %w", err)
		}

		// Create basic config file
		header := "ctrl_interface=/var/run/wpa_supplicant\nupdate_config=1\n\n"
		if err := os.WriteFile(configPath, []byte(header), 0600); err != nil {
			return fmt.Errorf("failed to create wpa_supplicant config: %w", err)
		}
	}

	// Read existing config
	// Validate configPath is within expected bounds
	if !strings.HasPrefix(configPath, "/etc/") {
		return fmt.Errorf("invalid config path: %s", configPath)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read wpa_supplicant config: %w", err)
	}

	// Generate network block
	networkBlock := l.generateWpaNetworkBlock(config)

	// Check if network already exists (by SSID)
	content := string(data)
	ssidLine := fmt.Sprintf(`ssid="%s"`, config.SSID)

	if strings.Contains(content, ssidLine) {
		// Network exists, replace it
		content = l.replaceWpaNetwork(content, config.SSID, networkBlock)
	} else {
		// Append new network
		content += "\n" + networkBlock + "\n"
	}

	// Write back
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write wpa_supplicant config: %w", err)
	}

	// Reload wpa_supplicant
	l.reloadWpaSupplicant()

	return nil
}

// generateWpaNetworkBlock generates a wpa_supplicant network configuration block.
func (l *LinuxSysConfig) generateWpaNetworkBlock(config WiFiConfig) string {
	var block strings.Builder

	block.WriteString("network={\n")
	block.WriteString(fmt.Sprintf("\tssid=\"%s\"\n", config.SSID))

	// Handle security type
	switch config.Security {
	case "open":
		block.WriteString("\tkey_mgmt=NONE\n")

	case "wpa2":
		if config.Password != "" {
			psk := l.generateWpaPSK(config.SSID, config.Password)
			block.WriteString(fmt.Sprintf("\tpsk=%s\n", psk))
		}
		block.WriteString("\tproto=RSN\n")
		block.WriteString("\tkey_mgmt=WPA-PSK\n")

	case "wpa3":
		if config.Password != "" {
			block.WriteString(fmt.Sprintf("\tpsk=\"%s\"\n", config.Password))
		}
		block.WriteString("\tproto=RSN\n")
		block.WriteString("\tkey_mgmt=SAE\n")

	case "wpa2-wpa3":
		if config.Password != "" {
			block.WriteString(fmt.Sprintf("\tpsk=\"%s\"\n", config.Password))
		}
		block.WriteString("\tproto=RSN\n")
		block.WriteString("\tkey_mgmt=WPA-PSK SAE\n")

	case "auto":
		fallthrough
	default:
		// Auto-detect or default: use password and let wpa_supplicant figure it out
		if config.Password != "" {
			block.WriteString(fmt.Sprintf("\tpsk=\"%s\"\n", config.Password))
		} else {
			block.WriteString("\tkey_mgmt=NONE\n")
		}
	}

	// Hidden network
	if config.Hidden {
		block.WriteString("\tscan_ssid=1\n")
	}

	// Priority
	if config.Priority > 0 {
		block.WriteString(fmt.Sprintf("\tpriority=%d\n", config.Priority))
	}

	block.WriteString("}")

	return block.String()
}

// generateWpaPSK generates a WPA PSK hash from SSID and password.
// This is the proper way to store WPA2 passwords in wpa_supplicant.
func (l *LinuxSysConfig) generateWpaPSK(ssid, password string) string {
	// For simplicity, we'll use cleartext password in quotes
	// In production, you might want to use wpa_passphrase command or implement PBKDF2
	// The wpa_supplicant accepts both formats

	// Try using wpa_passphrase command if available
	cmd := exec.Command("wpa_passphrase", ssid, password)
	output, err := cmd.Output()
	if err == nil {
		// Parse output to extract PSK
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "psk=") && !strings.Contains(line, "\"") {
				// Found the hex PSK (not the commented cleartext)
				return strings.TrimPrefix(line, "psk=")
			}
		}
	}

	// Fallback: use cleartext password (wpa_supplicant supports this)
	return fmt.Sprintf("\"%s\"", password)
}

// replaceWpaNetwork replaces an existing network block in wpa_supplicant config.
func (l *LinuxSysConfig) replaceWpaNetwork(content, ssid, newBlock string) string {
	lines := strings.Split(content, "\n")
	var result []string
	inNetwork := false
	inTargetNetwork := false
	networkDepth := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Track network blocks
		if strings.HasPrefix(trimmed, "network=") {
			inNetwork = true
			networkDepth = 0
			inTargetNetwork = false
		}

		if inNetwork {
			if strings.Contains(line, "{") {
				networkDepth++
			}
			if strings.Contains(line, "}") {
				networkDepth--
				if networkDepth == 0 {
					if inTargetNetwork {
						// Replace this network block
						result = append(result, newBlock)
						inTargetNetwork = false
					} else {
						// Keep this network block
						result = append(result, line)
					}
					inNetwork = false
					continue
				}
			}

			// Check if this is our target network
			if strings.Contains(line, fmt.Sprintf(`ssid="%s"`, ssid)) {
				inTargetNetwork = true
			}

			// Skip lines of target network (we'll replace the whole block)
			if !inTargetNetwork {
				result = append(result, line)
			}
		} else {
			result = append(result, line)
		}
	}

	return strings.Join(result, "\n")
}

// reloadWpaSupplicant attempts to reload wpa_supplicant configuration.
func (l *LinuxSysConfig) reloadWpaSupplicant() {
	// Try systemctl restart
	cmd := exec.Command("systemctl", "restart", "wpa_supplicant")
	if err := cmd.Run(); err == nil {
		return
	}

	// Try wpa_cli reconfigure
	cmd = exec.Command("wpa_cli", "reconfigure")
	if err := cmd.Run(); err == nil {
		return
	}

	// Try killall and restart (last resort)
	_ = exec.Command("killall", "-HUP", "wpa_supplicant").Run()
}

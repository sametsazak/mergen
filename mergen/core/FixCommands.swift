//
//  FixCommands.swift
//  mergen
//
//  Central registry mapping CIS checks to their auto-remediation shell commands.
//  No check module files need to be modified — the lookup is done by cisID / docID.
//

import Foundation

extension Vulnerability {

    // MARK: - Fix Registries

    /// Fixes that run as the current user (no password prompt).
    private static let userFixes: [String: String] = [
        // 2.3.1.1  AirDrop off
        "2.3.1.1":  "defaults write com.apple.NetworkBrowser DisableAirDrop -bool YES",
        // 2.3.1.2  AirPlay Receiver off
        "2.3.1.2":  "defaults write com.apple.controlcenter AirplayRecieverEnabled -int 0",
        // 2.3.3.10 Bluetooth sharing off
        "2.3.3.10": "defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false",
        // 2.5.2.1  Siri off
        "2.5.2.1":  "defaults write com.apple.Siri SiriProfessionalEnabled -bool false",
        // 2.6.3.2  Siri & Dictation improvement off
        "2.6.3.2":  "defaults write com.apple.assistant.support \"Siri Data Sharing Opt-In Status\" -int 2",
        // 2.6.3.3  Improve assistive voice off
        "2.6.3.3":  "defaults write com.apple.Accessibility AXSAudioDonationSiriImprovementEnabled -bool false",
        // 2.6.4    Personalized ads off
        "2.6.4":    "defaults write com.apple.AdLib allowApplePersonalizedAdvertising -bool false",
        // 2.8.1    Universal Control off
        "2.8.1":    "defaults -currentHost write com.apple.universalcontrol Disable -int 1",
        // 2.11.1   Screen saver interval  (≤ 20 min)
        "2.11.1":   "defaults -currentHost write com.apple.screensaver idleTime -int 1200",
        // 2.11.2   Password on wake
        "2.11.2":   "defaults -currentHost write com.apple.screensaver askForPassword -bool true && defaults -currentHost write com.apple.screensaver askForPasswordDelay -int 0",
        // 6.1.1    Show filename extensions
        "6.1.1":    "defaults write NSGlobalDomain AppleShowAllExtensions -bool true",
        // 6.3.1    Safari: don't auto-open safe files
        //          NOTE: On macOS Tahoe, Safari preferences are sandboxed — defaults write
        //          is blocked by cfprefsd. This must be changed manually in Safari > Settings.
        // "6.3.1": removed — not auto-fixable on Tahoe
        // 6.3.3    Safari: fraud warning
        "6.3.3":    "defaults write com.apple.Safari WarnAboutFraudulentWebsites -bool true",
        // 6.3.4    Safari: cross-site tracking prevention — check reads com.apple.Safari BlockStoragePolicy
        "6.3.4":    "defaults write com.apple.Safari BlockStoragePolicy -int 2",
        // 6.3.6    Safari: advertising privacy
        "6.3.6":    "defaults write com.apple.Safari WebKitPreferences.privateClickMeasurementEnabled -bool true",
        // 6.3.10   Safari: status bar — check reads com.apple.Safari ShowOverlayStatusBar
        "6.3.10":   "defaults write com.apple.Safari ShowOverlayStatusBar -bool true",
        // 6.4.1    Terminal: secure keyboard entry
        "6.4.1":    "defaults write com.apple.Terminal SecureKeyboardEntry -bool true",
    ]

    /// Fixes that require administrator privileges (shown as one password prompt).
    private static let adminFixes: [String: String] = [
        // 1.2  Critical updates install automatically
        "1.2":       "defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -int 1",
        // 1.3  Auto-download updates
        "1.3":       "defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true",
        // 1.4  App Store auto-updates
        "1.4":       "defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true",
        // 1.5  Security responses / config data
        "1.5":       "defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true",
        // 2.2.1  Firewall on
        "2.2.1":     "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
        // 2.2.2  Stealth mode on
        "2.2.2":     "/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on",
        // 2.3.2.1  Set time automatically — check reads com.apple.timezone.auto.plist Active
        "2.3.2.1":   "defaults write /Library/Preferences/com.apple.timezone.auto.plist Active -int 1",
        // 2.3.3.1  Screen sharing off (stop is best-effort; disable persists across reboot)
        "2.3.3.1":   "launchctl disable system/com.apple.screensharing; launchctl stop com.apple.screensharing 2>/dev/null; true",
        // 2.3.3.2  File sharing off
        "2.3.3.2":   "launchctl disable system/com.apple.smbd; launchctl stop com.apple.smbd 2>/dev/null; true",
        // 2.3.3.3  Printer sharing off
        "2.3.3.3":   "cupsctl --no-share-printers",
        // 2.3.3.4  Remote login (SSH) off
        "2.3.3.4":   "launchctl disable system/com.openssh.sshd; launchctl stop com.openssh.sshd 2>/dev/null; true",
        // 2.3.3.5  Remote management off
        "2.3.3.5":   "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop 2>/dev/null; true",
        // 2.3.3.6  Remote Apple Events off — check verifies launchctl disabled state
        "2.3.3.6":   "launchctl disable system/com.apple.AEServer; launchctl stop com.apple.AEServer 2>/dev/null; true",
        // 2.3.3.7  Internet sharing off
        "2.3.3.7":   "defaults write /Library/Preferences/SystemConfiguration/com.apple.nat NAT -dict-add Enabled -int 0",
        // 2.3.3.8  Content caching off
        "2.3.3.8":   "/usr/bin/AssetCacheManagerUtil deactivate 2>/dev/null; true",
        // 2.3.3.9  Media sharing off — check reads com.apple.amp.mediasharingd home-sharing-enabled
        "2.3.3.9":   "defaults write com.apple.amp.mediasharingd home-sharing-enabled -int 0; launchctl stop com.apple.amp.mediasharingd 2>/dev/null; true",
        // 2.6.3.1  Share Mac analytics off
        "2.6.3.1":   "defaults write '/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist' AutoSubmit -bool false",
        // 2.6.5    Gatekeeper on
        "2.6.5":     "spctl --master-enable",
        // 2.10.1.2 Sleep enabled (Apple Silicon) — 15 min sleep, 10 min display sleep
        "2.10.1.2":  "pmset -a sleep 15; pmset -a displaysleep 10",
        // 2.10.2   Power nap off
        "2.10.2":    "pmset -a powernap 0 && pmset -a darkwakes 0",
        // 2.10.3   Wake for network access off
        "2.10.3":    "pmset -a womp 0",
        // 2.11.4   Login window shows name + password fields (not user list)
        "2.11.4":    "defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true",
        // 2.11.5   Password hints off
        "2.11.5":    "defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0",
        // 2.13.1   Guest login off — check reads com.apple.loginwindow.plist GuestEnabled
        "2.13.1":    "defaults write /Library/Preferences/com.apple.loginwindow.plist GuestEnabled -bool false",
        // 2.13.2   Guest network access off — check reads com.apple.AppleFileServer guestAccess
        "2.13.2":    "defaults write /Library/Preferences/com.apple.AppleFileServer guestAccess -int 0",
        // 2.13.3   Auto-login off (delete is best-effort — key may already be absent)
        "2.13.3":    "defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null; true",
        // 4.1      Bonjour multicast advertising off
        "4.1":       "defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool true",
        // 4.2      Apache HTTP server off
        "4.2":       "launchctl disable system/org.apache.httpd; launchctl stop org.apache.httpd 2>/dev/null; true",
        // 4.3      NFS server off
        "4.3":       "launchctl disable system/com.apple.nfsd",
        // 5.2.1    Password lockout threshold ≤ 5 attempts
        "5.2.1":     "pwpolicy -n /Local/Default -setglobalpolicy maxFailedLoginAttempts=5",
        // 5.2.2    Minimum password length ≥ 15 characters
        "5.2.2":     "pwpolicy -n /Local/Default -setglobalpolicy minChars=15",
        // 5.4      Sudo authentication timeout = 0 (require password every time)
        "5.4":       "echo Defaults timestamp_timeout=0 > /etc/sudoers.d/cis_timeout && chmod 440 /etc/sudoers.d/cis_timeout",
        // 5.5      Sudo TTY tickets (per-terminal auth)
        "5.5":       "echo Defaults timestamp_type=tty > /etc/sudoers.d/cis_tty && chmod 440 /etc/sudoers.d/cis_tty",
        // 5.6      Root account off — set shell to /usr/bin/false (what the check validates)
        "5.6":       "dscl . -create /Users/root UserShell /usr/bin/false",
        // 5.11     Sudo log allowed commands
        "5.11":      "echo Defaults log_allowed > /etc/sudoers.d/cis_logging && chmod 440 /etc/sudoers.d/cis_logging",
    ]

    /// Fixes keyed by `docID` for standalone checks that have no CIS ID.
    private static let docIDAdminFixes: [Int32: String] = [
        // FastUserSwitchingCheck (docID 35)
        35: "defaults write /Library/Preferences/.GlobalPreferences MultipleSessionEnabled -bool false",
    ]

    // MARK: - Human-readable impact descriptions

    /// One-line description of what will change after the fix is applied.
    private static let fixDescriptions: [String: String] = [
        // Section 1
        "1.2":       "Critical security updates will install automatically.",
        "1.3":       "macOS updates will be downloaded automatically in the background.",
        "1.4":       "App Store application updates will install automatically.",
        "1.5":       "Security responses and system files will install automatically.",
        // Section 2 – AirDrop / AirPlay / Bluetooth
        "2.3.1.1":   "AirDrop will be disabled for all networks.",
        "2.3.1.2":   "AirPlay Receiver will be off — other devices can no longer cast to this Mac.",
        "2.3.3.10":  "Bluetooth Sharing will be disabled.",
        // Section 2 – Sharing services
        "2.3.3.1":   "Screen Sharing service will be disabled and stopped.",
        "2.3.3.2":   "File Sharing (SMB/AFP) service will be disabled and stopped.",
        "2.3.3.3":   "Printer Sharing will be turned off.",
        "2.3.3.4":   "Remote Login (SSH) service will be disabled and stopped.",
        "2.3.3.5":   "Remote Management (ARD) will be deactivated and stopped.",
        "2.3.3.6":   "Remote Apple Events will be disabled.",
        "2.3.3.7":   "Internet Sharing will be disabled.",
        "2.3.3.8":   "Content Caching service will be deactivated.",
        "2.3.3.9":   "Media Sharing service will be disabled.",
        // Section 2 – Time
        "2.3.2.1":   "System clock will sync automatically with a network time server.",
        // Section 2 – Firewall
        "2.2.1":     "macOS Application Firewall will be turned on, blocking unauthorized incoming connections.",
        "2.2.2":     "Firewall stealth mode will be enabled — your Mac will not respond to ping or port scans.",
        // Section 2 – Siri / Intelligence / Analytics
        "2.5.2.1":   "Siri will be disabled.",
        "2.6.3.1":   "Sending diagnostic and usage data to Apple will be turned off.",
        "2.6.3.2":   "Siri & Dictation improvement data sharing will be turned off.",
        "2.6.3.3":   "Assistive Voice improvement data sharing will be disabled.",
        "2.6.4":     "Apple personalized advertising will be disabled.",
        // Section 2 – Gatekeeper / Power / Login / Universal Control
        "2.6.5":     "Gatekeeper will be re-enabled — only apps from identified developers will run.",
        "2.8.1":     "Universal Control will be disabled, preventing keyboard/mouse sharing with nearby devices.",
        "2.10.1.2":  "Sleep will be set to 15 min and display sleep to 10 min.",
        "2.10.2":    "Power Nap and dark wake will be disabled.",
        "2.10.3":    "Wake for network access will be disabled.",
        "2.11.1":    "Screen saver will activate after 20 minutes of inactivity.",
        "2.11.2":    "Your password will be required immediately when the screen saver or sleep activates.",
        "2.11.4":    "Login window will show username and password fields instead of a user list.",
        "2.11.5":    "Password hints will no longer appear after failed login attempts.",
        "2.13.1":    "Guest account will be disabled.",
        "2.13.2":    "Guest access to shared folders will be disabled.",
        "2.13.3":    "Automatic login will be disabled — a password will be required at every startup.",
        // Section 4 – Network services
        "4.1":       "Bonjour multicast advertising will be disabled.",
        "4.2":       "Apache HTTP Server will be disabled and stopped.",
        "4.3":       "NFS file server will be disabled.",
        // Section 5 – Auth
        "5.2.1":     "Account will lock after 5 consecutive failed password attempts.",
        "5.2.2":     "Minimum password length will be set to 15 characters.",
        "5.4":       "sudo will require your password every time — no grace period between commands.",
        "5.5":       "sudo authentication will be scoped per terminal window (TTY tickets).",
        "5.6":       "Root account will be disabled.",
        "5.11":      "sudo will log all allowed commands to the system log.",
        // Section 6 – UI / Safari / Terminal
        "6.1.1":     "All file extensions will be visible in Finder.",
        // 6.3.1 removed — Safari preferences are sandboxed on Tahoe, cannot be auto-fixed.
        "6.3.3":     "Safari fraudulent website warning will be enabled.",
        "6.3.4":     "Safari cross-site tracking prevention will be enabled.",
        "6.3.6":     "Safari Private Click Measurement (ad privacy) will be enabled.",
        "6.3.10":    "Safari status bar will be shown, displaying link URLs on hover.",
        "6.4.1":     "Terminal secure keyboard entry will be enabled, blocking other apps from reading keystrokes.",
    ]

    /// docID-keyed descriptions for checks without a CIS ID.
    private static let docIDFixDescriptions: [Int32: String] = [
        35: "Fast User Switching will be disabled.",
    ]

    // MARK: - Public API

    /// Shell command that remediates this finding, or `nil` if not auto-fixable.
    var fixCommand: String? {
        if let cmd = Vulnerability.userFixes[cisID]  { return cmd }
        if let cmd = Vulnerability.adminFixes[cisID] { return cmd }
        if let cmd = Vulnerability.docIDAdminFixes[docID] { return cmd }
        return nil
    }

    /// Whether `fixCommand` needs to run with administrator privileges.
    var fixRequiresAdmin: Bool {
        if Vulnerability.userFixes[cisID]  != nil { return false }
        if Vulnerability.adminFixes[cisID] != nil { return true }
        if Vulnerability.docIDAdminFixes[docID] != nil { return true }
        return false
    }

    /// Human-readable description of what the fix will change, or `nil` if unknown.
    var fixDescription: String? {
        if let d = Vulnerability.fixDescriptions[cisID]       { return d }
        if let d = Vulnerability.docIDFixDescriptions[docID]  { return d }
        return nil
    }

    /// `true` when this check failed AND has an auto-remediation available.
    var isAutoFixable: Bool { checkstatus == "Red" && fixCommand != nil }
}

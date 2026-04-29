# Manual macOS Security Audit Guide

**Based on Mergen v2 (CIS Apple macOS 26 Tahoe Benchmark v1.0.0)**

A walkthrough for running every check Mergen performs — by hand. GUI navigation where Tahoe exposes it, Terminal commands where it doesn't. Use this if you'd rather understand each control than install another auditor.

> Source of truth: detection and fix commands extracted verbatim from `mergen-cli/internal/checks/*.go` (37 files) and `mergen/core/FixCommands.swift`. Severity ratings reflect the Go CLI's own ratings, which sometimes differ from the README — the code is authoritative.

---

## How to use this guide

1. Open **Terminal** (Applications → Utilities → Terminal, or `Cmd+Space` → "Terminal").
2. Confirm you're on a supported macOS:
   ```bash
   sw_vers
   ```
   This guide is calibrated for macOS 26 Tahoe; 13 Ventura and later are mostly compatible (Tahoe-specific differences are flagged inline).
3. **Take a Time Machine backup before running any fix command** — System Settings → General → Time Machine → Back Up Now. Several fixes change auth policy, sharing services, or sudo behavior; rolling back is much easier with a snapshot.
4. Work through each table top-to-bottom. For each row:
   - Run the **Verify** command. Compare against the row's pass condition (described in the check's name and severity).
   - If it fails: prefer the **GUI path** (left column inside System Settings); fall back to the **Fix** command if there's no GUI.
   - Tick the **☐** checkbox once you've verified or fixed it.
5. Re-run the verify command after a fix to confirm the change took effect.

### Legend

| Marker | Meaning |
|---|---|
| **Critical** | Exploitable without significant effort. Fix first. |
| **High** | Significant exposure if not remediated. Fix in same session. |
| **Medium** | Defense-in-depth. Fix when practical. |
| **Low** | Privacy hardening / advisory. Fix at your convenience. |
| **User** fix | No password needed. Run in a normal Terminal. |
| **Admin** fix | Needs `sudo`. You'll be prompted for your password. |
| **—** in Fix column | No automated remediation; the GUI path or note is the only way. |

### Tahoe-specific gotchas (read once)

- **`com.apple.alf` plist is gone.** All firewall queries use `socketfilterfw` directly.
- **`com.apple.auditd` is gone.** §3 (Logging & Auditing) checks always WARN — not your fault, no fix.
- **Screen saver keys live under `-currentHost`.** Verify commands try `-currentHost` first, fall back to user domain.
- **Safari preferences are sandboxed by `cfprefsd`.** `defaults write com.apple.Safari …` may silently fail. Prefer the Safari → Settings GUI for §6.3 checks.
- **Apple Intelligence (§2.5.1.x) controls require an MDM profile.** Without MDM, those checks can only return WARN. Manual GUI toggles in System Settings → Apple Intelligence & Siri are the practical workaround.

---

## §1 — Software Updates (6 checks)

| ☐ | CIS | Name (Severity) | GUI path | Verify | Fix |
|---|---|---|---|---|---|
| ☐ | 1.1 | Apple software updated within 30 days (High) | System Settings → General → Software Update → Update All | `defaults read /Library/Preferences/com.apple.SoftwareUpdate LastFullSuccessfulDate` (date must be within 30 days) | — (use GUI) |
| ☐ | 1.2 | Critical updates auto-install (Medium) | System Settings → General → Software Update → ⓘ → enable "Install Security Responses and system files" | `defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall` (expect `1`) | Admin: `sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -int 1` |
| ☐ | 1.3 | Auto-update enabled (Medium) | (same panel as 1.2 → "Download new updates when available") | `defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload` (expect `1`) | Admin: `sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true` |
| ☐ | 1.4 | App Store auto-updates enabled (Medium) | App Store → Settings → "Automatic Updates" | `defaults read /Library/Preferences/com.apple.commerce AutoUpdate` (expect `1`) | Admin: `sudo defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true` |
| ☐ | 1.5 | Security responses auto-install (High) | (same panel as 1.2) | `defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall` (expect `1`) | Admin: `sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true` |
| ☐ | 1.6 | Update deferment policy (Low) | MDM only (Jamf / Mosyle / etc.) | `defaults read /Library/Preferences/com.apple.SoftwareUpdate enforcedSoftwareUpdateDelay` (expect non-zero integer) | — (MDM-managed) |

---

## §2 — System Settings

### §2.1 — iCloud (2 checks)

| ☐ | CIS | Name (Severity) | GUI path | Verify | Fix |
|---|---|---|---|---|---|
| ☐ | 2.1.1.1 | iCloud Keychain disabled (Medium, advisory) | System Settings → [Your Name] → iCloud → Passwords & Keychain → toggle off | `osascript -l JavaScript -e "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowCloudKeychainSync').js"` (expect `false`; blank = no MDM, decide manually) | — (use GUI) |
| ☐ | 2.1.1.3 | iCloud Drive Desktop/Documents sync off (Medium) | System Settings → [Your Name] → iCloud → iCloud Drive → Options → uncheck "Desktop & Documents Folders" | `defaults read com.apple.finder FXICloudDriveDesktop; defaults read com.apple.finder FXICloudDriveDocuments` (both absent or `0`) | User: `defaults write com.apple.finder FXICloudDriveDesktop -bool false && defaults write com.apple.finder FXICloudDriveDocuments -bool false` |

### §2.2 — Firewall (2 checks)

> Tahoe: `com.apple.alf` plist removed; queries go through `socketfilterfw` only.

| ☐ | CIS | Name (Severity) | GUI path | Verify | Fix |
|---|---|---|---|---|---|
| ☐ | 2.2.1 | Firewall enabled (High) | System Settings → Network → Firewall → toggle on | `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate` (output contains `enabled`) | Admin: `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on` |
| ☐ | 2.2.2 | Firewall stealth mode (Medium) | System Settings → Network → Firewall → Options → enable "Stealth Mode" | `/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode` (output contains `enabled`) | Admin: `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on` |

### §2.3.1 — AirDrop / AirPlay (2 checks)

| ☐ | CIS | Name (Severity) | GUI path | Verify | Fix |
|---|---|---|---|---|---|
| ☐ | 2.3.1.1 | AirDrop disabled (Medium) | Control Center → AirDrop → Off, or Finder → AirDrop window → "Allow me to be discovered by: No One" | `defaults read com.apple.NetworkBrowser DisableAirDrop` (expect `1`) | User: `defaults write com.apple.NetworkBrowser DisableAirDrop -bool YES` |
| ☐ | 2.3.1.2 | AirPlay Receiver disabled (Low) | System Settings → General → AirDrop & Handoff → AirPlay Receiver → Off | `defaults read com.apple.controlcenter AirplayRecieverEnabled` (absent or `0`) | User: `defaults write com.apple.controlcenter AirplayRecieverEnabled -int 0` |

### §2.3.2 — Date & Time (2 checks)

| ☐ | CIS | Name (Severity) | GUI path | Verify | Fix |
|---|---|---|---|---|---|
| ☐ | 2.3.2.1 | Time set automatically (Medium) | System Settings → General → Date & Time → enable "Set time and date automatically" | `defaults read /Library/Preferences/com.apple.timezone.auto.plist Active` (expect `1`) | Admin: `sudo defaults write /Library/Preferences/com.apple.timezone.auto.plist Active -int 1` |
| ☐ | 2.3.2.2 | Clock within reasonable bounds (Low) | (same panel — set time zone correctly) | `date` (compare against a known good source like `https://time.is/`) | — (enable 2.3.2.1) |

### §2.3.3 — Sharing Services (10 checks)

> Most of these can be confirmed in one place: **System Settings → General → Sharing**. Toggle off anything you don't actively need.

| ☐ | CIS | Name (Severity) | GUI path | Verify | Fix |
|---|---|---|---|---|---|
| ☐ | 2.3.3.1 | Screen Sharing disabled (High) | System Settings → General → Sharing → Screen Sharing → off | `launchctl list com.apple.screensharing` (must error: "Could not find service") | Admin: `sudo launchctl disable system/com.apple.screensharing; sudo launchctl stop com.apple.screensharing 2>/dev/null; true` |
| ☐ | 2.3.3.2 | File Sharing disabled (High) | (same panel → File Sharing → off) | `launchctl print-disabled system \| grep com.apple.smbd` (expect `"com.apple.smbd" => disabled`) | Admin: `sudo launchctl disable system/com.apple.smbd; sudo launchctl stop com.apple.smbd 2>/dev/null; true` |
| ☐ | 2.3.3.3 | Printer Sharing disabled (Low) | (same panel → Printer Sharing → off) | `cupsctl 2>/dev/null \| grep _share_printers` (must NOT contain `_share_printers=1`) | Admin: `sudo cupsctl --no-share-printers` |
| ☐ | 2.3.3.4 | Remote Login (SSH) disabled (High) | (same panel → Remote Login → off) | `launchctl print-disabled system \| grep com.openssh.sshd` (expect `"com.openssh.sshd" => disabled`) | Admin: `sudo launchctl disable system/com.openssh.sshd; sudo launchctl stop com.openssh.sshd 2>/dev/null; true` |
| ☐ | 2.3.3.5 | Remote Management (ARD) disabled (High) | (same panel → Remote Management → off) | `launchctl list com.apple.RemoteDesktop.agent` (must error) | Admin: `sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop 2>/dev/null; true` |
| ☐ | 2.3.3.6 | Remote Apple Events disabled (Medium) | (same panel → Remote Apple Events → off) | `launchctl print-disabled system \| grep com.apple.AEServer` (expect `"com.apple.AEServer" => disabled`) | Admin: `sudo launchctl disable system/com.apple.AEServer; sudo launchctl stop com.apple.AEServer 2>/dev/null; true` |
| ☐ | 2.3.3.7 | Internet Sharing disabled (High) | (same panel → Internet Sharing → off) | `defaults read /Library/Preferences/SystemConfiguration/com.apple.nat 2>/dev/null` (must NOT contain `Enabled = 1`) | Admin: `sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.nat NAT -dict-add Enabled -int 0` |
| ☐ | 2.3.3.8 | Content Caching disabled (Low) | (same panel → Content Caching → off) | `/usr/bin/AssetCacheManagerUtil status 2>&1` (must NOT contain `activated: true`) | Admin: `sudo /usr/bin/AssetCacheManagerUtil deactivate 2>/dev/null; true` |
| ☐ | 2.3.3.9 | Media Sharing disabled (Low) | (same panel → Media Sharing → off) | `defaults read com.apple.amp.mediasharingd home-sharing-enabled` (absent or `0`) | Admin: `sudo defaults write com.apple.amp.mediasharingd home-sharing-enabled -int 0; sudo launchctl stop com.apple.amp.mediasharingd 2>/dev/null; true` |
| ☐ | 2.3.3.10 | Bluetooth Sharing disabled (Medium) | System Settings → General → Sharing → Bluetooth Sharing → off | `defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled` (absent or `0`) | User: `defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false` |

### §2.3.4 — Time Machine (1 check)

| ☐ | CIS | Name (Severity) | GUI path | Verify | Fix |
|---|---|---|---|---|---|
| ☐ | 2.3.4.1 | Time Machine backup configured (Medium) | System Settings → General → Time Machine → Add Backup Disk | `tmutil destinationinfo` (output contains `Name` or `Kind`) | — (use GUI) |

### §2.5 — Apple Intelligence & Siri (5 checks)

> Tahoe: 2.5.1.x require an MDM configuration profile to enforce. Without MDM these checks can't be auto-fixed; toggle the matching feature off in System Settings → Apple Intelligence & Siri instead.

| ☐ | CIS | Name (Severity) | GUI path | Verify | Fix |
|---|---|---|---|---|---|
| ☐ | 2.5.1.1 | External Intelligence Extensions disabled (Medium) | System Settings → Apple Intelligence & Siri → Extensions → off | `osascript -l JavaScript -e "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowExternalIntelligenceIntegrations').js"` (expect `false`) | — (MDM only) |
| ☐ | 2.5.1.2 | Writing Tools disabled (Medium) | System Settings → Apple Intelligence & Siri → Writing Tools → off | `osascript -l JavaScript -e "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowWritingTools').js"` (expect `false`) | — (MDM only) |
| ☐ | 2.5.1.3 | Mail Summarization disabled (Low) | Mail → Settings → "Summarize messages" → off | `osascript -l JavaScript -e "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowMailSummary').js"` (expect `false`) | — (MDM only) |
| ☐ | 2.5.1.4 | Notes Summarization disabled (Low) | Notes → Settings → AI features → off | `osascript -l JavaScript -e "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowNotesTranscription').js"` (expect `false`) | — (MDM only) |
| ☐ | 2.5.2.1 | Siri disabled (Low) | System Settings → Apple Intelligence & Siri → Siri → off | `defaults read com.apple.Siri SiriProfessionalEnabled` (absent or `0`) | User: `defaults write com.apple.Siri SiriProfessionalEnabled -bool false` |

### §2.6 — Privacy & Security (10 checks)

| ☐ | CIS | Name (Severity) | GUI path | Verify | Fix |
|---|---|---|---|---|---|
| ☐ | 2.6.1.1 | Location services enabled (Low) | System Settings → Privacy & Security → Location Services → toggle on | `launchctl list com.apple.locationd` (must succeed) | — (use GUI) |
| ☐ | 2.6.1.2 | Location services menu bar icon (Low) | System Settings → Privacy & Security → Location Services → scroll to bottom → enable "Show location icon in menu bar when system services request your location" | `defaults read com.apple.systemuiserver menuExtras` (output contains `Location.menu`) | — (use GUI) |
| ☐ | 2.6.3.1 | Diagnostic data sharing off (Low) | System Settings → Privacy & Security → Analytics & Improvements → "Share Mac Analytics" → off | `defaults read '/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist' AutoSubmit 2>/dev/null` (absent or NOT `1`) | Admin: `sudo defaults write '/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist' AutoSubmit -bool false` |
| ☐ | 2.6.3.2 | Improve Siri & Dictation off (Low) | System Settings → Privacy & Security → Analytics & Improvements → "Improve Siri & Dictation" → off | `defaults read com.apple.assistant.support 'Siri Data Sharing Opt-In Status' 2>/dev/null` (absent or NOT `1`) | User: `defaults write com.apple.assistant.support 'Siri Data Sharing Opt-In Status' -int 2` |
| ☐ | 2.6.3.3 | Improve assistive voice off (Low) | (same panel → "Improve Assistive Voice Features" → off) | `defaults read com.apple.Accessibility AXSAudioDonationSiriImprovementEnabled` (absent or `0`) | User: `defaults write com.apple.Accessibility AXSAudioDonationSiriImprovementEnabled -bool false` |
| ☐ | 2.6.3.4 | Share with app developers off (Low) | (same panel → "Share with App Developers" → off) | `osascript -l JavaScript -e "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowDiagnosticSubmission').js" 2>/dev/null` (expect `false`) | — (MDM only; use GUI) |
| ☐ | 2.6.4 | Personalized ads disabled (Low) | System Settings → Privacy & Security → Apple Advertising → "Personalized Ads" → off | `defaults read com.apple.AdLib allowApplePersonalizedAdvertising` (absent or `0`) | User: `defaults write com.apple.AdLib allowApplePersonalizedAdvertising -bool false` |
| ☐ | 2.6.5 | Gatekeeper enabled (High) | System Settings → Privacy & Security → Security → "Allow applications from": App Store, or App Store and identified developers | `spctl --status 2>&1` (output contains `assessments enabled`) | Admin: `sudo spctl --master-enable` |
| ☐ | 2.6.7 | Lockdown Mode (Low, advisory) | System Settings → Privacy & Security → Lockdown Mode → enable (only if you face elevated targeting) | `defaults read /Library/Preferences/com.apple.security.lockdown LockdownModeEnabled` (`1` = enabled) | — (use GUI; advisory) |
| ☐ | 2.6.8 | Admin password required for System Settings (Medium) | (no GUI in Tahoe — manual edit of `/etc/authorization` required) | `security authorizationdb read system.preferences 2>/dev/null` (output contains `<false/>` AND `<string>admin</string>`) | — (advanced; see [Apple Authorization Services docs](https://developer.apple.com/documentation/security/authorization_services)) |

### §2.7 — Hot Corners (1 check)

| ☐ | CIS | Name (Severity) | GUI path | Verify | Fix |
|---|---|---|---|---|---|
| ☐ | 2.7.1 | No hot corner set to "Disable Screen Saver" (Low) | System Settings → Desktop & Dock → Hot Corners → ensure no corner = "Disable Screen Saver" | `defaults read com.apple.dock wvous-tl-corner; defaults read com.apple.dock wvous-tr-corner; defaults read com.apple.dock wvous-bl-corner; defaults read com.apple.dock wvous-br-corner` (none may output `6`) | — (use GUI) |

### §2.8 — Continuity (1 check)

| ☐ | CIS | Name (Severity) | GUI path | Verify | Fix |
|---|---|---|---|---|---|
| ☐ | 2.8.1 | Universal Control disabled (Low) | System Settings → Displays → Advanced → "Allow your pointer and keyboard to move between any nearby Mac or iPad" → off | `defaults -currentHost read com.apple.universalcontrol Disable` (expect `1`) | User: `defaults -currentHost write com.apple.universalcontrol Disable -int 1` |

### §2.9 — Spotlight (1 check)

| ☐ | CIS | Name (Severity) | GUI path | Verify | Fix |
|---|---|---|---|---|---|
| ☐ | 2.9.1 | Spotlight query sharing off (Low) | System Settings → Spotlight → "Help Apple improve Search" → off | `osascript -l JavaScript -e "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.assistant.support').objectForKey('Search Queries Data Sharing Status').js" 2>/dev/null` (expect `2`) | User: `defaults write com.apple.assistant.support 'Search Queries Data Sharing Status' -int 2` |

### §2.10 — Energy / Power (3 checks)

| ☐ | CIS | Name (Severity) | GUI path | Verify | Fix |
|---|---|---|---|---|---|
| ☐ | 2.10.1.2 | Sleep enabled (Apple Silicon) (Medium) | System Settings → Lock Screen → "Turn display off when inactive" ≤ 20 min | `pmset -b -g 2>/dev/null \| grep -E '^ sleep\|^ displaysleep'` (non-empty) | Admin: `sudo pmset -a sleep 15 && sudo pmset -a displaysleep 10` |
| ☐ | 2.10.2 | Power Nap disabled (Intel only) (Low) | System Settings → Energy Saver → "Enable Power Nap" → off (Intel Macs only; not present on Apple Silicon) | `pmset -g custom 2>/dev/null \| grep powernap` (must NOT contain `1`) | Admin: `sudo pmset -a powernap 0 && sudo pmset -a darkwakes 0` |
| ☐ | 2.10.3 | Wake for network access disabled (Low) | System Settings → Energy Saver → "Wake for network access" → off | `pmset -g custom 2>/dev/null \| grep womp` (must NOT contain `1`) | Admin: `sudo pmset -a womp 0` |

### §2.11 — Login & Screen Saver (5 checks)

> Tahoe: screen saver keys live under `-currentHost`. The verify commands try `-currentHost` first.

| ☐ | CIS | Name (Severity) | GUI path | Verify | Fix |
|---|---|---|---|---|---|
| ☐ | 2.11.1 | Screen saver activates ≤ 20 min (Medium) | System Settings → Lock Screen → "Start Screen Saver when inactive" ≤ 20 min | `defaults -currentHost read com.apple.screensaver idleTime` (expect 1–1200) | User: `defaults -currentHost write com.apple.screensaver idleTime -int 1200` |
| ☐ | 2.11.2 | Password required on wake (High) | System Settings → Lock Screen → "Require password after screen saver begins or display is turned off" → Immediately | `defaults -currentHost read com.apple.screensaver askForPassword` (expect `1`) | User: `defaults -currentHost write com.apple.screensaver askForPassword -bool true && defaults -currentHost write com.apple.screensaver askForPasswordDelay -int 0` |
| ☐ | 2.11.3 | Login window banner message (Low) | System Settings → Lock Screen → "Show message when locked" | `defaults read /Library/Preferences/com.apple.loginwindow LoginwindowText` (non-empty string) | Admin: `sudo defaults write /Library/Preferences/com.apple.loginwindow LoginwindowText 'Authorized use only'` |
| ☐ | 2.11.4 | Login shows name + password fields (Low) | System Settings → Users & Groups → Edit (next to Automatic login as) → "Display login window as: Name and password" | `defaults read /Library/Preferences/com.apple.loginwindow SHOWFULLNAME` (expect `1`) | Admin: `sudo defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true` |
| ☐ | 2.11.5 | Password hints disabled (Medium) | System Settings → Users & Groups → Edit → uncheck "Show password hints" | `defaults read /Library/Preferences/com.apple.loginwindow RetriesUntilHint` (absent or `0`) | Admin: `sudo defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0` |

### §2.13 — Guest & Auto-Login (3 checks)

| ☐ | CIS | Name (Severity) | GUI path | Verify | Fix |
|---|---|---|---|---|---|
| ☐ | 2.13.1 | Guest login disabled (High) | System Settings → Users & Groups → Guest User → toggle off | `defaults read /Library/Preferences/com.apple.loginwindow.plist GuestEnabled` (absent or `0`) | Admin: `sudo defaults write /Library/Preferences/com.apple.loginwindow.plist GuestEnabled -bool false` |
| ☐ | 2.13.2 | Guest shared-folder access off (Medium) | System Settings → Users & Groups → Guest User ⓘ → uncheck "Allow guests to connect to shared folders" | `defaults read /Library/Preferences/com.apple.AppleFileServer guestAccess` (absent or `0`) | Admin: `sudo defaults write /Library/Preferences/com.apple.AppleFileServer guestAccess -int 0` |
| ☐ | 2.13.3 | Automatic login disabled (High) | System Settings → Users & Groups → "Automatic login as" → Off | `defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser` (must error / empty) | Admin: `sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null; true` |

---

## §3 — Logging & Auditing (2 checks)

> **Tahoe note:** `com.apple.auditd` was removed by Apple. Both checks below report WARN on Tahoe — there is nothing you can do about it from userspace. Skip and tick the boxes.

| ☐ | CIS | Name (Severity) | GUI path | Verify | Fix |
|---|---|---|---|---|---|
| ☐ | 3.1 | Security auditing enabled (Medium) | n/a (Tahoe) | `launchctl list com.apple.auditd` (succeed = pass; on Tahoe expect "Could not find" → WARN) | — (Tahoe: removed) |
| ☐ | 3.2 | Audit flags configured (Medium) | n/a (Tahoe) | `grep ^flags /etc/security/audit_control 2>/dev/null` (expect `lo, aa, ad, fd, fm`; on Tahoe file is absent → WARN) | — (Tahoe: file removed; pre-Tahoe: `sudo vi /etc/security/audit_control` and set `flags=lo,aa,ad,fd,fm,-all`) |

---

## §4 — Network (3 checks)

| ☐ | CIS | Name (Severity) | GUI path | Verify | Fix |
|---|---|---|---|---|---|
| ☐ | 4.1 | Bonjour multicast advertising disabled (Low) | (no GUI) | `defaults read /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements` (expect `1`) | Admin: `sudo defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool true` |
| ☐ | 4.2 | Apache HTTP server disabled (High) | (no GUI) | `launchctl list org.apache.httpd` (must error) | Admin: `sudo launchctl disable system/org.apache.httpd; sudo launchctl stop org.apache.httpd 2>/dev/null; true` |
| ☐ | 4.3 | NFS server disabled (High) | (no GUI) | `launchctl print-disabled system \| grep com.apple.nfsd` (expect `"com.apple.nfsd" => disabled`) | Admin: `sudo launchctl disable system/com.apple.nfsd` |

---

## §5 — Authentication & Authorization (13 checks)

### §5.1 — System Protections (3 checks, **all Recovery Mode only**)

> See the **Recovery Mode procedure** at the bottom of this guide for how to boot into recovery and run these.

| ☐ | CIS | Name (Severity) | Recovery Mode action | Verify (from regular Terminal) |
|---|---|---|---|---|
| ☐ | 5.1.1 | SIP enabled (Critical) | `csrutil enable` from Recovery Terminal, then restart | `csrutil status` (output contains `enabled`) |
| ☐ | 5.1.3 | AMFI enabled (Critical) | `nvram boot-args=""` from Recovery Terminal (clears any disable flag), then restart | `nvram -p` (must NOT contain `amfi_get_out_of_my_way=1`) |
| ☐ | 5.1.4 | Signed System Volume enabled (Critical) | `csrutil authenticated-root enable` from Recovery Terminal, then restart | `csrutil authenticated-root status` (output contains `enabled`) |

### §5.2 — Password Policy (2 checks)

| ☐ | CIS | Name (Severity) | GUI path | Verify | Fix |
|---|---|---|---|---|---|
| ☐ | 5.2.1 | Lockout after ≤ 5 failed attempts (High) | (no GUI; CLI only) | `pwpolicy -getaccountpolicies 2>/dev/null` (look for `policyAttributeMaximumFailedAuthentications` ≤ 5) | Admin: `sudo pwpolicy -n /Local/Default -setglobalpolicy maxFailedLoginAttempts=5` |
| ☐ | 5.2.2 | Minimum password length ≥ 15 chars (High) | (no GUI; CLI only) | `pwpolicy -getaccountpolicies 2>/dev/null` (look for `minChars=15` or higher) | Admin: `sudo pwpolicy -n /Local/Default -setglobalpolicy minChars=15` |

### §5.4 – §5.11 — Sudo, Root, Filesystem, XProtect (6 checks)

| ☐ | CIS | Name (Severity) | GUI path | Verify | Fix |
|---|---|---|---|---|---|
| ☐ | 5.4 | Sudo timeout = 0 (Medium) | (no GUI) | `sudo -V 2>&1 \| grep 'Authentication timestamp timeout'` (expect `0.0 minutes`) | Admin: `echo 'Defaults timestamp_timeout=0' \| sudo tee /etc/sudoers.d/cis_timeout && sudo chmod 440 /etc/sudoers.d/cis_timeout` |
| ☐ | 5.5 | Sudo TTY tickets enabled (Medium) | (no GUI) | `sudo -V` (output contains `Type of authentication timestamp record: tty`) | Admin: `echo 'Defaults timestamp_type=tty' \| sudo tee /etc/sudoers.d/cis_tty && sudo chmod 440 /etc/sudoers.d/cis_tty` |
| ☐ | 5.6 | Root account disabled (High) | Directory Utility → Edit menu → Disable Root User | `dscl . -read /Users/root UserShell` (expect `/usr/bin/false` or `nologin`) | Admin: `sudo dscl . -create /Users/root UserShell /usr/bin/false` (or `sudo dsenableroot -d`) |
| ☐ | 5.9 | Guest home folder removed (Low) | (no GUI) | `ls /Users/ 2>/dev/null` (must NOT contain `Guest`) | Admin: `sudo rm -rf /Users/Guest` (after disabling guest login per 2.13.1) |
| ☐ | 5.10 | XProtect running (High) | (managed by Apple — keep Software Update enabled) | `xprotect status` (`enabled: true`) — fallback: `launchctl list com.apple.XProtect.daemon.scan` (succeeds) | — (do not disable; ensure §1 software updates are on) |
| ☐ | 5.11 | Sudo logs allowed commands (Medium) | (no GUI) | `sudo -V` (output contains `Log when a command is allowed by sudoers`) | Admin: `echo 'Defaults log_allowed' \| sudo tee /etc/sudoers.d/cis_logging && sudo chmod 440 /etc/sudoers.d/cis_logging` |

### §5 — Encryption / Cert Trust (2 checks; no CIS sub-ID in Mergen)

| ☐ | Name (Severity) | GUI path | Verify | Fix |
|---|---|---|---|---|
| ☐ | FileVault full-disk encryption enabled (Critical) | System Settings → Privacy & Security → FileVault → Turn On FileVault | `fdesetup status` (output contains `FileVault is On`) | — (use GUI; safe-store the recovery key) |
| ☐ | Certificate trust settings clean (High) | Keychain Access → System → Certificates — review any custom trust overrides | `security dump-trust-settings 2>&1` (expect `No Trust Settings were found`) | — (delete suspicious overrides in Keychain Access manually) |

---

## §6 — User Interface

### §6.1 — Finder (2 checks)

| ☐ | CIS | Name (Severity) | GUI path | Verify | Fix |
|---|---|---|---|---|---|
| ☐ | 6.1.1 | Show all filename extensions (Low) | Finder → Settings → Advanced → check "Show all filename extensions" | `defaults read NSGlobalDomain AppleShowAllExtensions` (expect `1`) | User: `defaults write NSGlobalDomain AppleShowAllExtensions -bool true` |
| ☐ | 6.1.2 | Home folder permissions ≤ 750 (Medium) | (no GUI) | `ls -la /Users/ 2>/dev/null` (no home folder, except `Shared`, has `r` in the "others" position) | User: `chmod 700 ~/` (run for each affected user) |

### §6.3 — Safari (6 checks)

> Tahoe: Safari prefs are sandboxed by `cfprefsd`. The `defaults write` commands often silently no-op. **Use the Safari Settings GUI** as the primary fix path on Tahoe; the commands are kept here for verification and pre-Tahoe systems.

| ☐ | CIS | Name (Severity) | GUI path | Verify | Fix |
|---|---|---|---|---|---|
| ☐ | 6.3.1 | Auto-open safe downloads off (Medium) | Safari → Settings → General → uncheck "Open 'safe' files after downloading" | `defaults read com.apple.Safari AutoOpenSafeDownloads` (absent or `0`) | User (may be sandboxed on Tahoe — prefer GUI): `defaults write com.apple.Safari AutoOpenSafeDownloads -bool false` |
| ☐ | 6.3.3 | Fraudulent website warning on (Medium) | Safari → Settings → Security → check "Warn when visiting a fraudulent website" | `defaults read com.apple.Safari WarnAboutFraudulentWebsites` (expect `1`; absent = WARN, default is on) | User: `defaults write com.apple.Safari WarnAboutFraudulentWebsites -bool true` |
| ☐ | 6.3.4 | Cross-site tracking prevention on (Medium) | Safari → Settings → Privacy → check "Prevent cross-site tracking" | `defaults read com.apple.Safari BlockStoragePolicy` (expect `2`) | User: `defaults write com.apple.Safari BlockStoragePolicy -int 2` |
| ☐ | 6.3.6 | Private Click Measurement on (Low) | Safari → Settings → Privacy → check "Allow privacy-preserving measurement of ad effectiveness" | `defaults read com.apple.Safari WebKitPreferences.privateClickMeasurementEnabled` (absent or NOT `0`) | User: `defaults write com.apple.Safari WebKitPreferences.privateClickMeasurementEnabled -bool true` |
| ☐ | 6.3.8 | Internet plugins blocked (Medium) | Safari → Settings → Websites → Plug-ins → set per-site to "Off" / "Ask" | `defaults read com.apple.Safari PlugInFirstVisitPolicy` (expect `2`) | User: `defaults write com.apple.Safari PlugInFirstVisitPolicy -int 2` |
| ☐ | 6.3.10 | Status bar shown (Low) | Safari → View menu → Show Status Bar | `defaults read com.apple.Safari ShowOverlayStatusBar` (expect `1`) | User: `defaults write com.apple.Safari ShowOverlayStatusBar -bool true` |

### §6.4 — Terminal (1 check)

| ☐ | CIS | Name (Severity) | GUI path | Verify | Fix |
|---|---|---|---|---|---|
| ☐ | 6.4.1 | Secure Keyboard Entry on (Medium) | Terminal → Terminal menu → "Secure Keyboard Entry" | `osascript -l JavaScript -e "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.Terminal').objectForKey('SecureKeyboardEntry').js"` (expect `true`) | User: `defaults write com.apple.Terminal SecureKeyboardEntry -bool true` |

---

## Additional Checks (5)

These appear in Mergen without a CIS sub-ID assignment.

| ☐ | Name (Severity) | GUI path | Verify | Fix |
|---|---|---|---|---|
| ☐ | Bluetooth status in menu bar (Low) | System Settings → Control Center → Bluetooth → "Show in Menu Bar" | `defaults read com.apple.controlcenter.plist 'NSStatusItem Visible Bluetooth'` (expect `1`) | — (use GUI) |
| ☐ | Fast User Switching disabled (Medium) | System Settings → Control Center → Fast User Switching → off | `defaults read /Library/Preferences/.GlobalPreferences MultipleSessionEnabled` (absent or `0`) | Admin: `sudo defaults write /Library/Preferences/.GlobalPreferences MultipleSessionEnabled -bool false` |
| ☐ | Time Machine volumes encrypted (High) | System Settings → General → Time Machine → select disk → Options → enable encryption | `defaults read /Library/Preferences/com.apple.TimeMachine.plist 2>/dev/null` (must NOT contain `NotEncrypted`) | — (use GUI; encryption can only be set when adding the disk) |
| ☐ | EFI firmware up to date (Intel only) (High) | System Settings → General → Software Update — install all updates | If `sysctl -n machdep.cpu.brand_string` contains `Intel`: `system_profiler SPHardwareDataType \| grep 'Boot ROM'` (compare against [Apple's published versions](https://eclecticlight.co/2024/01/01/efi-and-firmware-versions/)). Skip if Apple Silicon. | — (run all Software Updates) |
| ☐ | Java 6 runtime not present (High) | (no GUI) | `java -version 2>&1` (must NOT contain `1.6` or `version "1.6`; "command not found" = pass) | — (install a supported JDK like Temurin 21 from adoptium.net; remove Java 6 from `/Library/Java/JavaVirtualMachines/`) |

---

## Recovery Mode procedure (for §5.1.1, §5.1.3, §5.1.4)

You only need this if SIP, AMFI, or SSV is currently disabled — which is unusual unless you intentionally turned them off for development.

**Apple Silicon (M1/M2/M3/M4):**
1. Shut the Mac down completely (Apple menu → Shut Down).
2. Press and hold the **Power** button until you see "Loading startup options."
3. Click **Options** → **Continue**.
4. Authenticate as an admin user.
5. Menu bar → **Utilities** → **Terminal**.
6. Run the recovery command for the failing check (e.g. `csrutil enable`).
7. Restart from the Apple menu.

**Intel:**
1. Shut down.
2. Press the **Power** button, then immediately hold **Cmd+R** until the Apple logo appears.
3. Authenticate, then **Utilities** → **Terminal**.
4. Run the command, restart.

After restart, run the **Verify** command from a normal Terminal session to confirm the change.

---

## Closing checklist

- [ ] All §1–§6 boxes ticked or noted as WARN/skip
- [ ] All Critical and High items either pass or have a documented reason for failing
- [ ] Time Machine snapshot taken before any fix was applied
- [ ] FileVault is on, recovery key stored somewhere safe (password manager, printed copy in a sealed envelope, etc.)
- [ ] Software Update is set to download and install automatically (1.2–1.5)

If something breaks after a fix:
- `sudo defaults delete <plist> <key>` removes the write you made.
- `sudo launchctl enable system/<service>; sudo launchctl start <service>` re-enables a service you disabled.
- For sudoers rules added under `/etc/sudoers.d/cis_*`: `sudo rm /etc/sudoers.d/cis_*` to revert.
- Restore from the Time Machine snapshot you took at step 3 if all else fails.

---

*Generated 2026-04-27 from `securesigner/mergen` (fork of `sametsazak/mergen`). Verify against upstream when CIS Benchmark version changes.*

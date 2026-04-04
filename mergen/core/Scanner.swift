//
//  Scanner.swift
//  mergen
//
//  Created by Samet Sazak
//
//  Updated for CIS Apple macOS 26 Tahoe Benchmark v1.0.0

import Foundation

class Scanner {
    var modules: [Vulnerability] = []
    var moduleCount: Int {
        modules.count
    }

    func loadModules(category: String? = nil) {
        modules = []

        // MARK: - Section 1: Install Updates, Patches and Additional Security Software
        modules.append(AppleSoftwareUpdateCheck())        // 1.1
        modules.append(CriticalUpdateInstallCheck())      // 1.2
        modules.append(AutomaticSoftwareUpdateCheck())    // 1.3
        modules.append(AppStoreUpdatesCheck())            // 1.4
        modules.append(SecurityUpdatesCheck())            // 1.5
        modules.append(SoftwareUpdateDefermentCheck())    // 1.6

        // MARK: - Section 2.1: iCloud
        modules.append(iCloudKeychainCheck())             // 2.1.1.1
        modules.append(iCloudDriveCheck())                // 2.1.1.3

        // MARK: - Section 2.2: Firewall
        modules.append(FirewallCheck())                   // 2.2.1
        modules.append(FirewallStealthModeCheck())        // 2.2.2

        // MARK: - Section 2.3: Sharing
        modules.append(AirDropDisabledCheck())            // 2.3.1.1
        modules.append(AirPlayReceiverDisabledCheck())    // 2.3.1.2
        modules.append(SetTimeAndDateAutomaticallyEnabledCheck()) // 2.3.2.1
        modules.append(TimeWithinLimitsCheck())           // 2.3.2.2
        modules.append(ScreenSharingDisabledCheck())      // 2.3.3.1
        modules.append(FileSharingDisabledCheck())        // 2.3.3.2
        modules.append(PrinterSharingDisabledCheck())     // 2.3.3.3
        modules.append(RemoteLoginDisabledCheck())        // 2.3.3.4
        modules.append(RemoteManagementDisabledCheck())   // 2.3.3.5
        modules.append(RemoteAppleEventsDisabledCheck())  // 2.3.3.6
        modules.append(InternetSharingDisabledCheck())    // 2.3.3.7
        modules.append(ContentCachingDisabledCheck())     // 2.3.3.8
        modules.append(MediaSharingDisabledCheck())       // 2.3.3.9
        modules.append(BluetoothSharingDisabledCheck())   // 2.3.3.10
        modules.append(TimeMachineEnabledCheck())         // 2.3.4.1

        // MARK: - Section 2.5: Apple Intelligence
        modules.append(ExternalIntelligenceExtensionsCheck()) // 2.5.1.1
        modules.append(WritingToolsCheck())               // 2.5.1.2
        modules.append(MailSummarizationCheck())          // 2.5.1.3
        modules.append(NotesSummarizationCheck())         // 2.5.1.4

        // MARK: - Section 2.6: Privacy & Security
        modules.append(LocationServicesCheck())           // 2.6.1.1
        modules.append(LocationServicesMenuBarCheck())    // 2.6.1.2
        modules.append(ShareMacAnalyticsCheck())          // 2.6.3.1
        modules.append(ImproveSiriDictationCheck())       // 2.6.3.2
        modules.append(ImproveAssistiveVoiceCheck())      // 2.6.3.3
        modules.append(ShareWithAppDevelopersCheck())     // 2.6.3.4
        modules.append(LimitAdTrackingCheck())            // 2.6.4
        modules.append(GatekeeperBypassCheck())           // 2.6.5
        modules.append(FileVaultCheck())                  // 2.6.6
        modules.append(AdminPasswordForSystemPrefsCheck()) // 2.6.8
        modules.append(LockdownModeCheck())               // 2.6.7 (advisory)

        // MARK: - Section 2.7: Screen Saver
        modules.append(ScreenSaverCornersCheck())         // 2.7.1

        // MARK: - Section 2.9: Spotlight
        modules.append(SpotlightImprovementCheck())       // 2.9.1

        // MARK: - Section 2.10: Power
        modules.append(SleepEnabledAppleSiliconCheck())   // 2.10.1.2
        modules.append(PowerNapDisabledCheck())           // 2.10.2
        modules.append(WakeForNetworkAccessCheck())       // 2.10.3

        // MARK: - Section 2.11: Login
        modules.append(ScreenSaverInactivityCheck())      // 2.11.1
        modules.append(PasswordOnWakeCheck())             // 2.11.2
        modules.append(LoginScreenMessageCheck())         // 2.11.3
        modules.append(LoginWindowNamePasswordCheck())    // 2.11.4
        modules.append(PasswordHintsCheck())              // 2.11.5

        // MARK: - Section 2.13: Guest Access
        modules.append(GuestLoginCheck())                 // 2.13.1
        modules.append(GuestConnectCheck())               // 2.13.2
        modules.append(AutomaticLoginDisabledCheck())     // 2.13.3

        // MARK: - Section 3: Logging and Auditing
        modules.append(SecurityAuditingCheck())           // 3.1
        modules.append(AuditFlagsCheck())                 // 3.3

        // MARK: - Section 4: Network Configurations
        modules.append(BonjourCheck())                    // 4.1
        modules.append(HttpServerCheck())                 // 4.2
        modules.append(NfsServerCheck())                  // 4.3

        // MARK: - Section 5: System Access, Authentication and Authorization
        modules.append(SIPStatusCheck())                  // 5.1.2
        modules.append(SecureKernelExtensionLoadingCheck()) // 5.1.x
        modules.append(AMFIEnabledCheck())                // 5.1.3
        modules.append(SSVEnabledCheck())                 // 5.1.4
        modules.append(PasswordLockoutThresholdCheck())   // 5.2.1
        modules.append(PasswordMinLengthCheck())          // 5.2.2
        modules.append(SudoTimeoutCheck())                // 5.4
        modules.append(SudoTTYTicketsCheck())             // 5.5
        modules.append(RootAccountDisabledCheck())        // 5.6
        modules.append(GuestHomeFolderCheck())            // 5.9
        modules.append(XProtectStatusCheck())             // 5.10
        modules.append(SudoLoggingCheck())                // 5.11

        // MARK: - Section 6: User Interface
        modules.append(FilenameExtensionsCheck())         // 6.1.1
        modules.append(HomeFolderPermissionsCheck())      // 6.1.2
        modules.append(SafariSafeFilesCheck())            // 6.3.1
        modules.append(SafariFraudWarningCheck())         // 6.3.3
        modules.append(SafariCrossSiteTrackingCheck())    // 6.3.4
        modules.append(SafariAdvertisingPrivacyCheck())   // 6.3.6
        modules.append(SafariStatusBarCheck())            // 6.3.10
        modules.append(TerminalSecureKeyboardCheck())     // 6.4.1

        // MARK: - Standalone Security Checks
        modules.append(DiagnosticDataCheck())
        modules.append(SiriEnabledCheck())
        modules.append(CertificateTrustCheck())
        modules.append(SSHCheck())
        modules.append(ShowWiFiStatusCheck())
        modules.append(BluetoothMenuBarCheck())
        modules.append(FastUserSwitchingCheck())


        // Removed in Tahoe benchmark: Java6Check, EFIVersionCheck, DVDOrCDSharingDisabledCheck

        // Filter modules by category if specified
        if let category = category {
            modules = modules.filter { $0.category == category }
        }
    }

}

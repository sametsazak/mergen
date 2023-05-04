//
//  Scanner.swift
//  mergen
//
//  Created by Samet Sazak
//

import Foundation

class Scanner {
    var modules: [Vulnerability] = []
    var moduleCount: Int {
        modules.count
    }
    
    func loadModules(category: String? = nil) {
        modules = []
        modules.append(GatekeeperBypassCheck())
//        modules.append(Crashtest())
        modules.append(FileVaultCheck())
        modules.append(SIPStatusCheck())
//        modules.append(XProtectAndMRTCheck())  # Disabled.
        modules.append(FirewallCheck())
        modules.append(CertificateTrustCheck())
        modules.append(SSHCheck())
        modules.append(iCloudDriveCheck())
        modules.append(GuestLoginCheck())
        modules.append(SiriEnabledCheck())
        modules.append(SecureKernelExtensionLoadingCheck())
        modules.append(DiagnosticDataCheck())
        modules.append(Java6Check())
        modules.append(EFIVersionCheck())
        modules.append(BonjourCheck())
        modules.append(HttpServerCheck())
        modules.append(NfsServerCheck())
        modules.append(PasswordHintsCheck())
        modules.append(GuestConnectCheck())
        modules.append(SafariSafeFilesCheck())
        modules.append(SafariInternetPluginsCheck())
        modules.append(FastUserSwitchingCheck())
        modules.append(FilenameExtensionsCheck())
        modules.append(AppleSoftwareUpdateCheck())
        modules.append(AutomaticSoftwareUpdateCheck())
        modules.append(AppStoreUpdatesCheck())
        modules.append(SecurityUpdatesCheck())
        modules.append(CriticalUpdateInstallCheck())
        modules.append(FirewallStealthModeCheck())
        modules.append(AirDropDisabledCheck())
//        modules.append(AirPlayReceiverDisabledCheck()) Passive module because I couldn't find a certain way to check this.
        modules.append(SetTimeAndDateAutomaticallyEnabledCheck())
        modules.append(TimeWithinLimitsCheck())
        modules.append(DVDOrCDSharingDisabledCheck())
        modules.append(ScreenSharingDisabledCheck())
        modules.append(FileSharingDisabledCheck())
        modules.append(PrinterSharingDisabledCheck())
        modules.append(RemoteLoginDisabledCheck())
        modules.append(RemoteManagementDisabledCheck())
        modules.append(RemoteAppleEventsDisabledCheck())
        modules.append(InternetSharingDisabledCheck())
        modules.append(ContentCachingDisabledCheck())
        modules.append(MediaSharingDisabledCheck())
        modules.append(BluetoothSharingDisabledCheck())
        modules.append(TimeMachineEnabledCheck())
//        modules.append(TimeMachineVolumesEncryptedCheck())  // Bad pipe usage.  NSFileHandleOperationException.
        modules.append(ShowWiFiStatusCheck())
        modules.append(BluetoothMenuBarCheck())
        modules.append(LocationServicesCheck())
        modules.append(LocationServicesMenuBarCheck())
        modules.append(LimitAdTrackingCheck())
        modules.append(ScreenSaverCornersCheck())
        modules.append(UniversalControlCheck())
        modules.append(WakeForNetworkAccessCheck())
        modules.append(ScreenSaverInactivityCheck())
        modules.append(PasswordOnWakeCheck())
        modules.append(SecurityAuditingCheck())
        
        // filter modules by category if specified
        if let category = category {
            modules = modules.filter { $0.category == category }
        }
    }
    
    func runScan(progressHandler: @escaping (Vulnerability) -> Void) {
        for module in modules {
            do {
                module.check()
                progressHandler(module)
            }
        }
    }
}

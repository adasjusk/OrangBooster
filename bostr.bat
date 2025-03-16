@echo off
if "%2"=="firstrun" exit
cmd /c "%0" null firstrun
if "%1"=="skipuac" goto skipuacstart
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )
:getPrivileges
if '%1'=='ELEV' (shift & goto gotPrivileges)
setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\elev.vbs"
ECHO UAC.ShellExecute "!batchPath!", "ELEV", "", "runas", 1 >> "%temp%\elev.vbs"
"%temp%\elev.vbs"
exit /B
:gotPrivileges
setlocal & pushd .
cd /d %~dp0
cmd /c "%0" skipuac firstrun
cd /d %~dp0
:skipuacstart
if "%2"=="firstrun" exit
chcp 65001 >null
cls
echo ╔═════════════════════════╗
echo ║ Entered Admin Mode ...  ║
echo ╚═════════════════════════╝
timeout /t 2 >null
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: INFORMATION FOR DEV's:                                                           ::
:: This Makes Directory Where Will Gonna Be All Files                               ::
:: Main Downloads Location: %appdata%\InterJava-Programs\                            ::
:: color 4 = Red                                                                    ::
:: color 3 = Blue                                                                   ::
:: color 2 = Green                                                                  ::
:: color 6 = Yellow                                                                 ::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::Coded By TheAdas! thanks to: ZorsMatuxas, Gurgliu, Adziis for testing and helping!::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
cls
echo ╔═══════════════════════════════════════════════╗
echo ║   You Must Know That You Entered Admin Mode!  ║
echo ║   With Admin You Can Change System Registry!! ║
echo ║   This Is Just Warning Btw It's Not A Virus   ║
echo ║  It Gets Flaged Because Of Registry Changing  ║
echo ║       I'm Not Responsible For Damage          ║
echo ║     Use P And B Versions For Testing !!!      ║
echo ║   This Program Could Flicker Durring Process  ║
echo ╚═══════════════════════════════════════════════╝
pause
cls
echo.
echo.
echo      [38;2;255;102;0m██████╗ ██████╗  █████╗ ███╗   ██╗ ██████╗ ███████╗
echo     [38;2;255;102;0m██╔═══██╗██╔══██╗██╔══██╗████╗  ██║██╔════╝ ██╔════╝
echo     [38;2;255;102;0m██║   ██║██████╔╝███████║██╔██╗ ██║██║  ███╗█████╗  
echo     [38;2;255;102;0m██║   ██║██╔══██╗██╔══██║██║╚██╗██║██║   ██║██╔══╝  
echo     [38;2;255;102;0m╚██████╔╝██║  ██║██║  ██║██║ ╚████║╚██████╔╝███████╗
echo       [38;2;255;102;0m╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝
echo  Configuring And Making Sure That Everything Works Propetly.
echo  #
timeout /t 1 >nul
cls
echo.
echo.
echo      [38;2;255;102;0m██████╗ ██████╗  █████╗ ███╗   ██╗ ██████╗ ███████╗
echo     [38;2;255;102;0m██╔═══██╗██╔══██╗██╔══██╗████╗  ██║██╔════╝ ██╔════╝
echo     [38;2;255;102;0m██║   ██║██████╔╝███████║██╔██╗ ██║██║  ███╗█████╗  
echo     [38;2;255;102;0m██║   ██║██╔══██╗██╔══██║██║╚██╗██║██║   ██║██╔══╝  
echo     [38;2;255;102;0m╚██████╔╝██║  ██║██║  ██║██║ ╚████║╚██████╔╝███████╗
echo       [38;2;255;102;0m╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝
echo  Configuring And Making Sure That Everything Works Propetly.
echo  ##
timeout /t 1 >nul
cls
echo.
echo.
echo      [38;2;255;102;0m██████╗ ██████╗  █████╗ ███╗   ██╗ ██████╗ ███████╗
echo     [38;2;255;102;0m██╔═══██╗██╔══██╗██╔══██╗████╗  ██║██╔════╝ ██╔════╝
echo     [38;2;255;102;0m██║   ██║██████╔╝███████║██╔██╗ ██║██║  ███╗█████╗  
echo     [38;2;255;102;0m██║   ██║██╔══██╗██╔══██║██║╚██╗██║██║   ██║██╔══╝  
echo     [38;2;255;102;0m╚██████╔╝██║  ██║██║  ██║██║ ╚████║╚██████╔╝███████╗
echo       [38;2;255;102;0m╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝
echo  Configuring And Making Sure That Everything Works Propetly.
echo  ###
timeout /t 1 >nul
cls
echo.
echo.
echo      [38;2;255;102;0m██████╗ ██████╗  █████╗ ███╗   ██╗ ██████╗ ███████╗
echo     [38;2;255;102;0m██╔═══██╗██╔══██╗██╔══██╗████╗  ██║██╔════╝ ██╔════╝
echo     [38;2;255;102;0m██║   ██║██████╔╝███████║██╔██╗ ██║██║  ███╗█████╗  
echo     [38;2;255;102;0m██║   ██║██╔══██╗██╔══██║██║╚██╗██║██║   ██║██╔══╝  
echo     [38;2;255;102;0m╚██████╔╝██║  ██║██║  ██║██║ ╚████║╚██████╔╝███████╗
echo       [38;2;255;102;0m╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝
echo  Configuring And Making Sure That Everything Works Propetly.
echo  ####
timeout /t 1 >nul
cls
echo.
echo.
echo      [38;2;255;102;0m██████╗ ██████╗  █████╗ ███╗   ██╗ ██████╗ ███████╗
echo     [38;2;255;102;0m██╔═══██╗██╔══██╗██╔══██╗████╗  ██║██╔════╝ ██╔════╝
echo     [38;2;255;102;0m██║   ██║██████╔╝███████║██╔██╗ ██║██║  ███╗█████╗  
echo     [38;2;255;102;0m██║   ██║██╔══██╗██╔══██║██║╚██╗██║██║   ██║██╔══╝  
echo     [38;2;255;102;0m╚██████╔╝██║  ██║██║  ██║██║ ╚████║╚██████╔╝███████╗
echo       [38;2;255;102;0m╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝
echo  Configuring And Making Sure That Everything Works Propetly.
echo  #####
timeout /t 1 >nul
cls
echo.
echo.
echo      [38;2;255;102;0m██████╗ ██████╗  █████╗ ███╗   ██╗ ██████╗ ███████╗
echo     [38;2;255;102;0m██╔═══██╗██╔══██╗██╔══██╗████╗  ██║██╔════╝ ██╔════╝
echo     [38;2;255;102;0m██║   ██║██████╔╝███████║██╔██╗ ██║██║  ███╗█████╗  
echo     [38;2;255;102;0m██║   ██║██╔══██╗██╔══██║██║╚██╗██║██║   ██║██╔══╝  
echo     [38;2;255;102;0m╚██████╔╝██║  ██║██║  ██║██║ ╚████║╚██████╔╝███████╗
echo       [38;2;255;102;0m╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝
echo  Configuring And Making Sure That Everything Works Propetly.
echo  ######
timeout /t 1 >nul
cls
goto menu
:menu 
MODE 56,38
title Orange Booster
echo.
echo.
echo    [38;2;255;102;0m██████╗ ██████╗  █████╗ ███╗   ██╗ ██████╗ ███████╗
echo   [38;2;255;102;0m██╔═══██╗██╔══██╗██╔══██╗████╗  ██║██╔════╝ ██╔════╝
echo   [38;2;255;102;0m██║   ██║██████╔╝███████║██╔██╗ ██║██║  ███╗█████╗  
echo   [38;2;255;102;0m██║   ██║██╔══██╗██╔══██║██║╚██╗██║██║   ██║██╔══╝  
echo   [38;2;255;102;0m╚██████╔╝██║  ██║██║  ██║██║ ╚████║╚██████╔╝███████╗
echo    [38;2;255;102;0m╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝
echo     ╔════════════════════════════════════════════╗
echo     ║ 1.  Delete Temp Files And Disk Cleanup     ║
echo     ║ 2.  Optimize Network Settings (RESTART REQ)║
echo     ║ 3.  Optimize Powerplan Settings            ║
echo     ║ 4.  Optimize Mouse Settings                ║
echo     ║ 5.  Optimize Memory Settings               ║
echo     ║ 6.  Optimize Various Settings              ║
echo     ║ 7.  Optimize Shell                         ║
echo     ║ 8.  Debloat PC                             ║
echo     ║ 9.  Disable Background Apps                ║
echo     ║ 10. Disable Xbox GameBar GameDVR           ║
echo     ╠════════════════════════════════════════════╣
echo     ║                Other Options               ║
echo     ╠════════════════════════════════════════════╣
echo     ║ 11. Privacy Options                        ║
echo     ║ 12. Tasks Options                          ║
echo     ║ 13. Wallpaper Options                      ║
echo     ║ 14. Debug Console                          ║
echo     ╠════════════════════════════════════════════╣
echo     ║           Orange Booster Update            ║
echo     ╠════════════════════════════════════════════╣
echo     ║ 15. Update Program To Newest Version       ║
echo     ║ 16. Convert This Program Build To V        ║
echo     ║ 17. Convert This Program Build To B        ║
echo     ║ 18. Convert This Program Build To M        ║
echo     ╠════════════════════════════════════════════╝
set /p input=%BS% [38;2;255;102;m    ╚══════^>[0m 

::Booost Options
if "%input%"=="1" goto TEMPORARY
if "%input%"=="2" goto NETWORK
if "%input%"=="3" goto POWERPLAN
if "%input%"=="4" goto MOUSE
if "%input%"=="5" goto MEMORY
if "%input%"=="6" goto GENERAL_OPTI
if "%input%"=="7" goto SHELL
if "%input%"=="8" goto DEBLOAT
if "%input%"=="9" goto BACKGROUND_APPS
if "%input%"=="10" goto XBOX
::Orange Stuff
if "%input%"=="11" goto PRIVACY
if "%input%"=="12" goto TASKS
if "%input%"=="13" goto WALLPAPER
if "%input%"=="14" goto debug
::Orange Booster Update
if "%input%"=="15" goto CHECK_UPDATES
if "%input%"=="16" goto PREVIEW
if "%input%"=="17" goto BETA
if "%input%"=="18" goto MAIN


:: Main Part: Engine

:TEMPORARY
del /s /f /q C:\WINDOWS\Temp\*.*
del /s /f /q C:\WINDOWS\Prefetch\*.*
del /s /f /q %USERPROFILE%\AppData\Local\Temp\*.*
cleanmgr.exe /LOWDISK /d C:
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 01 /t REG_DWORD /d 0 /f
pause
cls
goto menu


:NETWORK
netsh interface teredo set state disabled
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 255 /f
netsh interface ipv6 set interface * admin=disable
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpNoDelay /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpAckFrequency /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpDelAckTicks /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v IRPStackSize /t REG_DWORD /d 30 /f
ipconfig /flushdns
ipconfig /registerdns
ipconfig /release
ipconfig /renew
netsh winsock reset
cls
pause
goto menu

:POWERPLAN
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
powercfg -setactive e9a42b02-d5df-448d-aa00-03f14749eb61
cls
pause
goto menu

:MOUSE
:: Modify Accessibility\MouseKeys settings
reg add "HKCU\Control Panel\Accessibility\MouseKeys" /v Flags /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Accessibility\MouseKeys" /v MaximumSpeed /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Accessibility\MouseKeys" /v TimeToMaximumSpeed /t REG_SZ /d 0 /f

:: Modify Mouse settings
reg add "HKCU\Control Panel\Mouse" /v MouseAccel /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold2 /t REG_SZ /d 0 /f

:: Modify PrecisionTouchPad settings
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\PrecisionTouchPad" /v HonorMouseAccelSetting /t REG_DWORD /d 1 /f
cls
pause
goto menu

:MEMORY
bitsadmin /transfer RAM_MAP /download /priority high https://raw.githubusercontent.com/adasjusk/Orange-Booster/main/resursures/RAMMap.exe %appdata%\InterJava-Programs\RAM.exe
START %appdata%\InterJava-Programs\RAM.exe
cls
color 4
echo !!! When Program Opens Press On Top Of The Program "Empty" And Then Press All Of Them !!!
pause
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
cls
pause
goto menu

:GENERAL_OPTION
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdateDrivers /t REG_DWORD /d 1 /f
reg add "HKCU\Control Panel\Desktop" /v WaitToKillAppTimeout /t REG_DWORD /d 2000 /f
reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d 100 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoLowDiskSpaceChecks /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Windows Shake" /v ShakeToMinimize /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
cls
pause
goto menu

:SHELL
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" /v FolderType /t REG_SZ /d NotSpecified /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v NtfsDisableLastAccessUpdate /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnableSuperfetch /t REG_DWORD /d 0 /f
ie4uinit.exe -ClearIconCache
taskkill /f /im explorer.exe
start explorer.exe
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" /v FolderType /t REG_SZ /d NotSpecified /f
cls
pause
goto menu

:DEBLOAT
sc config "AJRouter" start= disabled
sc config "ALG" start= demand
sc config "AppIDSvc" start= demand
sc config "AppMgmt" start= demand
sc config "AppReadiness" start= demand
sc config "AppVClient" start= disabled
sc config "AppXSvc" start= demand
sc config "Appinfo" start= demand
sc config "AssignedAccessManagerSvc" start= disabled
sc config "AudioEndpointBuilder" start= auto
sc config "AudioSrv" start= auto
sc config "Audiosrv" start= auto
sc config "AxInstSV" start= demand
sc config "BDESVC" start= demand
sc config "BFE" start= auto
sc config "BITS" start= demand
sc config "BTAGService" start= demand
sc config "BcastDVRUserService_*" start= demand
sc config "BrokerInfrastructure" start= auto
sc config "Browser" start= demand
sc config "BthAvctpSvc" start= auto
sc config "BthHFSrv" start= auto
sc config "CDPSvc" start= demand
sc config "CDPUserSvc_*" start= auto
sc config "COMSysApp" start= demand
sc config "CaptureService_*" start= demand
sc config "CertPropSvc" start= demand
sc config "ClipSVC" start= demand
sc config "ConsentUxUserSvc_*" start= demand
sc config "CoreMessagingRegistrar" start= auto
sc config "CredentialEnrollmentManagerUserSvc_*" start= demand
sc config "CryptSvc" start= auto
sc config "CscService" start= demand
sc config "DPS" start= auto
sc config "DcomLaunch" start= auto
sc config "DcpSvc" start= demand
sc config "DevQueryBroker" start= demand
sc config "DeviceAssociationBrokerSvc_*" start= demand
sc config "DeviceAssociationService" start= demand
sc config "DeviceInstall" start= demand
sc config "DevicePickerUserSvc_*" start= demand
sc config "DevicesFlowUserSvc_*" start= demand
sc config "Dhcp" start= auto
sc config "DiagTrack" start= disabled
sc config "DialogBlockingService" start= disabled
sc config "DispBrokerDesktopSvc" start= auto
sc config "DisplayEnhancementService" start= demand
sc config "DmEnrollmentSvc" start= demand
sc config "Dnscache" start= auto
sc config "DoSvc" start= demand
sc config "DsSvc" start= demand
sc config "DsmSvc" start= demand
sc config "DusmSvc" start= auto
sc config "EFS" start= demand
sc config "EapHost" start= demand
sc config "EntAppSvc" start= demand
sc config "EventLog" start= auto
sc config "EventSystem" start= auto
sc config "FDResPub" start= demand
sc config "Fax" start= demand
sc config "FontCache" start= auto
sc config "FrameServer" start= demand
sc config "FrameServerMonitor" start= demand
sc config "GraphicsPerfSvc" start= demand
sc config "HomeGroupListener" start= demand
sc config "HomeGroupProvider" start= demand
sc config "HvHost" start= demand
sc config "IEEtwCollectorService" start= demand
sc config "IKEEXT" start= demand
sc config "InstallService" start= demand
sc config "InventorySvc" start= demand
sc config "IpxlatCfgSvc" start= demand
sc config "KeyIso" start= auto
sc config "KtmRm" start= demand
sc config "LSM" start= auto
sc config "LanmanServer" start= auto
sc config "LanmanWorkstation" start= auto
sc config "LicenseManager" start= demand
sc config "LxpSvc" start= demand
sc config "MSDTC" start= demand
sc config "MSiSCSI" start= demand
sc config "MapsBroker" start= demand
sc config "McpManagementService" start= demand
sc config "MessagingService_*" start= demand
sc config "MicrosoftEdgeElevationService" start= demand
sc config "MixedRealityOpenXRSvc" start= demand
sc config "MpsSvc" start= auto
sc config "MsKeyboardFilter" start= demand
sc config "NPSMSvc_*" start= demand
sc config "NaturalAuthentication" start= demand
sc config "NcaSvc" start= demand
sc config "NcbService" start= demand
sc config "NcdAutoSetup" start= demand
sc config "NetSetupSvc" start= demand
sc config "NetTcpPortSharing" start= disabled
sc config "Netlogon" start= auto
sc config "Netman" start= demand
sc config "NgcCtnrSvc" start= demand
sc config "NgcSvc" start= demand
sc config "NlaSvc" start= demand
sc config "OneSyncSvc_*" start= auto
sc config "P9RdrService_*" start= demand
sc config "PNRPAutoReg" start= demand
sc config "PNRPsvc" start= demand
sc config "PcaSvc" start= demand
sc config "PeerDistSvc" start= demand
sc config "PenService_*" start= demand
sc config "PerfHost" start= demand
sc config "PhoneSvc" start= demand
sc config "PimIndexMaintenanceSvc_*" start= demand
sc config "PlugPlay" start= demand
sc config "PolicyAgent" start= demand
sc config "Power" start= auto
sc config "PrintNotify" start= demand
sc config "PrintWorkflowUserSvc_*" start= demand
sc config "ProfSvc" start= auto
sc config "PushToInstall" start= demand
sc config "QWAVE" start= demand
sc config "RasAuto" start= demand
sc config "RasMan" start= demand
sc config "RemoteAccess" start= disabled
sc config "RemoteRegistry" start= disabled
sc config "RetailDemo" start= demand
sc config "RmSvc" start= demand
sc config "RpcEptMapper" start= auto
sc config "RpcLocator" start= demand
sc config "RpcSs" start= auto
sc config "SCPolicySvc" start= demand
sc config "SCardSvr" start= demand
sc config "SDRSVC" start= demand
sc config "SEMgrSvc" start= demand
sc config "SENS" start= auto
sc config "SNMPTRAP" start= demand
sc config "SNMPTrap" start= demand
sc config "SSDPSRV" start= demand
sc config "SamSs" start= auto
sc config "ScDeviceEnum" start= demand
sc config "Schedule" start= auto
sc config "SecurityHealthService" start= demand
sc config "Sense" start= demand
sc config "SensorDataService" start= demand
sc config "SensorService" start= demand
sc config "SensrSvc" start= demand
sc config "SessionEnv" start= demand
sc config "SgrmBroker" start= auto
sc config "SharedAccess" start= demand
sc config "SharedRealitySvc" start= demand
sc config "ShellHWDetection" start= auto
sc config "SmsRouter" start= demand
sc config "Spooler" start= auto
sc config "SstpSvc" start= demand
sc config "StateRepository" start= demand
sc config "StiSvc" start= demand
sc config "StorSvc" start= demand
sc config "SysMain" start= auto
sc config "SystemEventsBroker" start= auto
sc config "TabletInputService" start= demand
sc config "TapiSrv" start= demand
sc config "TermService" start= auto
sc config "TextInputManagementService" start= demand
sc config "Themes" start= auto
sc config "TieringEngineService" start= demand
sc config "TimeBroker" start= demand
sc config "TimeBrokerSvc" start= demand
sc config "TokenBroker" start= demand
sc config "TrkWks" start= auto
sc config "TroubleshootingSvc" start= demand
sc config "TrustedInstaller" start= demand
sc config "UI0Detect" start= demand
sc config "UdkUserSvc_*" start= demand
sc config "UevAgentService" start= disabled
sc config "UmRdpService" start= demand
sc config "UnistoreSvc_*" start= demand
sc config "UserDataSvc_*" start= demand
sc config "UserManager" start= auto
sc config "UsoSvc" start= demand
sc config "VGAuthService" start= auto
sc config "VMTools" start= auto
sc config "VSS" start= demand
sc config "VacSvc" start= demand
sc config "VaultSvc" start= auto
sc config "W32Time" start= demand
sc config "WEPHOSTSVC" start= demand
sc config "WFDSConMgrSvc" start= demand
sc config "WMPNetworkSvc" start= demand
sc config "WManSvc" start= demand
sc config "WPDBusEnum" start= demand
sc config "WSService" start= demand
sc config "WSearch" start= demand
sc config "WaaSMedicSvc" start= demand
sc config "WalletService" start= demand
sc config "WarpJITSvc" start= demand
sc config "WbioSrvc" start= demand
sc config "Wcmsvc" start= auto
sc config "WcsPlugInService" start= demand
sc config "WdNisSvc" start= demand
sc config "WdiServiceHost" start= demand
sc config "WdiSystemHost" start= demand
sc config "WebClient" start= demand
sc config "Wecsvc" start= demand
sc config "WerSvc" start= demand
sc config "WiaRpc" start= demand
sc config "WinDefend" start= auto
sc config "WinHttpAutoProxySvc" start= demand
sc config "WinRM" start= demand
sc config "Winmgmt" start= auto
sc config "WlanSvc" start= auto
sc config "WpcMonSvc" start= demand
sc config "WpnService" start= demand
sc config "WpnUserService_*" start= auto
sc config "WwanSvc" start= demand
sc config "XblAuthManager" start= demand
sc config "XblGameSave" start= demand
sc config "XboxGipSvc" start= demand
sc config "XboxNetApiSvc" start= demand
sc config "autotimesvc" start= demand
sc config "bthserv" start= demand
sc config "camsvc" start= demand
sc config "cbdhsvc_*" start= demand
sc config "cloudidsvc" start= demand
sc config "dcsvc" start= demand
sc config "defragsvc" start= demand
sc config "diagnosticshub.standardcollector.service" start= demand
sc config "diagsvc" start= demand
sc config "dmwappushservice" start= demand
sc config "dot3svc" start= demand
sc config "edgeupdate" start= demand
sc config "edgeupdatem" start= demand
sc config "embeddedmode" start= demand
sc config "fdPHost" start= demand
sc config "fhsvc" start= demand
sc config "gpsvc" start= auto
sc config "hidserv" start= demand
sc config "icssvc" start= demand
sc config "iphlpsvc" start= auto
sc config "lfsvc" start= demand
sc config "lltdsvc" start= demand
sc config "lmhosts" start= demand
sc config "mpssvc" start= auto
sc config "msiserver" start= demand
sc config "netprofm" start= demand
sc config "nsi" start= auto
sc config "p2pimsvc" start= demand
sc config "p2psvc" start= demand
sc config "perceptionsimulation" start= demand
sc config "pla" start= demand
sc config "seclogon" start= demand
sc config "shpamsvc" start= disabled
sc config "smphost" start= demand
sc config "spectrum" start= demand
sc config "sppsvc" start= demand
sc config "ssh-agent" start= disabled
sc config "svsvc" start= demand
sc config "swprv" start= demand
sc config "tiledatamodelsvc" start= auto
sc config "tzautoupdate" start= disabled
sc config "uhssvc" start= disabled
sc config "upnphost" start= demand
sc config "vds" start= demand
sc config "vm3dservice" start= demand
sc config "vmicguestinterface" start= demand
sc config "vmicheartbeat" start= demand
sc config "vmickvpexchange" start= demand
sc config "vmicrdv" start= demand
sc config "vmicshutdown" start= demand
sc config "vmictimesync" start= demand
sc config "vmicvmsession" start= demand
sc config "vmicvss" start= demand
sc config "vmvss" start= demand
sc config "wbengine" start= demand
sc config "wcncsvc" start= demand
sc config "webthreatdefsvc" start= demand
sc config "webthreatdefusersvc_*" start= auto
sc config "wercplsupport" start= demand
sc config "wisvc" start= demand
sc config "wlidsvc" start= demand
sc config "wlpasvc" start= demand
sc config "wmiApSrv" start= demand
sc config "workfolderssvc" start= demand
sc config "wscsvc" start= demand
sc config "wuauserv" start= demand
sc config "wudfsvc" start= demand
:: Edge Uninstaller Downloader
bitsadmin /transfer Edge /download /priority high https://raw.githubusercontent.com/adasjusk/Orange-Booster/main/resursures/edge.bat %appdata%\InterJava-Programs\edge.bat
:: Appx Uninstaller Downloader
bitsadmin /transfer Unbloater /download /priority high https://raw.githubusercontent.com/adasjusk/Orange-Booster/main/resursures/bloat.ps1 %appdata%\InterJava-Programs\bloat.ps1

:: Appx Uninstaller
SET ThisScriptsDirectory="%appdata%\InterJava-Programs\bloat.ps1"
SET PowerShellScriptPath="%ThisScriptsDirectory%bloat.ps1"
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%PowerShellScriptPath%""' -Verb RunAs}";
echo PRESS "OK" BOTTOM RIGHT AND DONE
pause
cmd /k %appdata%\InterJava-Programs\edge.bat

 
pause
cls
goto menu

:BACKGROUND_APPS
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f
cls
pause
goto menu

:XBOX
reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\System\GameConfigStore" /v GameDVR_FSEBehaviorMode /t REG_DWORD /d 2 /f
reg add "HKCU\System\GameConfigStore" /v GameDVR_HonorUserFSEBehaviorMode /t REG_DWORD /d 1 /f
reg add "HKCU\System\GameConfigStore" /v GameDVR_DXGIHonorFSEWindowsCompatible /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /v AutoGameModeEnabled /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 1 /f
cls
pause
goto menu

:: Orange More Options
:PRIVACY
bitsadmin /transfer PRIVACY_TOOL /download /priority high https://raw.githubusercontent.com/adasjusk/Orange-Booster/main/resursures/privacy.bat %appdata%\InterJava-Programs\privacy.bat
cmd /k %appdata%\InterJava-Programs\privacy.bat
cls
pause
goto menu

:TASKS
bitsadmin /transfer TASKS_TOOL /download /priority high https://raw.githubusercontent.com/adasjusk/Orange-Booster/main/resursures/tasks.bat %appdata%\InterJava-Programs\tasks.bat
cmd /k %appdata%\InterJava-Programs\tasks.bat
cls
pause
goto menu

:WALLPAPER
bitsadmin /transfer WALLPAPER_CHANGER /download /priority high https://raw.githubusercontent.com/adasjusk/Wallpapers-Changer/main/resursures/wallpaper_chng.bat %appdata%\InterJava-Programs\wallpaper_chng.bat
cmd /k %appdata%\InterJava-Programs\wallpaper_chng.bat
cls
pause
goto menu

::Orange Booster Update
:CHECK_UPDATES
echo Downloading Latest Update
timeout /t 1
echo BTW It's Just Downloading Stable Release Everytime This Program Dont Check Versions
timeout /t 1 >nul
cls
echo..
timeout /t 1 >nul
cls
echo...
timeout /t 1 >nul
cls
echo....
timeout /t 1 >nul
cls
echo FOUND
timeout /t 1 >nul
bitsadmin /transfer Update /download /priority high https://raw.githubusercontent.com/adasjusk/Orange-Booster/main/bostr.bat %appdata%\InterJava-Programs\bostr.bat
cmd /k %appdata%\InterJava-Programs\bostr.bat
pause
goto menu

:PREVIEW
echo Downloading Unstable Update
timeout /t 2 >nul
timeout /t 1 >nul
cls
echo..
timeout /t 1 >nul
cls
echo...
timeout /t 1 >nul
cls
echo....
timeout /t 1 >nul
cls
echo.....
timeout /t 1 >nul
cls
echo......
timeout /t 1 >nul
cls
echo.......
timeout /t 1 >nul
bitsadmin /transfer Preview_Build /download /priority high https://raw.githubusercontent.com/adasjusk/Orange-Booster/preview/preview_bostr.bat %appdata%\InterJava-Programs\preview_bostr.bat
%appdata%\InterJava-Programs\preview_bostr.bat
pause
goto menu

:BETA
echo downloading latest beta update for testers!
timeout /t 2 >nul
cls
echo..
timeout /t 1 >nul
cls
echo...
timeout /t 1 >nul
cls
echo....
timeout /t 1 >nul
bitsadmin /transfer Beta_Build /download /priority high https://raw.githubusercontent.com/adasjusk/Orange-Booster/beta/beta_bostr.bat %appdata%\InterJava-Programs\beta_bostr.bat
%appdata%\InterJava-Programs\beta_bostr.bat
pause
goto menu

:MAIN
bitsadmin /transfer Main_Release /download /priority high https://raw.githubusercontent.com/adasjusk/Orange-Booster/main/bostr.bat %appdata%\InterJava-Programs\bostr.bat
%appdata%\InterJava-Programs\bostr.bat
pause
goto menu

:debug
START C:\Windows\System32\cmd.exe /k title CMD
goto menu
::End Of The Script!
::Btw Im not responsible for :NO_UPDATES Script use at your own risk ask for help at my Discord: adasjusk

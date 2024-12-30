
; TODO(s):
; - In ActivateWindows() figure out a method to determine that the /ato execution failed.

#RequireAdmin

#include <StringConstants.au3>
#include <FileConstants.au3>

RemoveApplications()
ApplyTweaks()
CleanUpStartMenu()
ActivateWindows()

Func RemoveApplications()
	ConsoleWriteLine("Removing applications...")

	Local $sUwpAppListFileName = @ScriptDir & "\UwpApps.txt"
	Local $sTempFileName = @ScriptDir & "\__RemoveUwpApps.Temp.ps1"
	
	; Create a temporary PowerShell script
	Local $hFile = FileOpen($sTempFileName, $FO_OVERWRITE)
	If $hFile == -1 Then
		ConsoleWriteLine("  Failed. Could not create PowerShell script.")
		Return
	EndIf

	FileWrite($hFile, "$ListOfApps = @(" & @CRLF)

	; Let's parse our list of apps to be removed and generate a PowerShell script
	For $sAppName In FileReadToArray($sUwpAppListFileName)
		$sAppName = StringSplit($sAppName, "#")[1]
		If $sAppName == "" Then ContinueLoop
		$sAppName = StringStripWS($sAppName, $STR_STRIPALL)
		;ConsoleWriteLine($sAppName)
		FileWrite($hFile, "    """ & $sAppName & """" & @CRLF)
	Next
	FileWrite($hFile, ")" & @CRLF)
	FileWrite($hFile, "foreach ($App in $ListOfApps) {" & @CRLF)
	FileWrite($hFile, "    Write-Output ""  Removing $App... """ & @CRLF)
	FileWrite($hFile, "    Get-AppxPackage -Name ""$App"" -AllUsers | Remove-AppPackage -AllUsers" & @CRLF)
	FileWrite($hFile, "    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -Like ""$App"" | Remove-AppxProvisionedPackage -Online -AllUsers" & @CRLF)
	FileWrite($hFile, "}" & @CRLF)
	FileWrite($hFile, "[Environment]::Exit(1)" & @CRLF)
	FileClose($hFile)

	; Run and wait until PowerShell is active, then send keystrokes
	Run("PowerShell")
	Local $hWnd = WinWaitActive("Windows PowerShell")
	ControlSend($hWnd, "", "", "Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force{ENTER}")
	ControlSend($hWnd, "", "", "& """ & $sTempFileName & """{ENTER}")

	; Keep this scrip on sleep while PowerShell executing the script
	While WinGetHandle($hWnd)
		Sleep(10)
	WEnd

	; Remove temporary PowerShell script file
	FileDelete($sTempFileName)

	ConsoleWriteLine("  Done.")
EndFunc

Func ApplyTweaks()
	ConsoleWriteLine("Applying system tweaks...")

	; OK
	ConsoleWriteLine("  Disable Windows Updates...")
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "AUOptions", "REG_DWORD", 1)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate", "REG_DWORD", 1)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "DetectionFrequencyEnabled", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "DetectionFrequency", "REG_DWORD", 22)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "AllowAutoWindowsUpdateDownloadOverMeteredNetwork", "REG_DWORD", 0)

	ConsoleWriteLine("  Disable tracking...")
	RegWrite("HKCU\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors", "DisableLocation", "REG_DWORD", 1)
	RegWrite("HKCU\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors", "DisableLocationScripting", "REG_DWORD", 1)
	RegWrite("HKCU\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors", "DisableSensors", "REG_DWORD", 1)
	RegWrite("HKCU\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors", "DisableWindowsLocationProvider", "REG_DWORD", 1)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors", "DisableLocation", "REG_DWORD", 1)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors", "DisableLocationScripting", "REG_DWORD", 1)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors", "DisableSensors", "REG_DWORD", 1)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors", "DisableWindowsLocationProvider", "REG_DWORD", 1)

	ConsoleWriteLine("  Disable telemetry...")
	RunWait("sc stop ""DiagTrack""")
	RunWait("sc config ""DiagTrack"" start=disabled")
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowCommercialDataPipeline", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowDesktopAnalyticsProcessing", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowDeviceNameInTelemetry", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", "REG_DWORD", 0)
	RegWrite("HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowUpdateComplianceProcessing", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowWUfBCloudProcessing", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection", "MicrosoftEdgeDataOptIn", "REG_DWORD", 0)
	RegWrite("HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection", "MicrosoftEdgeDataOptIn", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection", "AllowTelemetry", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection", "MaxTelemetryAllowed", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection", "DisableOneSettingsDownloads", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection", "AllowTelemetry", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\MRT", "DontReportInfectionInformation", "REG_DWORD", 1)

	ConsoleWriteLine("  Applying privacy stuffs...")
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Camera", "AllowCamera", "REG_DWORD", 0)
	RegWrite("HKCU\Control Panel\International\User Profile", "HttpAcceptLanguageOptOut", "REG_DWORD", 0)
	RegWrite("HKCU\SOFTWARE\Microsoft\Input\TIPC", "Enabled", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent", "DisableSoftLanding", "REG_DWORD", 1)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent", "DisableCloudOptimizedContent", "REG_DWORD", 1)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent", "DisableWindowsConsumerFeatures", "REG_DWORD", 1)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect", "AllowProjectionToPC", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect", "RequirePinForPairing", "REG_DWORD", 2)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Biometrics", "Enabled", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoInstrumentation", "REG_DWORD", 1)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\System", "PublishUserActivities", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\System", "UploadUserActivities", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Speech", "AllowSpeechModelUpdate", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization", "RestrictImplicitTextCollection", "REG_DWORD", 1)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization", "RestrictImplicitInkCollection", "REG_DWORD", 1)
	RegWrite("HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization", "RestrictImplicitTextCollection", "REG_DWORD", 1)
	RegWrite("HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization", "RestrictImplicitInkCollection", "REG_DWORD", 1)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization", "AllowInputPersonalization", "REG_DWORD", 0)
	RegWrite("HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy", "HasAccepted", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "AllowOnlineTips", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\System", "EnableMmx", "REG_DWORD", 0)

	ConsoleWriteLine("  Disable Cortana...")
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search", "AllowSearchToUseLocation", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search", "AllowCortanaInAAD", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search", "AllowCortanaInAADPathOOBE", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search", "EnableDynamicContentInWSB", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search", "AllowCloudSearch", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search", "AllowCortana", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search", "ConnectedSearchUseWeb", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search", "DisableWebSearch", "REG_DWORD", 1)

	; OK
	ConsoleWriteLine("  Enable Dark Mode...")
	RegWrite("HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize", "SystemUsesLightTheme", "REG_DWORD", 0)
	RegWrite("HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize", "AppsUseLightTheme", "REG_DWORD", 0)

	ConsoleWriteLine("  Applying small tweaks...")
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\System", "AllowCrossDeviceClipboard", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\System", "EnableActivityFeed", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds", "EnableFeeds", "REG_DWORD", 0)
	RegWrite("HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer", "DisableSearchBoxSuggestions", "REG_DWORD", 1)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer", "StartPinAppsWhenInstalled", "REG_DWORD", 1)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer", "HideRecentlyAddedApps", "REG_DWORD", 1)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer", "ShowOrHideMostUsedApps", "REG_DWORD", 2)
	RegWrite("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "HideSCAMeetNow", "REG_DWORD", 1)
	RegWrite("HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt", "REG_DWORD", 0)
	RegWrite("HKCU\SOFTWARE\Microsoft\Windows Defender Security Center\Account protection", "DisableEnhancedNotifications", "REG_DWORD", 1)
	RegWrite("HKCU\SOFTWARE\Microsoft\Windows Defender Security Center\Account protection", "DisableNotifications", "REG_DWORD", 1)
	RegWrite("HKLM\SOFTWARE\Microsoft\OneDrive", "PreventNetworkTrafficPreUserSignIn", "REG_DWORD", 1)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive", "DisableMeteredNetworkFileSync", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\UEV\Agent\Configuration", "SyncOverMeteredNetwork", "REG_DWORD", 0)
	RegWrite("HKCU\SOFTWARE\Policies\Microsoft\UEV\Agent\Configuration", "SyncOverMeteredNetwork", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\UEV\Agent\Configuration", "SyncOverMeteredNetworkWhenRoaming", "REG_DWORD", 0)
	RegWrite("HKCU\SOFTWARE\Policies\Microsoft\UEV\Agent\Configuration", "SyncOverMeteredNetworkWhenRoaming", "REG_DWORD", 0)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync", "DisableSyncOnPaidNetwork", "REG_DWORD", 1)
	RegWrite("HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search", "ConnectedSearchUseWebOverMeteredConnections", "REG_DWORD", 0)

	ConsoleWriteLine("  Removing registry keys...")
	RegDelete("HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU")

	; Restart Windows Explorer
	RestartProcess("explorer.exe")

	ConsoleWriteLine("  Done.")
EndFunc

Func CleanUpStartMenu()
	ConsoleWriteLine("Removing pinned tiles from the Start Manu...")

	; What the...? So we can export our layout with Export-StartLayout no problem, but using Import-StartLayout does not change anything right away easily? 

	Local $sTempFileName = @ScriptDir & "\__CustomStartLayout.Temp.xml"

	Local $hFile = FileOpen($sTempFileName, $FO_OVERWRITE)
	If $hFile == -1 Then
		ConsoleWriteLine("  Failed. Could not create an XML file.")
		Return
	EndIf
	FileWrite($hFile, "<LayoutModificationTemplate xmlns:defaultlayout=""http://schemas.microsoft.com/Start/2014/FullDefaultLayout"" xmlns:start=""http://schemas.microsoft.com/Start/2014/StartLayout"" Version=""1"" xmlns=""http://schemas.microsoft.com/Start/2014/LayoutModification"">")
	FileWrite($hFile, "  <LayoutOptions StartTileGroupCellWidth=""6"" />")
	FileWrite($hFile, "  <DefaultLayoutOverride>")
	FileWrite($hFile, "    <StartLayoutCollection>")
	FileWrite($hFile, "      <defaultlayout:StartLayout GroupCellWidth=""6"" />")
	FileWrite($hFile, "    </StartLayoutCollection>")
	FileWrite($hFile, "  </DefaultLayoutOverride>")
	FileWrite($hFile, "</LayoutModificationTemplate>")
	FileClose($hFile)

	RegDelete("HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer", "LockedStartLayout")
	RegDelete("HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer", "StartLayoutFile")

	RestartProcess("explorer.exe")

	Sleep(5000)

	RegWrite("HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer", "LockedStartLayout", "REG_DWORD", 1)
	RegWrite("HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer", "StartLayoutFile", "REG_EXPAND_SZ", $sTempFileName)

	RestartProcess("explorer.exe")

	Sleep(5000)

	FileDelete($sTempFileName)
	RegDelete("HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer", "LockedStartLayout")
	RegDelete("HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer", "StartLayoutFile")

	ConsoleWriteLine("  Done.")
EndFunc

Func ActivateWindows()
	ConsoleWriteLine("Activating Windows...")

	Local $aParams[] = [ _
		"/ipk W269N-WFGWX-YVC9B-4J6C9-T83GX", _
		"/skms kms8.msguides.com", _
		"/ato" _
	]
	For $sParam In $aParams
		ShellExecute("slmgr.vbs", $sParam)
		If @error <> 0 Then
			ConsoleWriteLine("  Failed.")
			Return
		EndIf
	Next

	ConsoleWriteLine("  Done.")
EndFunc

Func ConsoleWriteLine($Output)
	ConsoleWrite($Output & @CRLF)
EndFunc

Func RestartProcess($sProcessName)
	Local $hKernel32 = DllOpen("kernel32.dll")
	Local $hProcess = DllCall($hKernel32, "int", "OpenProcess", "int", 0x1F0FFF, "int", True, "int", ProcessExists($sProcessName))
	DllCall($hKernel32, "int", "TerminateProcess", "int", $hProcess[0], "dword", 0)
	DllClose($hKernel32)
EndFunc
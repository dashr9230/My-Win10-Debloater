
#RequireAdmin

#include <StringConstants.au3>
#include <FileConstants.au3>

RemoveApplications()
ApplyTweaks()
CleanUpStartMenu()
ApplyMicrosoftEdgeSettings()
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
	FileWrite($hFile, "    Get-AppxPackage -Name ""$App"" -AllUsers | Remove-AppxPackage -AllUsers" & @CRLF)
	FileWrite($hFile, "    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -Like ""$App"" | Remove-AppxProvisionedPackage -Online -AllUsers" & @CRLF)
	FileWrite($hFile, "}" & @CRLF)
	FileWrite($hFile, "[Environment]::Exit(1)" & @CRLF)
	FileClose($hFile)

	; Run and wait until PowerShell is active, then send keystrokes
	Local $iPID = ShellExecute("powershell.exe")
	Local $hWnd = 0
	Do
		Sleep(250) ; Wait 250 milliseconds until WinList() gets repolled

		Local $aList = WinList()
		For $i = 1 To $aList[0][0]
			If $aList[$i][0] == "" Then ContinueLoop
			If WinGetProcess($aList[$i][1]) == $iPID Then
				$hWnd = $aList[$i][1]
				ExitLoop
			EndIf
		Next
	Until $hWnd <> 0

	ControlSend($hWnd, "", "", "Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force{ENTER}")
	ControlSend($hWnd, "", "", "& """ & $sTempFileName & """{ENTER}")

	; Keep this scrip on sleep while PowerShell executing the script
	While WinGetHandle($hWnd)
		Sleep(250)
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

Func ApplyMicrosoftEdgeSettings()
	ConsoleWriteLine("Applying Microsoft Edge settings...")

	; See "edge://policy/" for more policies and make sure "Show policies with no value" is checked
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "AADWebSSOAllowed", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "AADWebSiteSSOUsingThisProfileEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "AIGenThemesEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "AccessCodeCastEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "AccessibilityImageLabelsEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "AdditionalDnsQueryTypesEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "AddressBarMicrosoftSearchInBingProviderEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "AdsTransparencyEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "AdsSettingForIntrusiveAdsSites", "REG_DWORD", 2)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "AllowGamesMenu", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "AlternateErrorPagesEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "ApplicationGuardFavoritesSyncEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "ApplicationGuardTrafficIdentificationEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "AskBeforeCloseEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "AutoImportAtFirstRun", "REG_DWORD", 4)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "AutofillAddressEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "AutofillCreditCardEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "AutofillMembershipsEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "AutomaticHttpsDefault", "REG_DWORD", 2)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "AutoplayAllowed", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "BackgroundModeEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "BingAdsSuppression", "REG_DWORD", 1)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "BrowserAddProfileEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "BrowserGuestModeEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "BrowserSignin", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "BuiltInDnsClientEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "ComposeInlineEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "ConfigureDoNotTrack", "REG_DWORD", 1)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "ConfigureOnPremisesAccountAutoSignIn", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "ConfigureOnlineTextToSpeech", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "ConfigureShare", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "CopilotPageContext", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "CopilotPageContextEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "DefaultBrowserSettingsCampaignEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "DefaultSearchProviderContextMenuAccessAllowed", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "DesktopSharingHubEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "DiagnosticData", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "Edge3PSerpTelemetryEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "EdgeAdminCenterEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "EdgeAssetDeliveryServiceEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "EdgeCollectionsEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "EdgeDefaultProfileEnabled", "REG_SZ", "Default")
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "EdgeEDropEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "EdgeEntraCopilotPageContext", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "EdgeManagementEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "EdgeShoppingAssistantEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "EdgeWalletCheckoutEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "EdgeWalletEtreeEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "EdgeWorkspacesEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "EfficiencyModeEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "ExperimentationAndConfigurationServiceControl", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "FavoritesBarEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "GoogleSearchSidePanelEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "GuidedSwitchEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "HideFirstRunExperience", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "HighEfficiencyModeEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "HubsSidebarEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "ImplicitSignInEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "ImportOnEachLaunch", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "InAppSupportEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "LinkedAccountEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "LiveCaptionsAllowed", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "LocalBrowserDataShareEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "MAMEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "MSAWebSiteSSOUsingThisProfileAllowed", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "MicrosoftEdgeInsiderPromotionEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "MicrosoftEditorProofingEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "MicrosoftEditorSynonymsEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "MouseGestureEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "NetworkPredictionOptions", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "NewTabPageAppLauncherEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "NewTabPageBingChatEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "NewTabPageContentEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "NewTabPageQuickLinksEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "NewTabPageSearchBox", "REG_SZ", "redirect")
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "NonRemovableProfileEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "PasswordDismissCompromisedAlertEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "PasswordGeneratorEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "PasswordLeakDetectionEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "PasswordManagerEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "PasswordMonitorAllowed", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "PasswordProtectionWarningTrigger", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "PaymentMethodQueryEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "PersonalizationReportingEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "PinBrowserEssentialsToolbarButton", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "PinningWizardAllowed", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "ProactiveAuthWorkflowEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "PromotionalTabsEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "QRCodeGeneratorEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "QuickSearchShowMiniMenu", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "QuickViewOfficeFilesEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "ReadAloudEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "RelatedMatchesCloudServiceEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "RelatedWebsiteSetsEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "RemoteDebuggingAllowed", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "ResolveNavigationErrorsUseWebService", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "RoamingProfileSupportEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "SafeBrowsingDeepScanningEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "SafeBrowsingProxiedRealTimeChecksAllowed", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "SafeBrowsingSurveysEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "SearchFiltersEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "SearchForImageEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "SearchInSidebarEnabled", "REG_DWORD", 2)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "SearchSuggestEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "SearchbarAllowed", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "SearchbarIsEnabledOnStartup", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "SharedLinksEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "ShoppingListEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "ShowAcrobatSubscriptionButton", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "ShowDownloadsToolbarButton", "REG_DWORD", 1)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "ShowHistoryThumbnails", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "ShowHomeButton", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "ShowMicrosoftRewards", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "ShowOfficeShortcutInFavoritesBar", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "ShowPDFDefaultRecommendationsEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "ShowRecommendationsEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "SideSearchEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "SigninInterceptionEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "SleepingTabsEnabled", "REG_DWORD", 1)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "SpeechRecognitionEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "SplitScreenEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "SpotlightExperiencesAndRecommendationsEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "StandaloneHubsSidebarEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "StartupBoostEnabled", "REG_DWORD", 1)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "SyncDisabled", "REG_DWORD", 1)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "TabServicesEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "TextPredictionEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "TrackingPrevention", "REG_DWORD", 2)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "TranslateEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "TyposquattingCheckerEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "UploadFromPhoneEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "UserFeedbackAllowed", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "VisualSearchEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "WalletDonationEnabled", "REG_DWORD", 0)
	RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "WebWidgetAllowed", "REG_DWORD", 0)

	ConsoleWriteLine("  Done.")
EndFunc

Func ActivateWindows()
	ConsoleWriteLine("Activating Windows...")

	Local $asParams[] = [ _
		"/ipk W269N-WFGWX-YVC9B-4J6C9-T83GX", _
		"/skms kms8.msguides.com", _
		"/ato" _
	]
	For $sParam In $asParams
		If ShellExecuteWait("slmgr.vbs", $sParam) <> 0 Or @error <> 0 Then
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
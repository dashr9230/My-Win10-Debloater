
#
# Must execute the following command first:
#   Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force
#


function RemoveApplications() {
    Write-Output "Removing applications..."
    #
    #  To see all the installed apps, run PowerShell in administrator mode and execute this line:
    #    Get-AppxPackage | select Name
    #
    $ListOfApps = @(
        #"Microsoft.Windows.CloudExperienceHost"
        #"Microsoft.BioEnrollment"
        #"Microsoft.Windows.OOBENetworkConnectionFlow"
        #"Microsoft.AAD.BrokerPlugin"
        #"Microsoft.Windows.OOBENetworkCaptivePortal"
        #"MicrosoftWindows.Client.CBS"
        #"MicrosoftWindows.UndockedDevKit"
        #"Microsoft.Windows.StartMenuExperienceHost"
        #"Microsoft.Windows.ShellExperienceHost"
        #"windows.immersivecontrolpanel"
        #"Microsoft.Windows.Search"
        "Microsoft.549981C3F5F10" # Cortana
        #"Microsoft.VCLibs.140.00.UWPDesktop"
        #"Microsoft.NET.Native.Framework.2.2"
        #"Microsoft.NET.Native.Runtime.2.2"
        #"Microsoft.Windows.ContentDeliveryManager"
        #"Microsoft.VCLibs.140.00"
        #"Microsoft.UI.Xaml.2.0"
        "Microsoft.Windows.Photos"
        "Microsoft.Advertising.Xaml"
        "microsoft.windowscommunicationsapps" # People, Mail, and Calendar
        #"Microsoft.NET.Native.Framework.1.7"
        #"Microsoft.NET.Native.Runtime.1.7"
        "Microsoft.WindowsCamera"
        "Microsoft.DesktopAppInstaller"
        #"Microsoft.WindowsStore"
        #"Microsoft.XboxIdentityProvider"
        #"Windows.PrintDialog"
        #"Windows.CBSPreview"
        #"NcsiUwpApp"
        #"Microsoft.XboxGameCallableUI"
        #"Microsoft.Windows.SecureAssessmentBrowser"
        #"Microsoft.Windows.XGpuEjectDialog"
        #"Microsoft.Windows.SecHealthUI"
        #"Microsoft.Windows.PinningConfirmationDialog"
        #"Microsoft.Windows.PeopleExperienceHost"
        #"Microsoft.Windows.ParentalControls"
        #"Microsoft.Windows.NarratorQuickStart"
        #"Microsoft.Windows.CapturePicker"
        #"Microsoft.Windows.CallingShellApp"
        #"Microsoft.AsyncTextService"
        #"Microsoft.CredDialogHost"
        #"Microsoft.ECApp"
        #"1527c705-839a-4832-9118-54d4Bd6a0c89" # Microsoft.Windows.FilePicker
        #"c5e2524a-ea46-4f67-841f-6a9465d9d515" # Microsoft.Windows.FileExplorer
        #"E2A4F912-2574-4A75-9BB0-0D023378592B" # Microsoft.Windows.AppResolverUX
        #"F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE" # Microsoft.Windows.AppSuggestedFoldersToLibaryDialog
        #"Microsoft.AccountsControl"
        #"Microsoft.LockApp"
        #"Microsoft.MicrosoftEdgeDevToolsClient"
        #"Microsoft.Win32WebViewHost"
        #"Microsoft.Windows.Apprep.ChxApp"
        #"Microsoft.Windows.AssignedAccessLockApp"
        "Microsoft.WindowsAlarms"
        "Microsoft.SkypeApp"
        "Microsoft.ZuneVideo"
        "Microsoft.ZuneMusic"
        "Microsoft.YourPhone"
        #"Microsoft.XboxSpeechToTextOverlay"
        #"Microsoft.XboxGamingOverlay"
        #"Microsoft.XboxGameOverlay"
        #"Microsoft.XboxApp"
        #"Microsoft.Xbox.TCUI"
        "Microsoft.WindowsSoundRecorder"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.WindowsCalculator"
        #"Microsoft.WebpImageExtension"
        #"Microsoft.WebMediaExtensions"
        "Microsoft.Wallet"
        #"Microsoft.VP9VideoExtensions"
        #"Microsoft.StorePurchaseApp"
        "Microsoft.ScreenSketch"
        "Microsoft.People"
        "Microsoft.Office.OneNote"
        "Microsoft.MSPaint" # Paint 3D, not the OG Microsoft Paint
        "Microsoft.MixedReality.Portal"
        #"Microsoft.Services.Store.Engagement"
        #"Microsoft.Services.Store.Engagement"
        "Microsoft.MicrosoftStickyNotes"
        "Microsoft.MicrosoftSolitaireCollection"
        "Microsoft.MicrosoftOfficeHub"
        #"Microsoft.MicrosoftEdge.Stable"
        "Microsoft.Microsoft3DViewer"
        #"Microsoft.HEIFImageExtension"
        "Microsoft.Getstarted"
        "Microsoft.GetHelp"
        "Microsoft.BingWeather"
    )
    foreach ($App in $ListOfApps) {
        $Result = "  Removing $App... "
        Try {
            Get-AppxPackage -Name "$App" -AllUsers | Remove-AppPackage -AllUsers
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -Like "$App" | Remove-AppxProvisionedPackage -Online -AllUsers
            $Result += "Done."
        }
        Catch {
            $Result += "Failed."   
        }
        Write-Output $Result
    }

    Write-Output "  Removing OneDrive... "
    & "$env:SystemRoot\SysWOW64\OneDriveSetup.exe" /uninstall
}

function ApplyTweaks() {
    Write-Output "Applying system tweaks..."

    # TODOs:
    # - Disable Service Host: Touch Keyboard and Handwriting Panel Service
    # - Disable Service Host: Geolocation Service
    # - Disable Service Host: Connected Devices Platform Service
    # - Disable Service Host: Data Sharing Services
    # - Disable Service Host: Diagnostic Policy Service
    # - Disable Service Host: Diagnostic Service Host
    # - Disable Service Host: Windows Biometric Service
    # - Disable Service Host: Windows Push Notification System Service

    # OK
    Write-Output "  Disable Windows Updates..."
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type Dword -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type Dword -Value 1

    Write-Output "  Disable tracking..."
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Type Dword -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type Dword -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -Type Dword -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Type Dword -Value 1
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Type Dword -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type Dword -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -Type Dword -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Type Dword -Value 1

    Write-Output "  Disable telemetry..."
    #& sc config "DiagTrack" start=disabled
    Stop-Service "DiagTrack" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowCommercialDataPipeline" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowDesktopAnalyticsProcessing" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowDeviceNameInTelemetry" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type Dword -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowUpdateComplianceProcessing" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowWUfBCloudProcessing" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "MicrosoftEdgeDataOptIn" -Type Dword -Value 0
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "MicrosoftEdgeDataOptIn" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "MaxTelemetryAllowed" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DisableOneSettingsDownloads" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    New-Item -Path "HKLM:\Software\Policies\Microsoft\MRT" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Type Dword -Value 1

    Write-Output "  Applying privacy stuffs..."
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Camera" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Camera" -Name "AllowCamera" -Type Dword -Value 0
    Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type Dword -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Type Dword -Value 0
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Type Dword -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableCloudOptimizedContent" -Type Dword -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type Dword -Value 1
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" -Name "AllowProjectionToPC" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" -Name "RequirePinForPairing" -Type Dword -Value 2
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInstrumentation" -Type Dword -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type Dword -Value 0
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Speech" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Speech" -Name "AllowSpeechModelUpdate" -Type Dword -Value 0
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Force | Out-Null
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type Dword -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type Dword -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type Dword -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type Dword -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Type Dword -Value 0
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AllowOnlineTips" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableMmx" -Type Dword -Value 0

    #
    # TODO(s):
    #   - Figure out how can I possibly unpin stuff without getting UnauthorizedAccessException on $AppVerbs.DoIt()
    #   - Figure out how can I unpin all tiles like "A great app is on its way!". Currently only lists Windows Store and Microsoft Edge...
    #
    <#Write-Output "  Unpinning applications from the start menu..."
    foreach ($App in (New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items()) {
        foreach ($AppVerbs in $App.Verbs()) {
            If ($AppVerbs.Name -eq "Un&pin from Start") {
                $AppVerbs.DoIt()
            }
        }
    }#>
}

function ActiveWindows() {
    Write-Output "Activating Windows..."
    
    $Result = "  "
    Try {
        slmgr /ipk W269N-WFGWX-YVC9B-4J6C9-T83GX
        slmgr /skms kms8.msguides.com
        slmgr /ato
        $Result += "Done."
    }
    catch {
        $Result += "Failed."
    }
    Write-Output $Result
}

RemoveApplications
ApplyTweaks
ActiveWindows

#Export-StartLayout -Path "C:\Users\z2gp46jt\Desktop\Test4.xml"
#Write-Output ([Environment]::GetFolderPath("Desktop"))
#Write-Output ([Environment]::CurrentDirectory)
#Write-Output ([Environment]::CommandLine)

#$StartLayoutFile = [Environment]::CurrentDirectory + "\__StartLayout.xml"
#$StartLayoutFileContent = @" 
#<LayoutModificationTemplate xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification" xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1">
#</LayoutModificationTemplate>
#"@
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "LockedStartLayout" -Value 1
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "StartLayoutFile" -Value $StartLayoutFile
#New-Item -Path $StartLayoutFile -ItemType File
#Set-Content -Path $StartLayoutFile -Value $StartLayoutFileContent
#Stop-Process -Name explorer -Force
#Import-StartLayout -LayoutPath "C:\Users\z2gp46jt\Desktop\Test3.xml" -MountPath $env:SystemDrive\
#Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "LockedStartLayout" -Value 0
#Remove-Item -Path $StartLayoutFile
#Start-Process explorer

#$LocalShellPath = ([Environment]::GetFolderPath("UserProfile")) + "\AppData\Local\Microsoft\Windows\Shell\"
#$StartLayoutFile = $LocalShellPath + "CustomLayout.xml"
#New-Item -Path $StartLayoutFile -ItemType File

# Don't mind this mess...

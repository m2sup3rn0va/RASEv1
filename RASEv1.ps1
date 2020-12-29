Function Initialize-RootAVD
{
    <#
    .SYNOPSIS
        Root Android Studio Emulator with Android Version 9.0 and above.

    .DESCRIPTION
        This auto-script will assist in rooting the Android Studio Emulator running on Android Version 9.0 and above.
	Production-builds i.e. 'Google Play' System Images are not supported.
        You can use any system image irrespective of the architecture and ABIS installed.
	It will not work if you are using Android Version below 9.0.

    .PARAMETER avd
        Name of the AVD to be rooted (Mandatory)

    .EXAMPLE
         
        # Make sure you have AVD pre-created and the Android Version 9.0 and above
	# Production-builds i.e. 'Google Play' System Images are not supported
        # Also, make sure that you have run the AVD once and did the pre-setup so that all the keys are created in data folder
        PS C:\> Initialize-RootAVD -avd <NAME_OF_THE_AVD_TO_ROOT>

        # To get the list of AVD's present
        PS C:\> emulator.exe -list-avds

        # NOTE : MAKE SURE THAT YOU HAVE THESE BINARIES IN 'auto_install' FOLDER
        > SuperSU : Both APK and ZIP File : https://supersuroot.org/download/
        > Root Checker : https://apkpure.com/root-checker/com.joeykrim.rootcheck
        > OpenSSL for Windows (Portable) : https://sourceforge.net/projects/openssl-for-windows/files/
        > BurpSuite Exported Certificate

        # NOTE : IF YOU WANT TO DOWNLOAD BINARIES MANUALLY ONE-BY-ONE, THEN EMPTY THE 'auto_install' folder
        # SCRIPT WILL GUIDE YOU HOW TO PROCEED
    #>

    Param
    (
        [Parameter(Mandatory=$True, HelpMessage="Name of the AVD to root")]
        [string]
            $avd
    )

    Clear-Host
    $ErrorActionPreference = "SilentlyContinue"

    Write-Host "[+]================================================================================================================================"

    Get-ChildItem -Name "config.txt" 2>&1 | Out-Null
    if ($?)
    {
        Write-Host "[+] Found Config File"
        Write-Host "[+] Reading Configuration ..."
        $PLATFORM_TOOLS = Get-Content -Path "config.txt" | findstr "PLATFORM_TOOLS" | ForEach-Object{$_.Split("'")[1];}
        $EMULATOR_PATH = Get-Content -Path "config.txt" | findstr "EMULATOR_PATH" | ForEach-Object{$_.Split("'")[1];}
        $AVD_DIR = Get-Content -Path "config.txt" | findstr "AVD_DIR" | ForEach-Object{$_.Split("'")[1];}
        Start-Sleep -s 2
    }
    else
    {
        $data = "# Copy the PATH from Android SDK where you have 'platform-tools' and paste it here"
        Write-Output $data | Out-File -FilePath "config.txt"
        $data = "# All default values are pre-filled"
        Write-Output $data | Out-File -FilePath "config.txt" -Append
        $data = "# Make sure that you end the path with '\'"
        Write-Output $data | Out-File -FilePath "config.txt" -Append

        $data = '$PLATFORM_TOOLS = '
        $data += "'$env:LOCALAPPDATA\Android\Sdk\platform-tools\'"
        Write-Output $data | Out-File -FilePath "config.txt" -Append

        $data = "# Copy the PATH from Android SDK where you have 'emulator' and paste it here"
        Write-Output $data | Out-File -FilePath "config.txt" -Append
        
        $data = '$EMULATOR_PATH = '
        $data += "'$env:LOCALAPPDATA\Android\Sdk\emulator\'"
        Write-Output $data | Out-File -FilePath "config.txt" -Append

        $data = "# Copy the PATH where you have 'avds' created and paste it here"
        Write-Output $data | Out-File -FilePath "config.txt" -Append

        $data = '$AVD_DIR = '
        $data += "'$env:USERPROFILE\.android\avd\'"
        Write-Output $data | Out-File -FilePath "config.txt" -Append

        Write-Host "[+] Running for First Time"
        Write-Host "[+] Creating 'config.txt' on" $(Get-Location)
        Write-Host "[+] Make sure values in the 'config.txt' file is correct"
        Write-Host "[+] Re-run the script once done"
        Write-Host "[+]================================================================================================================================"
        break
    }

    Write-Host "[+]================================================================================================================================"

    # Checking adb is installed or not
    $ADB = -join("$PLATFORM_TOOLS", "adb.exe")

    Invoke-Expression (-join("$ADB", ' ', 'devices; $status=$?')) 2>&1 | Out-Null
    if ($status)
    {
        Write-Host "[+] Found ADB"
        Invoke-Expression (-join("$ADB", ' ', "devices")) 2>&1 | Out-Null
        Start-sleep -s 2
    }
    else
    {
        Write-Host "[+] ADB Not Found"
        Write-Host "[+] Please update the 'config.txt' file"
        Write-Host "[+]================================================================================================================================"
        break
    }

    Write-Host "[+]================================================================================================================================"

    # Checking emulator is installed or not
    $EMULATOR = -join("$EMULATOR_PATH", "emulator.exe")

    Invoke-Expression (-join("$EMULATOR", ' ', '-list-avds; $status=$?')) 2>&1 | Out-Null
    if ($status)
    {
        Write-Host "[+] Found Emulator"
        Start-sleep -s 2
    }
    else
    {
        Write-Host "[+] EMULATOR.EXE Not Found"
        Write-Host "[+] Please update the 'config.txt' file"
        Write-Host "[+]================================================================================================================================"
        break
    }

    Write-Host "[+]================================================================================================================================"

    # Checking if AVD Data Path is set correctly or not
    $avdDataPath = -join("$AVD_DIR", "$avd", ".avd")

    if ($(Test-Path "$avdDataPath") -eq $false)
    {
        Write-Host "[+] AVD Data Path Not Found"
        Write-Host "[+] Please update the 'config.txt' file"
        Write-Host "[+]================================================================================================================================"
        break
    }
    else
    {
        Write-Host "[+] AVD Data Path Validated"   
        Start-sleep -s 2
    }

    Write-Host "[+]================================================================================================================================"

    # Checking AVD Android Version
    $avdSDKVersion = ((Get-Content "$avdDataPath\config.ini" | findstr "image.sysdir.1").split('\')[1]).split('-')[1]
    if ($avdSDKVersion -lt "28")
    {
        Write-Host "[+] Script can only root AVD's with Android Version 9.0 and below"
        Write-Host "[+] Please refer to 'Get-Help Initialize-RootAVD'"
        Write-Host "[+]================================================================================================================================"
        break
    }
    else
    {
        Write-Host "[+] Rooting '$avd' is possible"
        Write-Host "[+] Let's Begin......"    
        Start-sleep -s 2
    }

    Write-Host "[+]================================================================================================================================"
    
    # Get AVD CPU Architecture
    $avdArch = ((Get-Content "$avdDataPath\config.ini" | findstr "hw.cpu.arch").split('=')[1]).Trim()
    Write-Host "[+] Architecture of the AVD : '$avd' - '$avdArch'"
    Start-sleep -s 2
    Write-Host "[+]================================================================================================================================"

    # Checking if SuperSu APK is in auto_install folder
    Get-ChildItem .\auto_install\ | findstr "supersu.apk" 2>&1 | Out-Null
    if ($LASTEXITCODE)
    {
        Write-Host "[+] NOT FOUND :: SuperSu APK"
        Write-Host "[+] Please follow below instructions :"
        Write-Host "[+] Download the latest APK from : https://supersuroot.org/download/"
        Write-Host "[+] Place the 'apk' in 'auto_install' folder"
        Write-Host "[+] Rename it as 'supersu.apk'"
        Write-Host "[+] After that, re-run the script"
        Write-Host "[+]================================================================================================================================"
        break
    }
    else 
    {
        Write-Host "[+] FOUND :: SuperSu APK"
        Start-sleep -s 2
    }

    Write-Host "[+]================================================================================================================================"

    # Checking if SuperSU ZIP File is in auto_install folder
    Get-ChildItem .\auto_install\ | findstr "supersu.zip" 2>&1 | Out-Null
    if ($LASTEXITCODE)
    {
        Write-Host "[+] NOT FOUND :: SuperSu ZIP"
        Write-Host "[+] Please follow below instructions :"
        Write-Host "[+] Download the latest ZIP from : https://supersuroot.org/download/"
        Write-Host "[+] Place the 'ZIP' in 'auto_install' folder"
        Write-Host "[+] Rename it as 'supersu.zip'"
        Write-Host "[+] After that, re-run the script"
        Write-Host "[+]================================================================================================================================"
        break
    }
    else
    {
        Write-Host "[+] FOUND :: SuperSu ZIP"
        Start-sleep -s 2
    }

    Write-Host "[+]================================================================================================================================"

    # Checking if Root Checker APK is in auto_install folder
    Get-ChildItem .\auto_install\ | findstr "rootchecker.apk" 2>&1 | Out-Null
    if ($LASTEXITCODE)
    {
        Write-Host "[+] NOT FOUND :: Root Checker APK"
        Write-Host "[+] Please follow below instructions :"
        Write-Host "[+] Download the latest APK from : https://apkpure.com/root-checker/com.joeykrim.rootcheck"
        Write-Host "[+] Place the 'APK' in 'auto_install' folder"
        Write-Host "[+] Rename it as 'rootchecker.apk'"
        Write-Host "[+] After that, re-run the script"
        Write-Host "[+]================================================================================================================================"
        break
    }
    else
    {
        Write-Host "[+] FOUND :: Root Checker APK"
        Start-sleep -s 2
    }

    Write-Host "[+]================================================================================================================================"

    # Checking if OpenSSL ZIP File is in auto_install folder
    Get-ChildItem .\auto_install\ | findstr "openssl.zip" 2>&1 | Out-Null
    if ($LASTEXITCODE)
    {
        Write-Host "[+] NOT FOUND :: OpenSSl for Windows"
        Write-Host "[+] Please follow below instructions :"
        Write-Host "[+] Download the latest 'ZIP' from : https://sourceforge.net/projects/openssl-for-windows/files/"
        Write-Host "[+] Place the 'ZIP' in 'auto_install' folder"
        Write-Host "[+] Extract the 'ZIP' and rename the contents folder to 'openssl'"
        Write-Host "[+] Delete the downloaded 'ZIP' folder"
        Write-Host "[+] Re-ZIP the folder 'openssl' with the name - 'openssl.zip' and delete 'openssl' folder"
        Write-Host "[+] After that, re-run the script"
        Write-Host "[+]================================================================================================================================"
        break
    }
    else
    {
        Write-Host "[+] FOUND :: OpenSSL for Windows"
        Start-sleep -s 2
    }

    Write-Host "[+]================================================================================================================================"

    # Checking if BurpCert is in auto_install folder
    Get-ChildItem .\auto_install\ | findstr "burp.cer" 2>&1 | Out-Null
    if ($LASTEXITCODE)
    {
        Write-Host "[+] NOT FOUND :: Burp Cert"
        Write-Host "[+] Please follow below instructions :"
        Write-Host "[+] Generate New Certificate from BurpSuite"
        Write-Host "[+] Export the cert and place it in 'auto_install' folder"
        Write-Host "[+] Rename the cert as 'burp.cer'"
        Write-Host "[+] After that, re-run the script"
        Write-Host "[+]================================================================================================================================"
        break
    }
    else
    {
        Write-Host "[+] FOUND :: BurpCert"
        Start-sleep -s 2
    }

    Write-Host "[+]================================================================================================================================"

    # Rooting the AVD
    Write-Host "[+] NOTE : MAKE SURE THAT NONE OF THE EMULATORS ARE RUNNING"
    Read-Host "[+] HIT ENTER TO CONFIRM"  2>&1 | Out-Null

    Write-Host "[+]================================================================================================================================"
    Write-Host "[+] Starting AVD : '$avd'"
    Start-Process -FilePath $EMULATOR -ArgumentList "-avd $avd -writable-system -selinux permissive -no-snapshot-load" -WindowStyle Hidden
    Write-Host "[+] Sleeping till the AVD boots up ......"
    Start-sleep -s 50
    Write-Host "[+]================================================================================================================================"

    Write-Host "[+] Extract Emulator Name via ADB"
    $emulatorName = (Invoke-Expression "$ADB devices" | findstr /EL "device").split()[0]
    Write-Host "[+] AVD Emulator Name : $emulatorName"
    Write-Host "[+]================================================================================================================================"

    Write-Host "[+] Respawn ADB to Root"
    Invoke-Expression "$ADB -s $emulatorName root" 2>&1 | Out-Null
    Start-sleep -s 10
    Write-Host "[+]================================================================================================================================"

    Write-Host "[+] Locating 'su' binary to replace"
    $avdSULocation = Invoke-Expression "$ADB -s $emulatorName shell 'which su'"
    $avdSULocation = $avdSULocation.replace('/su','')
    Write-Host "[+] Location of 'su' binary in AVD : $avdSULocation"
    Write-Host "[+]================================================================================================================================"

    Write-Host "[+] Check '/' mount status"
    Invoke-Expression "$ADB -s $emulatorName shell `'cat /proc/mounts | grep -iw '/ '`'"  | ForEach-Object{"  [*] $_"}
    Write-Host "[+]================================================================================================================================"

    Write-Host "[+] Mount 'tmpfs' on $avdSULocation"
    Invoke-Expression "$ADB -s $emulatorName shell 'mount -t tmpfs -o size=15M tmpfs $avdSULocation'"
    Write-Host "[+]================================================================================================================================"

    Write-Host "[+] Confirm whether 'tmpfs' is mounted on '$avdSULocation'"
    Invoke-Expression "$ADB -s $emulatorName shell `'cat /proc/mounts | grep '$avdSULocation'`'"  | ForEach-Object{"  [*] $_"}
    Write-Host "[+]================================================================================================================================"
    
    Write-Host "[+] Pushing Contents of SuperSu ZIP to 'tmpfs' mounted"

    # Extracting SuperSu ZIP
    Get-ChildItem -Directory .\auto_install\ | findstr "supersu" 2>&1 | Out-Null
    if ($LASTEXITCODE)
    {
        Expand-Archive -Path .\auto_install\supersu.zip -DestinationPath .\auto_install\
        Get-ChildItem -Directory .\auto_install\ | findstr "supersu" 2>&1 | Out-Null
        if ($LASTEXITCODE)
        {
            Write-Host "[+] PowerOff the AVD >>> Unzip 'supersu.zip' manually >>> Re-run the script"
            Write-Host "[+]================================================================================================================================"
            break
        }
        else
        {
            Write-Host "[+] UNZIPPED :: SuperSu"
            Start-sleep -s 2
        }
    }
    else 
    {
        Write-Host "[+] Found UNZIPPED SuperSu"   
    }

    $supersuLocation = ".\auto_install\supersu\$avdArch"
    Invoke-Expression "$ADB -s $emulatorName push '$supersuLocation\libsupol.so' '$avdSULocation'" | ForEach-Object{"  [*] $_"}
    Start-sleep -s 1

    Invoke-Expression "$ADB -s $emulatorName push '$supersuLocation\su.pie' '$avdSULocation'" | ForEach-Object{"  [*] $_"}
    Start-sleep -s 1

    Invoke-Expression "$ADB -s $emulatorName shell 'mv -f $avdSULocation/su.pie $avdSULocation/su'" 2>&1 | Out-Null
    Start-sleep -s 1

    Invoke-Expression "$ADB -s $emulatorName push '$supersuLocation\suinit' '$avdSULocation'" | ForEach-Object{"  [*] $_"}
    Start-sleep -s 1

    Invoke-Expression "$ADB -s $emulatorName push '$supersuLocation\sukernel' '$avdSULocation'" | ForEach-Object{"  [*] $_"}
    Start-sleep -s 1

    Invoke-Expression "$ADB -s $emulatorName push '$supersuLocation\supolicy' '$avdSULocation'" | ForEach-Object{"  [*] $_"}
    
    Write-Host "[+] Check all SU binaries are uploaded"
    Invoke-Expression "$ADB -s $emulatorName shell 'ls -l $avdSULocation'" | ForEach-Object{"  [*] $_"}
    Write-Host "[+]================================================================================================================================"
    
    Write-Host "[+] Auto-Installing required APKs"
    Invoke-Expression "$ADB -s $emulatorName install .\auto_install\supersu.apk" 2>&1 | Out-Null
    if (-Not $LASTEXITCODE)
    {
        Write-Host "[+] INSTALLED :: SuperSu"
    }
    else
    {
        Write-Host "[+] Issues installing SuperSu.apk"
        Write-Host "[+] Please install manually"
    }

    Invoke-Expression "$ADB -s $emulatorName install .\auto_install\rootchecker.apk" 2>&1 | Out-Null
    if (-Not $LASTEXITCODE)
    {
        Write-Host "[+] INSTALLED :: RootChecker"
    }
    else
    {
        Write-Host "[+] Issues installing RootChecker.apk"
        Write-Host "[+] Please install manually"
    }
    Start-Sleep -s 5
    Write-Host "[+]================================================================================================================================"

    Write-Host "[+] Launch 'su' in daemon mode"
    Invoke-Expression "$ADB -s $emulatorName shell 'chmod 0755 $avdSULocation/su'"
    Start-Sleep -s 2
    Invoke-Expression "$ADB -s $emulatorName shell 'setenforce 0'"
    Start-Sleep -s 2
    Invoke-Expression "$ADB -s $emulatorName shell 'su --install'"
    Start-Sleep -s 2
    Invoke-Expression "$ADB -s $emulatorName shell 'su --daemon&'"
    Start-sleep -s 2
    Write-Host "[+]================================================================================================================================"
    
    Write-Host "[+] Check 'su' daemon status"
    Invoke-Expression "$ADB -s $emulatorName shell 'ps -ef | grep daemonsu | grep master | grep -v grep'" | ForEach-Object{"  [*] $_"}
    Write-Host "[+]================================================================================================================================"

    Write-Host "[+] Hashing Burp Cert"

    # Extracting OpenSSL
    Get-ChildItem -Directory .\auto_install\ | findstr "openssl" 2>&1 | Out-Null
    if ($LASTEXITCODE)
    {
        Expand-Archive -Path .\auto_install\openssl.zip -DestinationPath .\auto_install
        Get-ChildItem -Directory .\auto_install\ | findstr "openssl" 2>&1 | Out-Null
        if ($LASTEXITCODE)
        {
            Write-Host "[+] PowerOff the AVD >>> Unzip 'openssl.zip' manually >>> Re-run the script"
            Write-Host "[+]================================================================================================================================"
            break
        }
        else
        {
            Write-Host "[+] UNZIPPED :: OpenSSL"
            Start-sleep -s 2
        }
    }
    else 
    {
        Write-Host "[+] Found UNZIPPED OpenSSL"   
    }

    $burpHash = .\auto_install\openssl\openssl.exe x509 -inform DER -subject_hash_old -in .\auto_install\burp.cer | Select-Object -First 1
    Rename-Item -Path .\auto_install\burp.cer -NewName "$burpHash.0" -Force
    Get-ChildItem .\auto_install\ | findstr "$burpHash.0" 2>&1 | Out-Null
    
    Write-Host "[+] Installing Burp Cert"
    Invoke-Expression "$ADB -s $emulatorName shell 'cp -rf /system/etc/security/cacerts /data/local/tmp/'"
    Invoke-Expression "$ADB -s $emulatorName push .\auto_install\'$burpHash.0' '/data/local/tmp/cacerts'" 2>&1 | Out-Null
    Invoke-Expression "$ADB -s $emulatorName shell 'mount -t tmpfs -o size=15M tmpfs /system/etc/security/cacerts'"
    Start-Sleep -s 2
    Invoke-Expression "$ADB -s $emulatorName shell 'cp -rf /data/local/tmp/cacerts/* /system/etc/security/cacerts/'"
    Invoke-Expression "$ADB -s $emulatorName shell 'ls -l /system/etc/security/cacerts | grep $burpHash'" | ForEach-Object{"  [*] $_"}
    Invoke-Expression "$ADB -s $emulatorName shell 'rm -rf /data/local/tmp/cacerts'"
    Write-Host "[+]================================================================================================================================"
    
    Write-Host "[+] Creating the snapshot of the AVD"
    $snapshotName = -join("$avd", "_Rooted")
    Invoke-Expression "$ADB -s $emulatorName emu avd snapshot save $snapshotName" 2>&1 | Out-Null
    Write-Host "[+]================================================================================================================================"

    Write-Host "[+] Please close the AVD : $avd"
    Read-Host -Prompt "[+] Once closed manually, Hit Enter" 2>&1 | Out-Null
    Write-Host "[+]================================================================================================================================"

    Write-Host "[+] Removing the 'default_boot' snapshot for the AVD"
    Remove-Item -Path $avdDataPath\snapshots\default_boot -Recurse -Force

    Write-Host "[+] Initiating Clean Up Process"
    Remove-Item -Path .\auto_install\openssl -Recurse -Force
    Remove-Item -Path .\auto_install\supersu -Recurse -Force
    Rename-Item -Path .\auto_install\$burpHash.0 -NewName 'burp.cer' -Force
    Write-Host "[+] All files cleaned"
    Write-Host "[+] HAPPY HACKING !!!!!!!"

    Write-Host "[+]================================================================================================================================"
}

Function Start-RootAVD
{
    <#
    .SYNOPSIS
        Start the Rooted Android Studio Emulator 

    .DESCRIPTION
        This will start the Rooted Android Studio Emulator with snapshot

    .PARAMETER avd
        Name of the AVD to be rooted (Mandatory)

    .EXAMPLE
         
        # Start the Rooted AVD
        PS C:\> Start-RootAVD -avd <NAME_OF_THE_AVD_TO_ROOT>

        # To get the list of AVD's present
        PS C:\> emulator.exe -list-avds
    #>

    Param
    (
        [Parameter(Mandatory=$True, HelpMessage="Name of the AVD")]
        [string]
            $avd
    )

    $ErrorActionPreference = "SilentlyContinue"

	Write-Host "[+]================================================================================================================================"
    Get-ChildItem -Name "config.txt" 2>&1 | Out-Null
    if ($?)
    {
        Write-Host "[+] Found Config File"
        Write-Host "[+] Reading Configuration ..."
        $EMULATOR_PATH = Get-Content -Path "config.txt" | findstr "EMULATOR_PATH" | ForEach-Object{$_.Split("'")[1];}
        Start-Sleep -s 2
    }
    else
    {
    	Write-Host "[+] Config File Not Found"
    	Write-Host "[+] Please re-run 'Initialize-RootAVD' to generate the default config file"
    	Write-Host "[+]================================================================================================================================"
    	break
    }

	$EMULATOR = -join("$EMULATOR_PATH", "emulator.exe")
	$snapshotName = -join("$avd", "_Rooted")

    Write-Host "[+]================================================================================================================================"
    Write-Host "[+] Initiating AVD : $avd"
    Start-Process -FilePath $EMULATOR -ArgumentList "-avd $avd -writable-system -selinux permissive -snapshot $snapshotName" -WindowStyle Hidden
    Write-Host "[+]================================================================================================================================"
    Write-Host
}

Function Deploy-EmulatorProxy
{
    <#
    .SYNOPSIS
        Enable or Disable http proxy on running emulators 

    .DESCRIPTION
        This will enable or disable all the settings related to http_proxy globally

    .PARAMETER emulator_name
        Name of the AVD to be rooted (Optional)

    .PARAMETER http_proxy
        Boot AVD with HTTP Proxy for Traffic Inspection (Optional)

    .PARAMETER show
    	Shows proxy settings on the emulator

    .EXAMPLE
         
        # Start the Rooted AVD
        PS C:\> Start-RootAVD -avd <NAME_OF_THE_AVD_TO_ROOT>

        # Once the emulator is running
        PS C:\> adb.exe devices

        # Get running emulator name whose proxy settings needs to be changed
        # To remove proxy settings
        PS C:\> Deploy-EmulatorProxy -emulator_name <emulator_name_from_adb_devices_command>

        # To set proxy settings
        PS C:\> Deploy-EmulatorProxy -emulator_name <emulator_name_from_adb_devices_command> -http_proxy <IP:PORT>

        # NOTE : "-http_proxy" is optional
    #>

    Param
    (
        [Parameter(Mandatory=$False, HelpMessage="Name of the Emulator")]
        [string]
            $emulator_name,

        [Parameter(Mandatory=$False, HelpMessage="HTTP Proxy for Traffic Inspection")]
        [string]
            $http_proxy,

        [Parameter(Mandatory=$False, HelpMessage="HTTP Proxy Settings")]
        [switch]
            $show = $false
    )

    $ErrorActionPreference = "SilentlyContinue"

    Write-Host "[+]================================================================================================================================"

    Get-ChildItem -Name "config.txt" 2>&1 | Out-Null
    if ($?)
    {
        Write-Host "[+] Found Config File"
        Write-Host "[+] Reading Configuration ..."
        $PLATFORM_TOOLS = Get-Content -Path "config.txt" | findstr "PLATFORM_TOOLS" | ForEach-Object{$_.Split("'")[1];}
        Start-Sleep -s 2
    }
    else
    {
    	Write-Host "[+] Config File Not Found"
    	Write-Host "[+] Please re-run 'Initialize-RootAVD' to generate the default config file"
    	Write-Host "[+]================================================================================================================================"
    	break
    }

    $ADB = -join("$PLATFORM_TOOLS", "adb.exe")

    if ($emulator_name.Length -eq 0)
    {
        if ((Invoke-Expression "$ADB devices" | findstr /EL "device").Count -gt 1)
        {
            Write-Host "[+] More than one device connected"
            Write-Host "[+] Please use '-emulator_name' switch"
            Write-Host "[+]================================================================================================================================"
            break
        }
        
        $emulator_name = (Invoke-Expression "$ADB devices" | findstr /EL "device").split()[0]

        if ($show)
        {
        	Write-Host "[+] Proxy Settings for Emulator : $emulator_name"
        	Invoke-Expression "$ADB -s $emulator_name shell 'settings get global http_proxy'" | ForEach-Object{"[+] Current Proxy: $_"}
            Write-Host "[+]================================================================================================================================"
            break
        }

        if ($http_proxy.Length -eq 0)
        {
            Write-Host "[+] Resetting Proxy Settings for Emulator : $emulator_name"
            Invoke-Expression "$ADB -s $emulator_name shell 'settings put global http_proxy :0'"
            Write-Host "[+] Proxy Set As : NULL"
        }
        else
        {
            Write-Host "[+] Setting Proxy for Emulator : $emulator_name"
            Invoke-Expression "$ADB -s $emulator_name shell 'settings put global http_proxy $http_proxy'"
            Write-Host "[+] Proxy Set As : $http_proxy"
        }
    }
    else 
    {

        if ($show)
        {
        	Write-Host "[+] Proxy Settings for Emulator : $emulator_name"
        	Invoke-Expression "$ADB -s $emulator_name shell 'settings get global http_proxy'" | ForEach-Object{"[+] Current Proxy: $_"}
            Write-Host "[+]================================================================================================================================"
            break
        }

        if ($http_proxy.Length -eq 0)
        {
            Write-Host "[+] Resetting Proxy Settings for Emulator : $emulator_name"
            Invoke-Expression "$ADB -s $emulator_name shell 'settings put global http_proxy :0'"
            Write-Host "[+] Proxy Set As : NULL"
        }
        else
        {
            Write-Host "[+] Setting Proxy for Emulator : $emulator_name"
            Invoke-Expression "$ADB -s $emulator_name shell 'settings put global http_proxy $http_proxy'"
            Write-Host "[+] Proxy Set As : $http_proxy"
        }
    }

    Write-Host "[+]================================================================================================================================"
    Write-Host
}

Function Install-BurpCert
{
    <#
    .SYNOPSIS
        Installs new Burpsuite Certificate in Rooted AVD

    .DESCRIPTION
        This will install new BurpSuite Certificate in the Rooted AVD's Root CA Store
        Make sure you have exported the new cert in 'auto_install' folder
        Also, 'OpenSSL for windows' should be there in 'auto_install' folder

    .PARAMETER avd
        Name of the AVD to be rooted (Mandatory)

    .EXAMPLE
         
        # Installing New Burp Cert in Rooted AVD
        PS C:\> Install-BurpCert -avd <NAME_OF_THE_AVD_TO_ROOT>

        # To get the list of AVD's present
        PS C:\> emulator.exe -list-avds
    #>

    Param
    (
        [Parameter(Mandatory=$True, HelpMessage="Name of the AVD to root")]
        [string]
            $avd
    )

    Clear-Host
    $ErrorActionPreference = "SilentlyContinue"

    Write-Host "[+]================================================================================================================================"

    Get-ChildItem -Name "config.txt" 2>&1 | Out-Null
    if ($?)
    {
        Write-Host "[+] Found Config File"
        Write-Host "[+] Reading Data from Config File"
        $PLATFORM_TOOLS = Get-Content -Path "config.txt" | findstr "PLATFORM_TOOLS" | ForEach-Object{$_.Split("'")[1];}
        $EMULATOR_PATH = Get-Content -Path "config.txt" | findstr "EMULATOR_PATH" | ForEach-Object{$_.Split("'")[1];}
        $AVD_DIR = Get-Content -Path "config.txt" | findstr "AVD_DIR" | ForEach-Object{$_.Split("'")[1];}
    }
    else
    {
        $data = "# Copy the PATH from Android SDK where you have 'platform-tools' and paste it here"
        Write-Output $data | Out-File -FilePath "config.txt"
        $data = "# All default values are pre-filled"
        Write-Output $data | Out-File -FilePath "config.txt" -Append
        $data = "# Make sure that you end the path with '\'"
        Write-Output $data | Out-File -FilePath "config.txt" -Append

        $data = '$PLATFORM_TOOLS = '
        $data += "'$env:LOCALAPPDATA\Android\Sdk\platform-tools\'"
        Write-Output $data | Out-File -FilePath "config.txt" -Append

        $data = "# Copy the PATH from Android SDK where you have 'emulator' and paste it here"
        Write-Output $data | Out-File -FilePath "config.txt" -Append
        
        $data = '$EMULATOR_PATH = '
        $data += "'$env:LOCALAPPDATA\Android\Sdk\emulator\'"
        Write-Output $data | Out-File -FilePath "config.txt" -Append

        $data = "# Copy the PATH where you have 'avds' created and paste it here"
        Write-Output $data | Out-File -FilePath "config.txt" -Append

        $data = '$AVD_DIR = '
        $data += "'$env:USERPROFILE\.android\avd\'"
        Write-Output $data | Out-File -FilePath "config.txt" -Append

        Write-Host "[+] Running for First Time"
        Write-Host "[+] Creating 'config.txt' on" $(Get-Location)
        Write-Host "[+] Make sure values in the 'config.txt' file is correct"
        Write-Host "[+] Re-run the script once done"
        Write-Host "[+]================================================================================================================================"
        break
    }

    Write-Host "[+]================================================================================================================================"

    # Checking adb is installed or not
    $ADB = -join("$PLATFORM_TOOLS", "adb.exe")

    Invoke-Expression (-join("$ADB", ' ', 'devices; $status=$?')) 2>&1 | Out-Null
    if ($status)
    {
        Write-Host "[+] Found ADB"
        Invoke-Expression (-join("$ADB", ' ', "devices")) 2>&1 | Out-Null
        Start-sleep -s 2
    }
    else
    {
        Write-Host "[+] ADB Not Found"
        Write-Host "[+] Please update the 'config.txt' file"
        Write-Host "[+]================================================================================================================================"
        break
    }

    Write-Host "[+]================================================================================================================================"

    # Checking emulator is installed or not
    $EMULATOR = -join("$EMULATOR_PATH", "emulator.exe")

    Invoke-Expression (-join("$EMULATOR", ' ', '-list-avds; $status=$?')) 2>&1 | Out-Null
    if ($status)
    {
        Write-Host "[+] Found Emulator"
        Start-sleep -s 2
    }
    else
    {
        Write-Host "[+] EMULATOR.EXE Not Found"
        Write-Host "[+] Please update the 'config.txt' file"
        Write-Host "[+]================================================================================================================================"
        break
    }

    Write-Host "[+]================================================================================================================================"

    # Checking if AVD Data Path is set correctly or not
    $avdDataPath = -join("$AVD_DIR", "$avd", ".avd")

    if ($(Test-Path "$avdDataPath") -eq $false)
    {
        Write-Host "[+] AVD Data Path Not Found"
        Write-Host "[+] Please update the 'config.txt' file"
        Write-Host "[+]================================================================================================================================"
        break
    }
    else
    {
        Write-Host "[+] AVD Data Path Validated"   
        Start-sleep -s 2
    }

    Write-Host "[+]================================================================================================================================"

    # Checking if OpenSSL ZIP File is in auto_install folder
    Get-ChildItem .\auto_install\ | findstr "openssl.zip" 2>&1 | Out-Null
    if ($LASTEXITCODE)
    {
        Write-Host "[+] NOT FOUND :: OpenSSl for Windows"
        Write-Host "[+] Please follow below instructions :"
        Write-Host "[+] Download the latest 'ZIP' from : https://sourceforge.net/projects/openssl-for-windows/files/"
        Write-Host "[+] Place the 'ZIP' in 'auto_install' folder"
        Write-Host "[+] Extract the 'ZIP' and rename the contents folder to 'openssl'"
        Write-Host "[+] Delete the downloaded 'ZIP' folder"
        Write-Host "[+] Re-ZIP the folder 'openssl' with the name - 'openssl.zip' and delete 'openssl' folder"
        Write-Host "[+] After that, re-run the script"
        Write-Host "[+]================================================================================================================================"
        break
    }
    else
    {
        Write-Host "[+] FOUND :: OpenSSL for Windows"
        Start-sleep -s 2
    }

    Write-Host "[+]================================================================================================================================"

    # Checking if BurpCert is in auto_install folder
    Get-ChildItem .\auto_install\ | findstr "burp.cer" 2>&1 | Out-Null
    if ($LASTEXITCODE)
    {
        Write-Host "[+] NOT FOUND :: Burp Cert"
        Write-Host "[+] Please follow below instructions :"
        Write-Host "[+] Generate New Certificate from BurpSuite"
        Write-Host "[+] Export the cert and place it in 'auto_install' folder"
        Write-Host "[+] Rename the cert as 'burp.cer'"
        Write-Host "[+] After that, re-run the script"
        Write-Host "[+]================================================================================================================================"
        break
    }
    else
    {
        Write-Host "[+] FOUND :: BurpCert"
        Start-sleep -s 2
    }

    Write-Host "[+]================================================================================================================================"

    Write-Host "[+] MAKE SURE THAT ALL THE EMULATORS ARE CLOSED"
    Read-Host "[+] HIT ENTER TO CONTINUE" 2>&1 | Out-Null
    
    Write-Host "[+]================================================================================================================================"

    # Extracting OpenSSL
    Expand-Archive -Path .\auto_install\openssl.zip -DestinationPath .\auto_install
    if ($LASTEXITCODE)
    {
        Write-Host "[+] Unable to UNZIP OpenSSL. Please unzip it manually"
        Write-Host "[+]================================================================================================================================"
        break
    }
    else
    {
        Write-Host "[+] UNZIPPED :: OpenSSL"
        Start-sleep -s 2
    }

    Write-Host "[+]================================================================================================================================"

    Write-Host "[+] Initiating AVD : $avd"
    $snapshotName = -join("$avd", "_Rooted")
    Start-Process -FilePath $EMULATOR -ArgumentList "-avd $avd -writable-system -selinux permissive -snapshot $snapshotName" -WindowStyle Hidden
    Write-Host "[+] Sleeping till the AVD boots up ......"
    Start-sleep -s 20
    
    Write-Host "[+]================================================================================================================================"

    Write-Host "[+] Extract Emulator Name via ADB"
    $emulatorName = (Invoke-Expression "$ADB devices" | findstr /EL "device").Split()[0]
    Write-Host "[+] AVD Emulator Name : $emulatorName"

    Write-Host "[+]================================================================================================================================"

    Write-Host "[+] Respawn ADB to Root"
    Invoke-Expression "$ADB -s $emulatorName root" 2>&1 | Out-Null
    Start-sleep -s 10

    Write-Host "[+]================================================================================================================================"

    Write-Host "[+] Hashing Burp Cert"
    $burpHash = .\auto_install\openssl\openssl.exe x509 -inform DER -subject_hash_old -in .\auto_install\burp.cer | Select-Object -First 1
    Rename-Item -Path .\auto_install\burp.cer -NewName "$burpHash.0" -Force
    Get-ChildItem .\auto_install\ | findstr "$burpHash.0" 2>&1 | Out-Null
    
    Write-Host "[+] Installing New Burpsuite Certificate"
    Invoke-Expression "$ADB -s $emulatorName push '.\auto_install\$burpHash.0' '/system/etc/security/cacerts'" 2>&1 | Out-Null
    Invoke-Expression "$ADB -s $emulatorName shell 'ls -l /system/etc/security/cacerts | grep $burpHash'" | ForEach-Object{"  [*] $_"}
    Write-Host "[+]================================================================================================================================"
    
    Write-Host "[+] Creating the snapshot of the AVD"
    $snapshotName = -join("$avd", "_Rooted")
    Invoke-Expression "$ADB -s $emulatorName emu avd snapshot save $snapshotName" 2>&1 | Out-Null
    Write-Host "[+]================================================================================================================================"

    Write-Host "[+] Please close the AVD : $avd"
    Read-Host -Prompt "[+] Once closed manually, Hit Enter" 2>&1 | Out-Null
    Write-Host "[+]================================================================================================================================"

    Write-Host "[+] Initiating Clean Up Process"
    Remove-Item -Path .\auto_install\openssl -Recurse -Force
    Rename-Item -Path .\auto_install\$burpHash.0 -NewName 'burp.cer' -Force
    Write-Host "[+] All files cleaned"
    Write-Host "[+] Burpsuite Certificate Renewed !!!!"

    Write-Host "[+]================================================================================================================================"
}
Function Build-RootAVD
{
    Clear-Host

    Write-Host
    Write-Host "# ========================================================================="
    Write-Host "# Root Android Studio Emulator with 'Android Version 9.0 and above'"
    Write-Host "# Production-builds i.e. 'Google Play' System Images are not supported"
    Write-Host "# Created By : Mr. Sup3rN0va || 12-Dec-2020"
    Write-Host "# -------------------------------------------------------------------------"
    Write-Host "#"
    Write-Host "# Details :"
    Write-Host "# PS C:\> Get-Help Initialize-RootAVD"
    Write-Host "# PS C:\> Get-Help Install-BurpCert"
    Write-Host "# PS C:\> Get-Help Start-RootAVD"
    Write-Host "# PS C:\> Get-Help Deploy-EmulatorProxy"
    Write-Host "#"
    Write-Host "# Usage Examples :"
    Write-Host "# PS C:\> Get-Help Initialize-RootAVD -Examples"
    Write-Host "# PS C:\> Get-Help Install-BurpCert -Examples"
    Write-Host "# PS C:\> Get-Help Start-RootAVD -Examples"
    Write-Host "# PS C:\> Get-Help Deploy-EmulatorProxy -Examples"
    Write-Host "#"
    Write-Host "# ========================================================================="
    Write-Host
}

# Entry Point
Build-RootAVD
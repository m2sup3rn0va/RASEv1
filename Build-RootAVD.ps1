# ===============================================================
# Root Android Studio Emulator with Android Version 9.0 and above
# Production-builds i.e. 'Google Play' System Images are not supported
# Created By : Mr. Sup3rN0va || 12-Dec-2020      
# ---------------------------------------------------------------
# Usage :                                        
#                                                
# Import-Module Build-RootAVD.ps1                 
# OR                                             
# . .\Build-RootAVD.ps1                
# ===============================================================

Function Build-RootAVD
{
    Clear-Host

    Write-Host "# ========================================================================="
    Write-Host "# Root Android Studio Emulator with 'Android Version 9.0 and above'"
    Write-Host "# Production-builds i.e. 'Google Play' System Images are not supported"
    Write-Host "# Created By : Mr. Sup3rN0va || 12-Dec-2020"
    Write-Host "# -------------------------------------------------------------------------"
    Write-Host "# Usage :"
    Write-Host "#"
    Write-Host "# PS C:\> Get-Help Initialize-RootAVD"
    Write-Host "# PS C:\> Get-Help Install-BurpCert"
    Write-Host "# PS C:\> Get-Help Start-RootAVD"
    Write-Host "# ========================================================================="
}

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
    $ErrorActionPreference = "Stop"

    Write-Host "[+]================================================================================================================================"

    # Checking whether the environment variables are set properly or not
    $adbStatus = (Get-Command adb).Name
    if ($adbStatus -eq 'adb.exe')
    {
        Write-Host
        Write-Host "[+] Found ADB in ENV::PATH"
        adb.exe devices 2>&1 | Out-Null
        Start-sleep -s 2
    }
    else
    {
        Write-Host
        Write-Host "[+] Android Platform Tools not in Path."
        Write-Host "[+] Exiting Now..."
        Write-Host
        Write-Host "[+]================================================================================================================================"
        break
    }

    $emulatorStatus = (Get-Command emulator).Name
    if ($emulatorStatus -eq 'emulator.exe')
    {
        Write-Host "[+] Found Emulator in ENV::PATH"
        Start-sleep -s 2
    }
    else
    {
        Write-Host "[+] Android Emulator Commands not in Path."
        Write-Host "[+] Exiting Now..."
        Write-Host
        Write-Host "[+]================================================================================================================================"
        break
    }
    
    Write-Host
    Write-Host "[+]================================================================================================================================"

    # Checking if AVD Data Path is set correctly or not
    $avdDataPath = "$env:USERPROFILE\.android\avd\"
    if ($(Test-Path "$avdDataPath") -eq $false)
    {
        while (1)
        {
            Write-Host
            Write-Host "[+] Please provide path where AVD image is saved"
            Write-Host "[+] Generally it's at $env:USERPROFILE\.android\avd\"
            $avdDataPath = Read-Host -Prompt "[+] Path "

            if ($(Test-Path "$avdDataPath"))
            {
                Write-Host
                Write-Host "[+] AVD Data Path Validated"
                Start-sleep -s 2
                break
            }
        }
    }
    else
    {
        Write-Host
        Write-Host "[+] AVD Data Path Validated"   
        Start-sleep -s 2
    }

    Write-Host
    Write-Host "[+]================================================================================================================================"

    # Checking AVD Android Version
    $avdSDKVersion = ((Get-Content "$avdDataPath\$avd.avd\config.ini" | findstr "image.sysdir.1").split('\')[1]).split('-')[1]
    if ($avdSDKVersion -lt "28")
    {
        Write-Host
        Write-Host "[+] Script can only root AVD's with Android Version 9.0 and below"
        Write-Host "[+] Please refer to 'Get-Help Initialize-RootAVD'"
        Write-Host
        Write-Host "[+]================================================================================================================================"
        break
    }
    else
    {
        Write-Host
        Write-Host "[+] Rooting '$avd' is possible"
        Write-Host "[+] Let's Begin......"    
        Start-sleep -s 2
    }

    Write-Host
    Write-Host "[+]================================================================================================================================"
    
    # Get AVD CPU Architecture
    $avdArch = ((Get-Content "$avdDataPath\$avd.avd\config.ini" | findstr "hw.cpu.arch").split('=')[1]).Trim()
    Write-Host
    Write-Host "[+] Architecture of the AVD : '$avd' - '$avdArch'"
    Write-Host
    Start-sleep -s 2
    Write-Host "[+]================================================================================================================================"

    # Checking if SuperSu APK is in auto_install folder
    Get-ChildItem .\auto_install\ | findstr /R /I "supersu.apk" 2>&1 | Out-Null
    if ($LASTEXITCODE)
    {
        Write-Host
        Write-Host "[+] NOT FOUND :: SuperSu APK"
        Write-Host "[+] Please follow below instructions :"
        Write-Host "[+] Download the latest APK from : https://supersuroot.org/download/"
        Write-Host "[+] Place the 'apk' in 'auto_install' folder"
        Write-Host "[+] Rename it as 'supersu.apk'"
        Write-Host "[+] After that, re-run the script"
        Write-Host
        Write-Host "[+]================================================================================================================================"
        break
    }
    else 
    {
        Write-Host
        Write-Host "[+] FOUND :: SuperSu APK"
        Start-sleep -s 2
    }

    Write-Host
    Write-Host "[+]================================================================================================================================"

    # Checking if SuperSU ZIP File is in auto_install folder
    Get-ChildItem .\auto_install\ | findstr /R /I "supersu.zip" 2>&1 | Out-Null
    if ($LASTEXITCODE)
    {
        Write-Host
        Write-Host "[+] NOT FOUND :: SuperSu ZIP"
        Write-Host "[+] Please follow below instructions :"
        Write-Host "[+] Download the latest ZIP from : https://supersuroot.org/download/"
        Write-Host "[+] Place the 'ZIP' in 'auto_install' folder"
        Write-Host "[+] Rename it as 'supersu.zip'"
        Write-Host "[+] After that, re-run the script"
        Write-Host
        Write-Host "[+]================================================================================================================================"
        break
    }
    else
    {
        Write-Host
        Write-Host "[+] FOUND :: SuperSu ZIP"
        Start-sleep -s 2
    }

    Write-Host
    Write-Host "[+]================================================================================================================================"

    # Checking if Root Checker APK is in auto_install folder
    Get-ChildItem .\auto_install\ | findstr /R /I "rootchecker.apk" 2>&1 | Out-Null
    if ($LASTEXITCODE)
    {
        Write-Host
        Write-Host "[+] NOT FOUND :: Root Checker APK"
        Write-Host "[+] Please follow below instructions :"
        Write-Host "[+] Download the latest APK from : https://apkpure.com/root-checker/com.joeykrim.rootcheck"
        Write-Host "[+] Place the 'APK' in 'auto_install' folder"
        Write-Host "[+] Rename it as 'rootchecker.apk'"
        Write-Host "[+] After that, re-run the script"
        Write-Host
        Write-Host "[+]================================================================================================================================"
        break
    }
    else
    {
        Write-Host
        Write-Host "[+] FOUND :: Root Checker APK"
        Start-sleep -s 2
    }

    Write-Host
    Write-Host "[+]================================================================================================================================"

    # Checking if OpenSSL ZIP File is in auto_install folder
    Get-ChildItem .\auto_install\ | findstr /R /I "openssl.zip$" 2>&1 | Out-Null
    if ($LASTEXITCODE)
    {
        Write-Host
        Write-Host "[+] NOT FOUND :: OpenSSl for Windows"
        Write-Host "[+] Please follow below instructions :"
        Write-Host "[+] Download the latest 'ZIP' from : https://sourceforge.net/projects/openssl-for-windows/files/"
        Write-Host "[+] Place the 'ZIP' in 'auto_install' folder"
        Write-Host "[+] Extract the 'ZIP' and rename the contents folder to 'openssl'"
        Write-Host "[+] Delete the downloaded 'ZIP' folder"
        Write-Host "[+] Re-ZIP the folder 'openssl' with the name - 'openssl.zip' and delete 'openssl' folder"
        Write-Host "[+] After that, re-run the script"
        Write-Host
        Write-Host "[+]================================================================================================================================"
        break
    }
    else
    {
        Write-Host
        Write-Host "[+] FOUND :: OpenSSL for Windows"
        Start-sleep -s 2
    }

    Write-Host
    Write-Host "[+]================================================================================================================================"

    # Checking if BurpCert is in auto_install folder
    Get-ChildItem .\auto_install\ | findstr /RI ".*.cer$" 2>&1 | Out-Null
    if ($LASTEXITCODE)
    {
        Write-Host
        Write-Host "[+] NOT FOUND :: Burp Cert"
        Write-Host "[+] Please follow below instructions :"
        Write-Host "[+] Generate New Certificate from BurpSuite"
        Write-Host "[+] Export the cert and place it in 'auto_install' folder"
        Write-Host "[+] Rename the cert as 'burp.cer'"
        Write-Host "[+] After that, re-run the script"
        Write-Host
        Write-Host "[+]================================================================================================================================"
        break
    }
    else
    {
        Write-Host
        Write-Host "[+] FOUND :: BurpCert"
        Start-sleep -s 2
    }

    Write-Host
    Write-Host "[+]================================================================================================================================"

    # Rooting the AVD
    Write-Host
    Write-Host "[+] NOTE : MAKE SURE THAT NONE OF THE EMULATORS ARE RUNNING"
    Write-Host
    Read-Host -Prompt "[+] Hit Enter to Confirm"

    Write-Host "[+] Starting AVD : '$avd'"
    $avdJobID = (emulator.exe -avd $avd -writable-system -selinux permissive -no-snapshot-load &).Id
    Write-Host "[+] AVD Started with Job ID : $avdJobID"
    Start-sleep -s 50

    Write-Host
    Write-Host "[+] Extract Emulator Name via ADB"
    $emulatorName = (adb.exe devices | findstr /EL "device").split()[0]
    Write-Host "[+] AVD Emulator Name : $emulatorName"

    Write-Host
    Write-Host "[+] Respawn ADB to Root"
    adb.exe -s $emulatorName root 2>&1 | Out-Null
    Start-sleep -s 10

    Write-Host
    Write-Host "[+] Locating 'su' binary to replace"
    $avdSULocation = adb.exe -s $emulatorName shell "which su"
    $avdSULocation = $avdSULocation.replace('/su','')
    Write-Host "[+] Location of 'su' binary in AVD : $avdSULocation"

    Write-Host
    Write-Host "[+] Check '/' mount status"
    adb.exe -s $emulatorName shell "cat /proc/mounts | grep -i ' / '"
    Write-Host

    Write-Host "[+] Mount 'tmpfs' on $avdSULocation"
    adb.exe -s $emulatorName shell "mount -t tmpfs -o size=15M tmpfs $avdSULocation"
    Write-Host

    Write-Host "[+] Confirm whether 'tmpfs' is mounted on '$avdSULocation'"
    adb.exe -s $emulatorName shell "cat /proc/mounts | grep '$avdSULocation'"
    Write-Host
    
    Write-Host "[+] Push Contents of SuperSu ZIP to 'tmpfs' mounted"

    # Extracting SuperSu ZIP
    Get-ChildItem -Directory .\auto_install\ | findstr "supersu" 2>&1 | Out-Null
    if ($LASTEXITCODE)
    {
        Expand-Archive -Path .\auto_install\supersu.zip -DestinationPath .\auto_install\
        Get-ChildItem -Directory .\auto_install\ | findstr "supersu" 2>&1 | Out-Null
        if ($LASTEXITCODE)
        {
            Write-Host
            Write-Host "[+]================================================================================================================================"
            Write-Host "[+] PowerOff the AVD >>> Unzip 'supersu.zip' manually >>> Re-run the script"
            Write-Host "[+]================================================================================================================================"
            break
        }
        else
        {
            Write-Host
            Write-Host "[+] UNZIPPED :: SuperSu"
            Start-sleep -s 2
        }
    }
    else 
    {
        Write-Host
        Write-Host "[+] Found UNZIPPED SuperSu"   
    }

    Write-Host
    $supersuLocation = ".\auto_install\supersu\$avdArch"
    adb.exe -s $emulatorName push "$supersuLocation\libsupol.so" "$avdSULocation"
    Start-sleep -s 1
	adb.exe -s $emulatorName push "$supersuLocation\su.pie" "$avdSULocation"
    Start-sleep -s 1
	adb.exe -s $emulatorName shell "mv -f $avdSULocation/su.pie $avdSULocation/su"
    Start-sleep -s 1
	adb.exe -s $emulatorName push "$supersuLocation\suinit" "$avdSULocation"
    Start-sleep -s 1
	adb.exe -s $emulatorName push "$supersuLocation\sukernel" "$avdSULocation"
    Start-sleep -s 1
    adb.exe -s $emulatorName push "$supersuLocation\supolicy" "$avdSULocation"
    
    Write-Host
    Write-Host "[+] Check all SU binaries are uploaded"
    adb.exe -s $emulatorName shell "ls -l $avdSULocation"
    Write-Host
    

    Write-Host "[+] Auto-Installing required APKs"
    adb.exe -s $emulatorName install .\auto_install\supersu.apk 2>&1 | Out-Null
    if (-Not $LASTEXITCODE)
    {
        Write-Host "[+] INSTALLED :: SuperSu"
    }
    else
    {
        Write-Host "[+] Issues installing SuperSu.apk"
        Write-Host "[+] Please install manually"
    }

    adb.exe -s $emulatorName install .\auto_install\rootchecker.apk 2>&1 | Out-Null
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

    Write-Host
    Write-Host "[+] Launch 'su' in daemon mode"
    adb.exe -s $emulatorName shell "chmod 0755 $avdSULocation/su"
    Start-Sleep -s 2
    adb.exe -s $emulatorName shell "setenforce 0"
    Start-Sleep -s 2
    adb.exe -s $emulatorName shell "su --install"
    Start-Sleep -s 2
    adb.exe -s $emulatorName shell "su --daemon&"
    Start-sleep -s 2
    
    Write-Host
    Write-Host "[+] Check 'su' daemon status"
    adb.exe -s $emulatorName shell "ps -ef | grep daemonsu"

    Write-Host
    Write-Host "[+] Hashing Burp Cert"

    # Extracting OpenSSL
    Get-ChildItem -Directory .\auto_install\ | findstr "openssl" 2>&1 | Out-Null
    if ($LASTEXITCODE)
    {
        Expand-Archive -Path .\auto_install\openssl.zip -DestinationPath .\auto_install
        Get-ChildItem -Directory .\auto_install\ | findstr "openssl" 2>&1 | Out-Null
        if ($LASTEXITCODE)
        {
            Write-Host
            Write-Host "[+]================================================================================================================================"
            Write-Host "[+] PowerOff the AVD >>> Unzip 'openssl.zip' manually >>> Re-run the script"
            Write-Host "[+]================================================================================================================================"
            break
        }
        else
        {
            Write-Host
            Write-Host "[+] UNZIPPED :: OpenSSL"
            Start-sleep -s 2
        }
    }
    else 
    {
        Write-Host
        Write-Host "[+] Found UNZIPPED OpenSSL"   
    }

    $burpHash = .\auto_install\openssl\openssl.exe x509 -inform DER -subject_hash_old -in .\auto_install\burp.cer | Select-Object -First 1
    Rename-Item -Path .\auto_install\burp.cer -NewName "$burpHash.0" -Force
    Get-ChildItem .\auto_install\ | findstr "$burpHash.0"
    Write-Host
    

    Write-Host "[+] Installing Burp Cert"
    adb.exe -s $emulatorName push .\auto_install\"$burpHash.0" "/system/etc/security/cacerts" 2>&1 | Out-Null
    adb.exe -s $emulatorName shell "ls -l /system/etc/security/cacerts | grep $burpHash"
    Write-Host
    

    Write-Host "[+] Burp Cert Installed Successfully to Root Cert Store"

    Write-Host
    Write-Host "[+] Creating the snapshot of the AVD"
    adb.exe -s $emulatorName emu avd snapshot save $avd"_Rooted" 2>&1 | Out-Null

    Write-Host
    Write-Host "[+] Please close the AVD : $avd"
    Read-Host -Prompt "[+] Once closed manually, Hit Enter"

    Write-Host "[+] Removing the 'default_boot' snapshot for the AVD"
    Remove-Item -Path $avdDataPath\$avd.avd\snapshots\default_boot -Recurse -Force

    Write-Host
    Write-Host "[+] Initiating Clean Up Process"
    Remove-Item -Path .\auto_install\openssl -Recurse -Force
    Remove-Item -Path .\auto_install\supersu -Recurse -Force
    Rename-Item -Path .\auto_install\9a5ba575.0 -NewName 'burp.cer' -Force
    Write-Host "[+] All files cleaned"
    Write-Host "[+] HAPPY HACKING !!!!!!!"

    Write-Host
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

    .PARAMETER http_proxy
        Boot AVD with HTTP Proxy for Traffic Inspection (Optional)

    .EXAMPLE
         
        # Start the Rooted AVD
        PS C:\> Start-RootAVD -avd <NAME_OF_THE_AVD_TO_ROOT> -http_proxy <IP:PORT>

        # NOTE : "-http_proxy" is optional 

        # To get the list of AVD's present
        PS C:\> emulator.exe -list-avds
    #>

    Param
    (
        [Parameter(Mandatory=$True, HelpMessage="Name of the AVD to root")]
        [string]
            $avd,

        [Parameter(Mandatory=$False, HelpMessage="Boot AVD with HTTP Proxy for Traffic Inspection")]
        [string]
            $http_proxy
    )

    $ErrorActionPreference = "Stop"

    Write-Host
    Write-Host "[+]================================================================================================================================"
    Write-Host "[+] Initiating AVD : $avd"

    if ($http_proxy.Length -eq 0)
    {
        Write-Host "[+] Starting AVD without Proxy Settings"
        $avdJobID = (emulator.exe -avd $avd -writable-system -selinux permissive -snapshot $avd"_Rooted" &).Id
        Write-Host "[+] AVD Started with Job ID : $avdJobID"
    }
    else
    {
        Write-Host "[+] Starting AVD with Proxy Settings"
        $avdJobID = (emulator.exe -avd $avd -writable-system -selinux permissive -snapshot $avd"_Rooted" -http-proxy $http_proxy &).Id
        Write-Host "[+] AVD Started with Job ID : $avdJobID"
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
    $ErrorActionPreference = "Stop"

    Write-Host "[+]================================================================================================================================"

    # Checking whether the environment variables are set properly or not
    $adbStatus = (Get-Command adb).Name
    if ($adbStatus -eq 'adb.exe')
    {
        Write-Host
        Write-Host "[+] Found ADB in ENV::PATH"
        Start-sleep -s 2
    }
    else
    {
        Write-Host
        Write-Host "[+] Android Platform Tools not in Path."
        Write-Host "[+] Exiting Now..."
        Write-Host
        Write-Host "[+]================================================================================================================================"
        break
    }

    $emulatorStatus = (Get-Command emulator).Name
    if ($emulatorStatus -eq 'emulator.exe')
    {
        Write-Host
        Write-Host "[+] Found Emulator in ENV::PATH"
        Start-sleep -s 2
    }
    else
    {
        Write-Host
        Write-Host "[+] Android Emulator Commands not in Path."
        Write-Host "[+] Exiting Now..."
        Write-Host
        Write-Host "[+]================================================================================================================================"
        break
    }
    
    Write-Host
    Write-Host "[+]================================================================================================================================"

    # Checking if AVD Data Path is set correctly or not
    $avdDataPath = "$env:USERPROFILE\.android\avd\"
    if ($(Test-Path "$avdDataPath") -eq $false)
    {
        while (1)
        {
            Write-Host
            Write-Host "[+] Please provide path where AVD image is saved"
            Write-Host "[+] Generally it's at $env:USERPROFILE\.android\avd\"
            $avdDataPath = Read-Host -Prompt "[+] Path "

            if ($(Test-Path "$avdDataPath"))
            {
                Write-Host
                Write-Host "[+] AVD Data Path Validated"
                Start-sleep -s 2
                break
            }
        }
    }
    else
    {
        Write-Host
        Write-Host "[+] AVD Data Path Validated"   
        Start-sleep -s 2
    }

    Write-Host
    Write-Host "[+]================================================================================================================================"

    # Checking if OpenSSL ZIP File is in auto_install folder
    Get-ChildItem .\auto_install\ | findstr /RI ".*.zip$" | findstr /I "openssl" 2>&1 | Out-Null
    if ($LASTEXITCODE)
    {
        Write-Host
        Write-Host "[+] NOT FOUND :: OpenSSl for Windows"
        Write-Host "[+] Please follow below instructions :"
        Write-Host "[+] Download the latest 'ZIP' from : https://sourceforge.net/projects/openssl-for-windows/files/"
        Write-Host "[+] Place the 'ZIP' in 'auto_install' folder"
        Write-Host "[+] Extract the 'ZIP' and rename the contents folder to 'openssl'"
        Write-Host "[+] Delete the downloaded 'ZIP' folder"
        Write-Host "[+] Re-ZIP the folder 'openssl' with the name - 'openssl.zip' and delete 'openssl' folder"
        Write-Host "[+] After that, re-run the script"
        Write-Host
        Write-Host "[+]================================================================================================================================"
        break
    }
    else
    {
        Write-Host
        Write-Host "[+] FOUND :: OpenSSL for Windows"
        Start-sleep -s 2
    }

    Write-Host
    Write-Host "[+]================================================================================================================================"

    # Checking if BurpCert is in auto_install folder
    Get-ChildItem .\auto_install\ | findstr /RI ".*.cer$" 2>&1 | Out-Null
    if ($LASTEXITCODE)
    {
        Write-Host
        Write-Host "[+] NOT FOUND :: Burp Cert"
        Write-Host "[+] Please follow below instructions :"
        Write-Host "[+] Generate New Certificate from BurpSuite"
        Write-Host "[+] Export the cert and place it in 'auto_install' folder"
        Write-Host "[+] Rename the cert as 'burp.cer'"
        Write-Host "[+] After that, re-run the script"
        Write-Host
        Write-Host "[+]================================================================================================================================"
        break
    }
    else
    {
        Write-Host
        Write-Host "[+] FOUND :: BurpCert"
        Start-sleep -s 2
    }

    Write-Host
    Write-Host "[+]================================================================================================================================"

    # Extracting OpenSSL
    Expand-Archive -Path .\auto_install\openssl.zip -DestinationPath .\auto_install
    if ($LASTEXITCODE)
    {
        Write-Host
        Write-Host "[+] Unable to UNZIP OpenSSL. Please unzip it manually"
        Write-Host
        Write-Host "[+]================================================================================================================================"
        break
    }
    else
    {
        Write-Host
        Write-Host "[+] UNZIPPED :: OpenSSL"
        Start-sleep -s 2
    }

    Write-Host
    Write-Host "[+]================================================================================================================================"

    Write-Host
    Write-Host "[+] Initiating AVD : $avd"
    $avdJobID = (emulator.exe -avd $avd -writable-system -selinux permissive -snapshot $avd"_Rooted" &).Id
    Write-Host "[+] AVD Started with Job ID : $avdJobID"
    Start-sleep -s 35

    Write-Host
    Write-Host "[+] Extract Emulator Name via ADB"
    $emulatorName = (adb.exe devices | findstr /EL "device").split()[0]
    Write-Host "[+] AVD Emulator Name : $emulatorName"

    Write-Host
    Write-Host "[+] Respawn ADB to Root"
    adb.exe -s $emulatorName root 2>&1 | Out-Null
    Start-sleep -s 10

    Write-Host
    Write-Host "[+] Hashing Burp Cert"
    $burpHash = .\auto_install\openssl\openssl.exe x509 -inform DER -subject_hash_old -in .\auto_install\burp.cer | Select-Object -First 1
    Rename-Item -Path .\auto_install\burp.cer -NewName "$burpHash.0"
    Get-ChildItem .\auto_install\ | findstr "$burpHash.0"

    Write-Host "[+] Installing Burp Cert"
    adb.exe -s $emulatorName push .\auto_install\"$burpHash.0" "/system/etc/security/cacerts" 2>&1 | Out-Null
    adb.exe -s $emulatorName shell "ls -l /system/etc/security/cacerts | grep $burpHash"

    Write-Host "[+] Burp Cert Installed Successfully to Root Cert Store"

    Write-Host
    Write-Host "[+]================================================================================================================================"

    Write-Host
    Write-Host "[+] Updating the Snapshot of the AVD"
    adb.exe -s $emulatorName emu avd snapshot save $avd"_Rooted"

    Write-Host
    Write-Host "[+] Please close the AVD : $avd"

    Write-Host
    Write-Host "[+]================================================================================================================================"

}

#Created by Leandro Iacono (leandro.iacono@tanium.com)
#Script to automate capture of: Process Memory Dump (Tanium Server/Client), WPR Trace (Tanium Server/Client), Tanium Server Info Page (JSON Capture), Netstat Info, Network Adapter Info, Tanium Server/Client Log Files
<#

Syntax:

TaniumPerf.ps1 { 
                -outputdir <path-to-store-output>
                -counter <Script-Max-Execution-Count>
                -pdump (-procdumppath <path-to-procdump-exe>) (-pname <name-of-process-to-dump>)
                -json (-user <username>) (-password <password>) (-domain <domain-name>) (-url <url-to-info-page>)
                -tlogs (-tlogpath <path-to-tanium-client/server-logs>)
                -wpr (-wprpath <path-to-wpr-exe>) (-wprduration <duration-secs-wpr-trace-(10-120sec)>)
                -netinfo
                -netadapterinfo
               }

WPR Profile Types:

	GeneralProfile              First level triage
	CPU                         CPU usage
	DiskIO                      Disk I/O activity
	FileIO                      File I/O activity
	Registry                    Registry I/O activity
	Network                     Networking I/O activity
	Heap                        Heap usage
	Pool                        Pool usage
	VirtualAllocation           VirtualAlloc usage
	Audio                       Audio glitches
	Video                       Video glitches
	Power                       Power usage
	InternetExplorer            Internet Explorer
	EdgeBrowser                 Edge Browser
	Minifilter                  Minifilter I/O activity
	GPU                         GPU activity
	Handle                      Handle usage
	XAMLActivity                XAML activity
	HTMLActivity                HTML activity
	DesktopComposition          Desktop composition activity
	XAMLAppResponsiveness       XAML App Responsiveness analysis
	HTMLResponsiveness          HTML Responsiveness analysis
	ResidentSet                 Resident Set analysis
	XAMLHTMLAppMemoryAnalysis   XAML/HTML application memory analysis
	UTC                         UTC Scenarios
	DotNET                      .NET Activity
	WdfTraceLoggingProvider     WDF Driver Activity


#>

[cmdletbinding()]

Param(
  
  #Output directory
  [Parameter(Mandatory=$true)][ValidateScript({if ((Test-Path $_ -PathType 'Container') -ne $true){Throw “$_ is not a valid path to store Script Output.”}else{return $true}})][string]$outputdir,

  #MaxNumber of captures (Counter)
  [Parameter(Mandatory=$true)][int]$counter = 3,

  #Network Stack Information Download
  [Parameter(Mandatory=$false)][switch]$netinfo,

  #Network Adapter Settings Output
  [Parameter(Mandatory=$false)][switch]$netadapterinfo,

  #Process Dump
  [Parameter(Mandatory=$false)][switch]$pdump,    
  [Parameter(Mandatory=$false)][ValidateScript({if ((Get-Command $_ -ErrorAction SilentlyContinue) -eq $null){Throw “$_ is not a valid path to PROCDUMP.EXE - Full path to PROCDUMP.EXE (including .EXE) required.”; return $false}else{return $true}})][string]$procdumppath,
  [Parameter(Mandatory=$false)][ValidateScript({if ((Get-Process $_) -eq $null){Throw “$_ is not a valid process to DUMP - check process name (exclude .exe) .”; return $false}else{return $true}})][string]$pname,
  
  #JSON Info Page
  [Parameter(Mandatory=$false)][switch]$json,    
  [Parameter(Mandatory=$false)][string]$user,
  [Parameter(Mandatory=$false)][string]$password,
  [Parameter(Mandatory=$false)][string]$domain,
  [Parameter(Mandatory=$false)][string]$url,

  #Tanium Logs (Server or Client)
  [Parameter(Mandatory=$false)][switch]$tlogs,    
  [Parameter(Mandatory=$false)][ValidateScript({if ((Test-Path $_ -PathType 'Container') -ne $true){Throw “$_ is not a valid path to Tanium Scripts Folder.”}else{return $true}})][string]$tlogpath,

  #WPR Capture
  [Parameter(Mandatory=$false)][switch]$wpr,
  [Parameter(Mandatory=$false)][ValidateScript({if ((Get-Command $_ -ErrorAction SilentlyContinue) -eq $null){Throw “$_ is not a valid path to WPR.EXE! - Full path to WPR.EXE (including .EXE) required.”; return $false}else{return $true}})][string]$wprpath,
  [Parameter(Mandatory=$false)][ValidateScript({if ($_ -lt 10 -and $_ -gt 120){Throw “$_ WPR Duration not valid. Must be between 10sec and 120sec”; return $false}else{return $true}})][int]$wprduration,
  [Parameter(Mandatory=$false)][string]$wprprofiles = "-start GeneralProfile.light"
  
)

cd $outputdir

#MAX number of times Script can Execute
$maxscriptexecution = $counter;

try
    {
    
    $counterfile = Test-Path counter.txt;

    if ($counterfile -eq $true)
        {
        
        $counterval = Get-Content counter.txt

        if ($counterval -ge $maxscriptexecution)
            {
            Write-Output "[ScriptCounter][ERROR] Script reached Max Number Execution ($maxscriptexecution)."
            Write-Output "[ScriptCounter][ERROR] We'll now exit script execution as a precuation."
            Stop-Transcript
            exit
            }
        else
            {
            Write-Output "[ScriptCounter][SUCCESS] Script did not reach Max Execution ($maxscriptexecution)."
            Write-Output "[ScriptCounter][SUCCESS] Continuing with Script Execution."
            }
        }

    elseif($counterfile -eq $false)
        {
        Write-Output "[ScriptCounter][SUCCESS] Looks like Script was never Executed Before."
        Write-Output "[ScriptCounter][SUCCESS] Continuing with Script Execution."

        $counterval = "0"
        $counterval | out-file counter.txt

        }
    else
        {
        Write-Output "[ScriptCounter][ERROR] Something Happened Checking Script Execution Count."
        Write-Output "[ScriptCounter][ERROR] We'll now exit script execution as a precuation."
        Stop-Transcript
        exit;
        }

    }

catch
    {
    Write-Output "[ScriptCounter][ERROR] Looks like we're unable to check how many times script execution ocurred."
    Write-Output "[ScriptCounter][ERROR] We'll now exit script execution as a precuation."
    Stop-Transcript
    exit;
    }


#timestamp for log files and logging
$timestamp = get-date -f MM-dd-yyyy_HH_mm_ss

#debug log
Start-transcript -path ($timestamp + "-debug.log")

md $timestamp | out-null
cd $timestamp

############# WPR CAPTURE #############

if($wpr -and $wprpath -and $wprduration -and $wprprofiles)
{
    if ($wprduration -ge 10 -and $wprduration -le 120)
        {
            try
                {

                #wpr folder name and output path
                $wprfoldername = $timestamp + "-wpr"

                md $wprfoldername | out-null
                
                Write-Output "[WPR][SUCCESS] WPR Directory Created: $wprfoldername"

                Write-Output "Attempting to Start WPR..."
                try 
                    {
                    &$wprpath $wprprofiles
                    Write-Output "[WPR][SUCCESS] WPR Capture Started"
                    }
                catch
                    {
                    Write-Output "[WPR][ERROR] WPR Start Capture Failed. Check WPR Path or WPR Command/Parameters."
                    Stop-Transcript
                    exit;
                    }

                Write-Output "[WPR][SUCCESS] Sleeping for $wprduration seconds to allow WPR capture to complete..."
                Start-Sleep -s $wprduration

                Write-Output "Attempting to Stop WPR..."

                try 
                    {
                    &$wprpath -stop wpr.etl
                    Write-Output "[WPR][SUCCESS] WPR Capture Stopped."
                    }
                catch
                    {
                    Write-Output "[WPR][ERROR] WPR Stop Capture Failed. Stopping Script Exection as a precaution."
                    Stop-Transcript
                    exit;
                    }
                
                 try 
                    {
                    Move-Item wpr.etl -Destination $wprfoldername
                    Write-Output "[WPR][SUCCESS] Moved WPR Capture to Output Directory."
                    }
                catch
                    {
                    Write-Output "[WPR][ERROR] Unable to move WPR.etl to Output Directory."
                    Write-Output "[WPR][ERROR] Search for WPR.etl on the server. Stopping Script Execution as a precaution."
                    Stop-Transcript
                    exit;
                    }

                Write-Output "[WPR][SUCCESS] WPR Trace Captured Succesfully."

                }
    
            catch
                {
                Write-Output "[WPR][ERROR] Unfortunately there was a problem capturing the WPR Trace."
                Write-Output "[WPR][ERROR] Likely a Permission or Folder/Path issue. WPPR Trace was not captured as expected."
                }
        }
    else
        {
        Write-Output "[WPR][ERROR] Windows Performance Recorder Arguments Error."
        Write-Output "[WPR][ERROR] Check WPR Arguments and Try Again."
        }

}

elseif($wpr -or $wprpath -or $wprduration)
{
    Write-Output "[WPR][ERROR] Windows Performance Recorder Arguments Error."
    Write-Output "[WPR][ERROR] Check WPR Arguments and Try Again."
}

############# JSON CAPTURE #############

if($json -and $url -and $user -and $password -and $domain)
{
    try
        {
            #Rework "Trust SSL Certificate" - http://www.bhargavs.com/index.php/2014/03/17/ignoring-ssl-trust-in-powershell-using-system-net-webclient/
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        
            #Set InfoPage Output path and filename
            $output = $timestamp + "-info.json"

            #get info page and save to output
            $webclient = new-object System.Net.WebClient            $credCache = new-object System.Net.CredentialCache            $creds = new-object System.Net.NetworkCredential($user,$password)            $credCache.Add($url, "Basic", $creds)            $webclient.Credentials = $credCache            $webclient.DownloadFile($url, $output)

            Write-Output "[JSON][SUCCESS] Info Page (JSON) Download Execution Logic Completed. Check $outputdir for the .json file to confirm download."
            Write-Output "[JSON][SUCCESS] If the JSON file is missing there was likely a problem Authenticating to Server (Basic vs NTLM). Contact your TAM for support."
        }
    catch
        {
            Write-Output "[JSON][ERROR] There was a problem capturing JSON Info Page."
            Write-Output "[JSON][ERROR] Its likely Authentication Failed, Incorrect URL provided, or Incorrect Credentials Provided."
        }

 }

elseif($json -or $url -or $user -or $password -or $domain)
    {
    Write-Output "[JSON][ERROR] JSON Arguments Error"
    Write-Output "[JSON][ERROR] URL, USER, PASSWORD & DOMAIN REQUIRED. Check JSON PARAMETERS and try again."
    }

############# TLOGS CAPTURE #############

if($tlogs -and $tlogpath)
{
    $test = Test-Path $tlogpath -PathType 'Container'

    if ($test -ne $false)
        {
            try
            {
                #logfile folder name and output path
                $tlogfoldername = $timestamp + " - tlogs"
                md $tlogfoldername | out-null

                Write-Output "[Tanium LOGS][SUCCESS] Tanium Log Output Directory Created: $tlogfoldername"

                try
                    {
                    #copy Tanium Server Logs
                    copy-item $tlogpath $tlogfoldername -recurse
                    Write-Output "[Tanium LOGS][SUCCESS] Tanium Logs Copied to: $tlogfoldername"
                    }

                catch
                    {
                    Write-Output "[Tanium LOGS][ERROR] Looks like there was an error copying Tanium Log Files."
                    Write-Output "[Tanium LOGS][ERROR] Likely could not find the Tanium Logs Directory."
                    }
            }
            catch
            {
                Write-Output "[Tanium LOGS][ERROR] Looks like there was an error copying Tanium Log Files."
                Write-Output "[Tanium LOGS][ERROR] Likely could not create Tanium Logs Output Directory."
            }
        }
    else
    {
        Write-Output "[Tanium LOGS][ERROR] Could not verify Tanium Log File Directory."
        Write-Output "[Tanium LOGS][ERROR] Check Specified Tanium Log Path and try again."
    }
}

elseif($tlogs -or $tlogpath)
{
    Write-Output "[Tanium LOGS][ERROR] INCORECT Tanium Log PARAMETERS COMBINATION SPECIFIED."
    Write-Output "[Tanium LOGS][ERROR] Tanium Log Copy Failed. Check TLog PARAMETERS and try again."
}

############# PROCDUMP CAPTURE #############

if($pdump -and $procdumppath -and $pname)
{

$test = Test-Path $procdumppath

if ($test -ne $false)
    {
    try
        {
            $command = $procdumppath + " -ma " + $pname + " " + $pname + ".dmp -accepteula"
            iex $command
            Write-Output "[PROCDUMP][SUCCESS] Process Dump Capture Completed."
        }
    catch
        {
            Write-Output "[PROCDUMP][ERROR] Couldn't Create PROCDUMP File."
            Write-Output "[PROCDUMP][ERROR] Likely could not find the PROCDUMPPATH or PROCESSNAME was not valid."
        }
    }
else
    {
        Write-Output "[PROCDUMP][ERROR] Could not validate PROCDUMP .exe location."
        Write-Output "[PROCDUMP][ERROR] Ensure PROCDUMP is installed, specified PATH is Valid and try again."
    }
} 

elseif($pdump -or $procdumppath -or $pname)
{
    Write-Output "[PROCDUMP][ERROR] INCORRECT PDUMP PARAMATERS COMBINATON SPECIFIED."
    Write-Output "[PROCDUMP][ERROR] PROCDUMP Failed. Check PROCDUMP PARAMETERS and try again."
}

############# NETINFO CAPTURE #############

if($netinfo)
{
    try 
    {
        #netinfo output path and filename
        $netoutput = $timestamp + "-netinfo.txt"

        netsh int ipv4 show dynamicportrange tcp | out-file $netoutput -append
        netstat -anob | out-file  $netoutput -append
        #netstat -anobp | out-file  $netoutput -append

        Write-Output "[NETINFO][SUCCESS] NETINFO Capture Completed..."
    }
    catch
    {
        Write-Output "[NETINFO][ERROR] Looks like there was an error capturing netinfo data."
        Write-Output "[NETINFO][ERROR] Likely do not have permission to retrieve network information."
    }
} 

############# NETADAPTER CAPTURE #############

if($netadapterinfo)
{
    try 
    {
        #netinfo output path and filename
        $netadapterinfooutput = $timestamp + "-netadapter.txt"

        Get-NetAdapter| out-file $netadapterinfooutput -append
        Get-NetAdapterAdvancedProperty | out-file $netadapterinfooutput -append
        Get-NetAdapterChecksumOffload | out-file $netadapterinfooutput -append
        Get-NetAdapterHardwareInfo | out-file $netadapterinfooutput -append
        Get-NetAdapterLso | out-file $netadapterinfooutput -append
        Get-NetAdapterRss | out-file $netadapterinfooutput -append
        Get-NetAdapterRsc | out-file $netadapterinfooutput -append
    
        Write-Output "[NETADAPTER][SUCCESS] Network Adapter Settings Capture Completed..."
    }
    catch
    {
        Write-Output "[NETADAPTER][ERROR] Looks like there was an error capturing netadapter data."
        Write-Output "[NETADAPTER][ERROR] Likely do not have permission to retrieve information or PowerShell CMDLET not present."
    }
} 


cd ..

[int]$counterval = Get-Content counter.txt
$counterval = ($counterval + 1)
$counterval | out-file counter.txt

Stop-Transcript
#############################################################
# get-windows-activation-keys.ps1
# 
# Purpose: Extract Windows activation keys from multiple sources
#          including registry, WMI, and firmware-embedded keys.
#          The script identifies and decodes product keys from
#          various locations where Windows stores activation
#          information.
#
# Usage: Run the script with administrative privileges
#        .\get-windows-activation-keys.ps1
#
# Note: The script will pause at the end. Press Enter to close the window.
#
# Sources used:
# - Registry: HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion
# - Registry: HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform
# - Registry: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation
# - WMI: SoftwareLicensingService class
#############################################################

# Check if running as administrator
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    return $isAdmin
}

# Display a warning if not running as administrator
if (-not (Test-Admin)) {
    Write-Warning "This script may not retrieve all keys without administrative privileges."
    Write-Warning "Consider rerunning as Administrator for complete results."
    Write-Host ""
}

# Your script code continues here with admin privileges
Write-Host "Script is running with administrator privileges!" -ForegroundColor Green

# Function to decode a Windows product key from the registry binary data
# This decoding algorithm works with both the DigitalProductId and DigitalProductId4 values
# Microsoft stores product keys in an encoded binary format to prevent simple extraction
# The algorithm below reverses the encoding to reveal the actual 25-character product key
function Get-WindowsProductKey {
    param (
        [byte[]]$DigitalProductId
    )
    
    # Ensure we have valid data
    if (-not $DigitalProductId -or $DigitalProductId.Length -lt 67) {
        return $null
    }
    
    # Define the charset for the product key
    $keyChars = "BCDFGHJKMPQRTVWXY2346789"
    
    # Starting with Windows 8, the encoding algorithm changed
    # This algorithm works for both pre-Windows 8 and Windows 8+
    
    # Last 8 bytes are used in decoding
    $keyStartIndex = 52
    
    # Initialize variables
    $key = ""
    
    # Process the bytes to extract the key
    for ($i = 24; $i -ge 0; $i--) {
        $keyChar = 0
        for ($j = 14; $j -ge 0; $j--) {
            $keyChar = ($keyChar * 256) -bxor $DigitalProductId[$j + $keyStartIndex]
            $DigitalProductId[$j + $keyStartIndex] = [math]::Floor($keyChar / 24)
            $keyChar = $keyChar % 24
        }
        $key = $keyChars[$keyChar] + $key
        
        # Add hyphens for readability
        if (($i % 5 -eq 0) -and ($i -ne 0)) {
            $key = "-" + $key
        }
    }
    
    return $key
}

# Function to get product name from registry
# Retrieves the Windows version name from the registry at:
# HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName
function Get-WindowsProductName {
    try {
        $productName = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "ProductName" -ErrorAction SilentlyContinue
        return $productName.ProductName
    }
    catch {
        return "Unknown Windows Version"
    }
}

# Main function to extract and display all activation keys
# This function attempts to retrieve Windows activation keys from 5 different sources:
# 1. BackupProductKeyDefault - A backup of the product key stored by Software Protection Platform
# 2. DigitalProductId - Legacy encoded product key format (pre-Windows 8)
# 3. DigitalProductId4 - Modern encoded product key format (Windows 8 and later)
# 4. OEMProductKey - Key provided by the computer manufacturer (OEM)
# 5. OA3xOriginalProductKey - Key embedded in firmware/BIOS by manufacturer (UEFI/ACPI)
function Get-AllWindowsKeys {
    
    Write-Host "Retrieving Windows activation keys..." -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    
    # Get system information
    $computerName = $env:COMPUTERNAME
    $productName = Get-WindowsProductName
    
    Write-Host "Computer Name: $computerName" -ForegroundColor Green
    Write-Host "Windows Version: $productName" -ForegroundColor Green
    Write-Host "=========================================`n" -ForegroundColor Cyan
    
    # Collection to store the results
    $results = @()
    
    # Method 1: Get key from SoftwareProtectionPlatform
    # Windows maintains a backup of the product key in plain text in the registry as part of
    # the Software Protection Platform service that manages Windows activation
    try {
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform"
        $digitalProductId = (Get-ItemProperty -Path $registryPath -Name "BackupProductKeyDefault" -ErrorAction SilentlyContinue).BackupProductKeyDefault
        if ($digitalProductId) {
            $results += [PSCustomObject]@{
                Source = "Backup Product Key"
                Key = $digitalProductId
                Description = "Plain text backup product key from Software Protection Platform registry key"
                RegistryPath = "$registryPath\BackupProductKeyDefault"
            }
        }
    }
    catch {
        Write-Verbose "Could not retrieve backup product key: $_"
    }
    
    # Method 2: Get digital product ID and decode it
    # The DigitalProductId is a binary value that contains an encoded version of the product key
    # This is the traditional way Windows stores activation keys (pre-Windows 8)
    # The encoding requires a special algorithm to decode back to a 25-character key
    try {
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        $digitalProductId = (Get-ItemProperty -Path $registryPath -Name "DigitalProductId" -ErrorAction SilentlyContinue).DigitalProductId
        if ($digitalProductId) {
            $decodedKey = Get-WindowsProductKey -DigitalProductId $digitalProductId
            if ($decodedKey) {
                $results += [PSCustomObject]@{
                    Source = "Digital Product ID"
                    Key = $decodedKey
                    Description = "Decoded from legacy binary format (pre-Windows 8)"
                    RegistryPath = "$registryPath\DigitalProductId"
                }
            }
        }
    }
    catch {
        Write-Verbose "Could not decode DigitalProductId: $_"
    }
    
    # Method 3: Get digital product ID4 (Windows 8+)
    # With Windows 8, Microsoft introduced a new encoding format called DigitalProductId4
    # While the internal format changed, our decoding algorithm still works with both formats
    # This is the preferred key storage method for modern Windows versions
    try {
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        $digitalProductId4 = (Get-ItemProperty -Path $registryPath -Name "DigitalProductId4" -ErrorAction SilentlyContinue).DigitalProductId4
        if ($digitalProductId4) {
            $decodedKey = Get-WindowsProductKey -DigitalProductId $digitalProductId4
            if ($decodedKey) {
                $results += [PSCustomObject]@{
                    Source = "Digital Product ID4"
                    Key = $decodedKey
                    Description = "Decoded from modern binary format (Windows 8+)"
                    RegistryPath = "$registryPath\DigitalProductId4"
                }
            }
        }
    }
    catch {
        Write-Verbose "Could not decode DigitalProductId4: $_"
    }
    
    # Method 4: Get OEM key from the registry
    # OEM (Original Equipment Manufacturer) devices often have a separate key stored
    # in the OEMInformation registry section that was installed by the manufacturer
    # This is typically the key that was used during the initial system setup
    try {
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"
        $oemKey = (Get-ItemProperty -Path $registryPath -Name "OEMProductKey" -ErrorAction SilentlyContinue).OEMProductKey
        if ($oemKey) {
            $results += [PSCustomObject]@{
                Source = "OEM Product Key"
                Key = $oemKey
                Description = "OEM-provided product key from the registry"
                RegistryPath = "$registryPath\OEMProductKey"
            }
        }
    }
    catch {
        Write-Verbose "Could not retrieve OEM product key: $_"
    }
    
    # Method 5: Use WMI to get the product key from firmware/BIOS
    # Modern OEM devices (Windows 8 and later) have the product key embedded directly 
    # in the firmware/BIOS in a feature called OA3 (OEM Activation 3.0)
    # This key is accessed via the SoftwareLicensingService WMI class rather than the registry
    # and is generally the most reliable key for OEM systems
    try {
        $wmiQuery = "SELECT * FROM SoftwareLicensingService"
        $wmiObj = Get-WmiObject -Query $wmiQuery -ErrorAction SilentlyContinue
        if ($wmiObj -and $wmiObj.OA3xOriginalProductKey) {
            $results += [PSCustomObject]@{
                Source = "WMI OA3x Key"
                Key = $wmiObj.OA3xOriginalProductKey
                Description = "Embedded OEM key from UEFI/ACPI firmware (most reliable for OEM systems)"
                AccessMethod = "WMI Query: $wmiQuery → OA3xOriginalProductKey property"
            }
        }
    }
    catch {
        Write-Verbose "Could not retrieve WMI product key: $_"
    }
    
    # Display the results
    if ($results.Count -gt 0) {
        Write-Host "`nWindows Activation Keys Found:" -ForegroundColor Green
        Write-Host "--------------------------------" -ForegroundColor Green
        
        foreach ($result in $results) {
            Write-Host "`nSource: " -NoNewline -ForegroundColor Cyan
            Write-Host "$($result.Source)" -ForegroundColor Yellow
            
            Write-Host "Key: " -NoNewline -ForegroundColor Cyan
            Write-Host "$($result.Key)" -ForegroundColor White
            
            Write-Host "Description: " -NoNewline -ForegroundColor Cyan
            Write-Host "$($result.Description)" -ForegroundColor Gray
            
            # Display the registry path or access method
            if ($result.RegistryPath) {
                Write-Host "Location: " -NoNewline -ForegroundColor Cyan
                Write-Host "$($result.RegistryPath)" -ForegroundColor Gray
            }
            elseif ($result.AccessMethod) {
                Write-Host "Location: " -NoNewline -ForegroundColor Cyan
                Write-Host "$($result.AccessMethod)" -ForegroundColor Gray
            }
        }
    }
    else {
        Write-Host "No Windows activation keys were found in the registry." -ForegroundColor Yellow
        Write-Host "This may be due to insufficient permissions or keys not being stored in expected locations." -ForegroundColor Yellow
    }
    
    Write-Host "`nKey Source Information:" -ForegroundColor Magenta
    Write-Host "------------------------" -ForegroundColor Magenta
    Write-Host "Backup Product Key    - Plain text key stored by Windows activation service" -ForegroundColor Gray
    Write-Host "Digital Product ID    - Legacy binary encoded key (Windows 7 and earlier)" -ForegroundColor Gray
    Write-Host "Digital Product ID4   - Modern binary encoded key (Windows 8 and later)" -ForegroundColor Gray
    Write-Host "OEM Product Key       - Key provided by computer manufacturer" -ForegroundColor Gray
    Write-Host "WMI OA3x Key         - Key embedded in firmware/BIOS by manufacturer (most reliable)" -ForegroundColor Gray
    
}

# Execute the main function
Get-AllWindowsKeys

# Keep the window open until the user presses Enter
Write-Host "`nPress Enter to close this window..." -ForegroundColor Yellow

# Robust pause mechanism that works regardless of how the script is launched
# Check if script is running in ISE or console host
$isConsoleHost = $Host.Name -eq "ConsoleHost"
$isISE = $Host.Name -eq "Windows PowerShell ISE Host"
$isPSCore = $PSVersionTable.PSEdition -eq "Core"

# Method 1: Standard Read-Host (works in most cases)
Read-Host

# Method 2: Use pause command if running from cmd or double-click (works only in ConsoleHost)
if ($isConsoleHost) {
    Write-Host "Press any key to continue..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Method 3: Use PowerShell specific pause for edge cases (works in ISE and other hosts)
if (-not $isConsoleHost -and -not $isISE) {
    Write-Host "Script complete. This window will close when you press a key." -ForegroundColor Yellow
    Start-Sleep -Seconds 1
    
    # Create a Windows Forms control to wait for user input
    Add-Type -AssemblyName System.Windows.Forms
    $dummy = New-Object System.Windows.Forms.Form
    $dummy.Size = New-Object System.Drawing.Size(1,1)
    $dummy.Add_Shown({$dummy.Activate()})
    [void]$dummy.ShowDialog()
}

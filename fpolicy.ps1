# Set some variables for your environment
$cluster = "cluster" # The Netapp FAS2520 system

# This is not recommended, but works in a test environment
# In production, you'll want to store an encrypted password

$securePassword = ConvertTo-SecureString “myPassword” -AsPlainText -Force
$cred = New-Object -TypeName System.Management.Automation.PSCredential ("admin",$securePassword)

$fpolicyName = "p_ransomware"
$fpolicyEvent = "e_ransomware"
     

# Using this site as a somewhat comprehesive list of known ransomware file name patterns
# https://fsrm.experiant.ca/

$rawcryptofilenames =  @((Invoke-WebRequest -Uri "https://fsrm.experiant.ca/api/v1/get").content | convertfrom-json | % {$_.filters})

# Side note, to get all extensions in a file system
# gci -recurse | Select-Object Name | ForEach-Object {$_.Name.split(".")[-1]} | select -Unique


# Netapp fpolicy has support for file extension monitoring, which is the string after the last period (.)
# For example, file1.txt.name.jpg has an extension of jpg

[string[]]$extensions = @()

# Extensions that should never be blocked. This list should probably be a lot longer, and ideally accessible as a web services request
# It would also be possible to store the list of good extensions as an external file.
[string[]]$goodExtensions = @("txt","doc","docx","xlsx","htm","html","*","jpg","bmp","gif","png","ppt") # The "*" should not be considered a wildcard here. "*" will only filter out exactly <file>.*, not f ex <file>.a*c

# For any other file extension that should be blocked, just some random strings for now to validate the script functionality
[string[]]$localBadExtensions = @("floon","baah")

foreach ($line in $rawcryptofilenames) 
{
    $extensions += $line.split(".")[-1] # Each line is split into an array, for example "*.payfornature@india.com.crypted" is split into ("*","payfornature@india","com","crypted")
                                        # Using -1 as index returns the last item in the array, in this case "crypted"
}

$globalUniqueExtensions = $extensions | Where-Object {$_} | select -Unique # This will filter out null strings. FpolicyScope will error out on null strings.

$badExtensions = $globalUniqueExtensions| Where-Object {$goodExtensions -notcontains $_} # Filter out known good extensions to minimize false positives

$badExtensions += $localBadExtensions

Connect-NcController -Name $cluster -Credential $cred

$existingFpolicyPolicy = Get-NcFpolicyPolicy
$existingFpolicyScope = Get-NcFpolicyScope

$dataSVMs = Get-NcVserver | Where-Object {$_.VserverType -eq "data"}

if ($existingFpolicyPolicy) # There has to be at least one existing Fpolicy, otherwise the compare-object will error out
{
    $newDataSVMs = Compare-Object -ReferenceObject $dataSVMs -DifferenceObject $existingFpolicyPolicy -Property Vserver
}
else
{
    $newDataSVMs = $dataSVMs # All SVMs are new
}

$sequenceNumber = 1

# Apply Fpolicy scope for all CIFS volumes for all SVMS
foreach ($dataSVM in $dataSVMs)
{
    if ($newDataSVMs.Vserver -contains $dataSVM.Vserver) # Create policy and event for each new SVM
    {
        New-NcFpolicyEvent -Name $fpolicyEvent -Protocol cifs -FileOperation ("create","rename") -VserverContext $dataSVM
        New-NcFpolicyPolicy -Name $fpolicyName -Event $fpolicyEvent -EngineName native -VserverContext $dataSVM
        New-NcFpolicyScope -PolicyName $fpolicyName -VserverContext $dataSVM
        
    }

    $dataVolsCIFS = Get-NcVol -Vserver $dataSVM | Where-Object {$_.VolumeSecurityAttributes.Style -eq "ntfs" -and $_.Name -notmatch "root"}
    
    Set-NcFpolicyScope -PolicyName $fpolicyName -VolumesToInclude $dataVolsCIFS -FileExtensionsToInclude $badExtensions -FileExtensionsToExclude $goodExtensions -VserverContext $dataSVM

    Enable-NcFpolicyPolicy $fpolicyName -SequenceNumber $sequenceNumber -VserverContext $dataSVM -ErrorAction SilentlyContinue # Silently continue on error "policy is already enabled"Get
    $sequenceNumber++
}




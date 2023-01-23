# P0werP4ss

Powershell script to encrypt, save and decrypt strings.<br>
It uses ***AES encryption*** and it saves encrypted strings in ***P0werP4ss.txt*** (same folder).<br> 
It also makes a ***backup*** named ***P0werP4ss.txt.back*** .<br>
To load the backup just use it to overwrite the main one.<br>

## Requirements
Powershell v7 or higher. Open Powershell and check your version:
```
PS C:\> $PSVersionTable
```
If needed install v7 with the following command:
```
PS C:\> winget install --id Microsoft.Powershell --source winget
```
Windows currently use v5. Installing v7 won't replace it. It will be added to your system. 

## Encryption example:
```
.\P0werP4ss.ps1

Supply values for the following parameters:
(Type !? for Help.)
Modality: Encrypt  
Password: PASSWORD
Password_Confirmation: PASSWORD
Insert the string to encode: Sup3rS3cur3P4ss

-----------------
Encrypted string added to P0werP4ss.txt !
-----------------
```
## Decryption example:

```
.\P0werP4ss.ps1

Supply values for the following parameters:
(Type !? for Help.)
Modality: Decrypt
Password: PASSWORD
Password_Confirmation: PASSWORD

-----------------
Decrypted Output:

Sup3rS3cur3P4ss
-----------------
```

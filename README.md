# P0werP4ss

Powershell script to encrypt, save and decrypt strings.<br>
It uses ***AES encryption*** and it saves encrypted strings in ***P0werP4ss.txt*** (same folder).<br> 
It also makes a ***backup*** named ***P0werP4ss.txt.back*** .<br>
To load the backup just use it to overwrite the main one.<br>
<br> 
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
<br>

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

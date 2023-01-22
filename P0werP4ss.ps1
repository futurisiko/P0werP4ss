#	#################
#	# P0werP4ss.ps1 #
#	#################
#
#	Powershell script to encrypt, save and decrypt strings.
#	It uses AES encryption and it saves encrypted strings in P0werP4ss.txt (same folder). 	
#	It also makes a backup named P0werP4ss.txt.back. 
#	To load the backup just use it to overwrite the main one.
# 
#	Encryption example:
#
#		.\P0werP4ss.ps1
#		Supply values for the following parameters:
#		(Type !? for Help.)
#		Modality: Encrypt  
#		Password: PASSWORD
#		Password_Confirmation: PASSWORD
#		Insert the string to encode: Sup3rS3cur3P4ss
#	
#		-----------------
#		Encrypted string added to P0werP4ss.txt !
#		-----------------
#
#	Decryption example:
#
#		.\P0werP4ss.ps1
#		Supply values for the following parameters:
#		(Type !? for Help.)
#		Modality: Decrypt
#		Password: PASSWORD
#		Password_Confirmation: PASSWORD
#	
#		-----------------
#		Decrypted Output:
#		
#		Sup3rS3cur3P4ss
#		-----------------
#
#	################
#	#   Credits:   #
#	#  futurisiko  #
#	################


### Base Param Declaration ###
Param(
    [Parameter(Mandatory = $true , HelpMessage = "Specify 'Encrypt' or 'Decrypt' ")]
    [ValidateSet('Encrypt', 'Decrypt')]
    [String]$Modality,
    
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [SecureString] $Password,
    
    [Parameter(Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [SecureString] $Password_Confirmation
)


### Encryp/Decrypt Function ### 	source (with some little mods) from DRTools by David Retzer
function AESEncryption {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Encrypt', 'Decrypt')]
        [String]$Mode,

        [Parameter(Mandatory = $true)]
        [String]$Key,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptText")]
        [String]$Text
    )

    Begin {
        $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
        $aesManaged = New-Object System.Security.Cryptography.AesManaged
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256
    }

    Process {
        $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))

        switch ($Mode) {
            'Encrypt' {
                 if ($Text) {$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)}
                
                 $encryptor = $aesManaged.CreateEncryptor()
                 $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
                 $encryptedBytes = $aesManaged.IV + $encryptedBytes
                 $aesManaged.Dispose()

                 if ($Text) {return [System.Convert]::ToBase64String($encryptedBytes)}
                
            }

            'Decrypt' {
                 if ($Text) {$cipherBytes = [System.Convert]::FromBase64String($Text)}
              
                 $aesManaged.IV = $cipherBytes[0..15]
                 $decryptor = $aesManaged.CreateDecryptor()
                 $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 16, $cipherBytes.Length - 16)
                 $aesManaged.Dispose()

                 if ($Text) {return [System.Text.Encoding]::UTF8.GetString($decryptedBytes).Trim([char]0)}
              
            }
        }
    }

    End {
        $shaManaged.Dispose()
        $aesManaged.Dispose()
    }
}


### Check if pass and confirmation match ###
try {
    $bstr1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    $bstr2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password_Confirmation)
    $length1 = [Runtime.InteropServices.Marshal]::ReadInt32($bstr1,-4)
    $length2 = [Runtime.InteropServices.Marshal]::ReadInt32($bstr2,-4)

    if ( $length1 -ne $length2 ) {
        Write-Warning "Passwords not matching!"
        exit 1
    }

    for ( $i = 0; $i -lt $length1; ++$i ) {
        $b1 = [Runtime.InteropServices.Marshal]::ReadByte($bstr1,$i)
        $b2 = [Runtime.InteropServices.Marshal]::ReadByte($bstr2,$i)

        if ( $b1 -ne $b2 ) {
            Write-Warning "Passwords not matching!"
            exit 1
        }
    }
}


### Clean Basic String Variables ### 
finally {
    if ( $bstr1 -ne [IntPtr]::Zero ) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr1)
    }
    if ( $bstr2 -ne [IntPtr]::Zero ) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr2)
    }
}


### Encrypt execution ###

if ($Modality -eq 'Encrypt') {
    $TextString = Read-Host "Insert the string to encode"
    $Quick = ConvertFrom-SecureString $Password -AsPlainText
    AESEncryption -Mode $Modality -Key $Quick -Text $TextString >> .\P0werP4ss.txt
    $Quick = ""
    Write-Host "`n-----------------`nEncrypted string added to P0werP4ss.txt !`n-----------------"
    copy .\P0werP4ss.txt .\P0werP4ss.txt.back
    exit 0
}


### Decryption execution ###
if ($Modality -eq 'Decrypt') {
    $file = Get-Content -Path '.\P0werP4ss.txt'
    $Quick = ConvertFrom-SecureString $Password -AsPlainText
    Write-Host "`n-----------------`nDecrypted Output:`n"
    for ($i=0; $i -lt $file.count; $i++) { AESEncryption -Mode $Modality -Key $Quick -Text $file[$i] }
    $Quick = ""
    Write-Host "-----------------"
    exit 0
}


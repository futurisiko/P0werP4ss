# PowerShell 7+
#
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
    [Parameter(Mandatory = $true, HelpMessage = "Specify 'Encrypt' or 'Decrypt'")]
    [ValidateSet('Encrypt', 'Decrypt')]
    [string]$Modality,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [SecureString]$Password
)

### Crypto Configuration ###
$PBKDF2Iterations    = 600000
$MaxPBKDF2Iterations = 1000000
$SaltSize            = 16   # 128 bit
$IvSize              = 16   # AES block size
$KeySize             = 32   # 256 bit
$RecordMagic         = [System.Text.Encoding]::ASCII.GetBytes('PPS1')
$ClearDecryptedOutputAfterSeconds = 30


### Utility Functions ###
function Clear-ByteArray {
    [CmdletBinding()]
    Param(
        [byte[]]$Bytes
    )

    if ($null -ne $Bytes -and $Bytes.Length -gt 0) {
        [Array]::Clear($Bytes, 0, $Bytes.Length)
    }
}

function Convert-SecureStringToUtf8Bytes {
    [CmdletBinding()]
    [OutputType([byte[]])]
    Param(
        [Parameter(Mandatory = $true)]
        [SecureString]$SecureString
    )

    $bstr = [IntPtr]::Zero
    $chars = $null

    try {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        $charCount = [int]([Runtime.InteropServices.Marshal]::ReadInt32($bstr, -4) / 2)

        $chars = New-Object char[] $charCount
        [Runtime.InteropServices.Marshal]::Copy($bstr, $chars, 0, $charCount)

        return [System.Text.Encoding]::UTF8.GetBytes($chars)
    }
    finally {
        if ($null -ne $chars) {
            [Array]::Clear($chars, 0, $chars.Length)
        }

        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
}

function Test-RecordMagic {
    [CmdletBinding()]
    [OutputType([bool])]
    Param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Buffer
    )

    if ($Buffer.Length -lt $RecordMagic.Length) {
        return $false
    }

    for ($i = 0; $i -lt $RecordMagic.Length; $i++) {
        if ($Buffer[$i] -ne $RecordMagic[$i]) {
            return $false
        }
    }

    return $true
}

function Clear-TerminalAfterDelay {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 3600)]
        [int]$Seconds
    )

    try {
        if ($Seconds -gt 0) {
            Start-Sleep -Seconds $Seconds
        }
    }
    finally {
        try {
            # Clear screen + scrollback buffer on terminals that support ANSI escape sequences.
            $esc = [char]27
            [Console]::Write("${esc}[3J${esc}[2J${esc}[H")
        }
        catch {
            # Fallback handled by Clear-Host below.
        }

        Clear-Host
    }
}

### Encrypt/Decrypt Function ###
function AESEncryption {
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Encrypt', 'Decrypt')]
        [string]$Mode,

        [Parameter(Mandatory = $true)]
        [byte[]]$Key,

        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    Begin {
        $hashAlgorithm = [System.Security.Cryptography.HashAlgorithmName]::SHA256
    }

    Process {
        switch ($Mode) {
            'Encrypt' {
                $salt = New-Object byte[] $SaltSize
                $iterationBytes = [System.BitConverter]::GetBytes([int]$PBKDF2Iterations)
                $plainBytes = $null
                $derivedKey = $null
                $cipherBytes = $null
                $record = $null
                $rng = $null
                $aes = $null
                $encryptor = $null

                try {
                    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
                    $rng.GetBytes($salt)

                    $derivedKey = [System.Security.Cryptography.Rfc2898DeriveBytes]::Pbkdf2(
                        $Key,
                        $salt,
                        $PBKDF2Iterations,
                        $hashAlgorithm,
                        $KeySize
                    )

                    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)

                    $aes = [System.Security.Cryptography.Aes]::Create()
                    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
                    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
                    $aes.BlockSize = 128
                    $aes.KeySize = 256
                    $aes.Key = $derivedKey
                    $aes.GenerateIV()

                    $encryptor = $aes.CreateEncryptor()
                    $cipherBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)

                    # Record format:
                    # [4 bytes magic][4 bytes iterations][16 bytes salt][16 bytes IV][ciphertext]
                    $record = New-Object byte[] ($RecordMagic.Length + 4 + $salt.Length + $aes.IV.Length + $cipherBytes.Length)

                    $offset = 0
                    [System.Buffer]::BlockCopy($RecordMagic, 0, $record, $offset, $RecordMagic.Length)
                    $offset += $RecordMagic.Length

                    [System.Buffer]::BlockCopy($iterationBytes, 0, $record, $offset, $iterationBytes.Length)
                    $offset += $iterationBytes.Length

                    [System.Buffer]::BlockCopy($salt, 0, $record, $offset, $salt.Length)
                    $offset += $salt.Length

                    [System.Buffer]::BlockCopy($aes.IV, 0, $record, $offset, $aes.IV.Length)
                    $offset += $aes.IV.Length

                    [System.Buffer]::BlockCopy($cipherBytes, 0, $record, $offset, $cipherBytes.Length)

                    return [System.Convert]::ToBase64String($record)
                }
                finally {
                    if ($null -ne $encryptor) { $encryptor.Dispose() }
                    if ($null -ne $aes) { $aes.Dispose() }
                    if ($null -ne $rng) { $rng.Dispose() }

                    Clear-ByteArray -Bytes $iterationBytes
                    Clear-ByteArray -Bytes $salt
                    Clear-ByteArray -Bytes $plainBytes
                    Clear-ByteArray -Bytes $derivedKey
                    Clear-ByteArray -Bytes $cipherBytes
                    Clear-ByteArray -Bytes $record
                }
            }

            'Decrypt' {
                $payload = $null
                $salt = $null
                $iv = $null
                $cipherBytes = $null
                $derivedKey = $null
                $decryptedBytes = $null
                $aes = $null
                $decryptor = $null

                try {
                    $payload = [System.Convert]::FromBase64String($Text)

                    if ($payload.Length -lt ($RecordMagic.Length + 4 + $SaltSize + $IvSize + 1)) {
                        throw "Invalid encrypted payload."
                    }

                    if (-not (Test-RecordMagic -Buffer $payload)) {
                        throw "Unsupported encrypted payload format."
                    }

                    $offset = $RecordMagic.Length

                    $iterations = [System.BitConverter]::ToInt32($payload, $offset)
                    if ($iterations -lt 1 -or $iterations -gt $MaxPBKDF2Iterations) {
                        throw "Invalid PBKDF2 iteration count in encrypted payload."
                    }
                    $offset += 4

                    $salt = New-Object byte[] $SaltSize
                    [System.Buffer]::BlockCopy($payload, $offset, $salt, 0, $SaltSize)
                    $offset += $SaltSize

                    $iv = New-Object byte[] $IvSize
                    [System.Buffer]::BlockCopy($payload, $offset, $iv, 0, $IvSize)
                    $offset += $IvSize

                    $cipherLength = $payload.Length - $offset
                    if ($cipherLength -lt 1) {
                        throw "Invalid encrypted payload."
                    }

                    $cipherBytes = New-Object byte[] $cipherLength
                    [System.Buffer]::BlockCopy($payload, $offset, $cipherBytes, 0, $cipherLength)

                    $derivedKey = [System.Security.Cryptography.Rfc2898DeriveBytes]::Pbkdf2(
                        $Key,
                        $salt,
                        $iterations,
                        $hashAlgorithm,
                        $KeySize
                    )

                    $aes = [System.Security.Cryptography.Aes]::Create()
                    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
                    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
                    $aes.BlockSize = 128
                    $aes.KeySize = 256
                    $aes.Key = $derivedKey
                    $aes.IV = $iv

                    $decryptor = $aes.CreateDecryptor()
                    $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 0, $cipherBytes.Length)

                    return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
                }
                finally {
                    if ($null -ne $decryptor) { $decryptor.Dispose() }
                    if ($null -ne $aes) { $aes.Dispose() }

                    Clear-ByteArray -Bytes $payload
                    Clear-ByteArray -Bytes $salt
                    Clear-ByteArray -Bytes $iv
                    Clear-ByteArray -Bytes $cipherBytes
                    Clear-ByteArray -Bytes $derivedKey
                    Clear-ByteArray -Bytes $decryptedBytes
                }
            }
        }
    }
}


### Encrypt / Decrypt execution ###
$PasswordBytes = $null

try {
    $PasswordBytes = Convert-SecureStringToUtf8Bytes -SecureString $Password

    if ($Modality -eq 'Encrypt') {
        $TextString = Read-Host "Insert the string to encode"
        AESEncryption -Mode $Modality -Key $PasswordBytes -Text $TextString >> .\P0werP4ss.txt
        AESEncryption -Mode $Modality -Key $PasswordBytes -Text $TextString >> .\P0werP4ss.txt.back
        Write-Host "`n-----------------`nEncrypted string added to P0werP4ss.txt !`n-----------------"
        exit 0
    }

    if ($Modality -eq 'Decrypt') {
        $DecryptedOutputWasPrinted = $false
    
        try {
            Write-Host "`n-----------------`nDecrypted Output:`n"
    
            foreach ($line in Get-Content .\P0werP4ss.txt) {
                if ([string]::IsNullOrWhiteSpace($line)) {
                    continue
                }
    
                AESEncryption -Mode $Modality -Key $PasswordBytes -Text $line
                $DecryptedOutputWasPrinted = $true
            }

            Write-Host "-----------------"
        }
        finally {
            if ($DecryptedOutputWasPrinted) {
                Clear-TerminalAfterDelay -Seconds $ClearDecryptedOutputAfterSeconds
            }
        }

        exit 0
    }

}

finally {
    Clear-ByteArray -Bytes $PasswordBytes
}

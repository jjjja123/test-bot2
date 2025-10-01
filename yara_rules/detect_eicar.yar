rule EICAR_Test_File
{
    meta:
        description = "Detects the EICAR antivirus test file"
        author = "security-bot"
        reference = "https://www.eicar.org/"

    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

    condition:
        $eicar
}
rule Suspicious_PDF
{
    meta:
        description = "Detects suspicious PDF patterns"
        author = "security-bot"

    strings:
        $js = "/JavaScript"
        $aa = "/AA"
        $open_action = "/OpenAction"

    condition:
        1 of them
}
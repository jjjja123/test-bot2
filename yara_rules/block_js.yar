rule Suspicious_JS
{
    meta:
        description = "Flags potentially malicious JavaScript files"
        author = "security-bot"

    strings:
        $eval = "eval("
        $unescape = "unescape("
        $document_write = "document.write("

    condition:
        any of them
}
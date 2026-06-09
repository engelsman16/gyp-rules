rule PkgJson_LifecycleScript
{
    meta:
        description  = "npm lifecycle hook present (preinstall/postinstall/prepare) — runs automatically at install time"
        technique    = "npm lifecycle script abuse"
        severity     = "LOW"

    strings:
        $pre     = "\"preinstall\""
        $post    = "\"postinstall\""
        $prepare = "\"prepare\""

    condition:
        any of them
}


rule PkgJson_ObfuscatedScript
{
    meta:
        description  = "Obfuscation technique (base64/eval/fromCharCode) in a script value — hides payload"
        technique    = "npm lifecycle script abuse"
        severity     = "CRITICAL"

    strings:
        $base64      = "base64"
        $eval        = "eval("
        $fromchar    = "fromCharCode"

    condition:
        any of them
}


rule PkgJson_NetworkInScript
{
    meta:
        description  = "curl or wget in a lifecycle script — network exfil or payload fetch"
        technique    = "npm lifecycle script abuse"
        severity     = "HIGH"

    strings:
        $curl = "curl"
        $wget = "wget"

    condition:
        any of them
}

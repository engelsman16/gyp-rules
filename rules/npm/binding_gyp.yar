rule BindingGyp_CmdExpansion
{
    meta:
        description  = "GYP command expansion syntax present — arbitrary shell execution at build time"
        source_ref   = "https://www.aikido.dev/blog/exploring-binding-gyp-npm-build-system"
        technique    = "GYP command expansion"
        severity     = "CRITICAL"

    strings:
        $exp1 = "<!("
        $exp2 = "<!@("
        $exp3 = "^!("

    condition:
        any of them
}


rule BindingGyp_NodeExec
{
    meta:
        description  = "node invoked inside a GYP command expansion"
        source_ref   = "https://www.aikido.dev/blog/exploring-binding-gyp-npm-build-system"
        technique    = "GYP command expansion"
        severity     = "CRITICAL"

    strings:
        $exp1 = "<!("
        $exp2 = "<!@("
        $exp3 = "^!("
        $node = "node"

    condition:
        any of ($exp*) and $node
}


rule BindingGyp_PythonExec
{
    meta:
        description  = "python/python3 invoked inside a GYP command expansion"
        source_ref   = "https://www.aikido.dev/blog/exploring-binding-gyp-npm-build-system"
        technique    = "GYP command expansion"
        severity     = "CRITICAL"

    strings:
        $exp1   = "<!("
        $exp2   = "<!@("
        $exp3   = "^!("
        $py1    = "python"
        $py2    = "python3"

    condition:
        any of ($exp*) and any of ($py*)
}


rule BindingGyp_PymodExpansion
{
    meta:
        description  = "<!pymod_do_main expansion — runs a Python module at build time"
        source_ref   = "https://www.aikido.dev/blog/exploring-binding-gyp-npm-build-system"
        technique    = "GYP command expansion"
        severity     = "CRITICAL"

    strings:
        $pymod = "<!pymod_do_main"

    condition:
        $pymod
}


rule BindingGyp_ShellExec
{
    meta:
        description  = "sh/bash/powershell invoked inside a GYP command expansion"
        source_ref   = "https://www.aikido.dev/blog/exploring-binding-gyp-npm-build-system"
        technique    = "GYP command expansion"
        severity     = "CRITICAL"

    strings:
        $exp1   = "<!("
        $exp2   = "<!@("
        $exp3   = "^!("
        $sh1    = " sh "
        $sh2    = " sh\""
        $sh3    = "bash"
        $sh4    = "powershell"

    condition:
        any of ($exp*) and any of ($sh*)
}


rule BindingGyp_NetworkFetch
{
    meta:
        description  = "curl or wget invoked inside a GYP command expansion"
        source_ref   = "https://www.aikido.dev/blog/exploring-binding-gyp-npm-build-system"
        technique    = "GYP command expansion"
        severity     = "CRITICAL"

    strings:
        $exp1  = "<!("
        $exp2  = "<!@("
        $exp3  = "^!("
        $curl  = "curl"
        $wget  = "wget"

    condition:
        any of ($exp*) and any of ($curl, $wget)
}


rule BindingGyp_StdoutSuppress
{
    meta:
        description  = "Output redirected to /dev/null or stderr merged — hides execution evidence"
        source_ref   = "https://www.aikido.dev/blog/exploring-binding-gyp-npm-build-system"
        technique    = "GYP command expansion"
        severity     = "CRITICAL"

    strings:
        $devnull = ">/dev/null"
        $stderr  = "2>&1"

    condition:
        any of them
}


rule BindingGyp_TypeNoneCombo
{
    meta:
        description  = "target with type:none combined with command expansion — pure side-effect build target"
        source_ref   = "https://www.aikido.dev/blog/exploring-binding-gyp-npm-build-system"
        technique    = "GYP command expansion"
        severity     = "CRITICAL"

    strings:
        $type_none = "\"type\": \"none\""
        $exp1      = "<!("
        $exp2      = "<!@("
        $exp3      = "^!("

    condition:
        $type_none and any of ($exp*)
}


rule BindingGyp_FileWriteExpansion
{
    meta:
        description  = "GYP <| file-write expansion — writes arbitrary content to files at build time"
        source_ref   = "https://www.aikido.dev/blog/exploring-binding-gyp-npm-build-system"
        technique    = "GYP command expansion"
        severity     = "CRITICAL"

    strings:
        $filewrite = "<|"

    condition:
        $filewrite
}

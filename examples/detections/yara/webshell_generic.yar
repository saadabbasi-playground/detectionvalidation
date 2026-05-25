/*
    YARA rule to detect generic web shells
    Author: Detection Team
    Severity: high
    Technique: T1505.003
    Version: 2.0
    Description: Detects common web shell patterns in PHP, ASP, and JSP files
*/

rule WebShell_Generic : webshell persistence {
    meta:
        description = "Detects generic web shell patterns in server-side scripts"
        author = "Detection Team"
        severity = "high"
        technique = "T1505.003"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
        version = "2.0"
        platform = "linux"

    strings:
        $php_exec1 = "eval(" nocase
        $php_exec2 = "system(" nocase
        $php_exec3 = "passthru(" nocase
        $php_exec4 = "shell_exec(" nocase
        $asp_exec = "Response.Write(Shell" nocase
        $jsp_exec = "Runtime.getRuntime().exec(" nocase
        $b64_decode = "base64_decode(" nocase
        $obfuscation1 = "str_replace(chr(" nocase

    condition:
        (
            ($php_exec1 or $php_exec2 or $php_exec3 or $php_exec4)
            and ($b64_decode or $obfuscation1)
        )
        or $asp_exec
        or $jsp_exec
}

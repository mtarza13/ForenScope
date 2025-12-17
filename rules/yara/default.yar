rule EVIFORGE_Suspicious_PowerShell_EncodedCommand
{
  meta:
    description = "Flags common encoded PowerShell invocation markers (defensive triage rule)"
    author = "EviForge"
    reference = "local-only"

  strings:
    $a1 = "EncodedCommand" ascii nocase
    $a2 = "-enc" ascii nocase
    $a3 = "FromBase64String" ascii nocase

  condition:
    any of them
}

rule EVIFORGE_Possible_MZ_PE_Header
{
  meta:
    description = "Detects DOS MZ header (may indicate PE executable)"
    author = "EviForge"

  strings:
    $mz = { 4D 5A }

  condition:
    $mz at 0
}

param([string]$Corpus, [string]$Jar)
# Assert sugli esiti attesi del corpus (documentati in fase di generazione).
$ErrorActionPreference = 'Continue'
$fails = 0
function Check($name, $ok, $detail) {
  if ($ok) { Write-Output "OK   $name" } else { Write-Output "FAIL $name -- $detail"; $script:fails++ }
}
function Scan($file) {
  $raw = & java -jar $Jar scan --jar $file 2>$null | ConvertFrom-Json
  if ($null -eq $raw -or $null -eq $raw.results -or $raw.results.Count -eq 0) { throw "scan vuoto per $file" }
  return $raw.results[0].findings
}
function Has($findings, $rule, $sev) {
  foreach ($f in $findings) { if ($f.rule -eq $rule -and $f.severity -eq $sev) { return $true } }
  return $false
}
function MaxSev($findings) {
  $rank = @{ 'INFO' = 0; 'LOW' = 1; 'MEDIUM' = 2; 'HIGH' = 3; 'CRITICAL' = 4 }
  $m = 0; foreach ($f in $findings) { $v = $rank[$f.severity]; if ($v -gt $m) { $m = $v } }
  return $m
}
$NEW_ENGINE = @('discord-webhook','telegram-bot-token','discord-token-classic','discord-token-mfa',
  'paste-raw-endpoint','powershell-encoded','powershell-suspicious','lolbin-download',
  'persistence-autostart','base64-blob','zip-slip-path','zip-trailing-data','zip-leading-data',
  'zip-duplicate-names','zip-case-collision','zip-header-count-mismatch',
  'exe-magic-wrong-extension','zip-magic-wrong-extension','class-magic-wrong-extension')
function NoNewEngine($findings) {
  foreach ($f in $findings) { if ($NEW_ENGINE -contains $f.rule) { return $false } }
  return $true
}

$f = Scan("$Corpus\01-clean-mod.jar")
Check '01 pulito (niente HIGH/CRITICAL)' (MaxSev $f -le 1) ((($f | ForEach-Object { $_.rule + ':' + $_.severity }) -join ', '))

$f = Scan("$Corpus\02-webhook-stealer.jar")
Check '02 discord-webhook HIGH' (Has $f 'discord-webhook' 'HIGH') 'assente'
Check '02 verdetto CRITICAL' (MaxSev $f -eq 4) 'no CRITICAL'
$ev = ($f | Where-Object { $_.rule -eq 'discord-webhook' } | ForEach-Object { $_.evidence }) -join "`n"
Check '02 segreto redatto' ($ev.Contains('<redacted') -and -not $ev.Contains('a' * 68)) 'segreto in chiaro?'

$f = Scan("$Corpus\03-dropper-ps.jar")
Check '03 powershell-encoded HIGH' (Has $f 'powershell-encoded' 'HIGH') 'assente'
Check '03 powershell-suspicious MEDIUM' (Has $f 'powershell-suspicious' 'MEDIUM') 'assente'
Check '03 max HIGH (no CRITICAL)' (MaxSev $f -eq 3) 'verdetto diverso'

$f = Scan("$Corpus\04-metadata-fp.jar")
Check '04 motore nuovo muto sui metadati' (NoNewEngine $f) 'nuova regola scattata sui metadati'
Check '04 FP legacy noto (CRITICAL domini)' (MaxSev $f -eq 4) 'legacy cambiato?'

$f = Scan("$Corpus\05-zipslip.jar")
Check '05 zip-slip-path HIGH' (Has $f 'zip-slip-path' 'HIGH') 'assente'

$f = Scan("$Corpus\06-appended.jar")
Check '06 zip-trailing-data HIGH' (Has $f 'zip-trailing-data' 'HIGH') 'assente'

$f = Scan("$Corpus\07-fake-txt-exe.jar")
Check '07 exe-magic-wrong-extension HIGH' (Has $f 'exe-magic-wrong-extension' 'HIGH') 'assente'

$f = Scan("$Corpus\08-telegram.jar")
Check '08 telegram-bot-token MEDIUM' (Has $f 'telegram-bot-token' 'MEDIUM') 'assente'
Check '08 max MEDIUM' (MaxSev $f -eq 2) 'verdetto diverso'

$f = Scan("$Corpus\09-blob-exe.jar")
Check '09 base64-blob HIGH' (Has $f 'base64-blob' 'HIGH') 'assente'

$f = Scan("$Corpus\10-blob-plain.jar")
Check '10 blob innocuo ignorato' (NoNewEngine $f) 'falso positivo sul blob'
Check '10 niente HIGH/CRITICAL' (MaxSev $f -le 2) 'verdetto diverso'

$f = Scan("$Corpus\11-matrix-fp-noto.jar")
$crit = @($f | Where-Object { $_.severity -eq 'CRITICAL' }).Count
Check '11 FP legacy noto (2 CRITICAL cheat)' ($crit -eq 2) "CRITICAL=$crit"

if ($fails -eq 0) { Write-Output 'CORPUS-VERIFY PASS (17/17)' } else { Write-Output "CORPUS-VERIFY FAIL($fails)"; exit 1 }

# Windows: start `ecb run` at logon (EXAMPLE ONLY)

The clipboard belongs to your interactive session, so do NOT run ecb as a
Windows service (a service gets its own, invisible clipboard). Use a task that
runs at logon in your user session.

PowerShell (adjust the path; review before running):

```powershell
$action  = New-ScheduledTaskAction -Execute "C:\Tools\ecb.exe" -Argument "run"
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$set     = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName "ecb" -Action $action -Trigger $trigger -Settings $set -Description "ecb clipboard sync"
```

Remove: `Unregister-ScheduledTask -TaskName ecb -Confirm:$false`

No secrets belong in the task: the device key is in the Windows Credential
Manager. Pause/resume with `ecb pause` / `ecb resume`.

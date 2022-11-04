Function Set-FirefoxSTIG {
    [string]$firefox64 = "C:\Program Files\Mozilla Firefox"
    [string]$firefox32 = "C:\Program Files (x86)\Mozilla Firefox"
    If (Test-Path -Path $firefox64) {
        Copy-Item -Path "$StagingPath\Support Files\FireFox Configuration Files\defaults" -Destination $firefox64 -Force -Recurse
        Copy-Item -Path "$StagingPath\Support Files\FireFox Configuration Files\mozilla.cfg" -Destination $firefox64 -Force
        Copy-Item -Path "$StagingPath\Support Files\FireFox Configuration Files\local-settings.js" -Destination $firefox64 -Force 
    }
    elseIf (Test-Path -Path $firefox32) {
        Copy-Item -Path "$StagingPath\Support Files\FireFox Configuration Files\defaults" -Destination $firefox32 -Force -Recurse
        Copy-Item -Path "$StagingPath\Support Files\FireFox Configuration Files\mozilla.cfg" -Destination $firefox32 -Force
        Copy-Item -Path "$StagingPath\Support Files\FireFox Configuration Files\local-settings.js" -Destination $firefox32 -Force 
    }
}

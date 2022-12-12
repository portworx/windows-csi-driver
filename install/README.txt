Install pxplugin.tgz at c:\pxplugin at windows node.
If needed, replace the pxplugin.exe binary build that supports node csi driver on windows.
Use the install script to  setup the binary to run as a service.

PS C:\pxplugin> .\install_pxplugin.ps1 -action install
Installing px-csi-win node plugin startup service... hostname lsundararajan-1128-win2019-1
Service "px-csi-win" installed successfully!
Set parameter "AppParameters" for service "px-csi-win".
Set parameter "AppDirectory" for service "px-csi-win".
Set parameter "DisplayName" for service "px-csi-win".
Set parameter "Description" for service "px-csi-win".
Set parameter "Start" for service "px-csi-win".
Reset parameter "ObjectName" for service "px-csi-win" to its default.
Set parameter "Type" for service "px-csi-win".
Reset parameter "AppThrottle" for service "px-csi-win" to its default.
Set parameter "AppStdout" for service "px-csi-win".
Set parameter "AppStderr" for service "px-csi-win".
Set parameter "AppRotateFiles" for service "px-csi-win".
Set parameter "AppRotateOnline" for service "px-csi-win".
Set parameter "AppRotateSeconds" for service "px-csi-win".
Set parameter "AppRotateBytes" for service "px-csi-win".
Done installing px-csi-win startup service.
PS C:\pxplugin> .\install_pxplugin.ps1 -action status

Status   Name               DisplayName
------   ----               -----------
Stopped  px-csi-win         px-csi-win - Portworx CSI Service

PS C:\pxplugin> .\install_pxplugin.ps1 -action start
PS C:\pxplugin> .\install_pxplugin.ps1 -action status

Status   Name               DisplayName
------   ----               -----------
Running  px-csi-win         px-csi-win - Portworx CSI Service

PS C:\pxplugin>
PS C:\pxplugin> .\install_pxplugin.ps1 -action uninstall
Service "px-csi-win" removed successfully!
PS C:\pxplugin>

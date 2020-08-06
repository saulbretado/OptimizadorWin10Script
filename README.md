# OptimizadorWin10Script
Este script te permite optimizar Windows 10 de forma completamente automática, ya que elimina (debloat) de forma automática programas y configuraciones que solo reducen el performance de tu instalación.

## Cambios por Chis Titus
- Dark Mode.
- Un comando para ejecutar todo.
- Agrego Chocolatey.
- O&O Shutup, configuración y ejecución.
- Desinstala aplicaciones de la Tiende de Microsoft.

## ¿Mi contribución?
- Traducción al español.
- Agregue sonido al terminar cada proceso.
- Reemplace el Windows Media Player Standard por VLC Media Player.

## Modifications
Este script también desinstala OneDrive, así como instala Adobe Reader, Chocolatey, Notepad++ y 7-Zip.

Cuando este traducido completamente, podrás cambiar o modificar las opciones que no te gusten o que no estén de acuerdo a tus necesidades. Por Ejemplo:

```
########## NOTA LOS SIMBOLOS #, estos habilitan lineas al borrarlos o deshabilitan lineas al agregarlos. En seguida puedes ver como AUC esta en Bajo (Low) y se deshabilito SMB1.
### Security Tweaks ###
	"SetUACLow",                  # "SetUACHigh",
	"DisableSMB1",                # "EnableSMB1",

########## AHORA CAMBIAMOS LA POSISION Y SE HABILITO SMB1 Y UAC SE CAMBIO A ALTO (HIGH)
### Security Tweaks ###
	"SetUACHigh",		#"SetUACLow",
	"EnableSMB1",		#"DisableSMB1",
```

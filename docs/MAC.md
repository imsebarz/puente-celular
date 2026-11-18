# Activación automática en macOS

El cliente SOCKS5 del README se ejecuta como usuario estándar. Para enrutar también aplicaciones sin SOCKS, el servicio de macOS crea una interfaz temporal y configura DNS durante la sesión. Al perder el iPhone retira esos cambios. Deja otra conexión disponible durante la primera prueba. Pulsa **Detener** en la app o vuelve a la Wi-Fi anterior para interrumpir el túnel.

## Crear un paquete para este Mac

Se requiere un Mac Apple Silicon con Xcode o sus herramientas, Python 3.10 o posterior y el binario Darwin arm64 de sing-box 1.14.4. El constructor compara el SHA-256 del ejecutable con la versión fijada en el código. Descarga el binario desde el proyecto de sing-box. [Distribución de sing-box](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4)

`networksetup -listallhardwareports` identifica la interfaz Wi-Fi. `ipconfig getoption en0 router` muestra la puerta de enlace si la interfaz es `en0`. Con la app del iPhone iniciada, prueba primero el transporte y el DNS en un puerto de loopback. Ajusta las rutas y la dirección del ejemplo.

```sh
python3 mac/full_tunnel/probe.py --engine /ruta/a/sing-box --config "$HOME/puente-privado/mac-config.json" --endpoint 172.20.10.1
python3 mac/full_tunnel/build_hotspot_package.py --engine /ruta/a/sing-box --config "$HOME/puente-privado/mac-config.json" --wifi en0 --phone 172.20.10.1 --output "$HOME/puente-privado/Puente.pkg"
```

El paquete se construye para el usuario, la interfaz, el emparejamiento y el Mac indicados. Cada persona debe construir el suyo. El servicio vuelve a comprobar la identidad del teléfono antes de activar rutas. Consulta con el administrador antes de instalarlo en un equipo administrado.

## Primera instalación

En un Mac donde Puente celular todavía no está instalado, ejecuta estos tres comandos desde una cuenta autorizada. Usan permisos administrativos para instalar los archivos de sistema y registrar el servicio.

```sh
sudo /usr/sbin/installer -pkg "$HOME/puente-privado/Puente.pkg" -target /
sudo /usr/bin/install -o root -g wheel -m 0644 /Library/PrivilegedHelperTools/co.puentecelular.hotspot/co.puentecelular.hotspot.plist /Library/LaunchDaemons/co.puentecelular.hotspot.plist
sudo /bin/launchctl bootstrap system /Library/LaunchDaemons/co.puentecelular.hotspot.plist
```

Conecta el Mac al hotspot y deja Puente celular visible. En sesiones posteriores, launchd activa el servicio sin solicitar sudo. El servicio cede ante una VPN detectada. Para comprobar la ruta efectiva, consulta `route -n get 1.1.1.1` y `route -n get 172.30.255.2`. Ambas deben salir por la misma interfaz `utun`. La ruta a la puerta de enlace del iPhone debe seguir en Wi-Fi. En `scutil --dns`, el primer resolver debe apuntar a `172.30.255.2`. Comprueba también una descarga HTTPS y un nombre DNS nuevo.

## Volver a la red habitual

Para una sesión, detén Puente celular en el iPhone o sal del hotspot. Comprueba que vuelvan la interfaz y el DNS que anotaste antes, y que funcione HTTPS. Para desactivar la automatización de forma persistente, ejecuta estos comandos una vez con una cuenta administradora.

```sh
sudo /bin/launchctl disable system/co.puentecelular.hotspot
sudo /bin/launchctl bootout system/co.puentecelular.hotspot
```

Para habilitarla de nuevo, ejecuta `sudo /bin/launchctl enable system/co.puentecelular.hotspot` y el comando de bootstrap de la primera instalación.

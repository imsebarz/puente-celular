# Puente celular

Una app de iPhone abre conexiones por datos celulares para un equipo conectado a su hotspot. El receptor verifica el certificado del teléfono y ofrece SOCKS5 en su propia dirección de loopback. La app emisora debe permanecer visible y el hotspot debe permitir la conexión local.

| Receptor | Uso disponible en este repositorio |
| --- | --- |
| Mac | Proxy SOCKS5 por aplicación. En Apple Silicon también hay un servicio opcional para rutas y DNS del sistema que requiere una instalación administrativa por Mac. |
| Windows y Linux | Cliente Python para aplicaciones compatibles con SOCKS5 autenticado y resolución remota. La activación automática del túnel para todo el sistema está pendiente. |
| Android y otro iPhone | Pueden conectarse al hotspot normal. Usar Puente celular como receptor requiere una app cliente. |

## Preparar un iPhone propio

1. En un Mac con Xcode, abre `ios/CellularTunnel.xcodeproj`. En **Signing & Capabilities**, selecciona tu equipo de desarrollo y sustituye `org.example.PuenteCelular` por un identificador propio. Conecta el iPhone, habilita el modo de desarrollador si iOS lo solicita y ejecuta la app en el dispositivo.
2. Activa **Compartir Internet** en el iPhone y conecta el receptor por Wi-Fi. Consulta la puerta de enlace de esa conexión. El ejemplo usa `172.20.10.1`. Si tu hotspot muestra otra, usa esa dirección.
3. En el Mac de preparación, instala Python 3.10 o posterior y comprueba que `openssl version` funciona. Desde la raíz del repositorio ejecuta el siguiente comando. El directorio de salida debe ser nuevo y estar fuera del repositorio.

```sh
python3 tools/create_pairing.py --server-host 172.20.10.1 --output "$HOME/puente-privado"
```

4. Transfiere **solo** `iphone-pairing.json` al iPhone por un medio privado. En la app, pulsa **Importar emparejamiento privado**, selecciona ese archivo y pulsa **Iniciar**. El archivo contiene la clave privada del teléfono. Guárdalo bajo tu control.
5. Entrega `mac-config.json` por un medio privado al receptor de confianza. A pesar de su nombre, el cliente de escritorio usa el mismo formato en los tres sistemas.

## Conectar un receptor

En macOS o Linux, guarda la configuración en una carpeta privada. Ejecuta desde la raíz del repositorio.

```sh
chmod 600 "$HOME/puente-privado/mac-config.json"
python3 mac/tunnel_client.py --config "$HOME/puente-privado/mac-config.json"
```

En Windows, guarda el archivo en una carpeta de tu perfil con acceso limitado a tu usuario. Desde PowerShell ejecuta lo siguiente.

```powershell
py -3 mac/tunnel_client.py --config "$env:LOCALAPPDATA\PuenteCelular\mac-config.json"
```

En la aplicación receptora configura SOCKS5 en `127.0.0.1`, puerto `1080`, con el usuario y contraseña del archivo de cliente. Activa la resolución DNS por el proxy cuando la aplicación la ofrezca. Puedes usar `socks5h` en los programas que acepten ese esquema. Verifica una página HTTPS con la app del iPhone visible. Detén el servidor del teléfono y abre un destino nuevo para comprobar cómo maneja tu aplicación la pérdida del proxy. Ctrl+C cierra el cliente local.

## Varios equipos y clientes móviles

Cada escritorio ejecuta su propio cliente y escucha solo en loopback. Con el protocolo actual, los receptores de confianza del mismo iPhone comparten el token del teléfono y su capacidad total. Cambiar el emparejamiento exige actualizar todos esos receptores. Para terceros que deban tener acceso revocable por separado, el siguiente paso es emitir una credencial por dispositivo y repartir la capacidad entre clientes.

Para Android, un receptor de todo el dispositivo necesitaría una app con `VpnService`. Para iOS, un receptor equivalente necesitaría Network Extension, la capacidad de firma correspondiente y autorización del usuario. Esas apps tendrían que convertir flujos de red al protocolo CT/1. El permiso de VPN del receptor y el requisito de mantener visible la app emisora son independientes.

El hotspot normal está disponible en los cinco sistemas según el plan del operador. La clasificación o el cobro de los datos de Puente celular requieren una comprobación aparte con el operador.

[Configuración opcional de todo el Mac](docs/MAC.md) · [Protocolo CT/1](docs/PROTOCOL.md)

## Comprobar el código

```sh
python3 tools/check_source.py
python3 -m unittest discover -s mac -p 'test_*.py'
python3 -m unittest discover -s tests
```

Las pruebas del relay usan sockets de loopback, TLS y certificados temporales. Una prueba física requiere un iPhone con datos celulares y un receptor conectado al hotspot.

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
5. Guarda `mac-config.json` para el primer receptor. En el iPhone aparece como **Emparejamiento inicial**. Para otros receptores, crea un perfil individual siguiendo los pasos de abajo. El cliente de escritorio usa el mismo formato en los tres sistemas.

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

1. Con el emparejamiento cargado, abre **Equipos autorizados → Añadir equipo**. Escribe un nombre reconocible y la dirección IPv4 privada del iPhone que muestra la conexión Wi-Fi del equipo. Pulsa **Guardar equipo**.
2. En la fila de ese equipo, pulsa **Compartir configuración**. Envía el archivo por AirDrop u otro medio privado al destinatario y arranca allí el cliente con ese archivo. Cada equipo tiene su propio token de acceso y contraseña SOCKS. El iPhone guarda las autorizaciones en su llavero y sigue aplicándolas al volver a abrir la app.
3. Para retirar un equipo, pulsa **Quitar acceso** en su fila y confirma su nombre. El iPhone cierra sus conexiones TCP y UDP y rechaza las nuevas. Los demás equipos pueden seguir usando la misma sesión. Para volver a autorizarlo, crea un perfil nuevo y entrégale el nuevo archivo.

Un perfil identifica a quien posea el archivo. Si dos equipos usan una copia del mismo archivo, revocarlo afecta a ambos. Al actualizar desde la app 0.3, **Emparejamiento inicial** conserva el acceso anterior. Si ya compartiste ese archivo, crea y prueba un perfil individual para cada receptor antes de retirar el inicial. Retirarlo también desconecta cualquier Mac que todavía lo use. Cerrar y recargar el mismo emparejamiento conserva la lista, incluso si está vacía.

Cada escritorio escucha en loopback. La capacidad celular del iPhone se comparte entre los equipos. Mantén la app visible mientras se usa el túnel.

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

Para comprobar la revocación en un iPhone, usa un perfil desechable y otro que deba conservar acceso.

```sh
python3 tools/test_revocation.py --revoke /ruta/privada/prueba.json --keep /ruta/privada/conservar.json
```

Espera a que aparezca **CUATRO FLUJOS ACTIVOS** y quita únicamente el perfil de prueba desde el iPhone. El verificador comprueba el cierre y el rechazo de TCP y UDP, mantiene los dos flujos originales del equipo conservado y verifica que pueda abrir otros. Usa consultas DNS a 1.1.1.1 y requiere acceso celular al puerto 53.

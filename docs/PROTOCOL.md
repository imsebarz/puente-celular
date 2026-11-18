# Protocolo privado CT/1

TCP transportado dentro de TLS >=1.2. Sin compresión, reanudación de aplicación ni
0-RTT. Un socket TLS por destino (no multiplexación entre destinos).

## Apertura

El cliente verifica SHA256 del DER leaf certificado ANTES de enviar bytes de
aplicación. Luego envía una sola línea JSON UTF8, limitada a4096 bytes:

`{"v":1,"token":"<64hex>","transport":"tcp|udp","host":"example.com","port":443}`

Host: IPv4, IPv6 sin scope ID o hostname ASCII A-label, máximo253 bytes. El servidor
rechaza trailing dot/labels vacías, controles y símbolos ajenos al formato. No se
resuelve el hostname en Mac. Port1…65535. Token256bits, comparación constante para
la longitud esperada. Nunca abrir destino antes de autenticar.

El servidor 0.3 responde `{"ok":true,"max_sessions":96}\n` después de autenticar
el token y tener NWConnection ready obligada a
cellular. Para UDP “ready” no demuestra que el destino sea alcanzable. Fallos antes
de ACK usan `{"ok":false,"error":"connection_rejected"}\n` y cierre.
El cliente 1.4 reconoce el campo opcional, deja margen para el cierre de TLS y
aplica un máximo local de 88. Sin el campo, usa el límite anterior de 30. La
capacidad anunciada corresponde a todo el servidor y se comparte entre equipos.

## Tramas después de ACK

`kind:u8 | length:u32 big-endian | payload:length bytes`

- `D` (0x44): datos TCP o UN datagrama UDP, máximo65507 bytes.
- `F` (0x46): EOF, longitud0. TCP permite seguir leyendo otra dirección.
- `E` (0x45): error genérico, máximo4096 bytes, seguido de cierre.

En TCP un extremo termina cuando ambas direcciones han confirmado envío de F.
En UDP F cierra el flujo. Socket/TLS desconectado cancela todo el destino. No hay
retry automático de datos: reintentarlos podría duplicar operaciones.

UDP ASSOCIATE Mac mantiene varios túneles por destino y reconstruye cabeceras
SOCKS5 al retornar; cierra todos al morir la conexión de control autenticada.
Fuente UDP se restringe al peer loopback y puerto admitido. FRAG!=0 se descarta.

Backpressure TCP: leer una trama nueva solo tras completar envío de la anterior.
UDP no admite backpressure del emisor local: la cola es limitada y puede descartar.

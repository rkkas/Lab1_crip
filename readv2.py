import sys, re
from collections import defaultdict
from scapy.all import PcapReader, IP, ICMP, Raw

PAD_40 = bytes(range(0x10, 0x38))  

WORDS = "de la que el en y a los se del las por un para con no una su al lo como mas pero sus le ya o este si porque tambien entre cuando muy sin sobre".split()

GREEN = "\033[1;92m" if sys.stdout.isatty() else ""
RESET = "\033[0m"      if sys.stdout.isatty() else ""

def caesar(s, k):
    r=[]
    for ch in s:
        if 'a'<=ch<='z': r.append(chr((ord(ch)-97 - k) % 26 + 97))
        elif 'A'<=ch<='Z': r.append(chr((ord(ch)-65 - k) % 26 + 65))
        else: r.append(ch)
    return ''.join(r)

def score(s):
    t = re.findall(r"[a-záéíóúñü]+", s.lower())
    hits = sum(t.count(w) for w in WORDS)
    return hits + 0.002*sum(c.isalpha() for c in s) + 0.001*s.count(' ')

def extract_cipher(pcap_path):
    flows = defaultdict(list)
    with PcapReader(pcap_path) as pr:
        for pkt in pr:
            if not (pkt.haslayer(IP) and pkt.haslayer(ICMP) and pkt.haslayer(Raw)): continue
            ic = pkt[ICMP]
            if ic.type != 8 or ic.code != 0: continue
            d = bytes(pkt[Raw].load)
            ch = None
            
            # Ajustado al payload de 56 bytes inyectado por pingv4.py
            if len(d) == 56 and d[16:] == PAD_40: 
                ch = chr(d[8])
                
            if ch: flows[(pkt[IP].src, pkt[IP].dst, ic.id)].append(ch)
            
    if not flows: return ""
    key = max(flows, key=lambda k: len(flows[k]))
    return ''.join(flows[key])

def main():
    if len(sys.argv) < 2:
        print("Uso: python3 readv2.py <captura.pcapng>")
        sys.exit(1)
        
    cipher = extract_cipher(sys.argv[1])
    if not cipher:
        print("No se encontraron Echo Requests válidos.")
        sys.exit(2)

    best_score, best_k, lines = -1, 0, []
    
    for k in range(26):
        dec = caesar(cipher, k)
        sc  = score(dec)
        lines.append((k, dec, sc))
        if sc > best_score: best_score, best_k = sc, k

    for k, dec, _ in lines:
        print(f"{GREEN}    {k:2d}         {dec}{RESET}" if k == best_k else f"    {k:2d}         {dec}")

if __name__ == "__main__":
    main()

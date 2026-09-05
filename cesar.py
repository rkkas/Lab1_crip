import sys

def cifrado_cesar(texto: str, corrimiento: int) -> str:
    k = corrimiento % 26
    out = []
    for ch in texto:
        if 'a' <= ch <= 'z':
            out.append(chr((ord(ch) - ord('a') + k) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z':
            out.append(chr((ord(ch) - ord('A') + k) % 26 + ord('A')))
        else:
            out.append(ch)  # espacios, signos, acentos, números, etc.
    return ''.join(out)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print('Uso: python3 cesar.py "texto a cifrar" <corrimiento>')
        sys.exit(1)
    texto = sys.argv[1]
    corrimiento = int(sys.argv[2])
    print(cifrado_cesar(texto, corrimiento))

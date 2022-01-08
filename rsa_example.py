#POKAZANIE JAK DZIAŁA RSA Z FUNKCJĄ SKRÓTU SHA256

import random
from hashlib import sha256
from Crypto.Util import number

def coprime(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def extended_gcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient * x, x
        y, lasty = lasty - quotient * y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)


# rozszerzony algorytm Euklidesa do znajdowania odwrotności multiplikatywnej dwóch liczb
def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Odwrotność modularna nie istnieje')
    return x % m


def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num ** 0.5) + 2, 2):
        if num % n == 0:
            return False
    return True


def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError('Obie liczby muszą być pierwsze.')
    elif p == q:
        raise ValueError('p i q nie mogą być równe')

    n = p * q

    # phi to tocjent n
    phi = (p - 1) * (q - 1)

    # wybierz liczbe e taka ze e i phi(n) sa wzglednie pierwsze
    e = random.randrange(1, phi)

    # uzycie algorymtu euklidesa do zweryfikowania czy e i phi(n) sa wzglednie pierwsze
    g = coprime(e, phi)

    while g != 1:
        e = random.randrange(1, phi)
        g = coprime(e, phi)

    # uzycie Rozszerzonego Algorytmu Euklidesa do wygenerowania prywatnego klucza
    d = modinv(e, phi)

    # Return public and private keypair
    # zwroc pare kluczy: publiczny i prywatny
    # klucz publiczny jest w formacie (e, n)
    # klucz prywatny jest w formacie (d, n)
    return ((e, n), (d, n))


def encrypt(privatek, plaintext):
    # rozpakuj klucz na skladowe
    key, n = privatek

    # przekonwertuj kazda litere w tekscie jawnym na liczby bazujące na literach uzywajac a^b mod m

    numberRepr = [ord(char) for char in plaintext]
    print("Number representation before encryption: ", numberRepr)
    cipher = [pow(ord(char), key, n) for char in plaintext]

    # zwroc liste
    return cipher


def decrypt(publick, ciphertext):
    # rozpakuj klucz na skladowe
    key, n = publick

    # wygeneruj tekst jawny oparty na szyfrogramie i kluczu uzywajac a^b mod m
    numberRepr = [pow(char, key, n) for char in ciphertext]
    plain = [chr(pow(char, key, n)) for char in ciphertext]

    # print("Decrypted number representation is: ", numberRepr)
    print("Odszyfrowany zapis liczbowy to: ", numberRepr)
    # zwroc liste jako string
    return ''.join(plain)


def hashFunction(message):
    hashed = sha256(message.encode("UTF-8")).hexdigest()
    return hashed


def verify(receivedHashed, message):
    ourHashed = hashFunction(message)
    if receivedHashed == ourHashed:
        print("Weryfikacja zakończyła się powodzeniem: ", )
        print(receivedHashed, " = ", ourHashed)
    else:
        print("Weryfikacja nie powiodła się")
        print(receivedHashed, " != ", ourHashed)


def main():
    # p = int(input("Wprowadź liczbę pierwszą: "))
    # q = int(input("Wprowadz inną liczbę pierwszą: (różną od wprowadzonej powyżej): "))
    # p =
    # q =
    p = number.getPrime(208)
    q = number.getPrime(208)

    print("Generowanie pary kluczy . . .")
    public, private = generate_keypair(p, q)

    print("Twoj klucz publiczny to ", public, " i twoj klucz prywatny to ", private)
    message = input("Wprowadz wiadomosc do zaszyfrowania kluczem prywatnym: ")
    print("")

    hashed = hashFunction(message)

    print("Szyfrowanie wiadomosci kluczem prywatnym ", private, " . . .")
    encrypted_msg = encrypt(private, hashed)
    print("Twoja zaszyfrowana wiadomosc to: ")
    print(''.join(map(lambda x: str(x), encrypted_msg)))
    # print(encrypted_msg)

    print("")
    print("Odszyfrowywanie wiadomosci z kluczem publicznym ", public, " . . .")

    decrypted_msg = decrypt(public, encrypted_msg)
    print("Odszyfrowana wiadomosc:")
    print(decrypted_msg)

    print("")
    print("Proces weryfikacji . . .")
    verify(decrypted_msg, message)


if __name__ == "__main__":
    main()

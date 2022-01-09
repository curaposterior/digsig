"""digicheck - create and verify signatures for files

Usage:
  digsig.py keys <bitsnum>
  digsig.py public <keyfilename>
  digsig.py sign <filename> <keyfilename> <sig_file>
  digsig.py check <filename> <keyfilename> <sig_file>
  digsig.py (-h | --help)

argument keys: generuje klucze
argument public: wyswietla klucz publiczny
argument sign: tworzy podpis
argument check: sprawdza prawdziwosc podpisu
argument -h: pomoc

Skrypt potrafi: wygenerować klucze, stworzyć
podpis dla pliku oraz sprawdzić autentyczność
pliku na podstawie klucza publicznego.

Aby program działał poprawnie zainstaluj
wszystkie paczki przy użyciu komendy:
pip install -r requirements.txt

Options:
  -h --help     Pokaz tą wiadomość.
"""

import docopt  #proste menu i pobieranie argumentow z powloki
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Signature import PKCS1_v1_5


#generowanie kluczy
def generate_keys(bytesNumber=4096):
    randomGenerator = Random.new().read
    key = RSA.generate(bytesNumber, randomGenerator)
    return (key, key.exportKey('PEM'), key.publickey().exportKey('PEM')) #zwracamy dwa klucze w formacie pem

  
def generate_signature(key, data, sig_f):
    print("Generating Signature")
    with open(data, 'rb') as f:
        data = f.read()
    with open(key, 'rb') as f:
        key = f.read()
    h = SHA256.new(data)
    rsa = RSA.importKey(key)
    signer = PKCS1_v1_5.new(rsa)
    signature = signer.sign(h)
    with open(sig_f, 'wb') as f:
        f.write(signature)


def verify_signature(key, data, sig_f):
    print("Sprawdzanie podpisu")
    with open(key, 'rb') as f:
        key = f.read()
    with open(data, 'rb') as f:
        data = f.read()
    h = SHA256.new(data)
    rsa = RSA.importKey(key)
    signer = PKCS1_v1_5.new(rsa)
    with open(sig_f, 'rb') as f:
        signature = f.read()
    rsp = "Success" if (signer.verify(h, signature)) else "\nVerification Failure"
    print(rsp)


if __name__ == '__main__':
    args = docopt.docopt(__doc__)
    if args["keys"]:
        key_set = generate_keys(int(args["<bitsnum>"]))

        with open("private.pem", 'wb') as f:
            f.write(key_set[1])
        with open("public.pem", 'wb') as f:
            f.write(key_set[2])

        print("Wygenerowane klucze w formacie pem:")
        print(key_set[1].strip().decode())
        print(key_set[2].strip().decode())
        print("\nPliki zapisane pod nazwami: private.pem, public.pem")

    elif args["public"]:
        with open(args["<keyfilename>"], 'r') as f:
            print(f.read().split("\n\n")[0].strip())

    elif args["sign"]:
        generate_signature(args["<keyfilename>"], args["<filename>"], args["<sig_file>"])
        
    elif args["check"]:
        verify_signature(args["<keyfilename>"], args["<filename>"], args["<sig_file>"])
        pass

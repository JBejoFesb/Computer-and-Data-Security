# Sigurnost računala i podataka

# **Lab 1: Man-in-the-middle attacks (ARP spoofing)**

Ranjivosti ARP-a (Address Resolution Protocol) mogu se koristiti kao alat za zlonamjerne napade na povjerljivost, integritet te pristup podacima ili assetima žrtve.

ARP Spoofing je vrsta aktivnog man in the middle napada koji narušavanjem integriteta podataka neke žrtve može pratiti njen promet te prisluškivati poruke ukoliko one nisu kriptirane.

Unutar vježbe napad je izveden preko 3 docker kontenjera koji su kao postavljene virtualke glumile dvije žrtve i jednog napadača.

Napad se može izvesti na LAN mreži u kojoj se koristi ARP.

Napadač se konstantnim slanjem ARP replayeva predstavlja IP-em druge žrtve te prva žrtva nastavlja slati podatke na IP-adresu druge žrtve. To slanje podataka nije prekinuto na putu do druge žrtve jer napadač može samo preusmjeriti sav promet nazad na ispravnu MAC adresu.
Preusmjerivač ne zna kome pripada prava adresa te raspoznaje korisnike samo preko MAC adresi.
Tako napadač makar ima IP adresu druge žrtve i dalje prima podatke preko svoje MAC adrese.

![Untitled](Sigurnost%20rac%CC%8Cunala%20i%20podataka/Untitled.png)

Nakon početnog preuzimanja kontenjera koristeći assete sa profesorovog github repositorija-a započinjemo vježbu lansiranjem 3 kontenjera i namještanjem njihovih konfiguracija.

Naredbe ispod koriste se za pokretanje virtualki i njihovo gašenje:

```jsx
./start.sh
./stop.sh
```

Lista kontenjera nakon kreacije:

```c
$ docker ps
CONTAINER ID   IMAGE     COMMAND   CREATED          STATUS          PORTS     NAMES
0aa3d7578129   srp/arp   "bash"    44 minutes ago   Up 44 minutes             station-2
fa260ad1d321   srp/arp   "bash"    44 minutes ago   Up 44 minutes             evil-station
6af3c3a52583   srp/arp   "bash"    44 minutes ago   Up 44 minutes             station-1
```

Pokretanje kontenjera:

```c
docker exec -it station-1 bash
docker exec -it station-2 bash
docker exec -it evil-station bash
```

Spajanje dvije žrtve preko netcat servisa i test slanja u oba smjera:

![Untitled](Sigurnost%20rac%CC%8Cunala%20i%20podataka/Untitled%201.png)

```c
Korištene su naredbe:

netcat -lp 8080

za otvaranje servera, te:

netcat station-2 8080

za spajanje na server stanice 2 sa stanice 1
```

Napad se izvršava preko evil-stanice naredbom arpspoof i njezine konfiguracije nakon koje slijedi slanje arp replayeva žrtvi 1.

```c
arpspoof -t station-1 station-2
2:42:ac:12:0:3 2:42:ac:12:0:2 0806 42: arp reply 172.18.0.4 is-at 2:42:ac:12:0:3
2:42:ac:12:0:3 2:42:ac:12:0:2 0806 42: arp reply 172.18.0.4 is-at 2:42:ac:12:0:3
2:42:ac:12:0:3 2:42:ac:12:0:2 0806 42: arp reply 172.18.0.4 is-at 2:42:ac:12:0:3
```

Naredbom tcpdump kreće praćenje prometa žrtvi.

![Untitled](Sigurnost%20rac%CC%8Cunala%20i%20podataka/Untitled%202.png)

AR Protokol, odnosnje njegove slabosti mogu se koristiti i za napad na dostupnost korisnikovih podataka. 
Denial of service ili reduction of service napadi izvode se gušenjem prometa jedne od žrtviju floodanjem te žrtve sa arp replayevima.

# **Lab 2: Symmetric key cryptography - a crypto challenge**

U sklopu 2. vježbe proučavali smo proces kriptiranja i dekriptiranja u uvjetima enkripcije sa simetričnim ključem.

Kao glavni alat smo koristili [Fernet](https://cryptography.io/en/latest/fernet/).

Fernet koristi navedene kriptografske mehanizme manje kompleksije:

- AES šifru sa 128 bitnim ključem
- CBC enkripcijski način rada
- HMAC sa 256 bitnim ključem za zaštitu integriteta poruka
- Timestamp za osiguravanje svježine (*freshness*) poruka

Vježbi je dodan izazov dekripcije u kojemu je ime datoteke ključ, a datoteka sadrži ciphertext koji se dekripcijom pretvara u png koji čestita korisniku.

Ispravan ključ za dekripciju pronalazimo brute-force napadamo te koristimo aplikaciju koja radi na jednoj jezgri ili na više njih.

Rad jezgri može se provjeriti preko task managera, gdje smo pri kraju vježbe utvrdili ispravnost koda i njegovo korištenje resursa (laptop u laboratoriju sadrži i5 7500u čiji je thread bio na 50% iskorištenosti pri rješavanju 20-bitne entropije).

![Untitled](Sigurnost%20rac%CC%8Cunala%20i%20podataka/Untitled%203.png)

Program korišten za napad zasniva se na python jeziku i beskonačnom while loop-u koji uspoređuje dekriptirani plaintext sa zaglavljem datoteke u kojoj se nalaze informacije o samoj datoteci kao njezin tip (u ovom slučaju png).

**Pokretanje python virtualke**

```bash
python -m venv jbejo
```

**Instalacija i importanje Ferneta**

```bash
pip install cryptography
from cryptography.fernet import Fernet
```

**Kod za generiranje hasha baziran na našem imenu**

```bash
from cryptography.hazmat.primitives import hashes

def hash(input):
    if not isinstance(input, bytes):
        input = input.encode()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(input)
    hash = digest.finalize()

    return hash.hex()

if __name__=="__main__":
    h = hash('bejo_jakov')
    print(h)
```

Hash je 256 bitni jer koristimo Secure Hash Algorithm 256 za njegovo generiranje.

K**od za brute-force napad na 20-bitnu entropiju**

```python
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

def hash(input):
    if not isinstance(input, bytes):
        input = input.encode()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(input)
    hash = digest.finalize()

    return hash.hex()

def test_png(header):
    if header.startswith(b"\211PNG\r\n\032\n"):
        return True

def brute_force():
    filename = "3f7699d1bc4ee53a3e8f24bfd2577a150260f938f45b8d6a538819129263bd13.encrypted"
    # Reading from a file
    with open(filename, "rb") as file:
        ciphertext = file.read()

    ctr = 0
    while True:
        key_bytes = ctr.to_bytes(32, "big")
        key = base64.urlsafe_b64encode(key_bytes)

        if not (ctr + 1) % 1000:
            print(f"[*] Keys tested: {ctr + 1:,}", end="\r")

        try:
            plaintext = Fernet(key).decrypt(ciphertext)

            header = plaintext[:32]
            if test_png(header):
                print(f"[+] KEY FOUND: {key}")
                # Writing to a file
                with open("BINGO.png", "wb") as file:
                    file.write(plaintext)
                break

        except Exception:
            pass

        ctr += 1

if __name__ == "__main__":
    # hash_value = hash("cagalj_mario")
    # print(hash_value)
    brute_force()
```

Entropija od 20 bita probijena je u približno minutu. Ključ statistički nalazimo na otprilike pola mogućeg keyspace-a. 

![Untitled](Sigurnost%20rac%CC%8Cunala%20i%20podataka/Untitled%204.png)

Kada bi pokušali entropiju od 22 bita gurati na jednoj jezgri trajalo bi puno duže i stoga koristimo više-jezgreni program.

**Pseudo kod za napad na 22-bitnu entropiju**

```python
from multiprocessing import Pool

def brute_force(filename, chunk_start_index, chunk_size):
    ctr = 0

    filename = "ime datoteke"
				    with open(filename, "rb") as file:
				        ciphertext = file.read()
				
				while True:
				    key_bytes = ctr.to_bytes(32, "big")
				    key = base64.urlsafe_b64encode(key_bytes)
						
				    try:
				         plaintext = Fernet(key).decrypt(ciphertext)
				         print(key, plaintext)
				         break
				
				    except Exception:
				          pass
				
				    ctr += 1

def parallelize_attack(filename, key_entropy):
    # Split the keyspace into equally sized chunks;
    # the number of chunks corresponds to the number
    # of CPU cores on your system.
    total_keys = 2**key_entropy
    chunk_size = int(total_keys/os.cpu_count())

    with Pool() as pool:
        def key_found_event(event):
            print("Terminating the pool ...")
            pool.terminate()

        # Start parallel workers
        for chunk_start_index in range(0, total_keys, chunk_size):
            pool.apply_async(
                brute_force,
                (
                    filename,
                    chunk_start_index,
                    chunk_size,
                ),
                callback=key_found_event
            )

        pool.close()
        pool.join()
```

**Naredba za pronalazak broja jezgri procesora**

```python
os.cpu_count
```

Napad sa više jezgri ćemo izvršiti tako da raspodijelimo keyspace na onoliko dijelova koliko jezgri imamo, i time masivno ubrzamo napad.

# **Lab 3: Message authentication and integrity**

Vježba 3 posvećena je upoznavanju sa osnovama kriptografije i mehanizmima za autentikaciju i zaštitu integriteta poruka.
Prvi dio svodi se na praktično korištenje MAC (message authentication code) kako bi očuvali integritet poruke. Sustav je simetričan jer obe strane imaju isti ključ K koji u kombinaciji sa MAC algoritmom daje dodatak na samu poruku koji se na drugom kraju provjerava. Ukoliko je integritet bio narušen MAC kojeg je druga strana izračunala neće biti jednak onome koji je dostavljen uz poruku.

**Kod za generiranje MAC-a**

```python
from cryptography.hazmat.primitives import hashes, hmac

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature

if __name__ == "__main__":
    key = b"ainotnA"
    message = "ILAntonia"
    mac = generate_MAC(key, message)

    print(mac)
```

**Output u CMD-u**

![Untitled](Sigurnost%20rac%CC%8Cunala%20i%20podataka/Untitled%205.png)

Proces generiranja i provjere ključa može se izvesti i korištenjem textualnih datoteka koje možemo pročitati. U ovom primjeru MAC spremamo u datoteka.sig (signature).

**Kod za generiranje MAC-a iz tekstualne datoteke**

```python
from cryptography.hazmat.primitives import hashes, hmac

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature

if __name__ == "__main__":

    with open("datoteka.txt", "rb") as file:
        content = file.read()

    key = b"ainotnA"

    mac = generate_MAC(key, content)

    with open("datoteka.sig", "wb") as file:
        file.write(mac)

    print(mac)
```

MAC koji je zapisan u .sig datoteci je u binarnom obliku:

@‡ö²FØ»è”4µœ5+º\épûu'ap¼9Ò»¼

**Kod za provjeru MAC-a iz datoteka.sig**

```python
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature

def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True

if __name__ == "__main__":

    with open("datoteka.txt", "rb") as file:
        content = file.read()

    with open("datoteka.sig", "rb") as file:
        signature = file.read()

    key = b"ainotnA"

    ver = verify_MAC(key, signature, content)

    print(ver)

    # mac = generate_MAC(key, content)

    # with open("datoteka.sig", "wb") as file:
    #     file.write(mac)
```

Nakon osnova funkcioniranja MAC-a krenuli smo rješavati challange.
Zadatak se započinje sa preuzimanjem poruka i njihovih digitalnih potpisa koji se nalaze na A507 serveru sa "wget download" aplikacijom.

Ključ za MAC algoritam dan je imenom i prezimenom studenta, a cilj je napraviti kod koji će vrtiti loop koji će izlistati savjete za kupovinu Teslinih dionica po vremenski točnom redu. 

Kod funkcionira tako da po redu otvara .sig i .txt datoteke te ukoliko generirani MAC odgovara MAC-u dobivenom iz poruke, poruka je zadržala integritet i smije ju se prikazati.

Usporedba se ne smije vršiti na standardni način već se koristi naredba "h.verify(signature)" koja je kompleksnija od same usporedbe.

Na kraju te poruke treba rasporediti po timestampu i dobit ćemo ispravan savjet za kupnju ili prodaju dionica.
**Primjer .txt i .sig datoteka**

[challenges.zip](Sigurnost%20rac%CC%8Cunala%20i%20podataka/challenges.zip)

**Kod za challange**

```python
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature

def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True

if __name__ == "__main__":

    for ctr in range(1,11):
        msg_filename = f"order_{ctr}.txt"
        sig_filename = f"order_{ctr}.sig"
        with open(msg_filename, "rb") as file:
            content = file.read()  
        with open(sig_filename, "rb") as file:
            signature = file.read() 

        key = "bejo_jakov".encode()
        is_authentic = verify_MAC(key, signature, content)
        print(f'Message {content.decode():>45} {"OK" if is_authentic else "NOK":<6}')
```

Sljedeći zadatak bio je dovršiti kod za provjeru digitalnog potpisa.

Javnim ključem kojeg smo našli na serveru (svi imaju isti javni ključ, a profesor je enkriptirao potpis sa privatnim ključem) moramo dobiti jednaki potpis kao što je bio onaj dobiven kao par slike.

Jedan od parova nema ispravan potpis dok je drugi prošao provjeru kako treba.

**Kod za učitavanje public key-a i verifikaciju potpisa**

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def load_public_key():
    with open("public.pem", "rb") as f:
        PUBLIC_KEY = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return PUBLIC_KEY

def verify_signature_rsa(signature, message):
    PUBLIC_KEY = load_public_key()
    try:
        PUBLIC_KEY.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        return False
    else:
        return True

if __name__ == "__main__":

    with open("image_1.png", "rb") as file:
        image = file.read()

    with open("image_1.sig", "rb") as file:
        sig = file.read()

    with open("image_2.png", "rb") as file:
        image2 = file.read()

    with open("image_2.sig", "rb") as file:
        sig2 = file.read()

    print(verify_signature_rsa(sig,image))
    print(verify_signature_rsa(sig2,image2))
```

**Rezultat u CMD-u:**

![Untitled](Sigurnost%20rac%CC%8Cunala%20i%20podataka/Untitled%206.png)

# **Lab 4: Password-hashing (iterative hashing, salt, memory-hard functions)**

Lozinke su trenutno najkorišteniji alat za autentikaciju korisnika. U 4. vježbi smo se upoznali sa nekoliko načina za usporavanje probijanja lozinki.

"Iterative hashing" je strategija u kojoj administrator sustava daje kompromis između brzine i sigurnosti. Svaka lozinka se hashira, a potom se i taj hash value može hashirati koliko god je to potrebno puta. Svaka iteracija dodatno usporava sistem.

"Salt" je dodavanje randomiziranih textualnih podataka na samu lozinku koje su često jedinstvene za svakog korisnika. Služi kako bi učinilo pre-computed dictionary-e beskorisnima jer sigurno nemaju taj hash value već u sebi. Napadaču vrijeme za probijanje eksponencijalno raste i može žrtvi "staviti soli na rep".

Memory hard funkcije su kriptografske hash funkcije koje zahtjevaju ogromne količine memorije za stvaranje hash vrijednosti pa se stavlja dodatni napor na resurse napadača i smanjuje ekonomska dobit, a samim time i vjerojatnost napada.

**Kod za usporedbu okvirnog vremena potrebnog za stvaranje hash vrijednosti za nekoliko popularnijih hashfunkcija**

```python
from os import urandom
from prettytable import PrettyTable
from timeit import default_timer as time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from passlib.hash import sha512_crypt, pbkdf2_sha256, argon2

def time_it(function):
    def wrapper(*args, **kwargs):
        start_time = time()
        result = function(*args, **kwargs)
        end_time = time()
        measure = kwargs.get("measure")
        if measure:
            execution_time = end_time - start_time
            return result, execution_time
        return result
    return wrapper

@time_it
def aes(**kwargs):
    key = bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    ])

    plaintext = bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ])

    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    encryptor.update(plaintext)
    encryptor.finalize()

@time_it
def md5(input, **kwargs):
    digest = hashes.Hash(hashes.MD5(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def sha256(input, **kwargs):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def sha512(input, **kwargs):
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def pbkdf2(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = b"12QIp/Kd"
    rounds = kwargs.get("rounds", 10000)
    return pbkdf2_sha256.hash(input, salt=salt, rounds=rounds)

@time_it
def argon2_hash(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = b"0"*22
    rounds = kwargs.get("rounds", 12)              # time_cost
    memory_cost = kwargs.get("memory_cost", 2**10) # kibibytes
    parallelism = kwargs.get("rounds", 1)
    return argon2.using(
        salt=salt,
        rounds=rounds,
        memory_cost=memory_cost,
        parallelism=parallelism
    ).hash(input)

@time_it
def linux_hash_6(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = "12QIp/Kd"
    return sha512_crypt.hash(input, salt=salt, rounds=5000)

@time_it
def linux_hash(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = kwargs.get("salt")
    rounds = kwargs.get("rounds", 5000)
    if salt:
        return sha512_crypt.hash(input, salt=salt, rounds=rounds)
    return sha512_crypt.hash(input, rounds=rounds)

@time_it
def scrypt_hash(input, **kwargs):
    salt = kwargs.get("salt", urandom(16))
    length = kwargs.get("length", 32)
    n = kwargs.get("n", 2**14)
    r = kwargs.get("r", 8)
    p = kwargs.get("p", 1)
    kdf = Scrypt(
        salt=salt,
        length=length,
        n=n,
        r=r,
        p=p
    )
    hash = kdf.derive(input)
    return {
        "hash": hash,
        "salt": salt
    }

if __name__ == "__main__":
    ITERATIONS = 100
    password = b"super secret password"

    MEMORY_HARD_TESTS = []
    LOW_MEMORY_TESTS = []

    TESTS = [
        {
            "name": "AES",
            "service": lambda: aes(measure=True)
        },
        {
            "name": "HASH_MD5",
            "service": lambda: sha512(password, measure=True)
        },
        {
            "name": "HASH_SHA256",
            "service": lambda: sha512(password, measure=True)
        },
				{
		        "name": "Linux CRYPT",
            "service": lambda: linux_hash(password, measure=True)
        },
        {
            "name": "Linux CRYPT 1M",
            "service": lambda: linux_hash(password, rounds=10**5, measure=True)
        }
    ]

    table = PrettyTable()
    column_1 = "Function"
    column_2 = f"Avg. Time ({ITERATIONS} runs)"
    table.field_names = [column_1, column_2]
    table.align[column_1] = "l"
    table.align[column_2] = "c"
    table.sortby = column_2

    for test in TESTS:
        name = test.get("name")
        service = test.get("service")

        total_time = 0
        for iteration in range(0, ITERATIONS):
            print(f"Testing {name:>6} {iteration}/{ITERATIONS}", end="\r")
            _, execution_time = service()
            total_time += execution_time
        average_time = round(total_time/ITERATIONS, 6)
        table.add_row([name, average_time])
        print(f"{table}\n\n")

            "name": "Linux CRYPT",
            "service": lambda: linux_hash(password, measure=True)
        },
        {
            "name": "Linux CRYPT 1M",
            "service": lambda: linux_hash(password, rounds=10**5, measure=True)
        }

```

![Untitled](Sigurnost%20rac%CC%8Cunala%20i%20podataka/Untitled%207.png)

Vidimo iz primjera da korištenjem različitih funkcija imamo različit kompromis između sigurnosti i brzine. 

SHA256 i MD5 mogu generirati vrijednost u već nekoliko desetaka mikrosekundi dok funkcije poput Linux Crypt imaju popričino sporije vrijeme, to se može dodatno usporiti sa iterativnim hashiranjem.

---

# **Lab 5: Online and Offline Password Guessing Attacks**

---

Cilj vježbe bio je napad na virtualku (docker) zaštićen lozinkom. Cilj je probiti autentikaciju

Koristili smo online i offline vrstu napada. Online napad preko danog korisničkog imena i IP adrese pokušava prijavu u sustav koristeći neku od lozinki is odabranog “dictionary-a”.

U offline napadu pokušavamo probiti autentikaciju tako da napadamo lokalno spremljeni hash šifre.

---

U svrhu online napada koristimo Nmap alat za pretraživanje mreža kako bi uspostavili na kojem portu i preko kojeg protokola je uspostavljen Secure Shell sustav. 

![Untitled](Sigurnost%20rac%CC%8Cunala%20i%20podataka/Untitled%208.png)

Naravno bez da znamo šifru ne možemo ući u SSH pa s toga koristimo alat Hydra kako bi iz pre-compiled dictionarya pokušali pogodoiti šifru. Ovo je u suštini brute force napad pa više računalne snage daje bolje rezultate.

`# hydra -l <username> -x 4:6:a <your IP address> -V -t 1 ssh`

Parametar -t određuje thredove na kojima će se proces izvoditi, ukoliko za parametar postavimo 4 

Hydra dobija dopuštenje od OS-a da iskoristi 4 niti procesora. Kako je na laptopima u labosu procesor starije klase, očekivano, Hydra gotovo u potpunosti koristi njegove resurse, a pritom koristi i određenu količinu memorije.

![Untitled](Sigurnost%20rac%CC%8Cunala%20i%20podataka/Untitled%209.png)

Broj mogućih šifri iz rječnika je ogroman, pa ćak i sa 4 threada ovdje govorimo o dužem vremenu napada. Stoga koristimo manji rječnik u kojemu je namjerno postavljena naša šifra.

![Untitled](Sigurnost%20rac%CC%8Cunala%20i%20podataka/Untitled%2010.png)

Nakon 15 minuta šifra biva pronađena i možemo se uspješno ulogirati u SSH.

![Untitled](Sigurnost%20rac%CC%8Cunala%20i%20podataka/Untitled%2011.png)

---

Offline napad izvodimo korištenjem offline dictionarya i alata HashCat koji na temelju lokalno spremljenih hasheva radi usporedbe i time “crackira šifru”.

![Untitled](Sigurnost%20rac%CC%8Cunala%20i%20podataka/Untitled%2012.png)

Ovisno o entropiji hash se može naći na svega nekoliko posto kao kod kolegice Bartulović, ali može i potrajati. Prosječno vrijeme je 50%, a u mom slučaju HashCat je prošao oko 40% dictionarya.

Aplikacija nas uredno obavijesti da je lozinka cracked te je možemo testirati.

![Untitled](Sigurnost%20rac%CC%8Cunala%20i%20podataka/Untitled%2013.png)

U ovom slučaju lozinka je jednaka kao kod online napada te pri upisu u SSH uredno prolazi autentikaciju. Napadač sada može pristupiti SSH sustavu. 

![Untitled](Sigurnost%20rac%CC%8Cunala%20i%20podataka/Untitled%2014.png)

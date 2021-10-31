# Sigurnost računala i podataka

# **Lab 1: Man-in-the-middle attacks (ARP spoofing)**

Ranjivosti ARP-a (Address Resolution Protocol) mogu se koristiti kao alat za zlonamjerne napade na povjerljivost, integritet te pristup podacima ili assetima žrtve.

ARP Spoofing je vrsta aktivnog man in the middle napada koji narušavanjem integriteta podataka neke žrtve može pratiti njen promet te prisluškivati poruke ukoliko one nisu kriptirane.

Unutar vježbe napad je izveden preko 3 docker kontenjera koji su kao postavljene virtualke glumile dvije žrtve i jednog napadača.

Napad se može izvesti na LAN mreži u kojoj se koristi ARP.

Napadač se konstantnim slanjem ARP replayeva predstavlja IP-em druge žrtve te prva žrtva nastavlja slati podatke na IP-adresu druge žrtve. To slanje podataka nije prekinuto na putu do druge žrtve jer napadač može samo preusmjeriti sav promet nazad na ispravnu MAC adresu.
Preusmjerivač ne zna kome pripada prava adresa te raspoznaje korisnike samo preko MAC adresi.
Tako napadač makar ima IP adresu druge žrtve i dalje prima podatke preko svoje MAC adrese.

![Untitled](Sigurnost%20rac%CC%8Cunala%20i%20podataka%20cf05a4c0356347b09ec176f528693f45/Untitled.png)

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

![Untitled](Sigurnost%20rac%CC%8Cunala%20i%20podataka%20cf05a4c0356347b09ec176f528693f45/Untitled%201.png)

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

![Untitled](Sigurnost%20rac%CC%8Cunala%20i%20podataka%20cf05a4c0356347b09ec176f528693f45/Untitled%202.png)

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

![Untitled](Sigurnost%20rac%CC%8Cunala%20i%20podataka%20cf05a4c0356347b09ec176f528693f45/Untitled%203.png)

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

**Nedovršeni kod za brute-force napad na 20-bitnu entropiju**

```python
import base64
from cryptography.fernet import Fernet

def brute_force():
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

if __name__=="__main__":
    brute_force()
```

Entropija od 20 bita probijena je u približno minutu. Ključ statistički nalazimo na otprilike pola mogućeg keyspace-a. 

Kada bi pokušali entropiju od 22 bita gurati na jednoj jezgri trajalo bi puno duže i stoga koristimo više-jezgreni program.

**Nedovršeni kod za napad na 22-bitnu entropiju**

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
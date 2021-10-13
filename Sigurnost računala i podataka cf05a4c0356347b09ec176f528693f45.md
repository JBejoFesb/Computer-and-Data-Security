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
# Jednoduchý packet-sniffer, IPK druhý projekt
#### Autor: Veronika Molnárová

---

## Popis projektu
Projekt pozostáva z vytvorenia packet snifferu implementovaného v jazyku C. Na základe zadaných argumentov, program vyhladáva dané typy packetov na danom rozhlaní a portoch a získava z nich požadované informácie, ktoré vypisuje na standardný výstup. 

## Zpôsob spúšťania projektu

K danému projektu je priložený súbor Makefile slúžiaci na preloženie projektu. Projekt sa prekladá pomocou zavolania príkažu *make*, ktorý vytvorí spustitelný súbor **ipk-sniffer**. V prípade zavolania programu s nesprávnou syntaxou je užívateľovi vypísaná nápoveda. Po spustení programu, sniffer čaká na požadované packety na danom rozhraní, z ktorých následne získava požadované informácie, ktoré vypisuje štandardný výstup. Program je potrebé spúšťať ako *super-user* alebo spoločne s príkazom *sudo*. Program je možné počas behu sa ukončiť pomocou signálu CTRL+C.

Príklad spustenia programu:
```sh
$ make
gcc -o packet_sniffer.o -c packet_sniffer.c -lpcap
gcc -o ipk-sniffer packet_sniffer.o -lpcap
$ sudo ./ipk-sniffer
```

## Príklady použitia projektu

```sh
$ sudo ./ipk-sniffer
eth0
lo
any
bluetooth-monitor
nflog
```

```sh
$ sudo ./ipk-sniffer -i ens33 --icmp
timestamp: 2022-04-23T14:35:45.484+01:00
src MAC: 00:08:29:28:c7:af
dst MAC: 00:50:50:ea:24:41
frame length: 98 bytes
src IP: 192.167.217.118
dst IP: 143.231.37.121

0x0000:  00 50 50 EA 24 41 00 08  29 28 C7 AF 08 00 45 00  .PV.TF.. )X....E.
0x0010:  00 54 89 06 40 00 40 01  59 10 C0 A8 E3 80 8E FB  .T..@.@. Y.......
0x0020:  25 6E 08 00 80 6F 00 04  00 01 A1 F2 63 62 00 00  %n...o.. ....cb..
0x0030:  00 00 AC 63 07 00 00 00  00 00 10 11 12 13 14 15  ...c.... ........
0x0040:  16 17 18 19 1A 1B 1C 1D  1E 1F 20 21 22 23 24 25  ........ .. !"#$%
0x0050:  26 27 28 29 2A 2B 2C 2D  2E 2F 30 31 32 33 34 35  &'()*+,- ./012345
0x0060:  36 37  67
```

```sh
$ sudo ./ipk-sniffer -i ens33 -p 8080 --icmp --arp --tcp -n 2
timestamp: 2022-04-23T14:39:59.879+01:00
src MAC: 00:1c:29:78:c4:aa
dst MAC: ff:ff:ff:ff:ff:ff
frame length: 58 bytes
src IP: 192.167.217.118
dst IP: 128.222.113.27

0x0000:  FF FF FF FF FF FF 00 1C  29 78 C4 AA 08 06 00 01  ........ )X......
0x0010:  08 00 06 04 00 01 00 0C  29 58 C3 AF C0 A8 E3 80  ........ )X......
0x0020:  00 00 00 00 00 00 80 DE  71 1B 00 00 00 00 00 00  ........ q.......
0x0030:  00 00 00 00 00 00 00 00  00 00  ........ ..

timestamp: 2022-04-23T14:40:09.814+01:00
src MAC: 00:1c:29:78:c4:aa
dst MAC: 00:51:56:ea:73:26
frame length: 98 bytes
src IP: 192.167.217.118
dst IP: 142.221.37.121

0x0000:  00 51 56 EA 73 26 00 1C  29 78 C4 AA 08 00 45 00  .PV.TF.. )X....E.
0x0010:  00 54 1A 82 40 00 40 01  C7 94 C0 A8 E3 80 8E FB  .T..@.@. ........
0x0020:  25 6E 08 00 42 63 00 05  00 01 A9 F3 63 62 00 00  %n..Bc.. ....cb..
0x0030:  00 00 DD 6D 0C 00 00 00  00 00 10 11 12 13 14 15  ...m.... ........
0x0040:  16 17 18 19 1A 1B 1C 1D  1E 1F 20 21 22 23 24 25  ........ .. !"#$%
0x0050:  26 27 28 29 2A 2B 2C 2D  2E 2F 30 31 32 33 34 35  &'()*+,- ./012345
0x0060:  36 37  67

```


V prípade nastania vnútornej chyby počas behu programu je program ukončený s chybovou hláškou na štandardnom chybovom výstupe.

## Zoznam odovzdaných súborov
- Makefile
- packet_sniffer.c
- README.md
- manual.pdf
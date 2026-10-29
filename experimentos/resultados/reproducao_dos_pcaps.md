# Reprodução dos pcaps: incidentes contra a verdade de campo

Gerado por `python -m codigo.reprodutor.avaliar` em 29/10/2026.

Cada pcap do CICIoT2023 usado na regeração passou inteiro pelo reprodutor de tráfego: extrator em
janela de 100 quadros, modelo do sistema com o ponto de operação e a primeira versão da política de
acionamento (`codigo/reprodutor/reprodutor.py`, parâmetros padrão). Os incidentes foram conferidos
com os quadros dos sete atacantes do dataset, identificados pelo MAC. A verdade de campo é só da
avaliação: o sistema não a conhece.

Os pcaps de ataque tiveram o começo no treino do modelo (70% das janelas, ou o arquivo inteiro nos
rótulos com vários pcaps); a coluna "no teste" conta as janelas dos incidentes que ficaram fora do
treino. `DDoS-SYN_Flood1.pcap`, `DoS-SYN_Flood1.pcap` e `BenignTraffic2.pcap` ficaram inteiros fora.

## Pcaps de ataque

| Pcap | Categoria | Janelas | Incidentes | Janelas dos incidentes com atacante | No teste | Origem 1 é atacante | Destino 1 é atacante | Categoria certa | Atraso mediano (s) | Desde o atacante (s) |
|---|---|---|---|---|---|---|---|---|---|---|
| `DictionaryBruteForce.pcap` | BruteForce | 1.306 | 7 | 98,0% | 201 | 5/7 | 0/7 | 3/7 | 3,80 | 6,43 |
| `DDoS-ACK_Fragmentation.pcap` | DDoS | 24.983 | 4 | 100,0% | 6.976 | 3/4 | 1/4 | 2/4 | 1,00 | 1,00 |
| `DDoS-HTTP_Flood-.pcap` | DDoS | 28.755 | 10 | 100,0% | 8.607 | 2/10 | 0/10 | 2/10 | 2,88 | 4,74 |
| `DDoS-ICMP_Flood.pcap` | DDoS | 267.908 | 3 | 100,0% | 80.302 | 2/3 | 0/3 | 1/3 | 0,04 | 1,47 |
| `DDoS-ICMP_Fragmentation.pcap` | DDoS | 20.596 | 4 | 100,0% | 6.147 | 3/4 | 0/4 | 3/4 | 0,84 | 0,84 |
| `DDoS-PSHACK_Flood.pcap` | DDoS | 267.711 | 3 | 100,0% | 80.292 | 3/3 | 0/3 | 3/3 | 0,95 | 1,29 |
| `DDoS-RSTFINFlood.pcap` | DDoS | 266.831 | 3 | 100,0% | 80.041 | 3/3 | 0/3 | 2/3 | 0,04 | 1,90 |
| `DDoS-SYN_Flood.pcap` | DDoS | 265.924 | 4 | 100,0% | 0 | 4/4 | 0/4 | 3/4 | 0,40 | 0,40 |
| `DDoS-SYN_Flood1.pcap` | DDoS | 267.096 | 5 | 100,0% | 266.988 | 5/5 | 0/5 | 4/5 | 0,31 | 0,31 |
| `DDoS-SlowLoris.pcap` | DDoS | 23.390 | 12 | 100,0% | 4.726 | 5/12 | 7/12 | 5/12 | 2,48 | 2,48 |
| `DDoS-SynonymousIP_Flood.pcap` | DDoS | 268.524 | 3 | 100,0% | 80.541 | 3/3 | 0/3 | 0/3 | 1,30 | 4,29 |
| `DDoS-TCP_Flood.pcap` | DDoS | 265.670 | 4 | 100,0% | 79.141 | 3/4 | 0/4 | 3/4 | 0,28 | 1,73 |
| `DDoS-UDP_Flood.pcap` | DDoS | 266.502 | 4 | 100,0% | 79.949 | 3/4 | 0/4 | 3/4 | 0,96 | 2,86 |
| `DDoS-UDP_Fragmentation.pcap` | DDoS | 22.438 | 3 | 100,0% | 6.475 | 1/3 | 1/3 | 1/3 | 1,79 | 1,79 |
| `DoS-HTTP_Flood1.pcap` | DoS | 31.098 | 7 | 99,9% | 8.615 | 4/7 | 2/7 | 6/7 | 0,84 | 1,37 |
| `DoS-SYN_Flood.pcap` | DoS | 262.585 | 3 | 100,0% | 0 | 3/3 | 0/3 | 3/3 | 0,49 | 0,49 |
| `DoS-SYN_Flood1.pcap` | DoS | 264.025 | 4 | 100,0% | 263.890 | 4/4 | 0/4 | 4/4 | 0,03 | 0,37 |
| `DoS-TCP_Flood.pcap` | DoS | 260.027 | 2 | 100,0% | 77.979 | 2/2 | 0/2 | 2/2 | 0,72 | 0,72 |
| `DoS-UDP_Flood.pcap` | DoS | 166.737 | 3 | 100,0% | 49.962 | 3/3 | 0/3 | 3/3 | 0,07 | 0,58 |
| `Mirai-greeth_flood.pcap` | Mirai | 33.500 | 2 | 100,0% | 9.951 | 2/2 | 0/2 | 2/2 | 0,29 | 0,29 |
| `Mirai-greip_flood21.pcap` | Mirai | 11.954 | 1 | 100,0% | 3.585 | 1/1 | 0/1 | 1/1 | 0,12 | 0,12 |
| `Mirai-udpplain.pcap` | Mirai | 36.388 | 5 | 100,0% | 10.763 | 0/5 | 0/5 | 4/5 | 2,89 | 6,65 |
| `Recon-HostDiscovery.pcap` | Recon | 13.436 | 4 | 100,0% | 3.483 | 3/4 | 0/4 | 3/4 | 9,15 | 13,60 |
| `Recon-OSScan.pcap` | Recon | 9.824 | 16 | 100,0% | 877 | 16/16 | 0/16 | 16/16 | 2,55 | 2,56 |
| `Recon-PingSweep.pcap` | Recon | 226 | 2 | 100,0% | 0 | 2/2 | 0/2 | 2/2 | 3,86 | 3,86 |
| `Recon-PortScan.pcap` | Recon | 8.227 | 20 (+14) | 99,6% | 468 | 18/20 | 0/20 | 19/20 | 2,46 | 2,46 |
| `VulnerabilityScan.pcap` | Recon | 37.331 | 20 (+2) | 99,6% | 287 | 5/20 | 5/20 | 20/20 | 8,16 | 9,24 |
| `DNS_Spoofing.pcap` | Spoofing | 17.887 | 20 (+390) | 100,0% | 0 | 0/20 | 1/20 | 20/20 | 8,76 | 8,76 |
| `MITM-ArpSpoofing.pcap` | Spoofing | 24.764 | 20 (+222) | 100,0% | 0 | 0/20 | 9/20 | 20/20 | 4,15 | 4,15 |
| `Backdoor_Malware.pcap` | Web | 321 | 2 | 96,9% | 54 | 0/2 | 0/2 | 2/2 | 14,39 | 14,39 |
| `BrowserHijacking.pcap` | Web | 585 | 3 | 99,7% | 7 | 0/3 | 2/3 | 2/3 | 8,95 | 9,65 |
| `CommandInjection.pcap` | Web | 540 | 1 | 99,4% | 28 | 0/1 | 0/1 | 1/1 | 18,10 | 18,10 |
| `SqlInjection.pcap` | Web | 524 | 4 | 99,6% | 21 | 3/4 | 0/4 | 3/4 | 8,11 | 8,11 |
| `Uploading_Attack.pcap` | Web | 125 | 1 | 99,0% | 27 | 0/1 | 0/1 | 1/1 | 14,57 | 14,57 |
| `XSS.pcap` | Web | 384 | 2 | 98,9% | 75 | 2/2 | 0/2 | 2/2 | 13,56 | 13,56 |

Entre parênteses, as sequências de ataque que abririam incidente depois do teto de 20 por pcap: uma
rajada que reabriria um desses incidentes conta de novo, então o número é um teto, e não uma contagem
de incidentes (sem teto, o `DNS_Spoofing.pcap` dá 51 incidentes em 28 horas). "Categoria certa"
compara a categoria do incidente com a do pcap; nos pcaps de DDoS e DoS, é a regra das origens que
separa as duas.

Somando os pcaps de ataque:

- 211 incidentes; 100,0% das janelas deles têm algum quadro de atacante.
- A primeira origem listada é um IP de atacante em 113 de 211 incidentes; o primeiro destino é um IP de atacante em 28.
- Nos pcaps de DDoS e DoS, a regra das origens deu a categoria do arquivo em 50 de 75 incidentes da classe DDoS+DoS.

## Pcaps benignos: alarmes falsos

| Pcap | Janelas | Horas de captura | Incidentes | Por hora | Categorias |
|---|---|---|---|---|---|
| `BenignTraffic.pcap` | 36.227 | 9,3 | 0 | 0,00 | — |
| `BenignTraffic1.pcap` | 29.548 | 7,2 | 0 | 0,00 | — |
| `BenignTraffic2.pcap` | 31.031 | 8,0 | 1 | 0,12 | DoS 1 |

Só o `BenignTraffic2.pcap` ficou fora do treino; os outros dois foram treino no modelo do sistema, e
o alarme deles é dentro da amostra.

## O artefato de captura numa implantação

O modelo do sistema aplicado às janelas do `BenignTraffic2.pcap`, que ficou fora do treino, com os tamanhos
de quadro como o dataset gravou e como passariam no fio, num enlace Ethernet sem agregação de
segmentos (`rodadas_de_teste.md`, rodada f). Janela de ataque pela regra do ponto de operação; alarme
com 4 janelas de ataque seguidas.

| Tamanhos de quadro | Janelas | Como ataque | Alarmes | Por hora |
|---|---|---|---|---|
| como gravado | 31.032 | 0,9% | 1 | 0,12 |
| como no fio (preenchido até 60 e limitado a 1.514 bytes) | 31.032 | 1,5% | 18 | 2,24 |

## Como os números foram obtidos

- Comando: `python -m codigo.reprodutor.avaliar`, a partir da raiz do repositório.
- Os resultados de cada pcap ficam em `dados/processed/reproducao/` (fora do git); o manifesto ao
  lado deste relatório traz os SHA-256 do modelo, do ponto de operação e do código.
- Tempo somado de processamento: 45,8 min.

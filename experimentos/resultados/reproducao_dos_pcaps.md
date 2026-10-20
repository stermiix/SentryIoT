# Reprodução dos pcaps: incidentes contra a verdade de campo

Gerado por `python -m codigo.reprodutor.avaliar` em 19/10/2026.

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
| `DictionaryBruteForce.pcap` | BruteForce | 1.306 | 7 | 97,9% | 208 | 4/7 | 0/7 | 3/7 | 2,94 | 8,71 |
| `DDoS-ACK_Fragmentation.pcap` | DDoS | 24.983 | 5 | 100,0% | 6.981 | 3/5 | 1/5 | 2/5 | 0,91 | 0,91 |
| `DDoS-HTTP_Flood-.pcap` | DDoS | 28.755 | 11 | 100,0% | 8.607 | 2/11 | 0/11 | 2/11 | 3,19 | 6,21 |
| `DDoS-ICMP_Flood.pcap` | DDoS | 267.908 | 3 | 100,0% | 80.302 | 2/3 | 0/3 | 1/3 | 0,03 | 1,46 |
| `DDoS-ICMP_Fragmentation.pcap` | DDoS | 20.596 | 4 | 100,0% | 6.150 | 3/4 | 0/4 | 3/4 | 0,78 | 0,78 |
| `DDoS-PSHACK_Flood.pcap` | DDoS | 267.711 | 3 | 100,0% | 80.292 | 3/3 | 0/3 | 3/3 | 0,94 | 1,29 |
| `DDoS-RSTFINFlood.pcap` | DDoS | 266.831 | 4 | 100,0% | 80.041 | 4/4 | 0/4 | 4/4 | 0,11 | 1,97 |
| `DDoS-SYN_Flood.pcap` | DDoS | 265.924 | 5 | 100,0% | 0 | 5/5 | 0/5 | 3/5 | 0,40 | 0,40 |
| `DDoS-SYN_Flood1.pcap` | DDoS | 267.096 | 6 | 100,0% | 266.991 | 5/6 | 0/6 | 4/6 | 0,31 | 0,31 |
| `DDoS-SlowLoris.pcap` | DDoS | 23.390 | 13 | 100,0% | 4.768 | 6/13 | 7/13 | 5/13 | 2,03 | 2,64 |
| `DDoS-SynonymousIP_Flood.pcap` | DDoS | 268.524 | 4 | 100,0% | 80.541 | 3/4 | 0/4 | 1/4 | 2,29 | 4,56 |
| `DDoS-TCP_Flood.pcap` | DDoS | 265.670 | 6 | 100,0% | 79.149 | 3/6 | 0/6 | 3/6 | 0,96 | 2,81 |
| `DDoS-UDP_Flood.pcap` | DDoS | 266.502 | 5 | 100,0% | 79.949 | 3/5 | 0/5 | 3/5 | 1,81 | 3,64 |
| `DDoS-UDP_Fragmentation.pcap` | DDoS | 22.438 | 5 | 100,0% | 6.476 | 2/5 | 2/5 | 0/5 | 0,72 | 1,63 |
| `DoS-HTTP_Flood1.pcap` | DoS | 31.098 | 8 | 99,8% | 8.618 | 4/8 | 2/8 | 7/8 | 0,51 | 1,43 |
| `DoS-SYN_Flood.pcap` | DoS | 262.585 | 3 | 100,0% | 0 | 3/3 | 0/3 | 3/3 | 0,49 | 0,49 |
| `DoS-SYN_Flood1.pcap` | DoS | 264.025 | 4 | 100,0% | 263.890 | 4/4 | 0/4 | 4/4 | 0,02 | 0,36 |
| `DoS-TCP_Flood.pcap` | DoS | 260.027 | 2 | 100,0% | 77.979 | 2/2 | 0/2 | 2/2 | 0,72 | 0,72 |
| `DoS-UDP_Flood.pcap` | DoS | 166.737 | 3 | 100,0% | 49.962 | 3/3 | 0/3 | 3/3 | 0,04 | 0,57 |
| `Mirai-greeth_flood.pcap` | Mirai | 33.500 | 2 | 100,0% | 9.951 | 2/2 | 0/2 | 2/2 | 0,32 | 0,32 |
| `Mirai-greip_flood21.pcap` | Mirai | 11.954 | 1 | 100,0% | 3.585 | 1/1 | 0/1 | 1/1 | 0,10 | 0,10 |
| `Mirai-udpplain.pcap` | Mirai | 36.388 | 6 | 100,0% | 10.779 | 0/6 | 1/6 | 4/6 | 3,03 | 83,30 |
| `Recon-HostDiscovery.pcap` | Recon | 13.436 | 5 | 100,0% | 3.493 | 4/5 | 0/5 | 4/5 | 5,82 | 13,29 |
| `Recon-OSScan.pcap` | Recon | 9.824 | 19 | 99,8% | 882 | 17/19 | 0/19 | 18/19 | 2,02 | 2,02 |
| `Recon-PingSweep.pcap` | Recon | 226 | 2 | 100,0% | 0 | 2/2 | 0/2 | 2/2 | 3,33 | 3,33 |
| `Recon-PortScan.pcap` | Recon | 8.227 | 20 (+20) | 99,8% | 405 | 18/20 | 0/20 | 19/20 | 2,32 | 2,32 |
| `VulnerabilityScan.pcap` | Recon | 37.331 | 20 (+8) | 99,4% | 533 | 6/20 | 2/20 | 20/20 | 6,12 | 8,34 |
| `DNS_Spoofing.pcap` | Spoofing | 17.887 | 20 (+511) | 100,0% | 0 | 0/20 | 2/20 | 20/20 | 7,27 | 7,27 |
| `MITM-ArpSpoofing.pcap` | Spoofing | 24.764 | 20 (+290) | 100,0% | 0 | 0/20 | 9/20 | 20/20 | 2,75 | 2,75 |
| `Backdoor_Malware.pcap` | Web | 321 | 2 | 96,9% | 54 | 0/2 | 0/2 | 2/2 | 10,26 | 10,26 |
| `BrowserHijacking.pcap` | Web | 585 | 4 | 99,7% | 7 | 0/4 | 3/4 | 3/4 | 6,69 | 7,32 |
| `CommandInjection.pcap` | Web | 540 | 2 | 98,2% | 46 | 0/2 | 0/2 | 1/2 | 8,38 | 10,49 |
| `SqlInjection.pcap` | Web | 524 | 4 | 99,6% | 21 | 3/4 | 0/4 | 3/4 | 5,93 | 5,93 |
| `Uploading_Attack.pcap` | Web | 125 | 1 | 99,0% | 27 | 0/1 | 0/1 | 1/1 | 11,03 | 11,03 |
| `XSS.pcap` | Web | 384 | 2 | 98,9% | 75 | 2/2 | 0/2 | 2/2 | 10,56 | 10,56 |

Entre parênteses, as sequências de ataque que abririam incidente depois do teto de 20 por pcap: uma
rajada que reabriria um desses incidentes conta de novo, então o número é um teto, e não uma contagem
de incidentes (sem teto, o `DNS_Spoofing.pcap` dá 51 incidentes em 28 horas). "Categoria certa"
compara a categoria do incidente com a do pcap; nos pcaps de DDoS e DoS, é a regra das origens que
separa as duas.

Somando os pcaps de ataque:

- 231 incidentes; 100,0% das janelas deles têm algum quadro de atacante.
- A primeira origem listada é um IP de atacante em 119 de 231 incidentes; o primeiro destino é um IP de atacante em 29.
- Nos pcaps de DDoS e DoS, a regra das origens deu a categoria do arquivo em 53 de 83 incidentes da classe DDoS+DoS.

## Pcaps benignos: alarmes falsos

| Pcap | Janelas | Horas de captura | Incidentes | Por hora | Categorias |
|---|---|---|---|---|---|
| `BenignTraffic.pcap` | 36.227 | 9,3 | 0 | 0,00 | — |
| `BenignTraffic1.pcap` | 29.548 | 7,2 | 0 | 0,00 | — |
| `BenignTraffic2.pcap` | 31.031 | 8,0 | 4 | 0,50 | DoS 2, Recon 1, Web 1 |

Só o `BenignTraffic2.pcap` ficou fora do treino; os outros dois foram treino no modelo do sistema, e
o alarme deles é dentro da amostra.

## O artefato de captura numa implantação

O modelo do sistema aplicado às janelas do `BenignTraffic2.pcap`, que ficou fora do treino, com os tamanhos
de quadro como o dataset gravou e como passariam no fio, num enlace Ethernet sem agregação de
segmentos (`rodadas_de_teste.md`, rodada f). Janela de ataque pela regra do ponto de operação; alarme
com 3 janelas de ataque seguidas.

| Tamanhos de quadro | Janelas | Como ataque | Alarmes | Por hora |
|---|---|---|---|---|
| como gravado | 31.032 | 0,9% | 4 | 0,50 |
| como no fio (preenchido até 60 e limitado a 1.514 bytes) | 31.032 | 1,5% | 26 | 3,24 |

## Como os números foram obtidos

- Comando: `python -m codigo.reprodutor.avaliar`, a partir da raiz do repositório.
- Os resultados de cada pcap ficam em `dados/processed/reproducao/` (fora do git); o manifesto ao
  lado deste relatório traz os SHA-256 do modelo, do ponto de operação e do código.
- Tempo somado de processamento: 43,5 min.

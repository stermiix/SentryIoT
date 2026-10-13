# Captura normalizada: comparação de configurações

Gerado por `python -m codigo.classificador.rodadas` em 13/10/2026, com Python 3.11.2, scikit-learn 1.9.1, pandas 3.0.6 e numpy 2.4.6.

Os pcaps do CICIoT2023 não têm os tamanhos de quadro distribuídos do mesmo jeito: os de spoofing têm quadros menores que 60 bytes, e os benignos, quadros maiores que 1.514 bytes (`rodadas_de_teste.md`, rodada f). Quadro menor que 60 bytes não sai assim no fio: a placa de rede o completa antes de transmitir, e ele aparece no pcap quando a captura é feita na própria máquina que envia. Quadro maior que 1.514 bytes também não passa num enlace Ethernet de MTU 1.500: ele aparece quando a placa da máquina que captura junta segmentos TCP antes de entregá-los (offload de segmentação), ou numa rede com jumbo frames. Os pcaps não dizem qual foi o caso, e as duas medidas são compatíveis com capturas gravadas de jeitos diferentes. Elas também não separam a forma de gravar do ataque: um quadro ARP, que o spoofing usa, tem 42 bytes antes do preenchimento. O extrator tem duas opções, desligadas por padrão, que mudam só o tamanho medido: o preenchimento conta como 60 bytes o quadro menor que isso, e o teto conta como 1.514 o quadro maior. As duas aproximam o tamanho do quadro no fio, sem reproduzi-lo: no fio, um quadro agregado de 64 KB seria várias dezenas de quadros, e não um de 1.514 bytes, e a contagem de quadros, o `IAT` e o `Rate` da janela continuam os da captura.

Este relatório lê as pastas regeradas antes por `regerar --preencher` e por `regerar --preencher --limitar` e compara o modelo do sistema (configuração 0) com cinco alternativas, no corte por tempo e nas rodadas c (rotação do pcap benigno de fora), d (tráfego de fundo) e e (pcap fora do treino). Nas configurações 4 e 5, as janelas de fundo da parte de treino de cada pcap de ataque, sem nenhum quadro do atacante, entram no treino como Benign: a 4 sobre os dados de `dados/processed/regerado_preenchido_limitado` e a 5 sobre os dados de `dados/processed/regerado`. A comparação entre elas separa o efeito do fundo do efeito do tamanho do quadro.

| Configuração | O que muda | Dados | Opções do extrator |
|---|---|---|---|
| 0 | o modelo atual | `dados/processed/regerado` | nenhuma |
| 1 | preenchimento até 60 bytes | `dados/processed/regerado_preenchido` | `preencher` |
| 2 | preenchimento até 60 e teto de 1.514 bytes | `dados/processed/regerado_preenchido_limitado` | `limitar` e `preencher` |
| 3 | a 2 sem `Time_To_Live` | `dados/processed/regerado_preenchido_limitado` | `limitar` e `preencher` |
| 4 | a 2 com o fundo da parte de treino como Benign | `dados/processed/regerado_preenchido_limitado` | `limitar` e `preencher` |
| 5 | a 0 com o fundo da parte de treino como Benign | `dados/processed/regerado` | nenhuma |

Cada configuração foi treinada com as sementes 42, 1 e 2, que definem ao mesmo tempo o sorteio do teto e o Random Forest. Os valores são a média das sementes, com o menor e o maior entre parênteses, e o asterisco marca a diferença para a configuração 0 que conta pelo critério abaixo. A tabela-resumo fecha o relatório.

As diferenças entre duas condições (uma configuração e a de referência, o modelo com e sem um pcap no treino, com e sem o TTL) são pareadas: as duas usam a mesma semente e são medidas nas mesmas janelas. Em cada semente, a diferença ganha uma variância por reamostragem de blocos de 10 janelas vizinhas do mesmo pcap, sorteados juntos para as duas condições; a diferença publicada é a média das sementes, e a variância dela soma a média das variâncias por blocos (a do conjunto de teste) e a variância da diferença entre as sementes dividida pela quantidade delas (a do treino). A diferença só conta quando o intervalo de 95% não contém o zero; senão, é "sem diferença".

## Corte por tempo

A divisão publicada: o começo de cada pcap no treino e o fim no teste, e um pcap inteiro de fora nos rótulos de
vários pcaps. O asterisco marca a diferença para a configuração 0 que conta.

| Medida | Configuração 0 | Configuração 1 | Configuração 2 | Configuração 3 | Configuração 4 | Configuração 5 |
|---|---|---|---|---|---|---|
| Macro-F1 | 82,2% (82,1% a 82,3%) | 78,7% (78,5% a 78,9%) * | 78,8% (78,7% a 78,9%) * | 78,5% (78,4% a 78,6%) * | 71,3% (71,1% a 71,7%) * | 75,6% (75,4% a 75,7%) * |
| Acurácia | 98,3% (98,3% a 98,3%) | 97,8% (97,8% a 97,8%) * | 97,8% (97,8% a 97,8%) * | 97,6% (97,6% a 97,6%) * | 95,5% (95,4% a 95,7%) * | 96,1% (96,0% a 96,2%) * |
| Benigno classificado como ataque | 1,7% (1,6% a 1,9%) | 2,9% (2,8% a 2,9%) * | 3,4% (3,4% a 3,4%) * | 3,6% (3,5% a 3,7%) * | 1,7% (1,7% a 1,8%) | 0,9% (0,8% a 0,9%) * |
| Ataque classificado como benigno | 1,0% (1,0% a 1,0%) | 1,0% (1,0% a 1,0%) | 1,0% (1,0% a 1,0%) | 1,1% (1,1% a 1,1%) * | 3,8% (3,7% a 3,9%) * | 3,6% (3,5% a 3,7%) * |
| Recall DDoS+DoS | 98,9% (98,8% a 98,9%) | 98,8% (98,8% a 98,9%) * | 98,8% (98,8% a 98,8%) * | 98,7% (98,6% a 98,7%) * | 98,3% (98,1% a 98,5%) * | 98,4% (98,3% a 98,4%) * |
| Recall Mirai | 99,2% (99,2% a 99,3%) | 99,2% (99,2% a 99,2%) | 99,2% (99,2% a 99,2%) | 99,2% (99,2% a 99,2%) | 99,2% (99,2% a 99,2%) | 99,2% (99,2% a 99,2%) |
| Recall Recon | 87,7% (87,7% a 87,8%) | 86,5% (86,4% a 86,6%) * | 86,5% (86,3% a 86,6%) * | 85,2% (84,8% a 85,4%) * | 54,1% (53,7% a 54,3%) * | 55,0% (54,9% a 55,2%) * |
| Recall Spoofing | 99,4% (99,4% a 99,4%) | 87,2% (87,1% a 87,3%) * | 88,2% (87,9% a 88,4%) * | 89,3% (89,1% a 89,5%) * | 63,6% (63,2% a 64,1%) * | 79,9% (79,6% a 80,1%) * |
| Recall Web | 37,1% (37,0% a 37,2%) | 27,4% (26,5% a 28,2%) * | 27,8% (27,1% a 28,2%) * | 28,1% (27,7% a 28,6%) * | 25,5% (25,2% a 25,8%) * | 35,1% (34,4% a 35,7%) |
| Recall BruteForce | 34,8% (34,4% a 35,2%) | 34,4% (34,1% a 34,8%) | 34,9% (34,4% a 35,2%) | 34,7% (34,1% a 35,2%) | 34,4% (34,1% a 35,2%) | 34,4% (34,1% a 34,8%) |
| Recall Benign | 98,3% (98,1% a 98,4%) | 97,1% (97,1% a 97,2%) * | 96,6% (96,6% a 96,6%) * | 96,4% (96,3% a 96,5%) * | 98,3% (98,2% a 98,3%) | 99,1% (99,1% a 99,2%) * |
| Precisão Spoofing | 99,5% (99,5% a 99,5%) | 89,4% (89,3% a 89,4%) * | 89,9% (89,8% a 90,1%) * | 89,4% (89,1% a 89,6%) * | 90,9% (90,9% a 91,0%) * | 99,9% (99,8% a 99,9%) * |
| Precisão Web | 63,5% (62,1% a 64,7%) | 56,8% (53,7% a 59,8%) | 55,5% (54,4% a 56,2%) * | 53,7% (50,6% a 57,3%) * | 49,9% (47,8% a 52,7%) * | 67,4% (66,9% a 68,4%) |
| Precisão BruteForce | 98,6% (98,0% a 99,0%) | 97,2% (95,9% a 97,9%) | 96,0% (94,1% a 97,9%) | 96,9% (93,9% a 99,0%) | 98,9% (98,9% a 99,0%) | 98,6% (97,9% a 99,0%) |

## c. Rotação do pcap benigno de fora

Tráfego benigno classificado como ataque em cada pcap benigno, com o modelo que deixou esse pcap inteiro fora
do treino, e no total dos três. O pior é `BenignTraffic.pcap`.

| Configuração | `BenignTraffic2.pcap` | `BenignTraffic.pcap` | `BenignTraffic1.pcap` | Total |
|---|---|---|---|---|
| 0 | 1,7% (1,7% a 1,9%) | 38,5% (38,2% a 38,8%) | 1,5% (1,4% a 1,6%) | 15,4% (15,4% a 15,5%) |
| 1 | 2,9% (2,8% a 3,0%) * | 39,6% (39,0% a 39,9%) * | 2,4% (2,4% a 2,5%) * | 16,5% (16,3% a 16,6%) * |
| 2 | 3,4% (3,3% a 3,4%) * | 39,9% (39,5% a 40,1%) * | 2,5% (2,4% a 2,6%) * | 16,8% (16,7% a 16,9%) * |
| 3 | 3,6% (3,5% a 3,6%) * | 40,3% (40,2% a 40,5%) * | 2,9% (2,8% a 2,9%) * | 17,1% (17,0% a 17,2%) * |
| 4 | 1,7% (1,7% a 1,7%) | 6,1% (6,1% a 6,2%) * | 1,5% (1,4% a 1,5%) | 3,3% (3,3% a 3,4%) * |
| 5 | 0,9% (0,9% a 0,9%) * | 5,4% (5,3% a 5,4%) * | 0,8% (0,8% a 0,8%) * | 2,5% (2,5% a 2,6%) * |

## d. Tráfego de fundo

Fração das janelas sem nenhum quadro do atacante classificada como algum ataque, somando os pcaps de ataque.
Nas configurações 4 e 5 o fundo da parte de treino entra no treino como benigno, e a coluna da parte de treino
deixa de ser uma medida fora da amostra.

| Configuração | Parte de teste | Parte de treino |
|---|---|---|
| 0 | 72,3% (72,2% a 72,4%) | 75,2% (75,0% a 75,4%) |
| 1 | 73,0% (73,0% a 73,1%) * | 75,3% (74,7% a 75,7%) |
| 2 | 72,3% (72,3% a 72,4%) | 74,4% (73,1% a 75,1%) |
| 3 | 71,7% (71,5% a 71,8%) * | 73,3% (72,2% a 74,0%) * |
| 4 | 12,0% (11,8% a 12,3%) * | 0,0% (0,0% a 0,0%) * |
| 5 | 13,3% (13,2% a 13,3%) * | 0,0% (0,0% a 0,0%) * |

Por pcap, na parte de teste, a fração do fundo posta na categoria do próprio pcap (pcaps com ao menos 50 janelas
de fundo na parte de teste):

| Pcap | Categoria | Janelas de fundo no teste | Configuração 0 | Configuração 1 | Configuração 2 | Configuração 3 | Configuração 4 | Configuração 5 |
|---|---|---|---|---|---|---|---|---|
| `VulnerabilityScan.pcap` | Recon | 6.325 | 79,6% (79,4% a 79,7%) | 79,3% (79,0% a 79,6%) | 78,9% (78,5% a 79,1%) * | 78,3% (78,3% a 78,5%) * | 5,7% (5,7% a 5,8%) * | 6,2% (5,7% a 6,5%) * |
| `MITM-ArpSpoofing.pcap` | Spoofing | 3.565 | 99,5% (99,3% a 99,6%) | 96,8% (96,7% a 96,9%) * | 96,8% (96,7% a 96,8%) * | 96,8% (96,7% a 96,9%) * | 13,7% (13,4% a 13,9%) * | 18,3% (17,8% a 18,7%) * |
| `DNS_Spoofing.pcap` | Spoofing | 2.223 | 97,7% (97,6% a 97,8%) | 77,6% (74,7% a 79,9%) * | 80,9% (78,6% a 82,5%) * | 87,4% (85,2% a 88,8%) * | 23,7% (22,0% a 25,2%) * | 41,2% (40,2% a 42,0%) * |
| `Recon-PortScan.pcap` | Recon | 1.618 | 21,3% (21,1% a 21,5%) | 21,7% (21,0% a 22,2%) | 21,0% (20,6% a 21,4%) | 22,4% (22,1% a 22,7%) | 1,3% (1,2% a 1,6%) * | 1,2% (1,1% a 1,4%) * |
| `Recon-OSScan.pcap` | Recon | 1.550 | 47,0% (46,5% a 47,5%) | 46,9% (46,7% a 47,4%) | 46,2% (45,9% a 46,5%) | 47,0% (46,9% a 47,1%) | 2,3% (2,1% a 2,6%) * | 2,6% (2,4% a 3,0%) * |
| `DDoS-SlowLoris.pcap` | DDoS+DoS | 502 | 3,4% (3,0% a 3,8%) | 3,6% (3,4% a 4,0%) | 2,7% (2,6% a 3,0%) | 2,8% (2,2% a 3,2%) | 0,7% (0,6% a 0,8%) * | 0,9% (0,8% a 1,0%) * |
| `DDoS-ACK_Fragmentation.pcap` | DDoS+DoS | 463 | 4,6% (4,3% a 4,8%) | 4,8% (4,3% a 5,0%) | 4,2% (3,9% a 4,8%) | 2,9% (2,2% a 3,2%) | 1,1% (0,9% a 1,3%) * | 1,2% (0,6% a 1,7%) * |
| `DDoS-TCP_Flood.pcap` | DDoS+DoS | 356 | 7,1% (6,7% a 7,3%) | 7,4% (7,0% a 7,9%) | 7,4% (7,0% a 8,1%) | 7,1% (6,7% a 7,6%) | 3,4% (2,8% a 4,2%) * | 3,1% (2,8% a 3,4%) * |
| `DoS-HTTP_Flood1.pcap` | DDoS+DoS | 193 | 26,3% (25,4% a 26,9%) | 26,8% (26,4% a 27,5%) | 26,3% (25,4% a 26,9%) | 25,7% (24,9% a 26,4%) | 22,3% (22,3% a 22,3%) * | 22,8% (22,8% a 22,8%) * |
| `Recon-HostDiscovery.pcap` | Recon | 189 | 3,9% (2,6% a 5,3%) | 3,5% (3,2% a 4,2%) | 3,0% (2,1% a 4,2%) | 2,1% (1,6% a 2,6%) | 1,1% (1,1% a 1,1%) | 1,2% (1,1% a 1,6%) |
| `DictionaryBruteForce.pcap` | BruteForce | 119 | 2,0% (1,7% a 2,5%) | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) |
| `BrowserHijacking.pcap` | Web | 95 | 0,4% (0,0% a 1,1%) | 0,4% (0,0% a 1,1%) | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) |
| `Mirai-greeth_flood.pcap` | Mirai | 93 | 69,9% (69,9% a 69,9%) | 68,5% (63,4% a 74,2%) | 60,9% (55,9% a 67,7%) | 0,4% (0,0% a 1,1%) * | 0,0% (0,0% a 0,0%) * | 0,0% (0,0% a 0,0%) * |
| `CommandInjection.pcap` | Web | 85 | 1,2% (1,2% a 1,2%) | 1,2% (1,2% a 1,2%) | 1,2% (1,2% a 1,2%) | 1,2% (1,2% a 1,2%) | 1,2% (1,2% a 1,2%) | 1,2% (1,2% a 1,2%) |
| `DoS-SYN_Flood1.pcap` | DDoS+DoS | 72 | 42,6% (41,7% a 43,1%) | 39,8% (38,9% a 41,7%) | 38,4% (37,5% a 38,9%) | 38,9% (37,5% a 40,3%) | 10,6% (9,7% a 11,1%) * | 15,7% (13,9% a 18,1%) * |
| `DDoS-SYN_Flood1.pcap` | DDoS+DoS | 68 | 10,8% (10,3% a 11,8%) | 10,3% (10,3% a 10,3%) | 9,3% (8,8% a 10,3%) | 5,9% (5,9% a 5,9%) | 2,9% (2,9% a 2,9%) | 2,9% (2,9% a 2,9%) |
| `SqlInjection.pcap` | Web | 55 | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) |
| `Recon-PingSweep.pcap` | Recon | 50 | 16,0% (14,0% a 18,0%) | 18,0% (18,0% a 18,0%) | 16,0% (14,0% a 18,0%) | 18,7% (16,0% a 20,0%) | 1,3% (0,0% a 2,0%) | 0,0% (0,0% a 0,0%) |

## e. Pcap fora do treino

Recall de cada pcap, nas janelas de teste dele, quando nenhuma janela dele entra no treino:

| Pcap | Categoria | Janelas de teste | Configuração 0 | Configuração 1 | Configuração 2 | Configuração 3 | Configuração 4 | Configuração 5 |
|---|---|---|---|---|---|---|---|---|
| `Recon-HostDiscovery.pcap` | Recon | 3.842 | 38,4% (38,0% a 39,0%) | 36,8% (36,6% a 36,9%) * | 36,7% (36,3% a 37,0%) * | 36,7% (36,4% a 37,1%) * | 32,6% (32,5% a 32,7%) * | 33,3% (33,3% a 33,4%) * |
| `Recon-OSScan.pcap` | Recon | 1.397 | 73,0% (72,7% a 73,2%) | 73,2% (73,1% a 73,2%) | 73,0% (72,6% a 73,4%) | 71,3% (71,0% a 71,5%) * | 56,0% (55,7% a 56,3%) * | 55,8% (55,5% a 56,0%) * |
| `Recon-PingSweep.pcap` | Recon | 18 | 51,9% (50,0% a 55,6%) | 55,6% (55,6% a 55,6%) | 53,7% (50,0% a 55,6%) | 55,6% (50,0% a 61,1%) | 5,6% (5,6% a 5,6%) * | 1,9% (0,0% a 5,6%) * |
| `Recon-PortScan.pcap` | Recon | 850 | 79,4% (79,1% a 80,0%) | 79,3% (79,1% a 79,8%) | 79,0% (78,6% a 79,3%) | 69,8% (68,9% a 70,6%) * | 76,3% (75,9% a 76,8%) * | 75,9% (75,9% a 75,9%) * |
| `VulnerabilityScan.pcap` | Recon | 4.875 | 5,8% (5,5% a 6,0%) | 5,8% (5,6% a 6,1%) | 5,9% (5,4% a 6,5%) | 7,3% (7,1% a 7,5%) * | 0,6% (0,5% a 0,6%) * | 0,5% (0,5% a 0,6%) * |
| `Backdoor_Malware.pcap` | Web | 76 | 48,7% (47,4% a 50,0%) | 37,3% (35,5% a 39,5%) * | 35,1% (31,6% a 38,2%) * | 35,5% (35,5% a 35,5%) * | 31,6% (28,9% a 34,2%) * | 47,8% (44,7% a 50,0%) |
| `BrowserHijacking.pcap` | Web | 81 | 2,5% (2,5% a 2,5%) | 2,1% (1,2% a 2,5%) | 1,2% (0,0% a 2,5%) | 1,6% (1,2% a 2,5%) | 0,4% (0,0% a 1,2%) | 2,5% (2,5% a 2,5%) |
| `CommandInjection.pcap` | Web | 77 | 26,4% (24,7% a 27,3%) | 19,5% (18,2% a 20,8%) | 16,5% (15,6% a 16,9%) * | 18,6% (16,9% a 19,5%) * | 18,6% (16,9% a 20,8%) * | 25,1% (23,4% a 27,3%) |
| `SqlInjection.pcap` | Web | 102 | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) |
| `Uploading_Attack.pcap` | Web | 31 | 76,3% (71,0% a 80,6%) | 46,2% (45,2% a 48,4%) * | 45,2% (41,9% a 48,4%) * | 48,4% (48,4% a 48,4%) * | 47,3% (45,2% a 48,4%) * | 72,0% (64,5% a 77,4%) |
| `XSS.pcap` | Web | 98 | 63,6% (60,2% a 67,3%) | 37,4% (36,7% a 37,8%) * | 38,8% (37,8% a 39,8%) * | 40,5% (39,8% a 41,8%) * | 36,7% (33,7% a 39,8%) * | 57,8% (56,1% a 59,2%) |
| `DNS_Spoofing.pcap` | Spoofing | 3.143 | 94,1% (93,1% a 94,6%) | 38,0% (37,6% a 38,8%) * | 43,6% (40,2% a 46,2%) * | 44,4% (43,7% a 45,7%) * | 7,1% (6,3% a 7,6%) * | 40,3% (39,6% a 40,8%) * |
| `MITM-ArpSpoofing.pcap` | Spoofing | 3.864 | 99,3% (99,2% a 99,5%) | 85,0% (84,4% a 85,5%) * | 84,8% (84,7% a 84,9%) * | 84,4% (84,0% a 84,7%) * | 61,8% (61,2% a 62,2%) * | 81,4% (81,3% a 81,5%) * |
| `Mirai-greeth_flood.pcap` | Mirai | 9.957 | 99,9% (99,9% a 99,9%) | 99,9% (99,9% a 99,9%) | 99,9% (99,9% a 99,9%) | 99,9% (99,9% a 99,9%) | 99,9% (99,9% a 99,9%) | 99,9% (99,9% a 99,9%) |
| `Mirai-greip_flood21.pcap` | Mirai | 3.586 | 100,0% (100,0% a 100,0%) | 100,0% (100,0% a 100,0%) | 100,0% (100,0% a 100,0%) | 100,0% (100,0% a 100,0%) | 100,0% (100,0% a 100,0%) | 100,0% (100,0% a 100,0%) |
| `Mirai-udpplain.pcap` | Mirai | 10.915 | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) | 0,3% (0,0% a 0,4%) | 0,0% (0,0% a 0,0%) |
| `DictionaryBruteForce.pcap` | BruteForce | 273 | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) |
| `DDoS-ICMP_Flood.pcap` | DDoS+DoS | 14.916 | 99,9% (99,9% a 100,0%) | 99,9% (99,9% a 100,0%) | 99,9% (99,9% a 99,9%) | 99,9% (99,9% a 100,0%) | 99,9% (99,8% a 99,9%) | 99,9% (99,9% a 99,9%) |
| `DDoS-SlowLoris.pcap` | DDoS+DoS | 6.515 | 57,8% (55,8% a 60,6%) | 60,9% (60,4% a 61,6%) | 56,9% (53,8% a 58,7%) | 49,0% (43,3% a 54,2%) * | 33,9% (26,5% a 38,3%) * | 39,8% (38,2% a 41,0%) * |
| `DoS-HTTP_Flood1.pcap` | DDoS+DoS | 9.137 | 86,6% (86,5% a 86,8%) | 86,7% (86,6% a 86,7%) | 86,9% (86,6% a 87,1%) | 86,1% (85,9% a 86,3%) * | 85,3% (85,2% a 85,3%) * | 85,0% (84,9% a 85,1%) * |
| `DoS-UDP_Flood.pcap` | DDoS+DoS | 14.988 | 56,8% (56,5% a 57,4%) | 56,8% (56,4% a 57,3%) | 56,6% (56,2% a 57,1%) * | 56,7% (56,4% a 57,2%) | 56,6% (56,3% a 57,2%) | 56,9% (56,6% a 57,4%) |

Somando os pcaps de cada categoria:

| Categoria | Configuração 0 | Configuração 1 | Configuração 2 | Configuração 3 | Configuração 4 | Configuração 5 |
|---|---|---|---|---|---|---|
| DDoS+DoS | 77,1% (76,9% a 77,4%) | 77,5% (77,4% a 77,8%) | 76,9% (76,4% a 77,3%) | 75,7% (74,8% a 76,4%) * | 73,3% (72,2% a 74,1%) * | 74,2% (74,1% a 74,3%) * |
| Mirai | 55,3% (55,3% a 55,3%) | 55,3% (55,3% a 55,3%) | 55,3% (55,3% a 55,3%) | 55,3% (55,3% a 55,3%) | 55,5% (55,3% a 55,5%) * | 55,3% (55,3% a 55,3%) |
| Recon | 31,5% (31,4% a 31,7%) | 31,0% (30,9% a 31,2%) * | 30,9% (30,7% a 31,1%) * | 30,6% (30,5% a 30,8%) * | 24,7% (24,7% a 24,7%) * | 24,9% (24,8% a 24,9%) * |
| Spoofing | 97,0% (96,5% a 97,2%) | 64,0% (63,5% a 64,3%) * | 66,3% (64,9% a 67,5%) * | 66,5% (66,0% a 67,1%) * | 37,3% (37,0% a 37,6%) * | 63,0% (62,7% a 63,1%) * |
| Web | 31,3% (30,5% a 32,5%) | 20,6% (20,2% a 21,3%) * | 19,9% (19,8% a 20,0%) * | 20,9% (20,4% a 21,5%) * | 19,2% (18,3% a 20,0%) * | 29,4% (28,8% a 30,1%) |
| BruteForce | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) |

## O tamanho dos quadros em cada pasta

Fração das janelas mantidas com algum quadro menor que 60 bytes e maior que 1.514 bytes, por pasta de dados,
para conferir o que as opções do extrator fizeram:

| Categoria | Menor que 60 (0) | Maior que 1.514 (0) | Menor que 60 (1) | Maior que 1.514 (1) | Menor que 60 (2) | Maior que 1.514 (2) |
|---|---|---|---|---|---|---|
| DDoS+DoS | 0,0% | 1,4% | 0,0% | 1,4% | 0,0% | 0,0% |
| Mirai | 1,4% | 0,6% | 0,0% | 0,6% | 0,0% | 0,0% |
| Recon | 0,0% | 27,9% | 0,0% | 27,9% | 0,0% | 0,0% |
| Spoofing | 84,2% | 0,0% | 0,0% | 0,0% | 0,0% | 0,0% |
| Web | 0,0% | 38,7% | 0,0% | 38,7% | 0,0% | 0,0% |
| BruteForce | 0,0% | 32,9% | 0,0% | 32,9% | 0,0% | 0,0% |
| Benign | 0,0% | 87,8% | 0,0% | 87,8% | 0,0% | 0,0% |

## Quais diferenças contam

Nas medidas da tabela-resumo, a diferença para a configuração 0, com o intervalo de 95% entre parênteses:

- Configuração 1: macro-F1 no corte por tempo (-3,46 p.p., de -4,06 a -2,85), benigno como ataque no pior pcap benigno de fora (+1,05 p.p., de +0,65 a +1,46), fundo virando ataque (+0,75 p.p., de +0,38 a +1,12), recall de Recon com o pcap fora (-0,54 p.p., de -0,93 a -0,14), recall de Web com o pcap fora (-10,61 p.p., de -13,41 a -7,80), recall de Spoofing com o pcap fora (-33,00 p.p., de -34,76 a -31,24), Recon visto como algum ataque com o pcap fora (+2,68 p.p., de +2,19 a +3,17), Web visto como algum ataque com o pcap fora (+5,95 p.p., de +2,81 a +9,08) e Spoofing visto como algum ataque com o pcap fora (-5,77 p.p., de -6,61 a -4,93). Sem diferença: recall de BruteForce com o pcap fora e BruteForce visto como algum ataque com o pcap fora.
- Configuração 2: macro-F1 no corte por tempo (-3,36 p.p., de -3,88 a -2,83), benigno como ataque no pior pcap benigno de fora (+1,42 p.p., de +1,07 a +1,77), recall de Recon com o pcap fora (-0,60 p.p., de -1,06 a -0,14), recall de Web com o pcap fora (-11,40 p.p., de -14,63 a -8,17), recall de Spoofing com o pcap fora (-30,65 p.p., de -32,70 a -28,59), Recon visto como algum ataque com o pcap fora (+3,15 p.p., de +2,20 a +4,09) e Spoofing visto como algum ataque com o pcap fora (-5,73 p.p., de -6,55 a -4,91). Sem diferença: fundo virando ataque, recall de BruteForce com o pcap fora, Web visto como algum ataque com o pcap fora e BruteForce visto como algum ataque com o pcap fora.
- Configuração 3: macro-F1 no corte por tempo (-3,67 p.p., de -4,22 a -3,12), benigno como ataque no pior pcap benigno de fora (+1,82 p.p., de +1,47 a +2,16), fundo virando ataque (-0,60 p.p., de -1,05 a -0,16), recall de Recon com o pcap fora (-0,89 p.p., de -1,36 a -0,41), recall de Web com o pcap fora (-10,32 p.p., de -13,24 a -7,40), recall de Spoofing com o pcap fora (-30,48 p.p., de -32,32 a -28,65), Recon visto como algum ataque com o pcap fora (+2,86 p.p., de +2,22 a +3,50) e Spoofing visto como algum ataque com o pcap fora (-6,17 p.p., de -7,04 a -5,29). Sem diferença: recall de BruteForce com o pcap fora, Web visto como algum ataque com o pcap fora e BruteForce visto como algum ataque com o pcap fora.
- Configuração 4: macro-F1 no corte por tempo (-10,85 p.p., de -11,56 a -10,15), benigno como ataque no pior pcap benigno de fora (-32,37 p.p., de -33,37 a -31,36), fundo virando ataque (-60,26 p.p., de -61,44 a -59,08), recall de Recon com o pcap fora (-6,84 p.p., de -7,52 a -6,16), recall de Web com o pcap fora (-12,04 p.p., de -15,05 a -9,03), recall de Spoofing com o pcap fora (-59,67 p.p., de -61,87 a -57,48), Recon visto como algum ataque com o pcap fora (-7,33 p.p., de -8,29 a -6,37), Web visto como algum ataque com o pcap fora (-21,86 p.p., de -28,14 a -15,59), BruteForce visto como algum ataque com o pcap fora (-28,21 p.p., de -39,03 a -17,38) e Spoofing visto como algum ataque com o pcap fora (-42,38 p.p., de -44,55 a -40,20). Sem diferença: recall de BruteForce com o pcap fora.
- Configuração 5: macro-F1 no corte por tempo (-6,63 p.p., de -7,08 a -6,18), benigno como ataque no pior pcap benigno de fora (-33,14 p.p., de -34,11 a -32,17), fundo virando ataque (-59,02 p.p., de -60,19 a -57,85), recall de Recon com o pcap fora (-6,66 p.p., de -7,35 a -5,96), recall de Spoofing com o pcap fora (-33,99 p.p., de -36,17 a -31,82), Recon visto como algum ataque com o pcap fora (-13,04 p.p., de -14,09 a -11,99), Web visto como algum ataque com o pcap fora (-25,38 p.p., de -29,74 a -21,02), BruteForce visto como algum ataque com o pcap fora (-19,54 p.p., de -26,78 a -12,29) e Spoofing visto como algum ataque com o pcap fora (-32,14 p.p., de -34,42 a -29,86). Sem diferença: recall de Web com o pcap fora e recall de BruteForce com o pcap fora.

## Tabela-resumo

| Configuração | Macro-F1 no corte por tempo | Benigno como ataque no pior pcap benigno de fora (`BenignTraffic.pcap`) | Fundo virando ataque (parte de teste) | Recall Recon com o pcap fora | Recall Web com o pcap fora | Recall BruteForce com o pcap fora | Recall Spoofing com o pcap fora |
|---|---|---|---|---|---|---|---|
| 0 | 82,2% (82,1% a 82,3%) | 38,5% (38,2% a 38,8%) | 72,3% (72,2% a 72,4%) | 31,5% (31,4% a 31,7%) | 31,3% (30,5% a 32,5%) | 0,0% (0,0% a 0,0%) (como ataque 76,4% (75,5% a 77,3%)) | 97,0% (96,5% a 97,2%) |
| 1 | 78,7% (78,5% a 78,9%) * | 39,6% (39,0% a 39,9%) * | 73,0% (73,0% a 73,1%) * | 31,0% (30,9% a 31,2%) * | 20,6% (20,2% a 21,3%) * | 0,0% (0,0% a 0,0%) (como ataque 78,4% (77,3% a 79,5%)) | 64,0% (63,5% a 64,3%) * |
| 2 | 78,8% (78,7% a 78,9%) * | 39,9% (39,5% a 40,1%) * | 72,3% (72,3% a 72,4%) | 30,9% (30,7% a 31,1%) * | 19,9% (19,8% a 20,0%) * | 0,0% (0,0% a 0,0%) (como ataque 77,5% (76,2% a 79,5%)) | 66,3% (64,9% a 67,5%) * |
| 3 | 78,5% (78,4% a 78,6%) * | 40,3% (40,2% a 40,5%) * | 71,7% (71,5% a 71,8%) * | 30,6% (30,5% a 30,8%) * | 20,9% (20,4% a 21,5%) * | 0,0% (0,0% a 0,0%) (como ataque 76,6% (76,2% a 76,9%)) | 66,5% (66,0% a 67,1%) * |
| 4 | 71,3% (71,1% a 71,7%) * | 6,1% (6,1% a 6,2%) * | 12,0% (11,8% a 12,3%) * | 24,7% (24,7% a 24,7%) * | 19,2% (18,3% a 20,0%) * | 0,0% (0,0% a 0,0%) (como ataque 48,2% (44,3% a 50,5%) *) | 37,3% (37,0% a 37,6%) * |
| 5 | 75,6% (75,4% a 75,7%) * | 5,4% (5,3% a 5,4%) * | 13,3% (13,2% a 13,3%) * | 24,9% (24,8% a 24,9%) * | 29,4% (28,8% a 30,1%) | 0,0% (0,0% a 0,0%) (como ataque 56,9% (54,9% a 59,3%) *) | 63,0% (62,7% a 63,1%) * |

O asterisco marca a diferença para a configuração 0 cujo intervalo de 95% deixa o zero de fora. O pior pcap benigno de fora é `BenignTraffic.pcap`, o de maior alarme na configuração 0, e é o mesmo em todas as linhas. O fundo é o das janelas sem nenhum quadro do atacante, na parte de teste dos pcaps de ataque. O recall com o pcap fora soma os pcaps da categoria, cada um medido nas suas janelas de teste com o modelo que não o viu. BruteForce tem um pcap só: com ele fora a categoria some do treino, o recall é zero por construção, e entre parênteses fica a fração vista como algum ataque.

## Regra de adoção da configuração 5

A regra definida pela equipe: a configuração 5 passa a ser o modelo do sistema se, na média das sementes, (a) o benigno classificado como ataque no pior pcap benigno de fora do treino fica abaixo de 10%, (b) o recall de DDoS+DoS no corte por tempo fica em pelo menos 98% e (c) o recall do `Recon-PortScan.pcap` com o pcap fora do treino não cai mais de 5 pontos em relação à configuração 0. Se uma condição falha, o modelo continua o da configuração 0. O pior pcap benigno é o de cada configuração.

| Condição | Limite | Configuração 0 | Configuração 5 | Atende |
|---|---|---|---|---|
| (a) Benigno como ataque no pior pcap benigno de fora | abaixo de 10% | 38,5% (`BenignTraffic.pcap`) | 5,4% (`BenignTraffic.pcap`) | sim |
| (b) Recall DDoS+DoS no corte por tempo | pelo menos 98% | 98,87% | 98,37% | sim |
| (c) Recall do `Recon-PortScan.pcap` com o pcap fora | queda de até 5 p.p. | 79,4% | 75,9% (-3,53 p.p.) | sim |

Pela regra, a configuração 5 passa a ser o modelo do sistema. A diferença da condição (c), com o intervalo de 95% das diferenças pareadas, é -3,53 p.p. (de -5,29 a -1,77), diferente de zero.

## Como os números foram obtidos

- Comando: `python -m codigo.classificador.rodadas --capturas --nucleos 4`, a partir da raiz do repositório.
- Dados de cada pasta, regerados por `python -m codigo.classificador.regerar --janelas 100` com as opções do
  extrator de cada configuração:
  - `dados/processed/regerado`: manifesto `experimentos/resultados/manifesto_regeracao.json` (SHA-256 `2d8ed9c489f21f2e8ed0b8f1e312e974c820013ae020eaaf6b7ff4996dfbf7c3`), extrator com SHA-256 `8bd38fb392d5bec5a318699b2cef4a67a7c0c43461ecd01ce20be5b7db0b4a65` e opções nenhuma; 72 arquivos lidos, com o SHA-256 de cada um em `manifesto_rodadas_normalizadas.json`.
  - `dados/processed/regerado_preenchido`: manifesto `experimentos/resultados/regeracao_preenchido/manifesto_regeracao.json` (SHA-256 `cf34a445cde2c0d90f6d60e27b484a3e3abfcaa9436f5672af5ce640e80bb0b2`), extrator com SHA-256 `8bd38fb392d5bec5a318699b2cef4a67a7c0c43461ecd01ce20be5b7db0b4a65` e opções {'preencher': True}; 72 arquivos lidos, com o SHA-256 de cada um em `manifesto_rodadas_normalizadas.json`.
  - `dados/processed/regerado_preenchido_limitado`: manifesto `experimentos/resultados/regeracao_preenchido_limitado/manifesto_regeracao.json` (SHA-256 `23e1b2a92e03dd76e1949d8725a248e0671119c4e15f25b9f1d731b2dfba5243`), extrator com SHA-256 `8bd38fb392d5bec5a318699b2cef4a67a7c0c43461ecd01ce20be5b7db0b4a65` e opções {'limitar': True, 'preencher': True}; 72 arquivos lidos, com o SHA-256 de cada um em `manifesto_rodadas_normalizadas.json`.
- Treinos: `RandomForestClassifier` com 100 árvores e os demais parâmetros padrão, teto de 50.000 linhas por rótulo, corte de 70% das janelas de cada pcap, as mesmas funções de `treinar_regerado`; a configuração 0 é o mesmo treino de `rodadas_de_teste.md`.
- As tabelas em CSV começam com `rodadas_normalizadas_`; os valores completos, com as contagens, estão no manifesto.
- Tempo desta execução, na máquina em que rodou: 1.226,8 s. Os treinos já guardados em `dados/processed/rodadas/` são reaproveitados e não entram nessa conta; somados, os treinos de que os números saem levaram 4.862,9 s.
- Código: o SHA-256 de cada módulo de que os números saem (`rodadas.py`, `preparar.py`, `treinar.py`, `avaliar.py`, `treinar_regerado.py`, `regerar.py`, `mapeamento.py` e `extrator.py`) está no manifesto e entra na chave dos treinos guardados; commit `024d14e161eb`.
- Memória: pico de 5,1 GB no processo, o necessário para reproduzir com a mesma quantidade de núcleos.
- Com as mesmas entradas, o mesmo código e as mesmas sementes, os números saem iguais. Só mudam a data e os
  tempos.

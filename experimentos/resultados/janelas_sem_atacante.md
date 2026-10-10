# Janelas sem atacante

Gerado por `python -m codigo.classificador.atacantes` em 10/10/2026, com Python 3.11.2 e dpkt 1.9.8.

O CICIoT2023 (Neto et al., 2023) dá o rótulo de cada pcap ao arquivo inteiro, e cada janela reúne
quadros seguidos de todos os dispositivos da rede. Numa captura de ataque, parte das janelas não tem
nenhum quadro do dispositivo que ataca, e mesmo assim leva o rótulo do ataque. Este relatório mede
isso em cada pcap da pasta do dataset, com janela de 10 e 100 quadros.

Os atacantes são os sete Raspberry Pi da Tabela 1 do artigo do dataset, identificados pelo MAC:
`dc:a6:32:c9:e4:90`, `dc:a6:32:c9:e4:ab`, `dc:a6:32:c9:e4:d5`, `dc:a6:32:c9:e5:a4`, `dc:a6:32:c9:e5:ef`, `dc:a6:32:dc:27:d5` e `e4:5f:01:55:90:c4`.
Uma janela tem atacante quando algum quadro dela tem um desses MACs na origem ou no destino.

## Os atacantes em cada pcap

A contagem de quadros por MAC confirma a lista nos arquivos. Para cada pcap de ataque: a fração dos
quadros com um MAC da lista na origem e no destino, os MACs da lista com ao menos 1% dos quadros
(origem e destino somados) e os três MACs mais frequentes fora da lista. Um pcap em que o MAC
dominante não está na lista indicaria um atacante que ela não cobre.

| Arquivo | Rótulo | Quadros | Origem na lista | Destino na lista | Atacantes com mais de 1% | Mais frequentes fora da lista |
|---|---|---|---|---|---|---|
| `Backdoor_Malware.pcap` | Backdoor_Malware | 33.414 | 5,0% | 4,0% | `dc:a6:32:dc:27:d5` (6,5%), `dc:a6:32:c9:e5:a4` (2,5%) | `3c:18:a0:41:c3:a0` (72,8%), `ff:ff:ff:ff:ff:ff` (12,2%), `2c:71:ff:05:f1:15` (11,3%) |
| `BrowserHijacking.pcap` | BrowserHijacking | 59.821 | 13,9% | 7,7% | `dc:a6:32:dc:27:d5` (21,6%) | `3c:18:a0:41:c3:a0` (66,4%), `dc:a6:32:c9:e5:02` (13,6%), `dc:a6:32:c9:e4:c6` (12,3%) |
| `CommandInjection.pcap` | CommandInjection | 55.741 | 3,3% | 2,7% | `dc:a6:32:dc:27:d5` (4,0%), `dc:a6:32:c9:e5:a4` (2,0%) | `3c:18:a0:41:c3:a0` (80,0%), `dc:a6:32:c9:e6:f4` (22,1%), `ff:ff:ff:ff:ff:ff` (9,3%) |
| `DDoS-ACK_Fragmentation.pcap` | DDoS-ACK_Fragmentation | 2.503.835 | 83,2% | 11,3% | `dc:a6:32:c9:e4:ab` (24,4%), `dc:a6:32:dc:27:d5` (24,0%), `dc:a6:32:c9:e4:90` (15,7%), `dc:a6:32:c9:e5:ef` (11,8%), `e4:5f:01:55:90:c4` (8,9%), `dc:a6:32:c9:e4:d5` (5,8%), `dc:a6:32:c9:e5:a4` (4,0%) | `b0:c5:54:59:2e:99` (35,4%), `8c:85:80:6c:b6:47` (32,5%), `9c:8e:cd:1d:ab:9f` (23,1%) |
| `DDoS-HTTP_Flood-.pcap` | DDoS-HTTP_Flood | 2.881.005 | 24,5% | 67,0% | `dc:a6:32:dc:27:d5` (20,5%), `dc:a6:32:c9:e4:90` (13,2%), `e4:5f:01:55:90:c4` (13,0%), `dc:a6:32:c9:e4:ab` (12,3%), `dc:a6:32:c9:e5:a4` (11,7%), `dc:a6:32:c9:e4:d5` (10,7%), `dc:a6:32:c9:e5:ef` (10,1%) | `9c:8e:cd:1d:ab:9f` (23,9%), `b0:c5:54:59:2e:99` (14,3%), `b0:f1:ec:d3:e7:98` (11,9%) |
| `DDoS-ICMP_Flood.pcap` | DDoS-ICMP_Flood | 26.793.240 | 99,6% | 0,0% | `dc:a6:32:dc:27:d5` (17,7%), `dc:a6:32:c9:e5:a4` (16,8%), `e4:5f:01:55:90:c4` (15,8%), `dc:a6:32:c9:e5:ef` (15,7%), `dc:a6:32:c9:e4:d5` (15,6%), `dc:a6:32:c9:e4:ab` (11,4%), `dc:a6:32:c9:e4:90` (6,5%) | `1c:fe:2b:98:16:dd` (58,9%), `1c:12:b0:9b:0c:ec` (40,7%) |
| `DDoS-ICMP_Fragmentation.pcap` | DDoS-ICMP_Fragmentation | 2.064.692 | 93,0% | 0,5% | `dc:a6:32:c9:e5:a4` (19,2%), `e4:5f:01:55:90:c4` (17,4%), `dc:a6:32:c9:e4:ab` (16,9%), `dc:a6:32:c9:e4:d5` (12,4%), `dc:a6:32:c9:e5:ef` (11,2%), `dc:a6:32:dc:27:d5` (10,2%), `dc:a6:32:c9:e4:90` (6,3%) | `1c:fe:2b:98:16:dd` (38,5%), `cc:f4:11:9c:d0:00` (28,9%), `1c:12:b0:9b:0c:ec` (26,8%) |
| `DDoS-PSHACK_Flood.pcap` | DDoS-PSHACK_Flood | 26.774.357 | 98,3% | 1,3% | `dc:a6:32:c9:e5:a4` (19,8%), `dc:a6:32:c9:e4:ab` (17,5%), `dc:a6:32:c9:e4:90` (14,8%), `dc:a6:32:dc:27:d5` (13,0%), `dc:a6:32:c9:e4:d5` (12,3%), `dc:a6:32:c9:e5:ef` (11,7%), `e4:5f:01:55:90:c4` (10,5%) | `1c:fe:2b:98:16:dd` (49,2%), `1c:12:b0:9b:0c:ec` (43,1%), `9c:8e:cd:1d:ab:9f` (7,3%) |
| `DDoS-RSTFINFlood.pcap` | DDoS-RSTFINFlood | 26.686.473 | 99,6% | 0,0% | `dc:a6:32:dc:27:d5` (17,8%), `dc:a6:32:c9:e5:a4` (16,3%), `dc:a6:32:c9:e4:d5` (14,7%), `e4:5f:01:55:90:c4` (14,7%), `dc:a6:32:c9:e4:90` (12,7%), `dc:a6:32:c9:e5:ef` (11,9%), `dc:a6:32:c9:e4:ab` (11,5%) | `1c:fe:2b:98:16:dd` (47,1%), `28:6d:97:9e:f4:d5` (44,9%), `2c:71:ff:05:f1:15` (7,6%) |
| `DDoS-SYN_Flood.pcap` | DDoS-SYN_Flood | 26.597.011 | 97,8% | 1,5% | `dc:a6:32:c9:e4:ab` (26,9%), `dc:a6:32:dc:27:d5` (16,5%), `dc:a6:32:c9:e4:90` (15,9%), `e4:5f:01:55:90:c4` (14,6%), `dc:a6:32:c9:e5:ef` (14,0%), `dc:a6:32:c9:e4:d5` (11,3%) | `1c:12:b0:9b:0c:ec` (33,7%), `1c:fe:2b:98:16:dd` (29,6%), `cc:f4:11:9c:d0:00` (25,2%) |
| `DDoS-SYN_Flood1.pcap` | DDoS-SYN_Flood | 26.715.334 | 98,4% | 1,0% | `dc:a6:32:c9:e5:ef` (19,0%), `dc:a6:32:dc:27:d5` (16,4%), `dc:a6:32:c9:e4:ab` (16,1%), `dc:a6:32:c9:e4:d5` (15,4%), `dc:a6:32:c9:e4:90` (14,6%), `e4:5f:01:55:90:c4` (14,3%), `dc:a6:32:c9:e5:a4` (3,7%) | `b0:c5:54:59:2e:99` (29,6%), `44:01:bb:ec:10:4a` (27,6%), `9c:8e:cd:1d:ab:9f` (21,7%) |
| `DDoS-SlowLoris.pcap` | DDoS-SlowLoris | 2.351.454 | 32,8% | 28,9% | `dc:a6:32:dc:27:d5` (9,4%), `dc:a6:32:c9:e4:90` (9,0%), `dc:a6:32:c9:e4:ab` (9,0%), `e4:5f:01:55:90:c4` (8,8%), `dc:a6:32:c9:e5:a4` (8,6%), `dc:a6:32:c9:e4:d5` (8,5%), `dc:a6:32:c9:e5:ef` (8,4%) | `3c:18:a0:41:c3:a0` (33,5%), `40:5d:82:35:14:c8` (14,7%), `b0:c5:54:59:2e:99` (12,2%) |
| `DDoS-SynonymousIP_Flood.pcap` | DDoS-SynonymousIP_Flood | 26.855.630 | 99,8% | 0,0% | `dc:a6:32:c9:e4:ab` (29,2%), `dc:a6:32:c9:e4:90` (19,9%), `dc:a6:32:c9:e5:ef` (11,7%), `dc:a6:32:c9:e5:a4` (11,4%), `e4:5f:01:55:90:c4` (11,3%), `dc:a6:32:c9:e4:d5` (11,2%), `dc:a6:32:dc:27:d5` (5,1%) | `2c:71:ff:05:f1:15` (48,1%), `9c:8e:cd:1d:ab:9f` (44,8%), `8c:85:80:6c:b6:47` (6,9%) |
| `DDoS-TCP_Flood.pcap` | DDoS-TCP_Flood | 26.570.958 | 99,4% | 0,0% | `dc:a6:32:dc:27:d5` (23,2%), `dc:a6:32:c9:e4:d5` (15,8%), `dc:a6:32:c9:e5:ef` (13,8%), `dc:a6:32:c9:e4:ab` (12,9%), `dc:a6:32:c9:e4:90` (12,5%), `e4:5f:01:55:90:c4` (11,6%), `dc:a6:32:c9:e5:a4` (9,5%) | `1c:fe:2b:98:16:dd` (55,3%), `1c:12:b0:9b:0c:ec` (28,0%), `a0:d0:dc:c4:08:ff` (16,2%) |
| `DDoS-UDP_Flood.pcap` | DDoS-UDP_Flood | 26.653.551 | 99,4% | 0,0% | `e4:5f:01:55:90:c4` (15,4%), `dc:a6:32:c9:e4:ab` (15,3%), `dc:a6:32:dc:27:d5` (14,7%), `dc:a6:32:c9:e4:d5` (14,3%), `dc:a6:32:c9:e5:a4` (13,5%), `dc:a6:32:c9:e4:90` (13,4%), `dc:a6:32:c9:e5:ef` (12,8%) | `1c:fe:2b:98:16:dd` (50,8%), `1c:12:b0:9b:0c:ec` (34,2%), `a0:d0:dc:c4:08:ff` (14,5%) |
| `DDoS-UDP_Fragmentation.pcap` | DDoS-UDP_Fragmentation | 2.248.843 | 94,4% | 0,3% | `dc:a6:32:c9:e4:90` (33,0%), `dc:a6:32:c9:e4:d5` (24,4%), `dc:a6:32:c9:e5:ef` (13,0%), `dc:a6:32:c9:e4:ab` (10,5%), `dc:a6:32:dc:27:d5` (5,4%), `e4:5f:01:55:90:c4` (4,9%), `dc:a6:32:c9:e5:a4` (3,7%) | `28:6d:97:9e:f4:d5` (35,7%), `1c:fe:2b:98:16:dd` (33,0%), `2c:71:ff:05:f1:15` (18,5%) |
| `DNS_Spoofing.pcap` | DNS_Spoofing | 1.812.557 | 1,2% | 8,0% | `dc:a6:32:dc:27:d5` (9,2%) | `3c:18:a0:41:c3:a0` (77,6%), `56:4f:8a:e1:f3:2d` (23,6%), `24:05:88:30:6f:89` (11,1%) |
| `DictionaryBruteForce.pcap` | DictionaryBruteForce | 133.138 | 10,7% | 11,8% | `dc:a6:32:dc:27:d5` (22,5%) | `3c:18:a0:41:c3:a0` (59,3%), `dc:a6:32:c9:e4:c6` (16,3%), `70:ee:50:68:0e:32` (8,6%) |
| `DoS-HTTP_Flood1.pcap` | DoS-HTTP_Flood | 3.114.983 | 53,1% | 36,1% | `dc:a6:32:dc:27:d5` (89,2%) | `2c:71:ff:05:f1:15` (39,1%), `dc:a6:32:c9:e5:02` (19,8%), `b0:f1:ec:d3:e7:98` (17,2%) |
| `DoS-SYN_Flood.pcap` | DoS-SYN_Flood | 26.261.611 | 84,2% | 15,1% | `dc:a6:32:dc:27:d5` (99,3%) | `1c:fe:2b:98:16:dd` (35,0%), `a0:d0:dc:c4:08:ff` (34,5%), `1c:12:b0:9b:0c:ec` (30,0%) |
| `DoS-SYN_Flood1.pcap` | DoS-SYN_Flood | 26.405.653 | 98,2% | 1,1% | `dc:a6:32:dc:27:d5` (99,3%) | `cc:f4:11:9c:d0:00` (39,2%), `9c:8e:cd:1d:ab:9f` (36,4%), `c0:e7:bf:0a:79:d1` (18,2%) |
| `DoS-TCP_Flood.pcap` | DoS-TCP_Flood | 26.005.549 | 94,8% | 4,5% | `dc:a6:32:dc:27:d5` (99,3%) | `cc:f4:11:9c:d0:00` (72,6%), `1c:12:b0:9b:0c:ec` (26,9%) |
| `DoS-UDP_Flood.pcap` | DoS-UDP_Flood | 16.676.370 | 99,0% | 0,0% | `dc:a6:32:dc:27:d5` (99,0%) | `9c:8e:cd:1d:ab:9f` (45,6%), `1c:12:b0:9b:0c:ec` (36,6%), `cc:f4:11:9c:d0:00` (17,0%) |
| `MITM-ArpSpoofing.pcap` | MITM-ArpSpoofing | 2.491.622 | 1,1% | 2,9% | `dc:a6:32:dc:27:d5` (3,9%) | `3c:18:a0:41:c3:a0` (90,6%), `56:4f:8a:e1:f3:2d` (19,5%), `94:39:e5:5d:27:a6` (19,4%) |
| `Mirai-greeth_flood.pcap` | Mirai-greeth_flood | 3.352.569 | 97,1% | 0,0% | `dc:a6:32:c9:e4:90` (22,8%), `dc:a6:32:c9:e4:d5` (16,2%), `e4:5f:01:55:90:c4` (15,9%), `dc:a6:32:c9:e4:ab` (13,5%), `dc:a6:32:c9:e5:ef` (11,6%), `dc:a6:32:dc:27:d5` (9,1%), `dc:a6:32:c9:e5:a4` (7,9%) | `1c:fe:2b:98:16:dd` (72,8%), `9c:8e:cd:1d:ab:9f` (24,4%), `3c:18:a0:41:c3:a0` (2,5%) |
| `Mirai-greip_flood21.pcap` | Mirai-greip_flood | 1.196.296 | 98,7% | 0,2% | `dc:a6:32:c9:e4:90` (17,7%), `dc:a6:32:c9:e4:d5` (17,1%), `dc:a6:32:c9:e5:ef` (16,3%), `e4:5f:01:55:90:c4` (14,7%), `dc:a6:32:c9:e4:ab` (12,1%), `dc:a6:32:c9:e5:a4` (11,2%), `dc:a6:32:dc:27:d5` (9,8%) | `28:6d:97:7a:2b:2d` (98,9%) |
| `Mirai-udpplain.pcap` | Mirai-udpplain | 3.642.269 | 97,8% | 0,0% | `dc:a6:32:c9:e4:d5` (20,7%), `dc:a6:32:c9:e4:90` (18,1%), `dc:a6:32:c9:e5:a4` (17,7%), `dc:a6:32:dc:27:d5` (12,2%), `dc:a6:32:c9:e4:ab` (10,8%), `dc:a6:32:c9:e5:ef` (10,2%), `e4:5f:01:55:90:c4` (8,2%) | `1c:fe:2b:98:16:dd` (53,7%), `08:7c:39:ce:6e:2a` (34,7%), `cc:f4:11:9c:d0:00` (9,6%) |
| `Recon-HostDiscovery.pcap` | Recon-HostDiscovery | 1.371.112 | 28,1% | 20,3% | `dc:a6:32:dc:27:d5` (48,3%) | `3c:18:a0:41:c3:a0` (39,9%), `ff:ff:ff:ff:ff:ff` (8,3%), `28:6d:97:7a:2b:2d` (5,6%) |
| `Recon-OSScan.pcap` | Recon-OSScan | 992.241 | 12,2% | 9,9% | `dc:a6:32:dc:27:d5` (22,2%) | `3c:18:a0:41:c3:a0` (60,7%), `40:5d:82:35:14:c8` (16,6%), `ac:17:02:05:34:27` (13,8%) |
| `Recon-PingSweep.pcap` | Recon-PingSweep | 22.943 | 9,7% | 1,9% | `dc:a6:32:dc:27:d5` (11,6%) | `3c:18:a0:41:c3:a0` (71,0%), `ac:17:02:05:34:27` (17,2%), `ff:ff:ff:ff:ff:ff` (13,8%) |
| `Recon-PortScan.pcap` | Recon-PortScan | 831.856 | 17,3% | 14,6% | `dc:a6:32:dc:27:d5` (31,8%) | `3c:18:a0:41:c3:a0` (50,4%), `ac:17:02:05:34:27` (14,9%), `00:0c:29:1c:55:4a` (6,9%) |
| `SqlInjection.pcap` | SqlInjection | 53.462 | 4,7% | 4,2% | `dc:a6:32:dc:27:d5` (8,9%) | `3c:18:a0:41:c3:a0` (70,1%), `ac:17:02:05:34:27` (27,6%), `ff:ff:ff:ff:ff:ff` (9,4%) |
| `Uploading_Attack.pcap` | Uploading_Attack | 12.939 | 4,4% | 3,7% | `dc:a6:32:dc:27:d5` (5,6%), `dc:a6:32:c9:e5:a4` (2,6%) | `3c:18:a0:41:c3:a0` (73,9%), `ff:ff:ff:ff:ff:ff` (12,5%), `dc:a6:32:c9:e6:f4` (8,4%) |
| `VulnerabilityScan.pcap` | VulnerabilityScan | 3.802.533 | 5,1% | 4,6% | `dc:a6:32:dc:27:d5` (9,7%) | `3c:18:a0:41:c3:a0` (70,2%), `ac:17:02:05:34:27` (25,2%), `ff:ff:ff:ff:ff:ff` (8,7%) |
| `XSS.pcap` | XSS | 40.183 | 3,8% | 3,2% | `dc:a6:32:dc:27:d5` (4,4%), `dc:a6:32:c9:e5:a4` (2,6%) | `3c:18:a0:41:c3:a0` (73,8%), `ff:ff:ff:ff:ff:ff` (12,2%), `70:ee:50:68:0e:32` (9,2%) |

Nos pcaps benignos, os MACs da lista também aparecem:

- `BenignTraffic.pcap`: 3.664.164 quadros; `dc:a6:32:c9:e4:90` em 28 como origem e 7 como destino (0,00%); `dc:a6:32:c9:e4:ab` em 19 como origem e 4 como destino (0,00%); `dc:a6:32:c9:e4:d5` em 28 como origem e 7 como destino (0,00%); `dc:a6:32:c9:e5:a4` em 25 como origem e 11 como destino (0,00%); `dc:a6:32:c9:e5:ef` em 28 como origem e 10 como destino (0,00%); `dc:a6:32:dc:27:d5` em 18.563 como origem e 17.374 como destino (0,98%); `e4:5f:01:55:90:c4` em 19 como origem e 8 como destino (0,00%)
- `BenignTraffic1.pcap`: 2.988.642 quadros; `dc:a6:32:c9:e4:90` em 21 como origem e 9 como destino (0,00%); `dc:a6:32:c9:e4:ab` em 19 como origem e 9 como destino (0,00%); `dc:a6:32:c9:e4:d5` em 25 como origem e 8 como destino (0,00%); `dc:a6:32:c9:e5:a4` em 22 como origem e 4 como destino (0,00%); `dc:a6:32:c9:e5:ef` em 21 como origem e 6 como destino (0,00%); `dc:a6:32:dc:27:d5` em 14.784 como origem e 14.605 como destino (0,98%); `e4:5f:01:55:90:c4` em 18 como origem e 6 como destino (0,00%)
- `BenignTraffic2.pcap`: 3.138.002 quadros; `dc:a6:32:c9:e4:90` em 25 como origem e 5 como destino (0,00%); `dc:a6:32:c9:e4:ab` em 19 como origem e 7 como destino (0,00%); `dc:a6:32:c9:e4:d5` em 26 como origem e 8 como destino (0,00%); `dc:a6:32:c9:e5:a4` em 17 como origem e 4 como destino (0,00%); `dc:a6:32:c9:e5:ef` em 25 como origem e 5 como destino (0,00%); `dc:a6:32:dc:27:d5` em 16.646 como origem e 15.018 como destino (1,01%); `e4:5f:01:55:90:c4` em 18 como origem e 7 como destino (0,00%)

A regra de rótulo da regeração não usa a lista nos pcaps benignos: toda janela de um pcap benigno é
benigna. A presença desses MACs ali mostra que o dispositivo que ataca também gera tráfego comum, e
que o MAC sozinho não separa ataque de tráfego normal fora da captura de ataque.

## Janelas sem atacante, por pcap e por janela

A quantidade de janelas de cada pcap de ataque, quantas não têm nenhum quadro de um MAC da lista e a
fração que isso representa. São essas as janelas que a regeração descarta.

| Arquivo | Rótulo | Janelas de 10 | Sem atacante (10) | Fração (10) | Janelas de 100 | Sem atacante (100) | Fração (100) |
|---|---|---|---|---|---|---|---|
| `Backdoor_Malware.pcap` | Backdoor_Malware | 3.218 | 2.306 | 71,66% | 322 | 69 | 21,43% |
| `BrowserHijacking.pcap` | BrowserHijacking | 5.858 | 3.382 | 57,73% | 586 | 127 | 21,67% |
| `CommandInjection.pcap` | CommandInjection | 5.409 | 4.207 | 77,78% | 541 | 164 | 30,31% |
| `DDoS-ACK_Fragmentation.pcap` | DDoS-ACK_Fragmentation | 249.836 | 5.936 | 2,38% | 24.984 | 527 | 2,11% |
| `DDoS-HTTP_Flood-.pcap` | DDoS-HTTP_Flood | 287.559 | 6.603 | 2,30% | 28.756 | 186 | 0,65% |
| `DDoS-ICMP_Flood.pcap` | DDoS-ICMP_Flood | 2.679.086 | 1.783 | 0,07% | 267.909 | 46 | 0,02% |
| `DDoS-ICMP_Fragmentation.pcap` | DDoS-ICMP_Fragmentation | 205.967 | 2.826 | 1,37% | 20.597 | 118 | 0,57% |
| `DDoS-PSHACK_Flood.pcap` | DDoS-PSHACK_Flood | 2.677.112 | 1.640 | 0,06% | 267.712 | 94 | 0,04% |
| `DDoS-RSTFINFlood.pcap` | DDoS-RSTFINFlood | 2.668.315 | 1.655 | 0,06% | 266.832 | 90 | 0,03% |
| `DDoS-SYN_Flood.pcap` | DDoS-SYN_Flood | 2.659.244 | 2.622 | 0,10% | 265.925 | 223 | 0,08% |
| `DDoS-SYN_Flood1.pcap` | DDoS-SYN_Flood | 2.670.961 | 1.420 | 0,05% | 267.097 | 68 | 0,03% |
| `DDoS-SlowLoris.pcap` | DDoS-SlowLoris | 233.903 | 54.302 | 23,22% | 23.391 | 1.681 | 7,19% |
| `DDoS-SynonymousIP_Flood.pcap` | DDoS-SynonymousIP_Flood | 2.685.243 | 576 | 0,02% | 268.525 | 26 | 0,01% |
| `DDoS-TCP_Flood.pcap` | DDoS-TCP_Flood | 2.656.703 | 6.661 | 0,25% | 265.671 | 453 | 0,17% |
| `DDoS-UDP_Flood.pcap` | DDoS-UDP_Flood | 2.665.025 | 3.649 | 0,14% | 266.503 | 206 | 0,08% |
| `DDoS-UDP_Fragmentation.pcap` | DDoS-UDP_Fragmentation | 224.381 | 2.684 | 1,20% | 22.439 | 45 | 0,20% |
| `DNS_Spoofing.pcap` | DNS_Spoofing | 178.872 | 130.996 | 73,23% | 17.888 | 7.302 | 40,82% |
| `DictionaryBruteForce.pcap` | DictionaryBruteForce | 13.064 | 7.515 | 57,52% | 1.307 | 265 | 20,28% |
| `DoS-HTTP_Flood1.pcap` | DoS-HTTP_Flood | 310.988 | 12.085 | 3,89% | 31.099 | 218 | 0,70% |
| `DoS-SYN_Flood.pcap` | DoS-SYN_Flood | 2.625.859 | 1.806 | 0,07% | 262.586 | 10 | 0,00% |
| `DoS-SYN_Flood1.pcap` | DoS-SYN_Flood | 2.640.253 | 2.873 | 0,11% | 264.026 | 72 | 0,03% |
| `DoS-TCP_Flood.pcap` | DoS-TCP_Flood | 2.600.275 | 2.849 | 0,11% | 260.028 | 52 | 0,02% |
| `DoS-UDP_Flood.pcap` | DoS-UDP_Flood | 1.667.378 | 2.828 | 0,17% | 166.738 | 85 | 0,05% |
| `MITM-ArpSpoofing.pcap` | MITM-ArpSpoofing | 247.646 | 216.418 | 87,39% | 24.765 | 16.571 | 66,91% |
| `Mirai-greeth_flood.pcap` | Mirai-greeth_flood | 335.007 | 5.850 | 1,75% | 33.501 | 493 | 1,47% |
| `Mirai-greip_flood21.pcap` | Mirai-greip_flood | 119.545 | 14 | 0,01% | 11.955 | 0 | 0,00% |
| `Mirai-udpplain.pcap` | Mirai-udpplain | 363.888 | 1.807 | 0,50% | 36.389 | 16 | 0,04% |
| `Recon-HostDiscovery.pcap` | Recon-HostDiscovery | 134.369 | 43.839 | 32,63% | 13.437 | 441 | 3,28% |
| `Recon-OSScan.pcap` | Recon-OSScan | 98.243 | 68.493 | 69,72% | 9.825 | 5.738 | 58,40% |
| `Recon-PingSweep.pcap` | Recon-PingSweep | 2.262 | 1.722 | 76,13% | 227 | 113 | 49,78% |
| `Recon-PortScan.pcap` | Recon-PortScan | 82.278 | 51.406 | 62,48% | 8.228 | 4.445 | 54,02% |
| `SqlInjection.pcap` | SqlInjection | 5.245 | 4.210 | 80,27% | 525 | 200 | 38,10% |
| `Uploading_Attack.pcap` | Uploading_Attack | 1.252 | 895 | 71,49% | 126 | 20 | 15,87% |
| `VulnerabilityScan.pcap` | VulnerabilityScan | 373.312 | 285.198 | 76,40% | 37.332 | 18.496 | 49,54% |
| `XSS.pcap` | XSS | 3.845 | 2.869 | 74,62% | 385 | 72 | 18,70% |

## Como os números foram obtidos

- Comando: `python -m codigo.classificador.atacantes`, a partir da raiz do repositório, com os pcaps em `CICIoT2023`.
- Cada pcap é lido inteiro uma vez, em leitura contínua, sem o fatiamento em pedaços de 10 MB com que os
  autores geraram os CSVs oficiais. Os MACs são contados em todos os quadros do arquivo; as janelas são
  as do extrator (`codigo/captura/extrator.py`), só com quadros IPv4 e ARP, e a última janela de cada
  tamanho pode ficar incompleta.
- A tabela `janelas_sem_atacante.csv` tem uma linha por pcap e janela, e `janelas_sem_atacante_macs.csv` traz, por pcap, as
  contagens dos sete MACs da lista e dos 10 mais frequentes fora dela. O manifesto
  `manifesto_janelas_sem_atacante.json` guarda tudo, com o tamanho, a data de modificação e o SHA-256 de cada pcap: numa
  execução seguinte, só os pcaps novos ou alterados são lidos de novo.
- Pcaps, com o tamanho, os pacotes e o tempo de leitura de cada um:
  - `Backdoor_Malware.pcap`: 10.544.806 bytes, 33.414 pacotes, 0,3 s, SHA-256 `7b0a7cb3a9c569939526e3bc97e29ddfd1599e2c7af099b0e04d50ca8a4e3bd8`
  - `BenignTraffic.pcap`: 2.048.000.100 bytes, 3.664.164 pacotes, 31,3 s, SHA-256 `549a89337f529412f2507f862d06394c95e5966b9c01aaa980511590657d1dc8`
  - `BenignTraffic1.pcap`: 2.048.002.499 bytes, 2.988.642 pacotes, 26,0 s, SHA-256 `7af057c6681e076151cc28e123a44ea6ff0e3b174d39d456ba7ccf1ac22d24c0`
  - `BenignTraffic2.pcap`: 2.048.001.991 bytes, 3.138.002 pacotes, 27,3 s, SHA-256 `ddafc1c1d3432bdde55340423196ceee79bba47b48b14179ae48d561cca341b8`
  - `BrowserHijacking.pcap`: 35.038.616 bytes, 59.821 pacotes, 0,5 s, SHA-256 `aeac45ba4fdb14575af2e8193d3ef99783e15760eea76696a9155655f5c99138`
  - `CommandInjection.pcap`: 28.585.606 bytes, 55.741 pacotes, 0,5 s, SHA-256 `151c761536d530d8432589e35ed09f2162e51c78a28995fc2a7dbeae32082b13`
  - `DDoS-ACK_Fragmentation.pcap`: 2.048.001.110 bytes, 2.503.835 pacotes, 20,4 s, SHA-256 `004fc3523ca44423199a2deff0b83279f23c290d4efc9e60de1c935f23f96f69`
  - `DDoS-HTTP_Flood-.pcap`: 610.856.427 bytes, 2.881.005 pacotes, 24,8 s, SHA-256 `299c6f2180b3cf94ebb14e3e5aa5afe16ff51eac232f7f2c61a4384443eb7387`
  - `DDoS-ICMP_Flood.pcap`: 2.048.000.069 bytes, 26.793.240 pacotes, 198,0 s, SHA-256 `0455a66ec4296eaafe6c344352b3c047e8863f9e6e07dd84848854380974155f`
  - `DDoS-ICMP_Fragmentation.pcap`: 2.048.001.116 bytes, 2.064.692 pacotes, 15,7 s, SHA-256 `2c7b656619d03091bfb708e8a6408cbf0b98c4b32c9550e92f00547428f40540`
  - `DDoS-PSHACK_Flood.pcap`: 2.048.000.022 bytes, 26.774.357 pacotes, 218,5 s, SHA-256 `ad455d997fb960ef54d78ec8d33e684fc8a69a56cf1b557742c37a5ff135b8a0`
  - `DDoS-RSTFINFlood.pcap`: 2.048.000.045 bytes, 26.686.473 pacotes, 218,4 s, SHA-256 `35d4088099d0b74de066ae2ca8cae905c2c82c5de3d5b696f88016c64ec7c46e`
  - `DDoS-SYN_Flood.pcap`: 2.048.000.063 bytes, 26.597.011 pacotes, 217,6 s, SHA-256 `5e8124a87e12483af05cb5b4f36dc095c2a979b08f2ee4e18918c26ad3b041b8`
  - `DDoS-SYN_Flood1.pcap`: 2.048.000.055 bytes, 26.715.334 pacotes, 219,1 s, SHA-256 `ff5c25cd6d5eb7fd15b599a93e5e53b3c74bc2d528b8f0429c95ab2114ef6fc5`
  - `DDoS-SlowLoris.pcap`: 675.607.734 bytes, 2.351.454 pacotes, 19,6 s, SHA-256 `9dc14b610031d43366c302d4bc68e173a2d02bedd9470997cd9be6aa26d2eaea`
  - `DDoS-SynonymousIP_Flood.pcap`: 2.048.000.024 bytes, 26.855.630 pacotes, 219,1 s, SHA-256 `d2ef859ee93d34edce1d4bfc1de4ea234cf960a3bfd3cf374845a5ddb1d2767a`
  - `DDoS-TCP_Flood.pcap`: 2.048.000.035 bytes, 26.570.958 pacotes, 215,7 s, SHA-256 `39d7597311b1eacad9c46c0779f0493d9ee51b2e4b344ae6dd47221e5ad04cec`
  - `DDoS-UDP_Flood.pcap`: 2.048.000.061 bytes, 26.653.551 pacotes, 182,5 s, SHA-256 `541250a7494dca056bdf584e8c6705a346c85c8561319d251e3afc167c6c00c4`
  - `DDoS-UDP_Fragmentation.pcap`: 2.048.000.788 bytes, 2.248.843 pacotes, 17,0 s, SHA-256 `dfa0770d74d06ce8ae2c57479877e11d41e5f0f616d4cbd30bc5e51364225cee`
  - `DNS_Spoofing.pcap`: 971.824.063 bytes, 1.812.557 pacotes, 14,8 s, SHA-256 `edf47246de6b7e43bd27252ddf6716957952a736fafaa1b0060ca62f78d8c323`
  - `DictionaryBruteForce.pcap`: 39.130.622 bytes, 133.138 pacotes, 1,1 s, SHA-256 `09ad3cfabd139b950da3078fec0f0fd196fe36cd82237d898035437f4c69161b`
  - `DoS-HTTP_Flood1.pcap`: 1.491.704.312 bytes, 3.114.983 pacotes, 26,7 s, SHA-256 `2b7df8fce78461e435952e39cb2e33c445b137fa08ee7429d97fde6d93032d40`
  - `DoS-SYN_Flood.pcap`: 2.048.000.026 bytes, 26.261.611 pacotes, 212,9 s, SHA-256 `3f45569b3438b1ee5fa9105922a423789e4de176a66d550082f5f082f6546ebd`
  - `DoS-SYN_Flood1.pcap`: 2.048.000.065 bytes, 26.405.653 pacotes, 215,7 s, SHA-256 `d35fd7510fb9985e478f91010249e45caa453e6e15b88b093c811d104e5c2dfd`
  - `DoS-TCP_Flood.pcap`: 2.048.000.008 bytes, 26.005.549 pacotes, 227,7 s, SHA-256 `255b6f1cfabdb8c6a645ce40ab089d75df7b5eade61c29c5648ffc7281de3653`
  - `DoS-UDP_Flood.pcap`: 2.048.000.059 bytes, 16.676.370 pacotes, 114,8 s, SHA-256 `346e9afbba2ed957598b6ae46e98eed62c56120800e67bf05d177117a5dfc74b`
  - `MITM-ArpSpoofing.pcap`: 2.046.238.529 bytes, 2.491.622 pacotes, 21,4 s, SHA-256 `da097ba27f5690cf4fe47b916c825735af8a829074a71202624740bf4b7cc196`
  - `Mirai-greeth_flood.pcap`: 2.048.000.288 bytes, 3.352.569 pacotes, 38,5 s, SHA-256 `87f8de16e575f23fca6c159a94360c6dd2970c4d9a1711d46c9468f1cf724c0e`
  - `Mirai-greip_flood21.pcap`: 704.513.741 bytes, 1.196.296 pacotes, 11,9 s, SHA-256 `5a77e5c663c31759d7834047bd85197dfd51f2cb7dcc22bfe0a8d1dbf1973742`
  - `Mirai-udpplain.pcap`: 2.048.000.451 bytes, 3.642.269 pacotes, 27,6 s, SHA-256 `845a8c833c5841203b75d776a353526f55a7fbcd9ca3079b53848e85a62ed3a7`
  - `Recon-HostDiscovery.pcap`: 227.658.836 bytes, 1.371.112 pacotes, 11,1 s, SHA-256 `34035ba8a3e6d9db4e2d03e8f78c350980e1cedaa8c1e30a9d7abb080c93e9d3`
  - `Recon-OSScan.pcap`: 323.891.580 bytes, 992.241 pacotes, 8,5 s, SHA-256 `8e99115ca67ea6c34fd68bd713c5ba5ae671a0a90a327568f732279494f804f0`
  - `Recon-PingSweep.pcap`: 7.853.566 bytes, 22.943 pacotes, 0,2 s, SHA-256 `1aaf410fcc6dbfefa48b680b401344f0fa7b6e04c2acc9af427b5b7728b0ee89`
  - `Recon-PortScan.pcap`: 200.950.957 bytes, 831.856 pacotes, 6,9 s, SHA-256 `e13368bdc571a6ec53f8dd9e5491137dd0656c9d997bd62b323e957722bd4fc1`
  - `SqlInjection.pcap`: 9.823.016 bytes, 53.462 pacotes, 0,4 s, SHA-256 `712750bd64f8250861bd8a76bd1c33a44a4fe8d3dc2f34e2043c208edc19bde7`
  - `Uploading_Attack.pcap`: 3.326.177 bytes, 12.939 pacotes, 0,1 s, SHA-256 `13eb2c9478cb3d54921766436808cc89623f25179565241ece3c20a95ca71ee8`
  - `VulnerabilityScan.pcap`: 1.026.603.272 bytes, 3.802.533 pacotes, 31,1 s, SHA-256 `92321b9a016264f09a1f0bc487a91c88364dc41f2e67e73b10883c3fa3128439`
  - `XSS.pcap`: 12.571.710 bytes, 40.183 pacotes, 0,3 s, SHA-256 `62a9d0ca316f3e5eb9c910fc8c21dc169ef76033bafa22d17f85f53e64809bf0`

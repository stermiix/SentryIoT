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
| `DDoS-HTTP_Flood-.pcap` | DDoS-HTTP_Flood | 2.881.005 | 24,5% | 67,0% | `dc:a6:32:dc:27:d5` (20,5%), `dc:a6:32:c9:e4:90` (13,2%), `e4:5f:01:55:90:c4` (13,0%), `dc:a6:32:c9:e4:ab` (12,3%), `dc:a6:32:c9:e5:a4` (11,7%), `dc:a6:32:c9:e4:d5` (10,7%), `dc:a6:32:c9:e5:ef` (10,1%) | `9c:8e:cd:1d:ab:9f` (23,9%), `b0:c5:54:59:2e:99` (14,3%), `b0:f1:ec:d3:e7:98` (11,9%) |
| `DDoS-SYN_Flood.pcap` | DDoS-SYN_Flood | 26.597.011 | 97,8% | 1,5% | `dc:a6:32:c9:e4:ab` (26,9%), `dc:a6:32:dc:27:d5` (16,5%), `dc:a6:32:c9:e4:90` (15,9%), `e4:5f:01:55:90:c4` (14,6%), `dc:a6:32:c9:e5:ef` (14,0%), `dc:a6:32:c9:e4:d5` (11,3%) | `1c:12:b0:9b:0c:ec` (33,7%), `1c:fe:2b:98:16:dd` (29,6%), `cc:f4:11:9c:d0:00` (25,2%) |
| `DNS_Spoofing.pcap` | DNS_Spoofing | 1.812.557 | 1,2% | 8,0% | `dc:a6:32:dc:27:d5` (9,2%) | `3c:18:a0:41:c3:a0` (77,6%), `56:4f:8a:e1:f3:2d` (23,6%), `24:05:88:30:6f:89` (11,1%) |
| `DictionaryBruteForce.pcap` | DictionaryBruteForce | 133.138 | 10,7% | 11,8% | `dc:a6:32:dc:27:d5` (22,5%) | `3c:18:a0:41:c3:a0` (59,3%), `dc:a6:32:c9:e4:c6` (16,3%), `70:ee:50:68:0e:32` (8,6%) |
| `DoS-HTTP_Flood1.pcap` | DoS-HTTP_Flood | 3.114.983 | 53,1% | 36,1% | `dc:a6:32:dc:27:d5` (89,2%) | `2c:71:ff:05:f1:15` (39,1%), `dc:a6:32:c9:e5:02` (19,8%), `b0:f1:ec:d3:e7:98` (17,2%) |
| `DoS-SYN_Flood.pcap` | DoS-SYN_Flood | 26.261.611 | 84,2% | 15,1% | `dc:a6:32:dc:27:d5` (99,3%) | `1c:fe:2b:98:16:dd` (35,0%), `a0:d0:dc:c4:08:ff` (34,5%), `1c:12:b0:9b:0c:ec` (30,0%) |
| `MITM-ArpSpoofing.pcap` | MITM-ArpSpoofing | 2.491.622 | 1,1% | 2,9% | `dc:a6:32:dc:27:d5` (3,9%) | `3c:18:a0:41:c3:a0` (90,6%), `56:4f:8a:e1:f3:2d` (19,5%), `94:39:e5:5d:27:a6` (19,4%) |
| `Mirai-greip_flood21.pcap` | Mirai-greip_flood | 1.196.296 | 98,7% | 0,2% | `dc:a6:32:c9:e4:90` (17,7%), `dc:a6:32:c9:e4:d5` (17,1%), `dc:a6:32:c9:e5:ef` (16,3%), `e4:5f:01:55:90:c4` (14,7%), `dc:a6:32:c9:e4:ab` (12,1%), `dc:a6:32:c9:e5:a4` (11,2%), `dc:a6:32:dc:27:d5` (9,8%) | `28:6d:97:7a:2b:2d` (98,9%) |
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
| `DDoS-HTTP_Flood-.pcap` | DDoS-HTTP_Flood | 287.559 | 6.603 | 2,30% | 28.756 | 186 | 0,65% |
| `DDoS-SYN_Flood.pcap` | DDoS-SYN_Flood | 2.659.244 | 2.622 | 0,10% | 265.925 | 223 | 0,08% |
| `DNS_Spoofing.pcap` | DNS_Spoofing | 178.872 | 130.996 | 73,23% | 17.888 | 7.302 | 40,82% |
| `DictionaryBruteForce.pcap` | DictionaryBruteForce | 13.064 | 7.515 | 57,52% | 1.307 | 265 | 20,28% |
| `DoS-HTTP_Flood1.pcap` | DoS-HTTP_Flood | 310.988 | 12.085 | 3,89% | 31.099 | 218 | 0,70% |
| `DoS-SYN_Flood.pcap` | DoS-SYN_Flood | 2.625.859 | 1.806 | 0,07% | 262.586 | 10 | 0,00% |
| `MITM-ArpSpoofing.pcap` | MITM-ArpSpoofing | 247.646 | 216.418 | 87,39% | 24.765 | 16.571 | 66,91% |
| `Mirai-greip_flood21.pcap` | Mirai-greip_flood | 119.545 | 14 | 0,01% | 11.955 | 0 | 0,00% |
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
  - `BrowserHijacking.pcap`: 35.038.616 bytes, 59.821 pacotes, 0,5 s, SHA-256 `aeac45ba4fdb14575af2e8193d3ef99783e15760eea76696a9155655f5c99138`
  - `CommandInjection.pcap`: 28.585.606 bytes, 55.741 pacotes, 0,5 s, SHA-256 `151c761536d530d8432589e35ed09f2162e51c78a28995fc2a7dbeae32082b13`
  - `DDoS-HTTP_Flood-.pcap`: 610.856.427 bytes, 2.881.005 pacotes, 24,8 s, SHA-256 `299c6f2180b3cf94ebb14e3e5aa5afe16ff51eac232f7f2c61a4384443eb7387`
  - `DDoS-SYN_Flood.pcap`: 2.048.000.063 bytes, 26.597.011 pacotes, 217,6 s, SHA-256 `5e8124a87e12483af05cb5b4f36dc095c2a979b08f2ee4e18918c26ad3b041b8`
  - `DNS_Spoofing.pcap`: 971.824.063 bytes, 1.812.557 pacotes, 14,8 s, SHA-256 `edf47246de6b7e43bd27252ddf6716957952a736fafaa1b0060ca62f78d8c323`
  - `DictionaryBruteForce.pcap`: 39.130.622 bytes, 133.138 pacotes, 1,1 s, SHA-256 `09ad3cfabd139b950da3078fec0f0fd196fe36cd82237d898035437f4c69161b`
  - `DoS-HTTP_Flood1.pcap`: 1.491.704.312 bytes, 3.114.983 pacotes, 26,7 s, SHA-256 `2b7df8fce78461e435952e39cb2e33c445b137fa08ee7429d97fde6d93032d40`
  - `DoS-SYN_Flood.pcap`: 2.048.000.026 bytes, 26.261.611 pacotes, 212,9 s, SHA-256 `3f45569b3438b1ee5fa9105922a423789e4de176a66d550082f5f082f6546ebd`
  - `MITM-ArpSpoofing.pcap`: 2.046.238.529 bytes, 2.491.622 pacotes, 21,4 s, SHA-256 `da097ba27f5690cf4fe47b916c825735af8a829074a71202624740bf4b7cc196`
  - `Mirai-greip_flood21.pcap`: 704.513.741 bytes, 1.196.296 pacotes, 11,9 s, SHA-256 `5a77e5c663c31759d7834047bd85197dfd51f2cb7dcc22bfe0a8d1dbf1973742`
  - `Recon-HostDiscovery.pcap`: 227.658.836 bytes, 1.371.112 pacotes, 11,1 s, SHA-256 `34035ba8a3e6d9db4e2d03e8f78c350980e1cedaa8c1e30a9d7abb080c93e9d3`
  - `Recon-OSScan.pcap`: 323.891.580 bytes, 992.241 pacotes, 8,5 s, SHA-256 `8e99115ca67ea6c34fd68bd713c5ba5ae671a0a90a327568f732279494f804f0`
  - `Recon-PingSweep.pcap`: 7.853.566 bytes, 22.943 pacotes, 0,2 s, SHA-256 `1aaf410fcc6dbfefa48b680b401344f0fa7b6e04c2acc9af427b5b7728b0ee89`
  - `Recon-PortScan.pcap`: 200.950.957 bytes, 831.856 pacotes, 6,9 s, SHA-256 `e13368bdc571a6ec53f8dd9e5491137dd0656c9d997bd62b323e957722bd4fc1`
  - `SqlInjection.pcap`: 9.823.016 bytes, 53.462 pacotes, 0,4 s, SHA-256 `712750bd64f8250861bd8a76bd1c33a44a4fe8d3dc2f34e2043c208edc19bde7`
  - `Uploading_Attack.pcap`: 3.326.177 bytes, 12.939 pacotes, 0,1 s, SHA-256 `13eb2c9478cb3d54921766436808cc89623f25179565241ece3c20a95ca71ee8`
  - `VulnerabilityScan.pcap`: 1.026.603.272 bytes, 3.802.533 pacotes, 31,1 s, SHA-256 `92321b9a016264f09a1f0bc487a91c88364dc41f2e67e73b10883c3fa3128439`
  - `XSS.pcap`: 12.571.710 bytes, 40.183 pacotes, 0,3 s, SHA-256 `62a9d0ca316f3e5eb9c910fc8c21dc169ef76033bafa22d17f85f53e64809bf0`

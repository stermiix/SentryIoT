# Treino sobre os dados regerados

Gerado por `python -m codigo.classificador.treinar_regerado` em 10/10/2026, com Python 3.11.2, scikit-learn 1.9.1, pandas 3.0.6 e numpy 2.4.6.

O modelo treinado no `MERGED_CSV` oficial aprende o tamanho da janela, de 100 quadros nas classes de
DDoS, DoS e Mirai e de 10 nas demais, em vez do comportamento do tráfego (`teste_da_janela.md`), e o
rótulo oficial é dado ao arquivo inteiro, mesmo nas janelas sem nenhum quadro do atacante
(`janelas_sem_atacante.md`). Por isso os dados de treino foram gerados de novo a partir dos pcaps, com o
nosso extrator, em janela única e com o rótulo decidido janela a janela (decisão de 10/10/2026 no
`ROADMAP.md`). Este relatório traz o Random Forest de 7 categorias treinado nesses dados, um modelo por
janela, de 10 e 100 quadros, e as medidas de cada um na parte de teste.

## Os dados regerados

Os pcaps da pasta do dataset em 10/10/2026, lidos
inteiros pelo extrator em leitura contínua, com os dois tamanhos de janela. Regra de rótulo: num pcap
benigno toda janela é `BenignTraffic`; num pcap de ataque a janela recebe o rótulo do arquivo se tem
quadro com MAC de um Raspberry Pi atacante na origem ou no destino, e é descartada se não tem. A janela
descartada não vira benigna, porque o tráfego de fundo de uma captura de ataque pode estar contaminado.

| Arquivo | Rótulo | Categoria | Pacotes | Janelas de 10 | Mantidas (10) | Janelas de 100 | Mantidas (100) | Extração (s) |
|---|---|---|---|---|---|---|---|---|
| `Backdoor_Malware.pcap` | Backdoor_Malware | Web | 33.414 | 3.218 | 912 (28,3%) | 322 | 253 (78,6%) | 0,3 |
| `BenignTraffic.pcap` | BenignTraffic | Benign | 3.664.164 | 362.278 | 362.278 (100,0%) | 36.228 | 36.228 (100,0%) | 35,9 |
| `BenignTraffic1.pcap` | BenignTraffic | Benign | 2.988.642 | 295.489 | 295.489 (100,0%) | 29.549 | 29.549 (100,0%) | 29,5 |
| `BrowserHijacking.pcap` | BrowserHijacking | Web | 59.821 | 5.858 | 2.476 (42,3%) | 586 | 459 (78,3%) | 0,5 |
| `CommandInjection.pcap` | CommandInjection | Web | 55.741 | 5.409 | 1.202 (22,2%) | 541 | 377 (69,7%) | 0,5 |
| `DDoS-HTTP_Flood-.pcap` | DDoS-HTTP_Flood | DDoS | 2.881.005 | 287.559 | 280.956 (97,7%) | 28.756 | 28.570 (99,4%) | 27,4 |
| `DDoS-ICMP_Flood.pcap` | DDoS-ICMP_Flood | DDoS | 26.793.240 | 2.679.086 | 2.677.303 (99,9%) | 267.909 | 267.863 (100,0%) | 219,6 |
| `DDoS-SYN_Flood.pcap` | DDoS-SYN_Flood | DDoS | 26.597.011 | 2.659.244 | 2.656.622 (99,9%) | 265.925 | 265.702 (99,9%) | 235,9 |
| `DDoS-TCP_Flood.pcap` | DDoS-TCP_Flood | DDoS | 26.570.958 | 2.656.703 | 2.650.042 (99,7%) | 265.671 | 265.218 (99,8%) | 237,8 |
| `DDoS-UDP_Flood.pcap` | DDoS-UDP_Flood | DDoS | 26.653.551 | 2.665.025 | 2.661.376 (99,9%) | 266.503 | 266.297 (99,9%) | 203,0 |
| `DNS_Spoofing.pcap` | DNS_Spoofing | Spoofing | 1.812.557 | 178.872 | 47.876 (26,8%) | 17.888 | 10.586 (59,2%) | 15,7 |
| `DictionaryBruteForce.pcap` | DictionaryBruteForce | BruteForce | 133.138 | 13.064 | 5.549 (42,5%) | 1.307 | 1.042 (79,7%) | 1,2 |
| `DoS-HTTP_Flood1.pcap` | DoS-HTTP_Flood | DoS | 3.114.983 | 310.988 | 298.903 (96,1%) | 31.099 | 30.881 (99,3%) | 30,4 |
| `DoS-SYN_Flood.pcap` | DoS-SYN_Flood | DoS | 26.261.611 | 2.625.859 | 2.624.053 (99,9%) | 262.586 | 262.576 (100,0%) | 235,4 |
| `DoS-TCP_Flood.pcap` | DoS-TCP_Flood | DoS | 26.005.549 | 2.600.275 | 2.597.426 (99,9%) | 260.028 | 259.976 (100,0%) | 237,6 |
| `DoS-UDP_Flood.pcap` | DoS-UDP_Flood | DoS | 16.676.370 | 1.667.378 | 1.664.550 (99,8%) | 166.738 | 166.653 (99,9%) | 128,7 |
| `MITM-ArpSpoofing.pcap` | MITM-ArpSpoofing | Spoofing | 2.491.622 | 247.646 | 31.228 (12,6%) | 24.765 | 8.194 (33,1%) | 21,7 |
| `Mirai-greip_flood21.pcap` | Mirai-greip_flood | Mirai | 1.196.296 | 119.545 | 119.531 (100,0%) | 11.955 | 11.955 (100,0%) | 12,8 |
| `Recon-HostDiscovery.pcap` | Recon-HostDiscovery | Recon | 1.371.112 | 134.369 | 90.530 (67,4%) | 13.437 | 12.996 (96,7%) | 12,2 |
| `Recon-OSScan.pcap` | Recon-OSScan | Recon | 992.241 | 98.243 | 29.750 (30,3%) | 9.825 | 4.087 (41,6%) | 8,6 |
| `Recon-PingSweep.pcap` | Recon-PingSweep | Recon | 22.943 | 2.262 | 540 (23,9%) | 227 | 114 (50,2%) | 0,2 |
| `Recon-PortScan.pcap` | Recon-PortScan | Recon | 831.856 | 82.278 | 30.872 (37,5%) | 8.228 | 3.783 (46,0%) | 7,2 |
| `SqlInjection.pcap` | SqlInjection | Web | 53.462 | 5.245 | 1.035 (19,7%) | 525 | 325 (61,9%) | 0,5 |
| `Uploading_Attack.pcap` | Uploading_Attack | Web | 12.939 | 1.252 | 357 (28,5%) | 126 | 106 (84,1%) | 0,1 |
| `VulnerabilityScan.pcap` | VulnerabilityScan | Recon | 3.802.533 | 373.312 | 88.114 (23,6%) | 37.332 | 18.836 (50,5%) | 33,5 |
| `XSS.pcap` | XSS | Web | 40.183 | 3.845 | 976 (25,4%) | 385 | 313 (81,3%) | 0,3 |

Linhas regeradas por rótulo, somando os arquivos dele:

| Rótulo | Categoria | Arquivos | Linhas (10) | Linhas (100) |
|---|---|---|---|---|
| Backdoor_Malware | Web | `Backdoor_Malware.pcap` | 912 | 253 |
| BenignTraffic | Benign | `BenignTraffic.pcap` e `BenignTraffic1.pcap` | 657.767 | 65.777 |
| BrowserHijacking | Web | `BrowserHijacking.pcap` | 2.476 | 459 |
| CommandInjection | Web | `CommandInjection.pcap` | 1.202 | 377 |
| DDoS-HTTP_Flood | DDoS | `DDoS-HTTP_Flood-.pcap` | 280.956 | 28.570 |
| DDoS-ICMP_Flood | DDoS | `DDoS-ICMP_Flood.pcap` | 2.677.303 | 267.863 |
| DDoS-SYN_Flood | DDoS | `DDoS-SYN_Flood.pcap` | 2.656.622 | 265.702 |
| DDoS-TCP_Flood | DDoS | `DDoS-TCP_Flood.pcap` | 2.650.042 | 265.218 |
| DDoS-UDP_Flood | DDoS | `DDoS-UDP_Flood.pcap` | 2.661.376 | 266.297 |
| DNS_Spoofing | Spoofing | `DNS_Spoofing.pcap` | 47.876 | 10.586 |
| DictionaryBruteForce | BruteForce | `DictionaryBruteForce.pcap` | 5.549 | 1.042 |
| DoS-HTTP_Flood | DoS | `DoS-HTTP_Flood1.pcap` | 298.903 | 30.881 |
| DoS-SYN_Flood | DoS | `DoS-SYN_Flood.pcap` | 2.624.053 | 262.576 |
| DoS-TCP_Flood | DoS | `DoS-TCP_Flood.pcap` | 2.597.426 | 259.976 |
| DoS-UDP_Flood | DoS | `DoS-UDP_Flood.pcap` | 1.664.550 | 166.653 |
| MITM-ArpSpoofing | Spoofing | `MITM-ArpSpoofing.pcap` | 31.228 | 8.194 |
| Mirai-greip_flood | Mirai | `Mirai-greip_flood21.pcap` | 119.531 | 11.955 |
| Recon-HostDiscovery | Recon | `Recon-HostDiscovery.pcap` | 90.530 | 12.996 |
| Recon-OSScan | Recon | `Recon-OSScan.pcap` | 29.750 | 4.087 |
| Recon-PingSweep | Recon | `Recon-PingSweep.pcap` | 540 | 114 |
| Recon-PortScan | Recon | `Recon-PortScan.pcap` | 30.872 | 3.783 |
| SqlInjection | Web | `SqlInjection.pcap` | 1.035 | 325 |
| Uploading_Attack | Web | `Uploading_Attack.pcap` | 357 | 106 |
| VulnerabilityScan | Recon | `VulnerabilityScan.pcap` | 88.114 | 18.836 |
| XSS | Web | `XSS.pcap` | 976 | 313 |

Todas as 7 categorias do modelo têm ao menos um pcap. 9 dos 34 rótulos ainda não têm pcap.
Os números deste relatório são parciais até os outros pcaps chegarem: o modelo só conhece as variantes
de cada categoria que estão na tabela. Com pcaps novos na pasta, `regerar` extrai só eles e este comando
refaz o treino e o relatório.

## Treino e teste

Cada rótulo entra com no máximo 50.000 linhas, sorteadas com a semente 42, como na
amostra do treino exploratório. A divisão é por tempo: dentro de cada pcap, as primeiras
70% das janelas vão para o treino e as últimas 30%
para o teste, com o corte no total de janelas do arquivo, para não deixar janelas vizinhas dos dois lados.
Um rótulo com mais de um pcap tem o último arquivo, em ordem de nome, inteiro no teste. O modelo é o
`RandomForestClassifier` do scikit-learn com 100 árvores e os demais parâmetros padrão, sem
`StandardScaler`, com as 39 features e 7 categorias (DDoS e DoS juntos).

| Janela | Linhas regeradas | Após o teto | Treino | Teste | Arquivos inteiros no teste | Treino (s) |
|---|---|---|---|---|---|---|
| 10 | 19.219.946 | 802.773 | 563.988 | 238.785 | `BenignTraffic1.pcap` | 12,4 |
| 100 | 1.952.939 | 532.877 | 365.303 | 167.574 | `BenignTraffic1.pcap` | 9,7 |

Linhas por rótulo com janela de 10:

| Rótulo | Categoria | Regeradas | Após o teto | Treino | Teste |
|---|---|---|---|---|---|
| DDoS-UDP_Flood | DDoS | 2.661.376 | 50.000 | 34.722 | 15.278 |
| DDoS-ICMP_Flood | DDoS | 2.677.303 | 50.000 | 34.950 | 15.050 |
| DDoS-HTTP_Flood | DDoS | 280.956 | 50.000 | 34.728 | 15.272 |
| DDoS-TCP_Flood | DDoS | 2.650.042 | 50.000 | 34.949 | 15.051 |
| DDoS-SYN_Flood | DDoS | 2.656.622 | 50.000 | 34.989 | 15.011 |
| DoS-TCP_Flood | DoS | 2.597.426 | 50.000 | 35.043 | 14.957 |
| DoS-HTTP_Flood | DoS | 298.903 | 50.000 | 36.093 | 13.907 |
| DoS-SYN_Flood | DoS | 2.624.053 | 50.000 | 35.117 | 14.883 |
| DoS-UDP_Flood | DoS | 1.664.550 | 50.000 | 35.128 | 14.872 |
| Mirai-greip_flood | Mirai | 119.531 | 50.000 | 35.134 | 14.866 |
| Recon-PingSweep | Recon | 540 | 540 | 510 | 30 |
| Recon-OSScan | Recon | 29.750 | 29.750 | 20.666 | 9.084 |
| VulnerabilityScan | Recon | 88.114 | 50.000 | 44.558 | 5.442 |
| Recon-PortScan | Recon | 30.872 | 30.872 | 24.275 | 6.597 |
| Recon-HostDiscovery | Recon | 90.530 | 50.000 | 38.284 | 11.716 |
| MITM-ArpSpoofing | Spoofing | 31.228 | 31.228 | 13.018 | 18.210 |
| DNS_Spoofing | Spoofing | 47.876 | 47.876 | 34.822 | 13.054 |
| SqlInjection | Web | 1.035 | 1.035 | 665 | 370 |
| CommandInjection | Web | 1.202 | 1.202 | 1.028 | 174 |
| Backdoor_Malware | Web | 912 | 912 | 640 | 272 |
| Uploading_Attack | Web | 357 | 357 | 244 | 113 |
| XSS | Web | 976 | 976 | 639 | 337 |
| BrowserHijacking | Web | 2.476 | 2.476 | 2.195 | 281 |
| DictionaryBruteForce | BruteForce | 5.549 | 5.549 | 4.080 | 1.469 |
| BenignTraffic | Benign | 657.767 | 50.000 | 27.511 | 22.489 |

Linhas por rótulo com janela de 100:

| Rótulo | Categoria | Regeradas | Após o teto | Treino | Teste |
|---|---|---|---|---|---|
| DDoS-UDP_Flood | DDoS | 266.297 | 50.000 | 34.958 | 15.042 |
| DDoS-ICMP_Flood | DDoS | 267.863 | 50.000 | 35.084 | 14.916 |
| DDoS-HTTP_Flood | DDoS | 28.570 | 28.570 | 19.952 | 8.618 |
| DDoS-TCP_Flood | DDoS | 265.218 | 50.000 | 35.022 | 14.978 |
| DDoS-SYN_Flood | DDoS | 265.702 | 50.000 | 34.899 | 15.101 |
| DoS-TCP_Flood | DoS | 259.976 | 50.000 | 34.935 | 15.065 |
| DoS-HTTP_Flood | DoS | 30.881 | 30.881 | 21.744 | 9.137 |
| DoS-SYN_Flood | DoS | 262.576 | 50.000 | 34.965 | 15.035 |
| DoS-UDP_Flood | DoS | 166.653 | 50.000 | 35.093 | 14.907 |
| Mirai-greip_flood | Mirai | 11.955 | 11.955 | 8.369 | 3.586 |
| Recon-PingSweep | Recon | 114 | 114 | 96 | 18 |
| Recon-OSScan | Recon | 4.087 | 4.087 | 2.690 | 1.397 |
| VulnerabilityScan | Recon | 18.836 | 18.836 | 13.961 | 4.875 |
| Recon-PortScan | Recon | 3.783 | 3.783 | 2.933 | 850 |
| Recon-HostDiscovery | Recon | 12.996 | 12.996 | 9.154 | 3.842 |
| MITM-ArpSpoofing | Spoofing | 8.194 | 8.194 | 4.330 | 3.864 |
| DNS_Spoofing | Spoofing | 10.586 | 10.586 | 7.443 | 3.143 |
| SqlInjection | Web | 325 | 325 | 223 | 102 |
| CommandInjection | Web | 377 | 377 | 300 | 77 |
| Backdoor_Malware | Web | 253 | 253 | 177 | 76 |
| Uploading_Attack | Web | 106 | 106 | 75 | 31 |
| XSS | Web | 313 | 313 | 215 | 98 |
| BrowserHijacking | Web | 459 | 459 | 378 | 81 |
| DictionaryBruteForce | BruteForce | 1.042 | 1.042 | 769 | 273 |
| BenignTraffic | Benign | 65.777 | 50.000 | 27.538 | 22.462 |

## Resultados com janela de 10

Na parte de teste, de 238.785 linhas: acurácia 93,98%, macro-F1 76,95%, F1 ponderado 93,91%, teto destas linhas 99,81%. Tráfego benigno classificado como ataque: 13,37%.

| Categoria | Linhas de teste | Precisão | Recall | F1 | Falso positivo |
|---|---|---|---|---|---|
| DDoS+DoS | 134.281 | 98,50% | 97,97% | 98,23% | 1,92% |
| Mirai | 14.866 | 100,00% | 99,97% | 99,98% | 0,00% |
| Recon | 32.869 | 84,40% | 88,58% | 86,44% | 2,61% |
| Spoofing | 31.264 | 92,02% | 91,02% | 91,52% | 1,19% |
| Web | 1.547 | 32,86% | 28,70% | 30,64% | 0,38% |
| BruteForce | 1.469 | 73,47% | 33,56% | 46,07% | 0,08% |
| Benign | 22.489 | 84,97% | 86,63% | 85,79% | 1,59% |

Matriz de confusão, com a categoria real nas linhas e a prevista nas colunas:

| Real \ prevista | DDoS+DoS | Mirai | Recon | Spoofing | Web | BruteForce | Benign |
|---|---|---|---|---|---|---|---|
| DDoS+DoS | 131.550 | 0 | 1.438 | 320 | 247 | 1 | 725 |
| Mirai | 0 | 14.861 | 0 | 5 | 0 | 0 | 0 |
| Recon | 1.326 | 0 | 29.117 | 653 | 222 | 68 | 1.483 |
| Spoofing | 208 | 0 | 1.353 | 28.456 | 266 | 2 | 979 |
| Web | 180 | 0 | 542 | 185 | 444 | 3 | 193 |
| BruteForce | 130 | 0 | 612 | 73 | 94 | 493 | 67 |
| Benign | 158 | 0 | 1.436 | 1.231 | 78 | 104 | 19.482 |

Por pcap, a fração das janelas de teste na categoria esperada e a categoria mais prevista:

| Arquivo | Rótulo | Categoria esperada | Janelas de teste | Na esperada | Mais prevista |
|---|---|---|---|---|---|
| `Backdoor_Malware.pcap` | Backdoor_Malware | Web | 272 | 30,51% | Recon |
| `BenignTraffic.pcap` | BenignTraffic | Benign | 0 | sem teste | nenhuma |
| `BenignTraffic1.pcap` | BenignTraffic | Benign | 22.489 | 86,63% | Benign |
| `BrowserHijacking.pcap` | BrowserHijacking | Web | 281 | 41,99% | Web |
| `CommandInjection.pcap` | CommandInjection | Web | 174 | 17,82% | DDoS+DoS |
| `DDoS-HTTP_Flood-.pcap` | DDoS-HTTP_Flood | DDoS+DoS | 15.272 | 98,54% | DDoS+DoS |
| `DDoS-ICMP_Flood.pcap` | DDoS-ICMP_Flood | DDoS+DoS | 15.050 | 99,95% | DDoS+DoS |
| `DDoS-SYN_Flood.pcap` | DDoS-SYN_Flood | DDoS+DoS | 15.011 | 99,66% | DDoS+DoS |
| `DDoS-TCP_Flood.pcap` | DDoS-TCP_Flood | DDoS+DoS | 15.051 | 99,89% | DDoS+DoS |
| `DDoS-UDP_Flood.pcap` | DDoS-UDP_Flood | DDoS+DoS | 15.278 | 99,94% | DDoS+DoS |
| `DNS_Spoofing.pcap` | DNS_Spoofing | Spoofing | 13.054 | 89,74% | Spoofing |
| `DictionaryBruteForce.pcap` | DictionaryBruteForce | BruteForce | 1.469 | 33,56% | Recon |
| `DoS-HTTP_Flood1.pcap` | DoS-HTTP_Flood | DDoS+DoS | 13.907 | 83,58% | DDoS+DoS |
| `DoS-SYN_Flood.pcap` | DoS-SYN_Flood | DDoS+DoS | 14.883 | 99,68% | DDoS+DoS |
| `DoS-TCP_Flood.pcap` | DoS-TCP_Flood | DDoS+DoS | 14.957 | 99,89% | DDoS+DoS |
| `DoS-UDP_Flood.pcap` | DoS-UDP_Flood | DDoS+DoS | 14.872 | 99,49% | DDoS+DoS |
| `MITM-ArpSpoofing.pcap` | MITM-ArpSpoofing | Spoofing | 18.210 | 91,93% | Spoofing |
| `Mirai-greip_flood21.pcap` | Mirai-greip_flood | Mirai | 14.866 | 99,97% | Mirai |
| `Recon-HostDiscovery.pcap` | Recon-HostDiscovery | Recon | 11.716 | 98,05% | Recon |
| `Recon-OSScan.pcap` | Recon-OSScan | Recon | 9.084 | 86,87% | Recon |
| `Recon-PingSweep.pcap` | Recon-PingSweep | Recon | 30 | 46,67% | Recon |
| `Recon-PortScan.pcap` | Recon-PortScan | Recon | 6.597 | 89,98% | Recon |
| `SqlInjection.pcap` | SqlInjection | Web | 370 | 19,46% | Recon |
| `Uploading_Attack.pcap` | Uploading_Attack | Web | 113 | 30,09% | Recon |
| `VulnerabilityScan.pcap` | VulnerabilityScan | Recon | 5.442 | 69,61% | Recon |
| `XSS.pcap` | XSS | Web | 337 | 31,45% | Recon |

As 10 features mais importantes (redução média de impureza): `Time_To_Live` (10,6%), `IAT` (8,5%), `Rate` (8,0%), `Max` (8,0%), `Min` (7,0%), `Header_Length` (6,6%), `HTTP` (6,1%), `Tot sum` (4,4%), `ack_count` (4,4%) e `HTTPS` (4,1%).

## Resultados com janela de 100

Na parte de teste, de 167.574 linhas: acurácia 97,74%, macro-F1 82,46%, F1 ponderado 97,72%, teto destas linhas 100,00%. Tráfego benigno classificado como ataque: 1,83%.

| Categoria | Linhas de teste | Precisão | Recall | F1 | Falso positivo |
|---|---|---|---|---|---|
| DDoS+DoS | 122.799 | 99,77% | 98,89% | 99,33% | 0,62% |
| Mirai | 3.586 | 100,00% | 100,00% | 100,00% | 0,00% |
| Recon | 10.982 | 86,88% | 86,00% | 86,44% | 0,91% |
| Spoofing | 7.007 | 99,43% | 99,44% | 99,44% | 0,02% |
| Web | 465 | 48,63% | 41,94% | 45,03% | 0,12% |
| BruteForce | 273 | 93,33% | 35,90% | 51,85% | 0,00% |
| Benign | 22.462 | 92,31% | 98,17% | 95,15% | 1,27% |

Matriz de confusão, com a categoria real nas linhas e a prevista nas colunas:

| Real \ prevista | DDoS+DoS | Mirai | Recon | Spoofing | Web | BruteForce | Benign |
|---|---|---|---|---|---|---|---|
| DDoS+DoS | 121.439 | 0 | 950 | 11 | 42 | 0 | 357 |
| Mirai | 0 | 3.586 | 0 | 0 | 0 | 0 | 0 |
| Recon | 133 | 0 | 9.445 | 8 | 24 | 0 | 1.372 |
| Spoofing | 23 | 0 | 8 | 6.968 | 3 | 0 | 5 |
| Web | 51 | 0 | 133 | 4 | 195 | 1 | 81 |
| BruteForce | 30 | 0 | 115 | 0 | 8 | 98 | 22 |
| Benign | 40 | 0 | 220 | 17 | 129 | 6 | 22.050 |

Por pcap, a fração das janelas de teste na categoria esperada e a categoria mais prevista:

| Arquivo | Rótulo | Categoria esperada | Janelas de teste | Na esperada | Mais prevista |
|---|---|---|---|---|---|
| `Backdoor_Malware.pcap` | Backdoor_Malware | Web | 76 | 56,58% | Web |
| `BenignTraffic.pcap` | BenignTraffic | Benign | 0 | sem teste | nenhuma |
| `BenignTraffic1.pcap` | BenignTraffic | Benign | 22.462 | 98,17% | Benign |
| `BrowserHijacking.pcap` | BrowserHijacking | Web | 81 | 25,93% | Benign |
| `CommandInjection.pcap` | CommandInjection | Web | 77 | 38,96% | DDoS+DoS |
| `DDoS-HTTP_Flood-.pcap` | DDoS-HTTP_Flood | DDoS+DoS | 8.618 | 99,80% | DDoS+DoS |
| `DDoS-ICMP_Flood.pcap` | DDoS-ICMP_Flood | DDoS+DoS | 14.916 | 99,92% | DDoS+DoS |
| `DDoS-SYN_Flood.pcap` | DDoS-SYN_Flood | DDoS+DoS | 15.101 | 99,99% | DDoS+DoS |
| `DDoS-TCP_Flood.pcap` | DDoS-TCP_Flood | DDoS+DoS | 14.978 | 99,71% | DDoS+DoS |
| `DDoS-UDP_Flood.pcap` | DDoS-UDP_Flood | DDoS+DoS | 15.042 | 100,00% | DDoS+DoS |
| `DNS_Spoofing.pcap` | DNS_Spoofing | Spoofing | 3.143 | 98,98% | Spoofing |
| `DictionaryBruteForce.pcap` | DictionaryBruteForce | BruteForce | 273 | 35,90% | Recon |
| `DoS-HTTP_Flood1.pcap` | DoS-HTTP_Flood | DDoS+DoS | 9.137 | 86,21% | DDoS+DoS |
| `DoS-SYN_Flood.pcap` | DoS-SYN_Flood | DDoS+DoS | 15.035 | 99,97% | DDoS+DoS |
| `DoS-TCP_Flood.pcap` | DoS-TCP_Flood | DDoS+DoS | 15.065 | 99,94% | DDoS+DoS |
| `DoS-UDP_Flood.pcap` | DoS-UDP_Flood | DDoS+DoS | 14.907 | 99,91% | DDoS+DoS |
| `MITM-ArpSpoofing.pcap` | MITM-ArpSpoofing | Spoofing | 3.864 | 99,82% | Spoofing |
| `Mirai-greip_flood21.pcap` | Mirai-greip_flood | Mirai | 3.586 | 100,00% | Mirai |
| `Recon-HostDiscovery.pcap` | Recon-HostDiscovery | Recon | 3.842 | 94,14% | Recon |
| `Recon-OSScan.pcap` | Recon-OSScan | Recon | 1.397 | 76,74% | Recon |
| `Recon-PingSweep.pcap` | Recon-PingSweep | Recon | 18 | 50,00% | Recon |
| `Recon-PortScan.pcap` | Recon-PortScan | Recon | 850 | 83,06% | Recon |
| `SqlInjection.pcap` | SqlInjection | Web | 102 | 1,96% | Recon |
| `Uploading_Attack.pcap` | Uploading_Attack | Web | 31 | 83,87% | Web |
| `VulnerabilityScan.pcap` | VulnerabilityScan | Recon | 4.875 | 82,89% | Recon |
| `XSS.pcap` | XSS | Web | 98 | 74,49% | Web |

As 10 features mais importantes (redução média de impureza): `Time_To_Live` (14,2%), `HTTPS` (9,3%), `IAT` (7,2%), `Max` (6,5%), `Min` (6,2%), `Rate` (6,1%), `Protocol Type` (4,4%), `DNS` (3,8%), `HTTP` (3,5%) e `Variance` (3,3%).

## As duas janelas lado a lado

| Medida | Janela de 10 | Janela de 100 |
|---|---|---|
| Macro-F1 | 76,95% | 82,46% |
| Acurácia | 93,98% | 97,74% |
| Benigno classificado como ataque | 13,37% | 1,83% |
| Linhas de teste | 238.785 | 167.574 |

| Categoria | Recall (10) | Recall (100) | F1 (10) | F1 (100) |
|---|---|---|---|---|
| DDoS+DoS | 97,97% | 98,89% | 98,23% | 99,33% |
| Mirai | 99,97% | 100,00% | 99,98% | 100,00% |
| Recon | 88,58% | 86,00% | 86,44% | 86,44% |
| Spoofing | 91,02% | 99,44% | 91,52% | 99,44% |
| Web | 28,70% | 41,94% | 30,64% | 45,03% |
| BruteForce | 33,56% | 35,90% | 46,07% | 51,85% |
| Benign | 86,63% | 98,17% | 85,79% | 95,15% |

O maior macro-F1 é o da janela de 100, e a menor taxa de tráfego benigno classificado
como ataque é a da janela de 100. Com janela de 100, cada pcap gera cerca de um décimo das
janelas que gera com 10, e as classes raras ficam com poucas linhas de teste; na operação, a janela de 10
decide com menos quadros e responde mais vezes por segundo.

## IPs de origem por janela em DDoS e DoS

O modelo não separa DDoS de DoS: as features descrevem os pacotes, não quantas máquinas atacam. A separação
sai da quantidade de IPs de origem distintos das janelas do incidente, fora do modelo. A tabela resume essa
quantidade nas janelas regeradas de cada classe de DDoS e DoS presente, antes do teto.

Janela de 10:

| Rótulo | Categoria | Janelas | Mínimo | P25 | Mediana | P75 | Máximo | Média | Janelas com até 1 IP de origem |
|---|---|---|---|---|---|---|---|---|---|
| DDoS-UDP_Flood | DDoS | 2.661.376 | 1 | 1,0 | 1,0 | 1,0 | 10 | 1,18 | 83,55% |
| DDoS-ICMP_Flood | DDoS | 2.677.303 | 0 | 1,0 | 1,0 | 1,0 | 9 | 1,12 | 88,75% |
| DDoS-HTTP_Flood | DDoS | 280.956 | 0 | 1,0 | 1,0 | 2,0 | 10 | 1,78 | 59,96% |
| DDoS-TCP_Flood | DDoS | 2.650.042 | 1 | 1,0 | 1,0 | 1,0 | 10 | 1,18 | 83,55% |
| DDoS-SYN_Flood | DDoS | 2.656.622 | 0 | 1,0 | 1,0 | 1,0 | 10 | 1,17 | 84,74% |
| DoS-TCP_Flood | DoS | 2.597.426 | 1 | 1,0 | 1,0 | 1,0 | 9 | 1,05 | 95,62% |
| DoS-HTTP_Flood | DoS | 298.903 | 1 | 1,0 | 1,0 | 2,0 | 10 | 1,57 | 70,24% |
| DoS-SYN_Flood | DoS | 2.624.053 | 1 | 1,0 | 1,0 | 1,0 | 9 | 1,11 | 90,28% |
| DoS-UDP_Flood | DoS | 1.664.550 | 1 | 1,0 | 1,0 | 1,0 | 9 | 1,06 | 95,60% |

Janela de 100:

| Rótulo | Categoria | Janelas | Mínimo | P25 | Mediana | P75 | Máximo | Média | Janelas com até 1 IP de origem |
|---|---|---|---|---|---|---|---|---|---|
| DDoS-UDP_Flood | DDoS | 266.297 | 1 | 2,0 | 2,0 | 3,0 | 42 | 2,54 | 6,53% |
| DDoS-ICMP_Flood | DDoS | 267.863 | 1 | 2,0 | 2,0 | 2,0 | 38 | 2,12 | 14,86% |
| DDoS-HTTP_Flood | DDoS | 28.570 | 1 | 3,0 | 5,0 | 8,0 | 39 | 6,13 | 7,92% |
| DDoS-TCP_Flood | DDoS | 265.218 | 1 | 2,0 | 2,0 | 3,0 | 39 | 2,54 | 5,99% |
| DDoS-SYN_Flood | DDoS | 265.702 | 1 | 2,0 | 2,0 | 3,0 | 39 | 2,47 | 14,00% |
| DoS-TCP_Flood | DoS | 259.976 | 1 | 1,0 | 1,0 | 2,0 | 25 | 1,41 | 72,13% |
| DoS-HTTP_Flood | DoS | 30.881 | 1 | 2,0 | 4,0 | 7,0 | 42 | 5,59 | 12,39% |
| DoS-SYN_Flood | DoS | 262.576 | 1 | 1,0 | 2,0 | 2,0 | 31 | 1,83 | 43,96% |
| DoS-UDP_Flood | DoS | 166.653 | 1 | 1,0 | 1,0 | 2,0 | 44 | 1,55 | 67,10% |

Com janela de 10, a mediana de IPs de origem por janela vai de 1,0 a 1,0 nas classes de DDoS e de 1,0 a 1,0 nas de DoS: as faixas se cruzam, e a contagem de uma janela isolada não separa as duas categorias. A separação precisa olhar as janelas do incidente em conjunto.
Com janela de 100, a mediana de IPs de origem por janela vai de 2,0 a 5,0 nas classes de DDoS e de 1,0 a 4,0 nas de DoS: as faixas se cruzam, e a contagem de uma janela isolada não separa as duas categorias. A separação precisa olhar as janelas do incidente em conjunto.

## Ressalvas

- **Os números são parciais.** Faltam pcaps de 9 rótulos. Uma categoria representada por uma ou duas variantes pode ficar mais
  fácil do que será com todas.
- **Uma semente.** Divisão por tempo não sorteia, mas o teto por rótulo e o modelo usam a semente 42, e nada foi repetido com outra.
- **O teste vem das mesmas capturas.** As janelas de teste são o fim de cada pcap, da mesma rede e do
  mesmo dia das de treino. A medida vale para a captura, não para outra rede. O rótulo com dois pcaps
  tem um arquivo inteiro no teste, que é mais exigente; nos demais, as janelas na fronteira do corte
  são vizinhas das de treino.
- **As janelas descartadas não são avaliadas.** O tráfego de fundo dos pcaps de ataque fica fora do
  treino e do teste. O que o modelo faz com ele não está medido aqui.
- **O atacante também gera tráfego benigno.** O MAC `dc:a6:32:dc:27:d5` aparece em cerca de 1% dos
  quadros dos pcaps benignos (`janelas_sem_atacante.md`). A regra de rótulo não o usa nos pcaps benignos,
  então parte do tráfego comum desse dispositivo está no treino como benigno.
- **As seis colunas da janela deixaram de ser atalho.** Com uma janela só, `Number` vale o mesmo em todas
  as classes, a não ser na última janela de cada pcap, que pode ficar incompleta.

## Como os números foram obtidos

- Comando: `python -m codigo.classificador.treinar_regerado`, a partir da raiz do repositório, depois de `python -m codigo.classificador.regerar`. Ele refaz a leitura, o teto, a divisão, o treino, a avaliação e este relatório.
- Dados: `dados/processed/regerado/janela_<W>/<rotulo>.csv.gz`, registrados em `manifesto_regeracao.json` (gerado em 10/10/2026, pcaps em `CICIoT2023`), com o SHA-256 de cada pcap.
- Modelos: um por janela, em `modelos/`, fora do git: `rf_regerado_janela_10.joblib` (490,4 MB) e `rf_regerado_janela_100.joblib` (135,0 MB). Treinados com 4 núcleos; a quantidade de núcleos muda o tempo, e não o modelo. Predição com um núcleo, em ordem fixa.
- Divisões: o SHA-256 das posições de treino e de teste de cada janela está em `manifesto_treino_regerado.json`.
- `regeracao_metricas.csv` tem uma linha por janela e categoria; `regeracao_por_arquivo.csv`, uma por janela e pcap; `matrizes_confusao/regerado_janela_<W>.csv` é a matriz de confusão e `_por_rotulo.csv` abre a classe real nos 34 rótulos.
- Tempo total, na máquina em que rodou: 104,7 s.
- Com os mesmos CSVs regerados e a mesma semente, os números saem iguais. Só mudam a data e os tempos.

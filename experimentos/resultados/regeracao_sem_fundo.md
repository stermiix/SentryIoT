# Treino sobre os dados regerados: referência sem o fundo

Gerado por `python -m codigo.classificador.treinar_regerado` em 13/10/2026, com Python 3.11.2, scikit-learn 1.9.1, pandas 3.0.6 e numpy 2.4.6.

O modelo treinado no `MERGED_CSV` oficial aprende o tamanho da janela, de 100 quadros nas classes de
DDoS, DoS e Mirai e de 10 nas demais, em vez do comportamento do tráfego (`teste_da_janela.md`), e o
rótulo oficial é dado ao arquivo inteiro, mesmo nas janelas sem nenhum quadro do atacante
(`janelas_sem_atacante.md`). Por isso os dados de treino foram gerados de novo a partir dos pcaps, com o
nosso extrator, em janela única e com o rótulo decidido janela a janela (decisão de 10/10/2026 no
`ROADMAP.md`).

Este relatório refaz o treino de 10/10, que foi o do sistema até 13/10/2026 e fica como referência: sem o tráfego de fundo dos pcaps de ataque no treino, um modelo por janela, de 10 e 100 quadros. É a configuração 0 de `rodadas_normalizadas.md`, e o modelo de janela de 100 é o que `rodadas_de_teste.md` mede. O modelo do sistema está em `regeracao.md`.

## Os dados regerados

Os pcaps da pasta do dataset em 11/10/2026, lidos
inteiros pelo extrator em leitura contínua, com os dois tamanhos de janela. Regra de rótulo: num pcap
benigno toda janela é `BenignTraffic`; num pcap de ataque a janela recebe o rótulo do arquivo se tem
quadro com MAC de um Raspberry Pi atacante na origem ou no destino, e é descartada se não tem.

No treino de referência, a janela descartada não vira benigna, porque o tráfego de fundo de uma captura
de ataque pode conter efeito do ataque.

| Arquivo | Rótulo | Categoria | Pacotes | Janelas de 10 | Mantidas (10) | Janelas de 100 | Mantidas (100) | Extração (s) |
|---|---|---|---|---|---|---|---|---|
| `Backdoor_Malware.pcap` | Backdoor_Malware | Web | 33.414 | 3.218 | 912 (28,3%) | 322 | 253 (78,6%) | 0,4 |
| `BenignTraffic.pcap` | BenignTraffic | Benign | 3.664.164 | 362.278 | 362.278 (100,0%) | 36.228 | 36.228 (100,0%) | 44,0 |
| `BenignTraffic1.pcap` | BenignTraffic | Benign | 2.988.642 | 295.489 | 295.489 (100,0%) | 29.549 | 29.549 (100,0%) | 32,8 |
| `BenignTraffic2.pcap` | BenignTraffic | Benign | 3.138.002 | 310.319 | 310.319 (100,0%) | 31.032 | 31.032 (100,0%) | 34,4 |
| `BrowserHijacking.pcap` | BrowserHijacking | Web | 59.821 | 5.858 | 2.476 (42,3%) | 586 | 459 (78,3%) | 0,7 |
| `CommandInjection.pcap` | CommandInjection | Web | 55.741 | 5.409 | 1.202 (22,2%) | 541 | 377 (69,7%) | 0,6 |
| `DDoS-ACK_Fragmentation.pcap` | DDoS-ACK_Fragmentation | DDoS | 2.503.835 | 249.836 | 243.900 (97,6%) | 24.984 | 24.457 (97,9%) | 25,7 |
| `DDoS-HTTP_Flood-.pcap` | DDoS-HTTP_Flood | DDoS | 2.881.005 | 287.559 | 280.956 (97,7%) | 28.756 | 28.570 (99,4%) | 31,4 |
| `DDoS-ICMP_Flood.pcap` | DDoS-ICMP_Flood | DDoS | 26.793.240 | 2.679.086 | 2.677.303 (99,9%) | 267.909 | 267.863 (100,0%) | 261,3 |
| `DDoS-ICMP_Fragmentation.pcap` | DDoS-ICMP_Fragmentation | DDoS | 2.064.692 | 205.967 | 203.141 (98,6%) | 20.597 | 20.479 (99,4%) | 19,2 |
| `DDoS-PSHACK_Flood.pcap` | DDoS-PSHACK_Flood | DDoS | 26.774.357 | 2.677.112 | 2.675.472 (99,9%) | 267.712 | 267.618 (100,0%) | 276,4 |
| `DDoS-RSTFINFlood.pcap` | DDoS-RSTFINFlood | DDoS | 26.686.473 | 2.668.315 | 2.666.660 (99,9%) | 266.832 | 266.742 (100,0%) | 272,0 |
| `DDoS-SYN_Flood.pcap` | DDoS-SYN_Flood | DDoS | 26.597.011 | 2.659.244 | 2.656.622 (99,9%) | 265.925 | 265.702 (99,9%) | 283,6 |
| `DDoS-SYN_Flood1.pcap` | DDoS-SYN_Flood | DDoS | 26.715.334 | 2.670.961 | 2.669.541 (99,9%) | 267.097 | 267.029 (100,0%) | 275,5 |
| `DDoS-SlowLoris.pcap` | DDoS-SlowLoris | DDoS | 2.351.454 | 233.903 | 179.601 (76,8%) | 23.391 | 21.710 (92,8%) | 26,0 |
| `DDoS-SynonymousIP_Flood.pcap` | DDoS-SynonymousIP_Flood | DDoS | 26.855.630 | 2.685.243 | 2.684.667 (100,0%) | 268.525 | 268.499 (100,0%) | 276,6 |
| `DDoS-TCP_Flood.pcap` | DDoS-TCP_Flood | DDoS | 26.570.958 | 2.656.703 | 2.650.042 (99,7%) | 265.671 | 265.218 (99,8%) | 270,7 |
| `DDoS-UDP_Flood.pcap` | DDoS-UDP_Flood | DDoS | 26.653.551 | 2.665.025 | 2.661.376 (99,9%) | 266.503 | 266.297 (99,9%) | 238,5 |
| `DDoS-UDP_Fragmentation.pcap` | DDoS-UDP_Fragmentation | DDoS | 2.248.843 | 224.381 | 221.697 (98,8%) | 22.439 | 22.394 (99,8%) | 22,0 |
| `DNS_Spoofing.pcap` | DNS_Spoofing | Spoofing | 1.812.557 | 178.872 | 47.876 (26,8%) | 17.888 | 10.586 (59,2%) | 19,7 |
| `DictionaryBruteForce.pcap` | DictionaryBruteForce | BruteForce | 133.138 | 13.064 | 5.549 (42,5%) | 1.307 | 1.042 (79,7%) | 1,5 |
| `DoS-HTTP_Flood1.pcap` | DoS-HTTP_Flood | DoS | 3.114.983 | 310.988 | 298.903 (96,1%) | 31.099 | 30.881 (99,3%) | 34,3 |
| `DoS-SYN_Flood.pcap` | DoS-SYN_Flood | DoS | 26.261.611 | 2.625.859 | 2.624.053 (99,9%) | 262.586 | 262.576 (100,0%) | 270,7 |
| `DoS-SYN_Flood1.pcap` | DoS-SYN_Flood | DoS | 26.405.653 | 2.640.253 | 2.637.380 (99,9%) | 264.026 | 263.954 (100,0%) | 280,5 |
| `DoS-TCP_Flood.pcap` | DoS-TCP_Flood | DoS | 26.005.549 | 2.600.275 | 2.597.426 (99,9%) | 260.028 | 259.976 (100,0%) | 264,2 |
| `DoS-UDP_Flood.pcap` | DoS-UDP_Flood | DoS | 16.676.370 | 1.667.378 | 1.664.550 (99,8%) | 166.738 | 166.653 (99,9%) | 149,7 |
| `MITM-ArpSpoofing.pcap` | MITM-ArpSpoofing | Spoofing | 2.491.622 | 247.646 | 31.228 (12,6%) | 24.765 | 8.194 (33,1%) | 28,0 |
| `Mirai-greeth_flood.pcap` | Mirai-greeth_flood | Mirai | 3.352.569 | 335.007 | 329.157 (98,3%) | 33.501 | 33.008 (98,5%) | 47,9 |
| `Mirai-greip_flood21.pcap` | Mirai-greip_flood | Mirai | 1.196.296 | 119.545 | 119.531 (100,0%) | 11.955 | 11.955 (100,0%) | 14,6 |
| `Mirai-udpplain.pcap` | Mirai-udpplain | Mirai | 3.642.269 | 363.888 | 362.081 (99,5%) | 36.389 | 36.373 (100,0%) | 35,5 |
| `Recon-HostDiscovery.pcap` | Recon-HostDiscovery | Recon | 1.371.112 | 134.369 | 90.530 (67,4%) | 13.437 | 12.996 (96,7%) | 14,9 |
| `Recon-OSScan.pcap` | Recon-OSScan | Recon | 992.241 | 98.243 | 29.750 (30,3%) | 9.825 | 4.087 (41,6%) | 11,1 |
| `Recon-PingSweep.pcap` | Recon-PingSweep | Recon | 22.943 | 2.262 | 540 (23,9%) | 227 | 114 (50,2%) | 0,3 |
| `Recon-PortScan.pcap` | Recon-PortScan | Recon | 831.856 | 82.278 | 30.872 (37,5%) | 8.228 | 3.783 (46,0%) | 9,0 |
| `SqlInjection.pcap` | SqlInjection | Web | 53.462 | 5.245 | 1.035 (19,7%) | 525 | 325 (61,9%) | 0,6 |
| `Uploading_Attack.pcap` | Uploading_Attack | Web | 12.939 | 1.252 | 357 (28,5%) | 126 | 106 (84,1%) | 0,1 |
| `VulnerabilityScan.pcap` | VulnerabilityScan | Recon | 3.802.533 | 373.312 | 88.114 (23,6%) | 37.332 | 18.836 (50,5%) | 42,5 |
| `XSS.pcap` | XSS | Web | 40.183 | 3.845 | 976 (25,4%) | 385 | 313 (81,3%) | 0,4 |

Linhas regeradas por rótulo, somando os arquivos dele:

| Rótulo | Categoria | Arquivos | Linhas (10) | Linhas (100) |
|---|---|---|---|---|
| Backdoor_Malware | Web | `Backdoor_Malware.pcap` | 912 | 253 |
| BenignTraffic | Benign | `BenignTraffic.pcap`, `BenignTraffic1.pcap` e `BenignTraffic2.pcap` | 968.086 | 96.809 |
| BrowserHijacking | Web | `BrowserHijacking.pcap` | 2.476 | 459 |
| CommandInjection | Web | `CommandInjection.pcap` | 1.202 | 377 |
| DDoS-ACK_Fragmentation | DDoS | `DDoS-ACK_Fragmentation.pcap` | 243.900 | 24.457 |
| DDoS-HTTP_Flood | DDoS | `DDoS-HTTP_Flood-.pcap` | 280.956 | 28.570 |
| DDoS-ICMP_Flood | DDoS | `DDoS-ICMP_Flood.pcap` | 2.677.303 | 267.863 |
| DDoS-ICMP_Fragmentation | DDoS | `DDoS-ICMP_Fragmentation.pcap` | 203.141 | 20.479 |
| DDoS-PSHACK_Flood | DDoS | `DDoS-PSHACK_Flood.pcap` | 2.675.472 | 267.618 |
| DDoS-RSTFINFlood | DDoS | `DDoS-RSTFINFlood.pcap` | 2.666.660 | 266.742 |
| DDoS-SYN_Flood | DDoS | `DDoS-SYN_Flood.pcap` e `DDoS-SYN_Flood1.pcap` | 5.326.163 | 532.731 |
| DDoS-SlowLoris | DDoS | `DDoS-SlowLoris.pcap` | 179.601 | 21.710 |
| DDoS-SynonymousIP_Flood | DDoS | `DDoS-SynonymousIP_Flood.pcap` | 2.684.667 | 268.499 |
| DDoS-TCP_Flood | DDoS | `DDoS-TCP_Flood.pcap` | 2.650.042 | 265.218 |
| DDoS-UDP_Flood | DDoS | `DDoS-UDP_Flood.pcap` | 2.661.376 | 266.297 |
| DDoS-UDP_Fragmentation | DDoS | `DDoS-UDP_Fragmentation.pcap` | 221.697 | 22.394 |
| DNS_Spoofing | Spoofing | `DNS_Spoofing.pcap` | 47.876 | 10.586 |
| DictionaryBruteForce | BruteForce | `DictionaryBruteForce.pcap` | 5.549 | 1.042 |
| DoS-HTTP_Flood | DoS | `DoS-HTTP_Flood1.pcap` | 298.903 | 30.881 |
| DoS-SYN_Flood | DoS | `DoS-SYN_Flood.pcap` e `DoS-SYN_Flood1.pcap` | 5.261.433 | 526.530 |
| DoS-TCP_Flood | DoS | `DoS-TCP_Flood.pcap` | 2.597.426 | 259.976 |
| DoS-UDP_Flood | DoS | `DoS-UDP_Flood.pcap` | 1.664.550 | 166.653 |
| MITM-ArpSpoofing | Spoofing | `MITM-ArpSpoofing.pcap` | 31.228 | 8.194 |
| Mirai-greeth_flood | Mirai | `Mirai-greeth_flood.pcap` | 329.157 | 33.008 |
| Mirai-greip_flood | Mirai | `Mirai-greip_flood21.pcap` | 119.531 | 11.955 |
| Mirai-udpplain | Mirai | `Mirai-udpplain.pcap` | 362.081 | 36.373 |
| Recon-HostDiscovery | Recon | `Recon-HostDiscovery.pcap` | 90.530 | 12.996 |
| Recon-OSScan | Recon | `Recon-OSScan.pcap` | 29.750 | 4.087 |
| Recon-PingSweep | Recon | `Recon-PingSweep.pcap` | 540 | 114 |
| Recon-PortScan | Recon | `Recon-PortScan.pcap` | 30.872 | 3.783 |
| SqlInjection | Web | `SqlInjection.pcap` | 1.035 | 325 |
| Uploading_Attack | Web | `Uploading_Attack.pcap` | 357 | 106 |
| VulnerabilityScan | Recon | `VulnerabilityScan.pcap` | 88.114 | 18.836 |
| XSS | Web | `XSS.pcap` | 976 | 313 |

Todos os 34 rótulos têm pcap, de um a três arquivos cada.
Com pcaps novos na pasta, `regerar` extrai só eles e este comando refaz o treino e o relatório.

## Treino e teste

Cada rótulo entra com no máximo 50.000 linhas, sorteadas com a semente 42, como na
amostra do treino exploratório. A divisão é por tempo: dentro de cada pcap, as primeiras
70% das janelas vão para o treino e as últimas 30%
para o teste, com o corte no total de janelas do arquivo, para não deixar janelas vizinhas dos dois lados.
Um rótulo com mais de um pcap tem o último arquivo, pelo sufixo numérico do nome, inteiro no teste.
O modelo é o `RandomForestClassifier` do scikit-learn com 100 árvores e os demais parâmetros padrão,
sem `StandardScaler`, com as 39 features e 7 categorias (DDoS e DoS juntos).

| Janela | Linhas regeradas | Após o teto | Treino | Janelas de fundo no treino, como Benign | Teste | Arquivos inteiros no teste | Treino (s) |
|---|---|---|---|---|---|---|---|
| 10 | 34.403.562 | 1.252.773 | 865.851 | nenhuma | 386.922 | `BenignTraffic2.pcap`, `DDoS-SYN_Flood1.pcap` e `DoS-SYN_Flood1.pcap` | 17,2 |
| 100 | 3.476.234 | 841.298 | 567.732 | nenhuma | 273.566 | `BenignTraffic2.pcap`, `DDoS-SYN_Flood1.pcap` e `DoS-SYN_Flood1.pcap` | 13,0 |

O ponto de operação sai de uma parte de validação, nunca do teste. As últimas 15% da parte de treino de cada pcap, por tempo, são a validação, e um modelo treinado no resto (o treino reduzido, com a mesma semente) classifica todas as janelas dos pcaps benignos da validação, e não só as do teto. O limiar t é o menor da grade de 0,01 em 0,01 que deixa no máximo 1% delas como ataque. O modelo salvo é o do treino inteiro, com o t gravado ao lado.

| Janela | Treino reduzido | Janelas benignas na validação | t | N | Benigno da validação como ataque, no t | Com o argmax |
|---|---|---|---|---|---|---|
| 10 | 737.883 | 98.665 | 0,93 | 3 | 853 (0,86%) | 11.246 (11,40%) |
| 100 | 483.897 | 9.866 | 0,68 | 3 | 98 (0,99%) | 132 (1,34%) |

Como cada rótulo foi dividido. O rótulo com mais de um pcap tem um arquivo inteiro no teste, e o modelo
não vê nenhuma janela dele; nos demais, o teste é o fim do próprio pcap.

| Rótulo | Arquivos | Divisão |
|---|---|---|
| DDoS-ACK_Fragmentation | `DDoS-ACK_Fragmentation.pcap` | por tempo |
| DDoS-UDP_Flood | `DDoS-UDP_Flood.pcap` | por tempo |
| DDoS-SlowLoris | `DDoS-SlowLoris.pcap` | por tempo |
| DDoS-ICMP_Flood | `DDoS-ICMP_Flood.pcap` | por tempo |
| DDoS-RSTFINFlood | `DDoS-RSTFINFlood.pcap` | por tempo |
| DDoS-PSHACK_Flood | `DDoS-PSHACK_Flood.pcap` | por tempo |
| DDoS-HTTP_Flood | `DDoS-HTTP_Flood-.pcap` | por tempo |
| DDoS-UDP_Fragmentation | `DDoS-UDP_Fragmentation.pcap` | por tempo |
| DDoS-ICMP_Fragmentation | `DDoS-ICMP_Fragmentation.pcap` | por tempo |
| DDoS-TCP_Flood | `DDoS-TCP_Flood.pcap` | por tempo |
| DDoS-SYN_Flood | `DDoS-SYN_Flood.pcap` e `DDoS-SYN_Flood1.pcap` | por arquivo: `DDoS-SYN_Flood1.pcap` inteiro no teste |
| DDoS-SynonymousIP_Flood | `DDoS-SynonymousIP_Flood.pcap` | por tempo |
| DoS-TCP_Flood | `DoS-TCP_Flood.pcap` | por tempo |
| DoS-HTTP_Flood | `DoS-HTTP_Flood1.pcap` | por tempo |
| DoS-SYN_Flood | `DoS-SYN_Flood.pcap` e `DoS-SYN_Flood1.pcap` | por arquivo: `DoS-SYN_Flood1.pcap` inteiro no teste |
| DoS-UDP_Flood | `DoS-UDP_Flood.pcap` | por tempo |
| Mirai-greip_flood | `Mirai-greip_flood21.pcap` | por tempo |
| Mirai-greeth_flood | `Mirai-greeth_flood.pcap` | por tempo |
| Mirai-udpplain | `Mirai-udpplain.pcap` | por tempo |
| Recon-PingSweep | `Recon-PingSweep.pcap` | por tempo |
| Recon-OSScan | `Recon-OSScan.pcap` | por tempo |
| VulnerabilityScan | `VulnerabilityScan.pcap` | por tempo |
| Recon-PortScan | `Recon-PortScan.pcap` | por tempo |
| Recon-HostDiscovery | `Recon-HostDiscovery.pcap` | por tempo |
| MITM-ArpSpoofing | `MITM-ArpSpoofing.pcap` | por tempo |
| DNS_Spoofing | `DNS_Spoofing.pcap` | por tempo |
| SqlInjection | `SqlInjection.pcap` | por tempo |
| CommandInjection | `CommandInjection.pcap` | por tempo |
| Backdoor_Malware | `Backdoor_Malware.pcap` | por tempo |
| Uploading_Attack | `Uploading_Attack.pcap` | por tempo |
| XSS | `XSS.pcap` | por tempo |
| BrowserHijacking | `BrowserHijacking.pcap` | por tempo |
| DictionaryBruteForce | `DictionaryBruteForce.pcap` | por tempo |
| BenignTraffic | `BenignTraffic.pcap`, `BenignTraffic1.pcap` e `BenignTraffic2.pcap` | por arquivo: `BenignTraffic2.pcap` inteiro no teste |

Linhas por rótulo com janela de 10:

| Rótulo | Categoria | Regeradas | Após o teto | Treino | Teste |
|---|---|---|---|---|---|
| DDoS-ACK_Fragmentation | DDoS | 243.900 | 50.000 | 35.816 | 14.184 |
| DDoS-UDP_Flood | DDoS | 2.661.376 | 50.000 | 35.055 | 14.945 |
| DDoS-SlowLoris | DDoS | 179.601 | 50.000 | 34.483 | 15.517 |
| DDoS-ICMP_Flood | DDoS | 2.677.303 | 50.000 | 35.071 | 14.929 |
| DDoS-RSTFINFlood | DDoS | 2.666.660 | 50.000 | 34.716 | 15.284 |
| DDoS-PSHACK_Flood | DDoS | 2.675.472 | 50.000 | 34.842 | 15.158 |
| DDoS-HTTP_Flood | DDoS | 280.956 | 50.000 | 34.704 | 15.296 |
| DDoS-UDP_Fragmentation | DDoS | 221.697 | 50.000 | 35.229 | 14.771 |
| DDoS-ICMP_Fragmentation | DDoS | 203.141 | 50.000 | 35.061 | 14.939 |
| DDoS-TCP_Flood | DDoS | 2.650.042 | 50.000 | 35.186 | 14.814 |
| DDoS-SYN_Flood | DDoS | 5.326.163 | 50.000 | 25.072 | 24.928 |
| DDoS-SynonymousIP_Flood | DDoS | 2.684.667 | 50.000 | 34.997 | 15.003 |
| DoS-TCP_Flood | DoS | 2.597.426 | 50.000 | 35.114 | 14.886 |
| DoS-HTTP_Flood | DoS | 298.903 | 50.000 | 35.819 | 14.181 |
| DoS-SYN_Flood | DoS | 5.261.433 | 50.000 | 25.057 | 24.943 |
| DoS-UDP_Flood | DoS | 1.664.550 | 50.000 | 34.970 | 15.030 |
| Mirai-greip_flood | Mirai | 119.531 | 50.000 | 34.929 | 15.071 |
| Mirai-greeth_flood | Mirai | 329.157 | 50.000 | 34.856 | 15.144 |
| Mirai-udpplain | Mirai | 362.081 | 50.000 | 35.305 | 14.695 |
| Recon-PingSweep | Recon | 540 | 540 | 510 | 30 |
| Recon-OSScan | Recon | 29.750 | 29.750 | 20.666 | 9.084 |
| VulnerabilityScan | Recon | 88.114 | 50.000 | 44.582 | 5.418 |
| Recon-PortScan | Recon | 30.872 | 30.872 | 24.275 | 6.597 |
| Recon-HostDiscovery | Recon | 90.530 | 50.000 | 38.266 | 11.734 |
| MITM-ArpSpoofing | Spoofing | 31.228 | 31.228 | 13.018 | 18.210 |
| DNS_Spoofing | Spoofing | 47.876 | 47.876 | 34.822 | 13.054 |
| SqlInjection | Web | 1.035 | 1.035 | 665 | 370 |
| CommandInjection | Web | 1.202 | 1.202 | 1.028 | 174 |
| Backdoor_Malware | Web | 912 | 912 | 640 | 272 |
| Uploading_Attack | Web | 357 | 357 | 244 | 113 |
| XSS | Web | 976 | 976 | 639 | 337 |
| BrowserHijacking | Web | 2.476 | 2.476 | 2.195 | 281 |
| DictionaryBruteForce | BruteForce | 5.549 | 5.549 | 4.080 | 1.469 |
| BenignTraffic | Benign | 968.086 | 50.000 | 33.939 | 16.061 |

Linhas por rótulo com janela de 100:

| Rótulo | Categoria | Regeradas | Após o teto | Treino | Teste |
|---|---|---|---|---|---|
| DDoS-ACK_Fragmentation | DDoS | 24.457 | 24.457 | 17.425 | 7.032 |
| DDoS-UDP_Flood | DDoS | 266.297 | 50.000 | 35.139 | 14.861 |
| DDoS-SlowLoris | DDoS | 21.710 | 21.710 | 15.195 | 6.515 |
| DDoS-ICMP_Flood | DDoS | 267.863 | 50.000 | 35.084 | 14.916 |
| DDoS-RSTFINFlood | DDoS | 266.742 | 50.000 | 34.918 | 15.082 |
| DDoS-PSHACK_Flood | DDoS | 267.618 | 50.000 | 34.975 | 15.025 |
| DDoS-HTTP_Flood | DDoS | 28.570 | 28.570 | 19.952 | 8.618 |
| DDoS-UDP_Fragmentation | DDoS | 22.394 | 22.394 | 15.686 | 6.708 |
| DDoS-ICMP_Fragmentation | DDoS | 20.479 | 20.479 | 14.310 | 6.169 |
| DDoS-TCP_Flood | DDoS | 265.218 | 50.000 | 35.010 | 14.990 |
| DDoS-SYN_Flood | DDoS | 532.731 | 50.000 | 25.008 | 24.992 |
| DDoS-SynonymousIP_Flood | DDoS | 268.499 | 50.000 | 35.105 | 14.895 |
| DoS-TCP_Flood | DoS | 259.976 | 50.000 | 34.880 | 15.120 |
| DoS-HTTP_Flood | DoS | 30.881 | 30.881 | 21.744 | 9.137 |
| DoS-SYN_Flood | DoS | 526.530 | 50.000 | 24.675 | 25.325 |
| DoS-UDP_Flood | DoS | 166.653 | 50.000 | 35.012 | 14.988 |
| Mirai-greip_flood | Mirai | 11.955 | 11.955 | 8.369 | 3.586 |
| Mirai-greeth_flood | Mirai | 33.008 | 33.008 | 23.051 | 9.957 |
| Mirai-udpplain | Mirai | 36.373 | 36.373 | 25.458 | 10.915 |
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
| BenignTraffic | Benign | 96.809 | 50.000 | 33.992 | 16.008 |

## Resultados com janela de 10

Na parte de teste, de 386.922 linhas: acurácia 95,11%, macro-F1 75,71%, F1 ponderado 95,15%, teto destas linhas 99,89%. Tráfego benigno classificado como ataque: 12,66%. Ataque classificado como benigno: 1,51%.

| Categoria | Linhas de teste | Precisão | Recall | F1 | Falso positivo da categoria |
|---|---|---|---|---|---|
| DDoS+DoS | 258.808 | 98,81% | 96,99% | 97,89% | 2,35% |
| Mirai | 44.910 | 99,99% | 99,57% | 99,78% | 0,00% |
| Recon | 32.863 | 81,99% | 88,44% | 85,09% | 1,80% |
| Spoofing | 31.264 | 90,35% | 90,30% | 90,33% | 0,85% |
| Web | 1.547 | 35,83% | 27,54% | 31,14% | 0,20% |
| BruteForce | 1.469 | 76,45% | 34,04% | 47,10% | 0,04% |
| Benign | 16.061 | 71,45% | 87,34% | 78,60% | 1,51% |

O falso positivo de uma categoria é a fração das janelas das outras categorias que o modelo pôs nela.
Na linha Benign, ele é o ataque classificado como benigno, isto é, o ataque perdido, e não o alarme
falso; o alarme falso é o tráfego benigno classificado como ataque, dado acima.

As medidas acima estão na mistura do teste, que o teto deforma: cada rótulo entra com no máximo 50.000 linhas. Reponderadas para a mistura das janelas regeradas, antes do teto, em que cada rótulo pesa as janelas que tem: acurácia 99,04%, macro-F1 67,86%, F1 ponderado 99,12%, ataque classificado como benigno 0,19%. O tráfego benigno classificado como ataque não muda, porque o benigno é um rótulo só.

| Categoria | Precisão | Precisão reponderada | Recall | Recall reponderado | F1 | F1 reponderado |
|---|---|---|---|---|---|---|
| DDoS+DoS | 98,81% | 99,87% | 96,99% | 99,54% | 97,89% | 99,70% |
| Mirai | 99,99% | 100,00% | 99,57% | 99,43% | 99,78% | 99,71% |
| Recon | 81,99% | 59,63% | 88,44% | 85,31% | 85,09% | 70,20% |
| Spoofing | 90,35% | 50,31% | 90,30% | 89,89% | 90,33% | 64,51% |
| Web | 35,83% | 15,72% | 27,54% | 29,74% | 31,14% | 20,57% |
| BruteForce | 76,45% | 27,15% | 34,04% | 34,04% | 47,10% | 30,21% |
| Benign | 71,45% | 93,08% | 87,34% | 87,34% | 78,60% | 90,12% |

Matriz de confusão, com a categoria real nas linhas e a prevista nas colunas:

| Real \ prevista | DDoS+DoS | Mirai | Recon | Spoofing | Web | BruteForce | Benign |
|---|---|---|---|---|---|---|---|
| DDoS+DoS | 251.023 | 2 | 3.085 | 1.643 | 200 | 4 | 2.851 |
| Mirai | 19 | 44.716 | 84 | 45 | 2 | 0 | 44 |
| Recon | 1.614 | 1 | 29.063 | 546 | 216 | 81 | 1.342 |
| Spoofing | 329 | 0 | 1.336 | 28.231 | 265 | 1 | 1.102 |
| Web | 250 | 0 | 521 | 156 | 426 | 4 | 190 |
| BruteForce | 316 | 0 | 484 | 57 | 36 | 500 | 76 |
| Benign | 485 | 0 | 873 | 567 | 44 | 64 | 14.028 |

### Com o ponto de operação, janela de 10

A mesma parte de teste, com a regra do sistema: ataque se 1 − P(Benign) ≥ 0,93, na categoria de ataque mais provável; senão, Benign. O limiar só decide entre Benign e ataque: a janela que é ataque pelas duas regras fica na mesma categoria. A regra das 3 janelas seguidas vale para o alarme, e não para a janela; os alarmes estão em `ponto_de_operacao.md`.

| Medida | Argmax | Ponto de operação |
|---|---|---|
| Macro-F1 | 75,71% | 69,54% |
| Acurácia | 95,11% | 92,21% |
| Benigno classificado como ataque | 12,66% | 1,18% |
| Ataque classificado como benigno | 1,51% | 6,79% |

| Categoria | Linhas de teste | Precisão, argmax | Precisão, limiar | Recall, argmax | Recall, limiar | F1, argmax | F1, limiar |
|---|---|---|---|---|---|---|---|
| DDoS+DoS | 258.808 | 98,81% | 99,13% | 96,99% | 94,89% | 97,89% | 96,96% |
| Mirai | 44.910 | 99,99% | 99,99% | 99,57% | 99,57% | 99,78% | 99,78% |
| Recon | 32.863 | 81,99% | 91,98% | 88,44% | 71,30% | 85,09% | 80,33% |
| Spoofing | 31.264 | 90,35% | 98,74% | 90,30% | 85,06% | 90,33% | 91,39% |
| Web | 1.547 | 35,83% | 37,86% | 27,54% | 14,41% | 31,14% | 20,88% |
| BruteForce | 1.469 | 76,45% | 92,13% | 34,04% | 27,09% | 47,10% | 41,87% |
| Benign | 16.061 | 71,45% | 38,66% | 87,34% | 98,82% | 78,60% | 55,58% |

Matriz de confusão com o ponto de operação:

| Real \ prevista | DDoS+DoS | Mirai | Recon | Spoofing | Web | BruteForce | Benign |
|---|---|---|---|---|---|---|---|
| DDoS+DoS | 245.570 | 2 | 1.131 | 96 | 146 | 0 | 11.863 |
| Mirai | 11 | 44.716 | 38 | 13 | 0 | 0 | 132 |
| Recon | 1.423 | 1 | 23.430 | 134 | 88 | 25 | 7.762 |
| Spoofing | 204 | 0 | 389 | 26.592 | 112 | 1 | 3.966 |
| Web | 187 | 0 | 137 | 42 | 223 | 2 | 956 |
| BruteForce | 288 | 0 | 257 | 13 | 12 | 398 | 501 |
| Benign | 45 | 0 | 91 | 40 | 8 | 6 | 15.871 |

Por pcap, a fração das janelas de teste na categoria esperada, com o argmax e com o ponto de operação, e a categoria mais prevista pelo argmax:

| Arquivo | Rótulo | Categoria esperada | Janelas de teste | Na esperada, argmax | Na esperada, limiar | Mais prevista |
|---|---|---|---|---|---|---|
| `Backdoor_Malware.pcap` | Backdoor_Malware | Web | 272 | 27,57% | 13,24% | Recon |
| `BenignTraffic.pcap` | BenignTraffic | Benign | 0 | sem teste | sem teste | nenhuma |
| `BenignTraffic1.pcap` | BenignTraffic | Benign | 0 | sem teste | sem teste | nenhuma |
| `BenignTraffic2.pcap` | BenignTraffic | Benign | 16.061 | 87,34% | 98,82% | Benign |
| `BrowserHijacking.pcap` | BrowserHijacking | Web | 281 | 39,50% | 22,78% | Web |
| `CommandInjection.pcap` | CommandInjection | Web | 174 | 20,11% | 8,05% | DDoS+DoS |
| `DDoS-ACK_Fragmentation.pcap` | DDoS-ACK_Fragmentation | DDoS+DoS | 14.184 | 99,50% | 99,24% | DDoS+DoS |
| `DDoS-HTTP_Flood-.pcap` | DDoS-HTTP_Flood | DDoS+DoS | 15.296 | 99,02% | 98,31% | DDoS+DoS |
| `DDoS-ICMP_Flood.pcap` | DDoS-ICMP_Flood | DDoS+DoS | 14.929 | 99,93% | 99,92% | DDoS+DoS |
| `DDoS-ICMP_Fragmentation.pcap` | DDoS-ICMP_Fragmentation | DDoS+DoS | 14.939 | 99,63% | 99,41% | DDoS+DoS |
| `DDoS-PSHACK_Flood.pcap` | DDoS-PSHACK_Flood | DDoS+DoS | 15.158 | 99,99% | 99,97% | DDoS+DoS |
| `DDoS-RSTFINFlood.pcap` | DDoS-RSTFINFlood | DDoS+DoS | 15.284 | 100,00% | 100,00% | DDoS+DoS |
| `DDoS-SYN_Flood.pcap` | DDoS-SYN_Flood | DDoS+DoS | 0 | sem teste | sem teste | nenhuma |
| `DDoS-SYN_Flood1.pcap` | DDoS-SYN_Flood | DDoS+DoS | 24.928 | 99,76% | 99,76% | DDoS+DoS |
| `DDoS-SlowLoris.pcap` | DDoS-SlowLoris | DDoS+DoS | 15.517 | 67,22% | 38,68% | DDoS+DoS |
| `DDoS-SynonymousIP_Flood.pcap` | DDoS-SynonymousIP_Flood | DDoS+DoS | 15.003 | 99,95% | 99,95% | DDoS+DoS |
| `DDoS-TCP_Flood.pcap` | DDoS-TCP_Flood | DDoS+DoS | 14.814 | 99,92% | 99,90% | DDoS+DoS |
| `DDoS-UDP_Flood.pcap` | DDoS-UDP_Flood | DDoS+DoS | 14.945 | 99,93% | 99,90% | DDoS+DoS |
| `DDoS-UDP_Fragmentation.pcap` | DDoS-UDP_Fragmentation | DDoS+DoS | 14.771 | 98,02% | 97,60% | DDoS+DoS |
| `DNS_Spoofing.pcap` | DNS_Spoofing | Spoofing | 13.054 | 89,02% | 83,68% | Spoofing |
| `DictionaryBruteForce.pcap` | DictionaryBruteForce | BruteForce | 1.469 | 34,04% | 27,09% | BruteForce |
| `DoS-HTTP_Flood1.pcap` | DoS-HTTP_Flood | DDoS+DoS | 14.181 | 86,68% | 81,60% | DDoS+DoS |
| `DoS-SYN_Flood.pcap` | DoS-SYN_Flood | DDoS+DoS | 0 | sem teste | sem teste | nenhuma |
| `DoS-SYN_Flood1.pcap` | DoS-SYN_Flood | DDoS+DoS | 24.943 | 99,76% | 99,76% | DDoS+DoS |
| `DoS-TCP_Flood.pcap` | DoS-TCP_Flood | DDoS+DoS | 14.886 | 99,95% | 99,86% | DDoS+DoS |
| `DoS-UDP_Flood.pcap` | DoS-UDP_Flood | DDoS+DoS | 15.030 | 99,52% | 99,25% | DDoS+DoS |
| `MITM-ArpSpoofing.pcap` | MITM-ArpSpoofing | Spoofing | 18.210 | 91,21% | 86,04% | Spoofing |
| `Mirai-greeth_flood.pcap` | Mirai-greeth_flood | Mirai | 15.144 | 99,95% | 99,95% | Mirai |
| `Mirai-greip_flood21.pcap` | Mirai-greip_flood | Mirai | 15.071 | 99,95% | 99,95% | Mirai |
| `Mirai-udpplain.pcap` | Mirai-udpplain | Mirai | 14.695 | 98,78% | 98,78% | Mirai |
| `Recon-HostDiscovery.pcap` | Recon-HostDiscovery | Recon | 11.734 | 98,04% | 86,37% | Recon |
| `Recon-OSScan.pcap` | Recon-OSScan | Recon | 9.084 | 86,23% | 76,53% | Recon |
| `Recon-PingSweep.pcap` | Recon-PingSweep | Recon | 30 | 43,33% | 6,67% | Recon |
| `Recon-PortScan.pcap` | Recon-PortScan | Recon | 6.597 | 89,03% | 82,99% | Recon |
| `SqlInjection.pcap` | SqlInjection | Web | 370 | 17,03% | 14,59% | Recon |
| `Uploading_Attack.pcap` | Uploading_Attack | Web | 113 | 35,40% | 8,85% | Recon |
| `VulnerabilityScan.pcap` | VulnerabilityScan | Recon | 5.418 | 70,87% | 15,98% | Recon |
| `XSS.pcap` | XSS | Web | 337 | 30,27% | 13,35% | Recon |

As 10 features mais importantes (redução média de impureza): `Min` (13,2%), `Time_To_Live` (10,6%), `Max` (8,3%), `IAT` (6,2%), `Rate` (5,9%), `Header_Length` (5,5%), `Tot sum` (5,3%), `Protocol Type` (5,1%), `Tot size` (4,9%) e `HTTPS` (4,2%).

### Nos arquivos inteiros de teste, com janela de 10

`BenignTraffic2.pcap`, `DDoS-SYN_Flood1.pcap` e `DoS-SYN_Flood1.pcap`, pcaps de que o modelo não viu nenhuma janela, com as janelas que o teto sorteou de cada um. 65.932 linhas, acurácia 96,74%, macro-F1 96,32% entre as categorias presentes, tráfego benigno classificado como ataque 12,66%. A precisão e o falso positivo de cada categoria valem só dentro desses arquivos. A medida depende de qual pcap fica de fora: a rotação do
pcap benigno de fora está em `rodadas_de_teste.md`.

| Categoria | Linhas de teste | Precisão | Recall | F1 |
|---|---|---|---|---|
| DDoS+DoS | 49.871 | 99,03% | 99,76% | 99,40% |
| Benign | 16.061 | 100,00% | 87,34% | 93,24% |

## Resultados com janela de 100

Na parte de teste, de 273.566 linhas: acurácia 98,26%, macro-F1 82,27%, F1 ponderado 98,26%, teto destas linhas 100,00%. Tráfego benigno classificado como ataque: 1,86%. Ataque classificado como benigno: 1,03%.

| Categoria | Linhas de teste | Precisão | Recall | F1 | Falso positivo da categoria |
|---|---|---|---|---|---|
| DDoS+DoS | 214.373 | 99,76% | 98,88% | 99,32% | 0,86% |
| Mirai | 24.458 | 99,98% | 99,25% | 99,61% | 0,00% |
| Recon | 10.982 | 86,89% | 87,65% | 87,27% | 0,55% |
| Spoofing | 7.007 | 99,46% | 99,41% | 99,44% | 0,01% |
| Web | 465 | 64,66% | 36,99% | 47,06% | 0,03% |
| BruteForce | 273 | 97,96% | 35,16% | 51,75% | 0,00% |
| Benign | 16.008 | 85,56% | 98,14% | 91,42% | 1,03% |

O falso positivo de uma categoria é a fração das janelas das outras categorias que o modelo pôs nela.
Na linha Benign, ele é o ataque classificado como benigno, isto é, o ataque perdido, e não o alarme
falso; o alarme falso é o tráfego benigno classificado como ataque, dado acima.

As medidas acima estão na mistura do teste, que o teto deforma: cada rótulo entra com no máximo 50.000 linhas. Reponderadas para a mistura das janelas regeradas, antes do teto, em que cada rótulo pesa as janelas que tem: acurácia 99,46%, macro-F1 82,05%, F1 ponderado 99,46%, ataque classificado como benigno 0,29%. O tráfego benigno classificado como ataque não muda, porque o benigno é um rótulo só.

| Categoria | Precisão | Precisão reponderada | Recall | Recall reponderado | F1 | F1 reponderado |
|---|---|---|---|---|---|---|
| DDoS+DoS | 99,76% | 99,93% | 98,88% | 99,71% | 99,32% | 99,82% |
| Mirai | 99,98% | 99,96% | 99,25% | 99,25% | 99,61% | 99,60% |
| Recon | 86,89% | 85,30% | 87,65% | 87,62% | 87,27% | 86,45% |
| Spoofing | 99,46% | 98,65% | 99,41% | 99,31% | 99,44% | 98,98% |
| Web | 64,66% | 59,08% | 36,99% | 34,65% | 47,06% | 43,68% |
| BruteForce | 97,96% | 96,90% | 35,16% | 35,16% | 51,75% | 51,60% |
| Benign | 85,56% | 90,66% | 98,14% | 98,14% | 91,42% | 94,25% |

Matriz de confusão, com a categoria real nas linhas e a prevista nas colunas:

| Real \ prevista | DDoS+DoS | Mirai | Recon | Spoofing | Web | BruteForce | Benign |
|---|---|---|---|---|---|---|---|
| DDoS+DoS | 211.969 | 5 | 1.036 | 18 | 13 | 0 | 1.332 |
| Mirai | 44 | 24.275 | 74 | 1 | 6 | 0 | 58 |
| Recon | 195 | 0 | 9.626 | 7 | 21 | 0 | 1.133 |
| Spoofing | 28 | 0 | 6 | 6.966 | 3 | 0 | 4 |
| Web | 61 | 0 | 132 | 4 | 172 | 1 | 95 |
| BruteForce | 45 | 0 | 97 | 0 | 6 | 96 | 29 |
| Benign | 136 | 0 | 108 | 8 | 45 | 1 | 15.710 |

### Com o ponto de operação, janela de 100

A mesma parte de teste, com a regra do sistema: ataque se 1 − P(Benign) ≥ 0,68, na categoria de ataque mais provável; senão, Benign. O limiar só decide entre Benign e ataque: a janela que é ataque pelas duas regras fica na mesma categoria. A regra das 3 janelas seguidas vale para o alarme, e não para a janela; os alarmes estão em `ponto_de_operacao.md`.

| Medida | Argmax | Ponto de operação |
|---|---|---|
| Macro-F1 | 82,27% | 81,10% |
| Acurácia | 98,26% | 98,02% |
| Benigno classificado como ataque | 1,86% | 1,21% |
| Ataque classificado como benigno | 1,03% | 1,35% |

| Categoria | Linhas de teste | Precisão, argmax | Precisão, limiar | Recall, argmax | Recall, limiar | F1, argmax | F1, limiar |
|---|---|---|---|---|---|---|---|
| DDoS+DoS | 214.373 | 99,76% | 99,80% | 98,88% | 98,81% | 99,32% | 99,30% |
| Mirai | 24.458 | 99,98% | 99,98% | 99,25% | 99,25% | 99,61% | 99,61% |
| Recon | 10.982 | 86,89% | 86,75% | 87,65% | 81,93% | 87,27% | 84,27% |
| Spoofing | 7.007 | 99,46% | 99,46% | 99,41% | 99,41% | 99,44% | 99,44% |
| Web | 465 | 64,66% | 64,73% | 36,99% | 35,91% | 47,06% | 46,20% |
| BruteForce | 273 | 97,96% | 97,83% | 35,16% | 32,97% | 51,75% | 49,32% |
| Benign | 16.008 | 85,56% | 81,96% | 98,14% | 98,79% | 91,42% | 89,59% |

Matriz de confusão com o ponto de operação:

| Real \ prevista | DDoS+DoS | Mirai | Recon | Spoofing | Web | BruteForce | Benign |
|---|---|---|---|---|---|---|---|
| DDoS+DoS | 211.831 | 5 | 986 | 18 | 14 | 0 | 1.519 |
| Mirai | 40 | 24.275 | 74 | 2 | 8 | 0 | 59 |
| Recon | 200 | 0 | 8.998 | 7 | 22 | 0 | 1.755 |
| Spoofing | 28 | 0 | 7 | 6.966 | 3 | 0 | 3 |
| Web | 61 | 0 | 122 | 4 | 167 | 1 | 110 |
| BruteForce | 45 | 0 | 97 | 0 | 6 | 90 | 35 |
| Benign | 59 | 0 | 88 | 7 | 38 | 1 | 15.815 |

Por pcap, a fração das janelas de teste na categoria esperada, com o argmax e com o ponto de operação, e a categoria mais prevista pelo argmax:

| Arquivo | Rótulo | Categoria esperada | Janelas de teste | Na esperada, argmax | Na esperada, limiar | Mais prevista |
|---|---|---|---|---|---|---|
| `Backdoor_Malware.pcap` | Backdoor_Malware | Web | 76 | 55,26% | 55,26% | Web |
| `BenignTraffic.pcap` | BenignTraffic | Benign | 0 | sem teste | sem teste | nenhuma |
| `BenignTraffic1.pcap` | BenignTraffic | Benign | 0 | sem teste | sem teste | nenhuma |
| `BenignTraffic2.pcap` | BenignTraffic | Benign | 16.008 | 98,14% | 98,79% | Benign |
| `BrowserHijacking.pcap` | BrowserHijacking | Web | 81 | 13,58% | 13,58% | Benign |
| `CommandInjection.pcap` | CommandInjection | Web | 77 | 36,36% | 33,77% | DDoS+DoS |
| `DDoS-ACK_Fragmentation.pcap` | DDoS-ACK_Fragmentation | DDoS+DoS | 7.032 | 99,37% | 99,32% | DDoS+DoS |
| `DDoS-HTTP_Flood-.pcap` | DDoS-HTTP_Flood | DDoS+DoS | 8.618 | 99,81% | 99,81% | DDoS+DoS |
| `DDoS-ICMP_Flood.pcap` | DDoS-ICMP_Flood | DDoS+DoS | 14.916 | 99,93% | 99,93% | DDoS+DoS |
| `DDoS-ICMP_Fragmentation.pcap` | DDoS-ICMP_Fragmentation | DDoS+DoS | 6.169 | 99,63% | 99,63% | DDoS+DoS |
| `DDoS-PSHACK_Flood.pcap` | DDoS-PSHACK_Flood | DDoS+DoS | 15.025 | 99,99% | 99,99% | DDoS+DoS |
| `DDoS-RSTFINFlood.pcap` | DDoS-RSTFINFlood | DDoS+DoS | 15.082 | 100,00% | 100,00% | DDoS+DoS |
| `DDoS-SYN_Flood.pcap` | DDoS-SYN_Flood | DDoS+DoS | 0 | sem teste | sem teste | nenhuma |
| `DDoS-SYN_Flood1.pcap` | DDoS-SYN_Flood | DDoS+DoS | 24.992 | 99,97% | 99,97% | DDoS+DoS |
| `DDoS-SlowLoris.pcap` | DDoS-SlowLoris | DDoS+DoS | 6.515 | 83,39% | 81,87% | DDoS+DoS |
| `DDoS-SynonymousIP_Flood.pcap` | DDoS-SynonymousIP_Flood | DDoS+DoS | 14.895 | 99,99% | 99,99% | DDoS+DoS |
| `DDoS-TCP_Flood.pcap` | DDoS-TCP_Flood | DDoS+DoS | 14.990 | 99,74% | 99,74% | DDoS+DoS |
| `DDoS-UDP_Flood.pcap` | DDoS-UDP_Flood | DDoS+DoS | 14.861 | 100,00% | 100,00% | DDoS+DoS |
| `DDoS-UDP_Fragmentation.pcap` | DDoS-UDP_Fragmentation | DDoS+DoS | 6.708 | 97,17% | 96,93% | DDoS+DoS |
| `DNS_Spoofing.pcap` | DNS_Spoofing | Spoofing | 3.143 | 98,92% | 98,92% | Spoofing |
| `DictionaryBruteForce.pcap` | DictionaryBruteForce | BruteForce | 273 | 35,16% | 32,97% | Recon |
| `DoS-HTTP_Flood1.pcap` | DoS-HTTP_Flood | DDoS+DoS | 9.137 | 89,55% | 89,37% | DDoS+DoS |
| `DoS-SYN_Flood.pcap` | DoS-SYN_Flood | DDoS+DoS | 0 | sem teste | sem teste | nenhuma |
| `DoS-SYN_Flood1.pcap` | DoS-SYN_Flood | DDoS+DoS | 25.325 | 99,94% | 99,94% | DDoS+DoS |
| `DoS-TCP_Flood.pcap` | DoS-TCP_Flood | DDoS+DoS | 15.120 | 99,99% | 99,99% | DDoS+DoS |
| `DoS-UDP_Flood.pcap` | DoS-UDP_Flood | DDoS+DoS | 14.988 | 99,88% | 99,86% | DDoS+DoS |
| `MITM-ArpSpoofing.pcap` | MITM-ArpSpoofing | Spoofing | 3.864 | 99,82% | 99,82% | Spoofing |
| `Mirai-greeth_flood.pcap` | Mirai-greeth_flood | Mirai | 9.957 | 99,98% | 99,98% | Mirai |
| `Mirai-greip_flood21.pcap` | Mirai-greip_flood | Mirai | 3.586 | 100,00% | 100,00% | Mirai |
| `Mirai-udpplain.pcap` | Mirai-udpplain | Mirai | 10.915 | 98,34% | 98,34% | Mirai |
| `Recon-HostDiscovery.pcap` | Recon-HostDiscovery | Recon | 3.842 | 93,10% | 91,57% | Recon |
| `Recon-OSScan.pcap` | Recon-OSScan | Recon | 1.397 | 77,24% | 74,23% | Recon |
| `Recon-PingSweep.pcap` | Recon-PingSweep | Recon | 18 | 55,56% | 44,44% | Recon |
| `Recon-PortScan.pcap` | Recon-PortScan | Recon | 850 | 81,06% | 80,35% | Recon |
| `SqlInjection.pcap` | SqlInjection | Web | 102 | 0,98% | 0,98% | Recon |
| `Uploading_Attack.pcap` | Uploading_Attack | Web | 31 | 74,19% | 70,97% | Web |
| `VulnerabilityScan.pcap` | VulnerabilityScan | Recon | 4.875 | 87,61% | 76,96% | Recon |
| `XSS.pcap` | XSS | Web | 98 | 68,37% | 66,33% | Web |

As 10 features mais importantes (redução média de impureza): `Time_To_Live` (10,6%), `Max` (10,1%), `Tot sum` (8,6%), `Tot size` (7,2%), `Min` (6,5%), `Std` (6,0%), `AVG` (5,3%), `Rate` (5,1%), `HTTPS` (4,8%) e `Variance` (4,7%).

### Nos arquivos inteiros de teste, com janela de 100

`BenignTraffic2.pcap`, `DDoS-SYN_Flood1.pcap` e `DoS-SYN_Flood1.pcap`, pcaps de que o modelo não viu nenhuma janela, com as janelas que o teto sorteou de cada um. 66.325 linhas, acurácia 99,52%, macro-F1 99,45% entre as categorias presentes, tráfego benigno classificado como ataque 1,86%. A precisão e o falso positivo de cada categoria valem só dentro desses arquivos. A medida depende de qual pcap fica de fora: a rotação do
pcap benigno de fora está em `rodadas_de_teste.md`.

| Categoria | Linhas de teste | Precisão | Recall | F1 |
|---|---|---|---|---|
| DDoS+DoS | 50.317 | 99,73% | 99,95% | 99,84% |
| Benign | 16.008 | 99,99% | 98,14% | 99,06% |

## As duas janelas lado a lado

| Medida | Janela de 10 | Janela de 100 |
|---|---|---|
| Macro-F1 | 75,71% | 82,27% |
| Macro-F1 reponderado | 67,86% | 82,05% |
| Acurácia | 95,11% | 98,26% |
| Benigno classificado como ataque | 12,66% | 1,86% |
| Ataque classificado como benigno | 1,51% | 1,03% |
| Linhas de teste | 386.922 | 273.566 |

| Categoria | Recall (10) | Recall (100) | F1 (10) | F1 (100) |
|---|---|---|---|---|
| DDoS+DoS | 96,99% | 98,88% | 97,89% | 99,32% |
| Mirai | 99,57% | 99,25% | 99,78% | 99,61% |
| Recon | 88,44% | 87,65% | 85,09% | 87,27% |
| Spoofing | 90,30% | 99,41% | 90,33% | 99,44% |
| Web | 27,54% | 36,99% | 31,14% | 47,06% |
| BruteForce | 34,04% | 35,16% | 47,10% | 51,75% |
| Benign | 87,34% | 98,14% | 78,60% | 91,42% |

O maior macro-F1 é o da janela de 100, e a menor taxa de tráfego benigno classificado como ataque é a da janela de 100. Com janela de 100, cada pcap gera cerca de um décimo das janelas que gera com 10, e as classes raras ficam com poucas linhas de teste; na operação, a janela de 10 decide com menos quadros e responde mais vezes por segundo.

## IPs de origem por janela em DDoS e DoS

O modelo não separa DDoS de DoS: as features descrevem os pacotes, não quantas máquinas atacam. A separação
sai da quantidade de IPs de origem distintos das janelas do incidente, fora do modelo. A tabela resume essa
quantidade nas janelas regeradas de cada classe de DDoS e DoS presente, antes do teto.

Janela de 10:

| Rótulo | Categoria | Janelas | Mínimo | P25 | Mediana | P75 | Máximo | Média | Janelas com até 1 IP de origem |
|---|---|---|---|---|---|---|---|---|---|
| DDoS-ACK_Fragmentation | DDoS | 243.900 | 0 | 1,0 | 1,0 | 2,0 | 9 | 1,48 | 63,16% |
| DDoS-UDP_Flood | DDoS | 2.661.376 | 1 | 1,0 | 1,0 | 1,0 | 10 | 1,18 | 83,55% |
| DDoS-SlowLoris | DDoS | 179.601 | 0 | 2,0 | 3,0 | 4,0 | 10 | 3,02 | 23,25% |
| DDoS-ICMP_Flood | DDoS | 2.677.303 | 0 | 1,0 | 1,0 | 1,0 | 9 | 1,12 | 88,75% |
| DDoS-RSTFINFlood | DDoS | 2.666.660 | 1 | 1,0 | 1,0 | 1,0 | 10 | 1,17 | 84,12% |
| DDoS-PSHACK_Flood | DDoS | 2.675.472 | 0 | 1,0 | 1,0 | 1,0 | 9 | 1,17 | 84,03% |
| DDoS-HTTP_Flood | DDoS | 280.956 | 0 | 1,0 | 1,0 | 2,0 | 10 | 1,78 | 59,96% |
| DDoS-UDP_Fragmentation | DDoS | 221.697 | 0 | 1,0 | 1,0 | 2,0 | 10 | 1,39 | 74,38% |
| DDoS-ICMP_Fragmentation | DDoS | 203.141 | 0 | 1,0 | 1,0 | 2,0 | 10 | 1,46 | 70,34% |
| DDoS-TCP_Flood | DDoS | 2.650.042 | 1 | 1,0 | 1,0 | 1,0 | 10 | 1,18 | 83,55% |
| DDoS-SYN_Flood | DDoS | 5.326.163 | 0 | 1,0 | 1,0 | 1,0 | 10 | 1,17 | 84,87% |
| DDoS-SynonymousIP_Flood | DDoS | 2.684.667 | 0 | 1,0 | 1,0 | 1,0 | 10 | 1,01 | 98,91% |
| DoS-TCP_Flood | DoS | 2.597.426 | 1 | 1,0 | 1,0 | 1,0 | 9 | 1,05 | 95,62% |
| DoS-HTTP_Flood | DoS | 298.903 | 1 | 1,0 | 1,0 | 2,0 | 10 | 1,57 | 70,24% |
| DoS-SYN_Flood | DoS | 5.261.433 | 1 | 1,0 | 1,0 | 1,0 | 10 | 1,08 | 93,07% |
| DoS-UDP_Flood | DoS | 1.664.550 | 1 | 1,0 | 1,0 | 1,0 | 9 | 1,06 | 95,60% |

Janela de 100:

| Rótulo | Categoria | Janelas | Mínimo | P25 | Mediana | P75 | Máximo | Média | Janelas com até 1 IP de origem |
|---|---|---|---|---|---|---|---|---|---|
| DDoS-ACK_Fragmentation | DDoS | 24.457 | 1 | 2,0 | 3,0 | 5,0 | 29 | 4,02 | 6,48% |
| DDoS-UDP_Flood | DDoS | 266.297 | 1 | 2,0 | 2,0 | 3,0 | 42 | 2,54 | 6,53% |
| DDoS-SlowLoris | DDoS | 21.710 | 1 | 7,0 | 10,0 | 16,0 | 48 | 11,74 | 1,39% |
| DDoS-ICMP_Flood | DDoS | 267.863 | 1 | 2,0 | 2,0 | 2,0 | 38 | 2,12 | 14,86% |
| DDoS-RSTFINFlood | DDoS | 266.742 | 1 | 2,0 | 2,0 | 3,0 | 40 | 2,47 | 7,22% |
| DDoS-PSHACK_Flood | DDoS | 267.618 | 1 | 2,0 | 2,0 | 3,0 | 50 | 2,44 | 7,72% |
| DDoS-HTTP_Flood | DDoS | 28.570 | 1 | 3,0 | 5,0 | 8,0 | 39 | 6,13 | 7,92% |
| DDoS-UDP_Fragmentation | DDoS | 22.394 | 1 | 2,0 | 4,0 | 5,0 | 36 | 4,36 | 8,44% |
| DDoS-ICMP_Fragmentation | DDoS | 20.479 | 1 | 3,0 | 4,0 | 6,0 | 45 | 4,85 | 6,99% |
| DDoS-TCP_Flood | DDoS | 265.218 | 1 | 2,0 | 2,0 | 3,0 | 39 | 2,54 | 5,99% |
| DDoS-SYN_Flood | DDoS | 532.731 | 1 | 2,0 | 2,0 | 3,0 | 40 | 2,44 | 14,05% |
| DDoS-SynonymousIP_Flood | DDoS | 268.499 | 1 | 1,0 | 1,0 | 1,0 | 45 | 1,12 | 90,41% |
| DoS-TCP_Flood | DoS | 259.976 | 1 | 1,0 | 1,0 | 2,0 | 25 | 1,41 | 72,13% |
| DoS-HTTP_Flood | DoS | 30.881 | 1 | 2,0 | 4,0 | 7,0 | 42 | 5,59 | 12,39% |
| DoS-SYN_Flood | DoS | 526.530 | 1 | 1,0 | 1,0 | 2,0 | 36 | 1,63 | 57,08% |
| DoS-UDP_Flood | DoS | 166.653 | 1 | 1,0 | 1,0 | 2,0 | 44 | 1,55 | 67,10% |

Com janela de 10, a mediana de IPs de origem por janela vai de 1,0 a 3,0 nas classes de DDoS e de 1,0 a 1,0 nas de DoS: as faixas se cruzam, e a contagem de uma janela isolada não separa as duas categorias.
Com janela de 100, a mediana de IPs de origem por janela vai de 1,0 a 10,0 nas classes de DDoS e de 1,0 a 4,0 nas de DoS: as faixas se cruzam, e a contagem de uma janela isolada não separa as duas categorias.

A contagem inclui os IPs de origem de todos os quadros IPv4 da janela, também os da vítima e os do tráfego
de fundo, e não só os das máquinas que atacam.

## Rodadas anteriores, como referência

As medidas das rodadas parciais, antes de os outros pcaps chegarem. Cada rodada é o mesmo comando sobre
os pcaps que havia na pasta na data.

Rodada de 10/10/2026: 26 pcaps, 25 rótulos (9 sem pcap).

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

O que mudou da última rodada para esta:

- Pcaps: de 26 para 38. Rótulos que entraram: DDoS-ACK_Fragmentation, DDoS-ICMP_Fragmentation, DDoS-PSHACK_Flood, DDoS-RSTFINFlood, DDoS-SlowLoris, DDoS-SynonymousIP_Flood, DDoS-UDP_Fragmentation, Mirai-greeth_flood e Mirai-udpplain.
- Janela de 10: macro-F1 de 76,95% para 75,71% (-1,25 p.p.); benigno classificado como ataque de 13,37% para 12,66% (-0,71 p.p.); recall por categoria: DDoS+DoS de 97,97% para 96,99% (-0,97 p.p.); Mirai de 99,97% para 99,57% (-0,40 p.p.); Recon de 88,58% para 88,44% (-0,15 p.p.); Spoofing de 91,02% para 90,30% (-0,72 p.p.); Web de 28,70% para 27,54% (-1,16 p.p.); BruteForce de 33,56% para 34,04% (+0,48 p.p.); Benign de 86,63% para 87,34% (+0,71 p.p.).
- Janela de 100: macro-F1 de 82,46% para 82,27% (-0,20 p.p.); benigno classificado como ataque de 1,83% para 1,86% (+0,03 p.p.); recall por categoria: DDoS+DoS de 98,89% para 98,88% (-0,01 p.p.); Mirai de 100,00% para 99,25% (-0,75 p.p.); Recon de 86,00% para 87,65% (+1,65 p.p.); Spoofing de 99,44% para 99,41% (-0,03 p.p.); Web de 41,94% para 36,99% (-4,95 p.p.); BruteForce de 35,90% para 35,16% (-0,73 p.p.); Benign de 98,17% para 98,14% (-0,03 p.p.).

## Ressalvas

- **Uma a três capturas por rótulo.** Todos os 34 rótulos têm pcap, mas a variedade dentro de cada um
  é a de poucas capturas da mesma rede. O que o modelo aprendeu de uma variante pode não valer para
  outra captura dela.
- **Uma semente neste relatório.** Divisão por tempo não sorteia, mas o teto por rótulo e o modelo usam a semente 42. A variação entre sementes está em `rodadas_de_teste.md`.
- **O teste vem das mesmas capturas.** As janelas de teste são o fim de cada pcap, da mesma rede e do
  mesmo dia das de treino. A medida vale para a captura, não para outra rede. Os rótulos com mais de
  um pcap têm um arquivo inteiro no teste, que sai à parte e depende de qual arquivo fica de fora; nos
  demais, as janelas na fronteira do corte são vizinhas das de treino. A rotação do arquivo de fora e o
  recall com o pcap inteiro fora do treino estão em `rodadas_de_teste.md`.
- **As janelas descartadas não são avaliadas aqui.** O tráfego de fundo dos pcaps de ataque fica fora do
  treino e do teste. O que o modelo faz com ele está em `rodadas_de_teste.md`.
- **O atacante também gera tráfego benigno.** O MAC `dc:a6:32:dc:27:d5` aparece em cerca de 1% dos quadros dos pcaps benignos (`janelas_sem_atacante.md`), e 5,5% das janelas de 10 e 27,1% das janelas de 100 desses pcaps têm ao menos um quadro de um MAC da lista. A regra de rótulo não usa a lista nos pcaps benignos, então parte do tráfego comum desse dispositivo está no treino como benigno.
- **As seis colunas da janela deixaram de ser atalho.** Com uma janela só, `Number` vale o mesmo em todas
  as classes, a não ser na última janela de cada pcap, que pode ficar incompleta.

## Como os números foram obtidos

- Comando: `python -m codigo.classificador.treinar_regerado --sem-fundo`, a partir da raiz do repositório, depois de `python -m codigo.classificador.regerar`. Ele refaz a leitura, o teto, a divisão, o treino, a avaliação e este relatório.
- Dados: `dados/processed/regerado/janela_<W>/<rotulo>.csv.gz`, registrados em `manifesto_regeracao.json` (gerado em 11/10/2026, pcaps em `CICIoT2023`), com o SHA-256 de cada pcap, a versão 2 da regra e o extrator de SHA-256 `8bd38fb392d5bec5a318699b2cef4a67a7c0c43461ecd01ce20be5b7db0b4a65`.
- Modelos: um por janela, em `modelos/`, fora do git, com o ponto de operação num JSON ao lado: `rf_regerado_janela_10_sem_fundo.joblib` (596,9 MB) e `rf_regerado_janela_10_sem_fundo.ponto_de_operacao.json` e `rf_regerado_janela_100_sem_fundo.joblib` (184,5 MB) e `rf_regerado_janela_100_sem_fundo.ponto_de_operacao.json`. Treinados com 4 núcleos; a quantidade de núcleos muda o tempo, e não o modelo. Predição com um núcleo, em ordem fixa.
- Divisões: o SHA-256 das posições de treino e de teste de cada janela está em `manifesto_treino_regerado_sem_fundo.json`.
- `regeracao_sem_fundo_metricas.csv` tem uma linha por janela, regra e categoria; `regeracao_sem_fundo_por_arquivo.csv`, uma por janela e pcap; `matrizes_confusao/regerado_janela_<W>_sem_fundo.csv` é a matriz de confusão com o argmax, `_limiar.csv` a com o ponto de operação, e `_por_rotulo.csv` abre a classe real nos 34 rótulos.
- Tempo total, na máquina em que rodou: 214,5 s. Pico de memória do processo: 2,7 GB, que é o necessário para reproduzir.
- Com os mesmos CSVs regerados e a mesma semente, os números saem iguais. Só mudam a data e os tempos.

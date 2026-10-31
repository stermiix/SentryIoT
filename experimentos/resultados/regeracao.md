# Treino sobre os dados regerados

Gerado por `python -m codigo.classificador.treinar_regerado` em 29/10/2026, com Python 3.11.2, scikit-learn 1.9.1, pandas 3.0.6 e numpy 2.4.6.

O modelo treinado no `MERGED_CSV` oficial aprende o tamanho da janela, de 100 quadros nas classes de
DDoS, DoS e Mirai e de 10 nas demais, em vez do comportamento do tráfego (`teste_da_janela.md`), e o
rótulo oficial é dado ao arquivo inteiro, mesmo nas janelas sem nenhum quadro do atacante
(`janelas_sem_atacante.md`). Por isso os dados de treino foram gerados de novo a partir dos pcaps, com o
nosso extrator, em janela única e com o rótulo decidido janela a janela (decisão de 10/10/2026 no
`ROADMAP.md`).

Este relatório traz o modelo do sistema: o Random Forest de 7 categorias com janela de 100 quadros, treinado com as janelas de fundo da parte de treino de cada pcap de ataque como Benign (a configuração 5 de `rodadas_normalizadas.md`) e com o ponto de operação escolhido numa parte de validação: entre a categoria mais provável (argmax) e os limiares t sobre 1 − P(Benign), a regra de maior recall de ataque na validação com no máximo 1% do benigno dela como ataque (decisões de 13/10/2026); o incidente abre com 4 janelas de ataque seguidas (decisão de 28/10/2026). As medidas são as da parte de teste, com o argmax e com o melhor limiar, lado a lado.

Os controles estão em outros relatórios: a comparação com o modelo de 10/10, com o pcap inteiro fora do treino, a rotação do pcap benigno de fora e o tráfego de fundo, em `rodadas_normalizadas.md`; o ponto de operação em três sementes, por janela e por alarme, em `ponto_de_operacao.md`; os demais controles do modelo de 10/10, que continuam valendo como referência, em `rodadas_de_teste.md`.

## O que mudou em relação ao modelo anterior

O modelo anterior, do treino gravado em 11/10/2026, com janela de 100, foi treinado sem o fundo e decidia pela categoria mais provável. Ele fica como referência: `python -m codigo.classificador.treinar_regerado --sem-fundo` o refaz em `regeracao_sem_fundo.md`. Na mesma parte de teste:

| Medida | Modelo anterior | Este modelo, argmax (ponto de operação) | Este modelo, limiar t = 0,61 |
|---|---|---|---|
| Macro-F1 | 82,27% | 75,71% | 74,01% |
| Acurácia | 98,26% | 96,15% | 95,75% |
| Benigno classificado como ataque | 1,86% | 0,94% | 1,04% |
| Recall DDoS+DoS | 98,88% | 98,42% | 98,42% |
| Recall Mirai | 99,25% | 99,22% | 99,22% |
| Recall Recon | 87,65% | 54,92% | 50,13% |
| Recall Spoofing | 99,41% | 80,11% | 72,38% |
| Recall Web | 36,99% | 35,70% | 36,99% |
| Recall BruteForce | 35,16% | 34,80% | 34,80% |
| Recall Benign | 98,14% | 99,06% | 98,96% |

O corte por tempo não mostra o motivo da troca. Com o fundo no treino, cai o alarme falso no pcap benigno de fora do treino e o fundo dos pcaps de ataque classificado como ataque, e caem também o recall de Recon e o de Spoofing, no corte por tempo e com o pcap fora do treino. As três sementes, as diferenças pareadas e a regra com que a equipe adotou este modelo estão em `rodadas_normalizadas.md`; o ponto de operação por janela e por alarme, nas rotações do pcap benigno de fora e nos pcaps de ataque, em `ponto_de_operacao.md`.

## Os dados regerados

Os pcaps da pasta do dataset em 11/10/2026, lidos
inteiros pelo extrator em leitura contínua, com os dois tamanhos de janela. Regra de rótulo: num pcap
benigno toda janela é `BenignTraffic`; num pcap de ataque a janela recebe o rótulo do arquivo se tem
quadro com MAC de um Raspberry Pi atacante na origem ou no destino, e é descartada se não tem.

A janela descartada, o tráfego de fundo do pcap de ataque, entra no treino como Benign quando está na parte
de treino do pcap, e fica fora do teste. Até 13/10/2026 ela ficava fora do treino, porque pode conter efeito
do ataque; com ela no treino, o alarme falso no pcap benigno de fora e o fundo virando ataque caem (`rodadas_normalizadas.md`).

| Arquivo | Rótulo | Categoria | Pacotes | Janelas de 100 | Mantidas (100) | Extração (s) |
|---|---|---|---|---|---|---|
| `Backdoor_Malware.pcap` | Backdoor_Malware | Web | 33.414 | 322 | 253 (78,6%) | 0,4 |
| `BenignTraffic.pcap` | BenignTraffic | Benign | 3.664.164 | 36.228 | 36.228 (100,0%) | 44,0 |
| `BenignTraffic1.pcap` | BenignTraffic | Benign | 2.988.642 | 29.549 | 29.549 (100,0%) | 32,8 |
| `BenignTraffic2.pcap` | BenignTraffic | Benign | 3.138.002 | 31.032 | 31.032 (100,0%) | 34,4 |
| `BrowserHijacking.pcap` | BrowserHijacking | Web | 59.821 | 586 | 459 (78,3%) | 0,7 |
| `CommandInjection.pcap` | CommandInjection | Web | 55.741 | 541 | 377 (69,7%) | 0,6 |
| `DDoS-ACK_Fragmentation.pcap` | DDoS-ACK_Fragmentation | DDoS | 2.503.835 | 24.984 | 24.457 (97,9%) | 25,7 |
| `DDoS-HTTP_Flood-.pcap` | DDoS-HTTP_Flood | DDoS | 2.881.005 | 28.756 | 28.570 (99,4%) | 31,4 |
| `DDoS-ICMP_Flood.pcap` | DDoS-ICMP_Flood | DDoS | 26.793.240 | 267.909 | 267.863 (100,0%) | 261,3 |
| `DDoS-ICMP_Fragmentation.pcap` | DDoS-ICMP_Fragmentation | DDoS | 2.064.692 | 20.597 | 20.479 (99,4%) | 19,2 |
| `DDoS-PSHACK_Flood.pcap` | DDoS-PSHACK_Flood | DDoS | 26.774.357 | 267.712 | 267.618 (100,0%) | 276,4 |
| `DDoS-RSTFINFlood.pcap` | DDoS-RSTFINFlood | DDoS | 26.686.473 | 266.832 | 266.742 (100,0%) | 272,0 |
| `DDoS-SYN_Flood.pcap` | DDoS-SYN_Flood | DDoS | 26.597.011 | 265.925 | 265.702 (99,9%) | 283,6 |
| `DDoS-SYN_Flood1.pcap` | DDoS-SYN_Flood | DDoS | 26.715.334 | 267.097 | 267.029 (100,0%) | 275,5 |
| `DDoS-SlowLoris.pcap` | DDoS-SlowLoris | DDoS | 2.351.454 | 23.391 | 21.710 (92,8%) | 26,0 |
| `DDoS-SynonymousIP_Flood.pcap` | DDoS-SynonymousIP_Flood | DDoS | 26.855.630 | 268.525 | 268.499 (100,0%) | 276,6 |
| `DDoS-TCP_Flood.pcap` | DDoS-TCP_Flood | DDoS | 26.570.958 | 265.671 | 265.218 (99,8%) | 270,7 |
| `DDoS-UDP_Flood.pcap` | DDoS-UDP_Flood | DDoS | 26.653.551 | 266.503 | 266.297 (99,9%) | 238,5 |
| `DDoS-UDP_Fragmentation.pcap` | DDoS-UDP_Fragmentation | DDoS | 2.248.843 | 22.439 | 22.394 (99,8%) | 22,0 |
| `DNS_Spoofing.pcap` | DNS_Spoofing | Spoofing | 1.812.557 | 17.888 | 10.586 (59,2%) | 19,7 |
| `DictionaryBruteForce.pcap` | DictionaryBruteForce | BruteForce | 133.138 | 1.307 | 1.042 (79,7%) | 1,5 |
| `DoS-HTTP_Flood1.pcap` | DoS-HTTP_Flood | DoS | 3.114.983 | 31.099 | 30.881 (99,3%) | 34,3 |
| `DoS-SYN_Flood.pcap` | DoS-SYN_Flood | DoS | 26.261.611 | 262.586 | 262.576 (100,0%) | 270,7 |
| `DoS-SYN_Flood1.pcap` | DoS-SYN_Flood | DoS | 26.405.653 | 264.026 | 263.954 (100,0%) | 280,5 |
| `DoS-TCP_Flood.pcap` | DoS-TCP_Flood | DoS | 26.005.549 | 260.028 | 259.976 (100,0%) | 264,2 |
| `DoS-UDP_Flood.pcap` | DoS-UDP_Flood | DoS | 16.676.370 | 166.738 | 166.653 (99,9%) | 149,7 |
| `MITM-ArpSpoofing.pcap` | MITM-ArpSpoofing | Spoofing | 2.491.622 | 24.765 | 8.194 (33,1%) | 28,0 |
| `Mirai-greeth_flood.pcap` | Mirai-greeth_flood | Mirai | 3.352.569 | 33.501 | 33.008 (98,5%) | 47,9 |
| `Mirai-greip_flood21.pcap` | Mirai-greip_flood | Mirai | 1.196.296 | 11.955 | 11.955 (100,0%) | 14,6 |
| `Mirai-udpplain.pcap` | Mirai-udpplain | Mirai | 3.642.269 | 36.389 | 36.373 (100,0%) | 35,5 |
| `Recon-HostDiscovery.pcap` | Recon-HostDiscovery | Recon | 1.371.112 | 13.437 | 12.996 (96,7%) | 14,9 |
| `Recon-OSScan.pcap` | Recon-OSScan | Recon | 992.241 | 9.825 | 4.087 (41,6%) | 11,1 |
| `Recon-PingSweep.pcap` | Recon-PingSweep | Recon | 22.943 | 227 | 114 (50,2%) | 0,3 |
| `Recon-PortScan.pcap` | Recon-PortScan | Recon | 831.856 | 8.228 | 3.783 (46,0%) | 9,0 |
| `SqlInjection.pcap` | SqlInjection | Web | 53.462 | 525 | 325 (61,9%) | 0,6 |
| `Uploading_Attack.pcap` | Uploading_Attack | Web | 12.939 | 126 | 106 (84,1%) | 0,1 |
| `VulnerabilityScan.pcap` | VulnerabilityScan | Recon | 3.802.533 | 37.332 | 18.836 (50,5%) | 42,5 |
| `XSS.pcap` | XSS | Web | 40.183 | 385 | 313 (81,3%) | 0,4 |

Linhas regeradas por rótulo, somando os arquivos dele:

| Rótulo | Categoria | Arquivos | Linhas (100) |
|---|---|---|---|
| Backdoor_Malware | Web | `Backdoor_Malware.pcap` | 253 |
| BenignTraffic | Benign | `BenignTraffic.pcap`, `BenignTraffic1.pcap` e `BenignTraffic2.pcap` | 96.809 |
| BrowserHijacking | Web | `BrowserHijacking.pcap` | 459 |
| CommandInjection | Web | `CommandInjection.pcap` | 377 |
| DDoS-ACK_Fragmentation | DDoS | `DDoS-ACK_Fragmentation.pcap` | 24.457 |
| DDoS-HTTP_Flood | DDoS | `DDoS-HTTP_Flood-.pcap` | 28.570 |
| DDoS-ICMP_Flood | DDoS | `DDoS-ICMP_Flood.pcap` | 267.863 |
| DDoS-ICMP_Fragmentation | DDoS | `DDoS-ICMP_Fragmentation.pcap` | 20.479 |
| DDoS-PSHACK_Flood | DDoS | `DDoS-PSHACK_Flood.pcap` | 267.618 |
| DDoS-RSTFINFlood | DDoS | `DDoS-RSTFINFlood.pcap` | 266.742 |
| DDoS-SYN_Flood | DDoS | `DDoS-SYN_Flood.pcap` e `DDoS-SYN_Flood1.pcap` | 532.731 |
| DDoS-SlowLoris | DDoS | `DDoS-SlowLoris.pcap` | 21.710 |
| DDoS-SynonymousIP_Flood | DDoS | `DDoS-SynonymousIP_Flood.pcap` | 268.499 |
| DDoS-TCP_Flood | DDoS | `DDoS-TCP_Flood.pcap` | 265.218 |
| DDoS-UDP_Flood | DDoS | `DDoS-UDP_Flood.pcap` | 266.297 |
| DDoS-UDP_Fragmentation | DDoS | `DDoS-UDP_Fragmentation.pcap` | 22.394 |
| DNS_Spoofing | Spoofing | `DNS_Spoofing.pcap` | 10.586 |
| DictionaryBruteForce | BruteForce | `DictionaryBruteForce.pcap` | 1.042 |
| DoS-HTTP_Flood | DoS | `DoS-HTTP_Flood1.pcap` | 30.881 |
| DoS-SYN_Flood | DoS | `DoS-SYN_Flood.pcap` e `DoS-SYN_Flood1.pcap` | 526.530 |
| DoS-TCP_Flood | DoS | `DoS-TCP_Flood.pcap` | 259.976 |
| DoS-UDP_Flood | DoS | `DoS-UDP_Flood.pcap` | 166.653 |
| MITM-ArpSpoofing | Spoofing | `MITM-ArpSpoofing.pcap` | 8.194 |
| Mirai-greeth_flood | Mirai | `Mirai-greeth_flood.pcap` | 33.008 |
| Mirai-greip_flood | Mirai | `Mirai-greip_flood21.pcap` | 11.955 |
| Mirai-udpplain | Mirai | `Mirai-udpplain.pcap` | 36.373 |
| Recon-HostDiscovery | Recon | `Recon-HostDiscovery.pcap` | 12.996 |
| Recon-OSScan | Recon | `Recon-OSScan.pcap` | 4.087 |
| Recon-PingSweep | Recon | `Recon-PingSweep.pcap` | 114 |
| Recon-PortScan | Recon | `Recon-PortScan.pcap` | 3.783 |
| SqlInjection | Web | `SqlInjection.pcap` | 325 |
| Uploading_Attack | Web | `Uploading_Attack.pcap` | 106 |
| VulnerabilityScan | Recon | `VulnerabilityScan.pcap` | 18.836 |
| XSS | Web | `XSS.pcap` | 313 |

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
| 100 | 3.476.234 | 841.298 | 567.732 | 40.966 | 273.566 | `BenignTraffic2.pcap`, `DDoS-SYN_Flood1.pcap` e `DoS-SYN_Flood1.pcap` | 15,6 |

O ponto de operação sai de uma parte de validação, nunca do teste. As últimas 15% da parte de treino de cada pcap, por tempo, são a validação, e um modelo treinado no resto (o treino reduzido, com a mesma semente e com o fundo da parte reduzida) classifica todas as janelas da validação, e não só as do teto: as dos pcaps benignos e as com o atacante dos pcaps de ataque. Os candidatos são a categoria mais provável (argmax) e os limiares t sobre 1 − P(Benign), de 0,01 em 0,01. Entre os que deixam no máximo 1% das janelas benignas como ataque, vence o de maior recall de ataque na validação. O melhor limiar é o que venceria entre os limiares; ele fica nas tabelas para comparação. O modelo salvo é o do treino inteiro, com a regra gravada ao lado.

| Janela | Treino reduzido | Janelas benignas na validação | Janelas de ataque na validação | Argmax: benigno como ataque e recall de ataque | Melhor limiar: benigno como ataque e recall de ataque | Regra escolhida | N |
|---|---|---|---|---|---|---|---|
| 100 | 517.271 | 9.866 | 321.428 | 0,79% e 99,55% | 0,61: 0,95% e 99,51% | argmax | 4 |

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

## Resultados com janela de 100

Na parte de teste, de 273.566 linhas: acurácia 96,15%, macro-F1 75,71%, F1 ponderado 96,21%, teto destas linhas 100,00%. Tráfego benigno classificado como ataque: 0,94%. Ataque classificado como benigno: 3,52%.

| Categoria | Linhas de teste | Precisão | Recall | F1 | Falso positivo da categoria |
|---|---|---|---|---|---|
| DDoS+DoS | 214.373 | 99,84% | 98,42% | 99,13% | 0,58% |
| Mirai | 24.458 | 99,98% | 99,22% | 99,60% | 0,00% |
| Recon | 10.982 | 85,24% | 54,92% | 66,80% | 0,40% |
| Spoofing | 7.007 | 99,89% | 80,11% | 88,91% | 0,00% |
| Web | 465 | 66,94% | 35,70% | 46,56% | 0,03% |
| BruteForce | 273 | 98,96% | 34,80% | 51,49% | 0,00% |
| Benign | 16.008 | 63,63% | 99,06% | 77,49% | 3,52% |

O falso positivo de uma categoria é a fração das janelas das outras categorias que o modelo pôs nela.
Na linha Benign, ele é o ataque classificado como benigno, isto é, o ataque perdido, e não o alarme
falso; o alarme falso é o tráfego benigno classificado como ataque, dado acima.

As medidas acima estão na mistura do teste, que o teto deforma: cada rótulo entra com no máximo 50.000 linhas. Reponderadas para a mistura das janelas regeradas, antes do teto, em que cada rótulo pesa as janelas que tem: acurácia 98,89%, macro-F1 76,17%, F1 ponderado 98,87%, ataque classificado como benigno 0,96%. O tráfego benigno classificado como ataque não muda, porque o benigno é um rótulo só.

| Categoria | Precisão | Precisão reponderada | Recall | Recall reponderado | F1 | F1 reponderado |
|---|---|---|---|---|---|---|
| DDoS+DoS | 99,84% | 99,96% | 98,42% | 99,61% | 99,13% | 99,78% |
| Mirai | 99,98% | 99,96% | 99,22% | 99,22% | 99,60% | 99,59% |
| Recon | 85,24% | 83,48% | 54,92% | 53,39% | 66,80% | 65,13% |
| Spoofing | 99,89% | 99,64% | 80,11% | 79,90% | 88,91% | 88,69% |
| Web | 66,94% | 61,84% | 35,70% | 33,40% | 46,56% | 43,37% |
| BruteForce | 98,96% | 98,36% | 34,80% | 34,80% | 51,49% | 51,41% |
| Benign | 63,63% | 74,73% | 99,06% | 99,06% | 77,49% | 85,19% |

Matriz de confusão, com a categoria real nas linhas e a prevista nas colunas:

| Real \ prevista | DDoS+DoS | Mirai | Recon | Spoofing | Web | BruteForce | Benign |
|---|---|---|---|---|---|---|---|
| DDoS+DoS | 210.992 | 5 | 793 | 4 | 17 | 0 | 2.562 |
| Mirai | 18 | 24.267 | 60 | 0 | 3 | 0 | 110 |
| Recon | 164 | 0 | 6.031 | 1 | 19 | 0 | 4.767 |
| Spoofing | 28 | 0 | 7 | 5.613 | 1 | 0 | 1.358 |
| Web | 37 | 0 | 56 | 1 | 166 | 0 | 205 |
| BruteForce | 39 | 0 | 72 | 0 | 5 | 95 | 62 |
| Benign | 56 | 0 | 56 | 0 | 37 | 1 | 15.858 |

### Argmax e limiar, janela de 100

A mesma parte de teste com as duas regras que concorreram na validação: o argmax e o melhor limiar, a janela ataque se 1 − P(Benign) ≥ 0,61, na categoria de ataque mais provável. O limiar só decide entre Benign e ataque: a janela que é ataque pelas duas regras fica na mesma categoria. Na validação, venceu o argmax, e ele é o ponto de operação do modelo; o teste não entra na escolha. A regra das 4 janelas seguidas vale para o alarme, e não para a janela; os alarmes estão em `ponto_de_operacao.md`.

| Medida | Argmax (ponto de operação) | Limiar, t = 0,61 |
|---|---|---|
| Macro-F1 | 75,71% | 74,01% |
| Acurácia | 96,15% | 95,75% |
| Benigno classificado como ataque | 0,94% | 1,04% |
| Ataque classificado como benigno | 3,52% | 3,91% |

| Categoria | Linhas de teste | Precisão, argmax | Precisão, limiar | Recall, argmax | Recall, limiar | F1, argmax | F1, limiar |
|---|---|---|---|---|---|---|---|
| DDoS+DoS | 214.373 | 99,84% | 99,83% | 98,42% | 98,42% | 99,13% | 99,12% |
| Mirai | 24.458 | 99,98% | 99,98% | 99,22% | 99,22% | 99,60% | 99,60% |
| Recon | 10.982 | 85,24% | 83,64% | 54,92% | 50,13% | 66,80% | 62,69% |
| Spoofing | 7.007 | 99,89% | 99,86% | 80,11% | 72,38% | 88,91% | 83,93% |
| Web | 465 | 66,94% | 61,43% | 35,70% | 36,99% | 46,56% | 46,17% |
| BruteForce | 273 | 98,96% | 95,00% | 34,80% | 34,80% | 51,49% | 50,94% |
| Benign | 16.008 | 63,63% | 61,16% | 99,06% | 98,96% | 77,49% | 75,59% |

Matriz de confusão com o limiar t = 0,61:

| Real \ prevista | DDoS+DoS | Mirai | Recon | Spoofing | Web | BruteForce | Benign |
|---|---|---|---|---|---|---|---|
| DDoS+DoS | 210.994 | 5 | 796 | 6 | 18 | 0 | 2.554 |
| Mirai | 31 | 24.268 | 73 | 0 | 10 | 0 | 76 |
| Recon | 169 | 0 | 5.505 | 0 | 23 | 0 | 5.285 |
| Spoofing | 32 | 0 | 8 | 5.072 | 2 | 0 | 1.893 |
| Web | 34 | 0 | 49 | 1 | 172 | 0 | 209 |
| BruteForce | 44 | 0 | 81 | 0 | 8 | 95 | 45 |
| Benign | 45 | 0 | 70 | 0 | 47 | 5 | 15.841 |

Por pcap, a fração das janelas de teste na categoria esperada, com o argmax e com o melhor limiar, e a categoria mais prevista pelo argmax:

| Arquivo | Rótulo | Categoria esperada | Janelas de teste | Na esperada, argmax | Na esperada, limiar | Mais prevista |
|---|---|---|---|---|---|---|
| `Backdoor_Malware.pcap` | Backdoor_Malware | Web | 76 | 52,63% | 53,95% | Web |
| `BenignTraffic.pcap` | BenignTraffic | Benign | 0 | sem teste | sem teste | nenhuma |
| `BenignTraffic1.pcap` | BenignTraffic | Benign | 0 | sem teste | sem teste | nenhuma |
| `BenignTraffic2.pcap` | BenignTraffic | Benign | 16.008 | 99,06% | 98,96% | Benign |
| `BrowserHijacking.pcap` | BrowserHijacking | Web | 81 | 13,58% | 14,81% | Benign |
| `CommandInjection.pcap` | CommandInjection | Web | 77 | 33,77% | 35,06% | Web |
| `DDoS-ACK_Fragmentation.pcap` | DDoS-ACK_Fragmentation | DDoS+DoS | 7.032 | 99,30% | 99,33% | DDoS+DoS |
| `DDoS-HTTP_Flood-.pcap` | DDoS-HTTP_Flood | DDoS+DoS | 8.618 | 99,81% | 99,81% | DDoS+DoS |
| `DDoS-ICMP_Flood.pcap` | DDoS-ICMP_Flood | DDoS+DoS | 14.916 | 99,93% | 99,93% | DDoS+DoS |
| `DDoS-ICMP_Fragmentation.pcap` | DDoS-ICMP_Fragmentation | DDoS+DoS | 6.169 | 99,50% | 99,51% | DDoS+DoS |
| `DDoS-PSHACK_Flood.pcap` | DDoS-PSHACK_Flood | DDoS+DoS | 15.025 | 100,00% | 100,00% | DDoS+DoS |
| `DDoS-RSTFINFlood.pcap` | DDoS-RSTFINFlood | DDoS+DoS | 15.082 | 100,00% | 100,00% | DDoS+DoS |
| `DDoS-SYN_Flood.pcap` | DDoS-SYN_Flood | DDoS+DoS | 0 | sem teste | sem teste | nenhuma |
| `DDoS-SYN_Flood1.pcap` | DDoS-SYN_Flood | DDoS+DoS | 24.992 | 99,97% | 99,97% | DDoS+DoS |
| `DDoS-SlowLoris.pcap` | DDoS-SlowLoris | DDoS+DoS | 6.515 | 71,57% | 71,37% | DDoS+DoS |
| `DDoS-SynonymousIP_Flood.pcap` | DDoS-SynonymousIP_Flood | DDoS+DoS | 14.895 | 100,00% | 100,00% | DDoS+DoS |
| `DDoS-TCP_Flood.pcap` | DDoS-TCP_Flood | DDoS+DoS | 14.990 | 99,72% | 99,72% | DDoS+DoS |
| `DDoS-UDP_Flood.pcap` | DDoS-UDP_Flood | DDoS+DoS | 14.861 | 100,00% | 100,00% | DDoS+DoS |
| `DDoS-UDP_Fragmentation.pcap` | DDoS-UDP_Fragmentation | DDoS+DoS | 6.708 | 96,68% | 96,69% | DDoS+DoS |
| `DNS_Spoofing.pcap` | DNS_Spoofing | Spoofing | 3.143 | 79,13% | 70,66% | Spoofing |
| `DictionaryBruteForce.pcap` | DictionaryBruteForce | BruteForce | 273 | 34,80% | 34,80% | BruteForce |
| `DoS-HTTP_Flood1.pcap` | DoS-HTTP_Flood | DDoS+DoS | 9.137 | 87,82% | 87,94% | DDoS+DoS |
| `DoS-SYN_Flood.pcap` | DoS-SYN_Flood | DDoS+DoS | 0 | sem teste | sem teste | nenhuma |
| `DoS-SYN_Flood1.pcap` | DoS-SYN_Flood | DDoS+DoS | 25.325 | 99,94% | 99,94% | DDoS+DoS |
| `DoS-TCP_Flood.pcap` | DoS-TCP_Flood | DDoS+DoS | 15.120 | 99,98% | 99,97% | DDoS+DoS |
| `DoS-UDP_Flood.pcap` | DoS-UDP_Flood | DDoS+DoS | 14.988 | 99,88% | 99,88% | DDoS+DoS |
| `MITM-ArpSpoofing.pcap` | MITM-ArpSpoofing | Spoofing | 3.864 | 80,90% | 73,78% | Spoofing |
| `Mirai-greeth_flood.pcap` | Mirai-greeth_flood | Mirai | 9.957 | 99,94% | 99,94% | Mirai |
| `Mirai-greip_flood21.pcap` | Mirai-greip_flood | Mirai | 3.586 | 100,00% | 100,00% | Mirai |
| `Mirai-udpplain.pcap` | Mirai-udpplain | Mirai | 10.915 | 98,31% | 98,31% | Mirai |
| `Recon-HostDiscovery.pcap` | Recon-HostDiscovery | Recon | 3.842 | 90,47% | 89,93% | Recon |
| `Recon-OSScan.pcap` | Recon-OSScan | Recon | 1.397 | 58,05% | 55,40% | Recon |
| `Recon-PingSweep.pcap` | Recon-PingSweep | Recon | 18 | 0,00% | 0,00% | Benign |
| `Recon-PortScan.pcap` | Recon-PortScan | Recon | 850 | 78,00% | 77,88% | Recon |
| `SqlInjection.pcap` | SqlInjection | Web | 102 | 1,96% | 1,96% | Benign |
| `Uploading_Attack.pcap` | Uploading_Attack | Web | 31 | 74,19% | 74,19% | Web |
| `VulnerabilityScan.pcap` | VulnerabilityScan | Recon | 4.875 | 22,17% | 12,59% | Benign |
| `XSS.pcap` | XSS | Web | 98 | 65,31% | 68,37% | Web |

As 10 features mais importantes (redução média de impureza): `Time_To_Live` (12,9%), `Max` (9,7%), `Tot sum` (8,5%), `HTTPS` (6,7%), `Tot size` (6,5%), `AVG` (5,9%), `Std` (4,7%), `Rate` (4,6%), `Variance` (4,3%) e `IAT` (3,9%).

### Nos arquivos inteiros de teste, com janela de 100

`BenignTraffic2.pcap`, `DDoS-SYN_Flood1.pcap` e `DoS-SYN_Flood1.pcap`, pcaps de que o modelo não viu nenhuma janela, com as janelas que o teto sorteou de cada um. 66.325 linhas, acurácia 99,74%, macro-F1 99,72% entre as categorias presentes, tráfego benigno classificado como ataque 0,94%. A precisão e o falso positivo de cada categoria valem só dentro desses arquivos. A medida depende de qual pcap fica de fora: a rotação do
pcap benigno de fora está em `rodadas_normalizadas.md` e `ponto_de_operacao.md`.

| Categoria | Linhas de teste | Precisão | Recall | F1 |
|---|---|---|---|---|
| DDoS+DoS | 50.317 | 99,89% | 99,95% | 99,92% |
| Benign | 16.008 | 99,98% | 99,06% | 99,52% |

## IPs de origem por janela em DDoS e DoS

O modelo não separa DDoS de DoS: as features descrevem os pacotes, não quantas máquinas atacam. A separação
sai da quantidade de IPs de origem distintos das janelas do incidente, fora do modelo. A tabela resume essa
quantidade nas janelas regeradas de cada classe de DDoS e DoS presente, antes do teto.

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

Com janela de 100, a mediana de IPs de origem por janela vai de 1,0 a 10,0 nas classes de DDoS e de 1,0 a 4,0 nas de DoS: as faixas se cruzam, e a contagem de uma janela isolada não separa as duas categorias.

A contagem inclui os IPs de origem de todos os quadros IPv4 da janela, também os da vítima e os do tráfego
de fundo, e não só os das máquinas que atacam.

## Ressalvas

- **Uma a três capturas por rótulo.** Todos os 34 rótulos têm pcap, mas a variedade dentro de cada um
  é a de poucas capturas da mesma rede. O que o modelo aprendeu de uma variante pode não valer para
  outra captura dela.
- **Uma semente neste relatório.** Divisão por tempo não sorteia, mas o teto por rótulo e o modelo usam a semente 42. A variação entre sementes está em `rodadas_normalizadas.md` e `ponto_de_operacao.md`.
- **O teste vem das mesmas capturas.** As janelas de teste são o fim de cada pcap, da mesma rede e do
  mesmo dia das de treino. A medida vale para a captura, não para outra rede. Os rótulos com mais de
  um pcap têm um arquivo inteiro no teste, que sai à parte e depende de qual arquivo fica de fora; nos
  demais, as janelas na fronteira do corte são vizinhas das de treino. A rotação do arquivo de fora e o
  recall com o pcap inteiro fora do treino estão em `rodadas_normalizadas.md` e `ponto_de_operacao.md`.
- **O fundo entra no treino como benigno.** Parte dele pode conter efeito do ataque, e o modelo aprende a
  chamar de benigno o que se parece com ele; o recall de Recon e o de Spoofing caem por isso. O fundo da
  parte de teste não entra no teste deste relatório: o que o modelo faz com ele está em `rodadas_normalizadas.md` e em
  `ponto_de_operacao.md`.
- **O atacante também gera tráfego benigno.** O MAC `dc:a6:32:dc:27:d5` aparece em cerca de 1% dos quadros dos pcaps benignos (`janelas_sem_atacante.md`), e 27,1% das janelas de 100 desses pcaps têm ao menos um quadro de um MAC da lista. A regra de rótulo não usa a lista nos pcaps benignos, então parte do tráfego comum desse dispositivo está no treino como benigno.
- **As seis colunas da janela deixaram de ser atalho.** Com uma janela só, `Number` vale o mesmo em todas
  as classes, a não ser na última janela de cada pcap, que pode ficar incompleta.

## Como os números foram obtidos

- Comando: `python -m codigo.classificador.treinar_regerado`, a partir da raiz do repositório, depois de `python -m codigo.classificador.regerar`. Ele refaz a leitura, o teto, a divisão, o treino, a avaliação e este relatório.
- Dados: `dados/processed/regerado/janela_<W>/<rotulo>.csv.gz`, registrados em `manifesto_regeracao.json` (gerado em 11/10/2026, pcaps em `CICIoT2023`), com o SHA-256 de cada pcap, a versão 2 da regra e o extrator de SHA-256 `8bd38fb392d5bec5a318699b2cef4a67a7c0c43461ecd01ce20be5b7db0b4a65`.
- Modelos: um por janela, em `modelos/`, fora do git, com o ponto de operação num JSON ao lado: `rf_regerado_janela_100.joblib` (365,6 MB) e `rf_regerado_janela_100.ponto_de_operacao.json`. Treinados com 4 núcleos; a quantidade de núcleos muda o tempo, e não o modelo. Predição com um núcleo, em ordem fixa.
- Divisões: o SHA-256 das posições de treino e de teste de cada janela está em `manifesto_treino_regerado.json`.
- `regeracao_metricas.csv` tem uma linha por janela, regra e categoria; `regeracao_por_arquivo.csv`, uma por janela e pcap; `matrizes_confusao/regerado_janela_<W>.csv` é a matriz de confusão com o argmax, `_limiar.csv` a com o melhor limiar, `_ponto.csv` a da regra escolhida na validação, e `_por_rotulo.csv` abre a classe real nos 34 rótulos.
- Tempo total, na máquina em que rodou: 58,7 s. Pico de memória do processo: 1,7 GB, que é o necessário para reproduzir.
- Com os mesmos CSVs regerados e a mesma semente, os números saem iguais. Só mudam a data e os tempos.

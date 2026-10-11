# Rodadas de teste do modelo de janela de 100

Gerado por `python -m codigo.classificador.rodadas` em 11/10/2026, com Python 3.11.2, scikit-learn 1.9.1, pandas 3.0.6 e numpy 2.4.6.

O modelo do sistema é o Random Forest de 7 categorias treinado nos dados regerados com janela de 100
quadros (`regeracao.md`). O relatório da regeração mede uma divisão por tempo, com uma semente e só nas
janelas que têm um quadro do atacante. As rodadas abaixo refazem o treino com as mesmas funções (leitura
com teto, divisão por tempo, treino e avaliação) e medem o que aquela divisão não mostra. Cada rodada diz
o que foi feito, traz os números e diz o que eles mostram, sem recomendar uma saída.

Rodadas feitas: a, b, c, d, e, f, g, h e i. Em cada treino, a semente define ao mesmo tempo o sorteio do teto de 50.000 linhas por rótulo e o Random Forest. A rodada b usa as sementes 42, 1, 2, 3 e 4; as que treinam um modelo por rotação ou por pcap usam as 3 primeiras. Nas tabelas, um valor com parênteses é a média das sementes, com o menor e o maior entre parênteses.

Uma diferença entre duas condições só é tratada como diferença quando as faixas das sementes não se
cruzam; dentro delas, é "sem diferença".

## Resumo

- a. O modelo salvo reproduz as medidas publicadas (0 diferenças em 39), e o retreino com a semente 42 dá 0 predições diferentes das dele.
- b. Entre 5 sementes, macro-F1 82,21% (82,09% a 82,29%) e benigno classificado como ataque 1,71% (1,60% a 1,86%).
- c. Benigno classificado como ataque com cada pcap benigno fora do treino: `BenignTraffic2.pcap` 1,73% (1,65% a 1,87%); `BenignTraffic.pcap` 38,51% (38,21% a 38,84%); `BenignTraffic1.pcap` 1,48% (1,39% a 1,56%). No total dos três, 15,42% (15,36% a 15,53%).
- d. Janelas de fundo dos pcaps de ataque, sem nenhum quadro do atacante, classificadas como ataque: 72,28% (72,20% a 72,38%) na parte de teste.
- e. Recall com o pcap inteiro fora do treino, contra dentro da captura: Recon 31,53% (31,42% a 31,68%) contra 87,70% (87,65% a 87,77%); Web 31,25% (30,54% a 32,47%) contra 37,06% (36,99% a 37,20%); BruteForce 0,00% (0,00% a 0,00%) contra 34,80% (34,43% a 35,16%); Spoofing 96,95% (96,46% a 97,25%) contra 99,42% (99,41% a 99,44%).
- f. Janelas com quadro menor que 60 bytes: DDoS+DoS 0,0%, Mirai 1,4%, Recon 0,0%, Spoofing 84,2%, Web 0,0%, BruteForce 0,0%, Benign 0,0%; com quadro maior que 1.514 bytes: DDoS+DoS 1,4%, Mirai 0,6%, Recon 27,9%, Spoofing 0,0%, Web 38,7%, BruteForce 32,9%, Benign 87,8%.
- g. Pontos candidatos do limiar: t = 0,60 com 2,00% de benigno como ataque e 98,94% de recall de ataque; t = 0,75 com 0,75% de benigno como ataque e 98,19% de recall de ataque; t = 0,80 com 0,46% de benigno como ataque e 97,64% de recall de ataque.
- h. Recall com o intervalo por blocos: Web 37,0% (31,1% a 43,1%); BruteForce 35,2% (19,2% a 52,0%); Recon 87,7% (86,6% a 88,7%); Spoofing 99,4% (99,0% a 99,7%).
- i. Uma janela leva 1,63 ms para ser classificada sozinha e 0,015 ms num lote de 1.000; o modelo tem 184,5 MB.

## a. Reprodução do modelo publicado

**O que foi feito.** O modelo salvo `rf_regerado_janela_100.joblib` (SHA-256 `b67e9013e67acbc6…`, semente 42, 100 árvores) classificou a parte de teste refeita com a leitura, o teto e a divisão do repositório, e as medidas foram comparadas com as de `manifesto_treino_regerado.json`. O modelo foi treinado de novo com a semente 42 e as predições dos dois foram comparadas janela a janela.

| Conferência | Resultado |
|---|---|
| Linhas de treino e de teste | 567.732 e 273.566 (iguais às publicadas) |
| SHA-256 das posições de treino e de teste | iguais aos de `manifesto_treino_regerado.json` |
| `treino_sha256` gravado no modelo | igual |
| Medidas do modelo salvo no teste refeito | 39 conferidas, 0 diferentes das publicadas |
| Matriz de confusão por rótulo | idêntica à publicada |
| Predições do retreino com a semente 42 contra as do modelo salvo | 0 diferentes em 273.566 janelas |

## b. Sementes

**O que foi feito.** O treino da divisão por tempo com as sementes 42, 1, 2, 3 e 4. A divisão por tempo não sorteia; a semente muda quais linhas dos rótulos acima do teto entram e o Random Forest. Desvio amostral (n − 1).

| Medida | Semente 42 | Média | Desvio | Menor a maior |
|---|---|---|---|---|
| Macro-F1 | 82,27% | 82,21% | 0,08 p.p. | 82,09% a 82,29% |
| Acurácia | 98,26% | 98,26% | 0,01 p.p. | 98,25% a 98,27% |
| Benigno classificado como ataque | 1,86% | 1,71% | 0,12 p.p. | 1,60% a 1,86% |
| Ataque classificado como benigno | 1,03% | 1,04% | 0,01 p.p. | 1,03% a 1,05% |
| Recall DDoS+DoS | 98,88% | 98,87% | 0,02 p.p. | 98,85% a 98,89% |
| Recall Mirai | 99,25% | 99,24% | 0,01 p.p. | 99,24% a 99,25% |
| Recall Recon | 87,65% | 87,64% | 0,13 p.p. | 87,42% a 87,77% |
| Recall Spoofing | 99,41% | 99,41% | 0,03 p.p. | 99,37% a 99,44% |
| Recall Web | 36,99% | 37,12% | 0,12 p.p. | 36,99% a 37,20% |
| Recall BruteForce | 35,16% | 34,95% | 0,33 p.p. | 34,43% a 35,16% |
| Recall Benign | 98,14% | 98,29% | 0,12 p.p. | 98,14% a 98,40% |
| F1 DDoS+DoS | 99,32% | 99,31% | 0,01 p.p. | 99,31% a 99,32% |
| F1 Mirai | 99,61% | 99,60% | 0,01 p.p. | 99,60% a 99,61% |
| F1 Recon | 87,27% | 87,36% | 0,19 p.p. | 87,12% a 87,59% |
| F1 Spoofing | 99,44% | 99,44% | 0,01 p.p. | 99,42% a 99,45% |
| F1 Web | 47,06% | 46,75% | 0,47 p.p. | 46,13% a 47,20% |
| F1 BruteForce | 51,75% | 51,59% | 0,32 p.p. | 51,09% a 51,89% |
| F1 Benign | 91,42% | 91,44% | 0,06 p.p. | 91,40% a 91,54% |

**O que os números mostram.** O macro-F1 varia 0,20 p.p. entre as sementes e o benigno classificado como ataque, 0,26 p.p. As categorias com poucas janelas de teste variam mais. É essa a faixa que as outras rodadas usam como ruído.

## c. Rotação do pcap de fora do treino

**O que foi feito.** Nos rótulos com mais de um pcap (o benigno e os dois SYN), um pcap fica inteiro fora do treino. A divisão publicada deixa de fora o último pela ordem do nome; aqui o pcap de fora anda uma posição a cada rotação, até cada pcap benigno ficar de fora uma vez. Os rótulos de um pcap só mantêm o corte por tempo. A medida é no pcap de fora inteiro, com todas as janelas dele, e não só nas que o teto sorteou.

| Rotação | Pcap benigno de fora | Janelas | Benigno como ataque | Como DDoS+DoS | Como Recon | Como Spoofing | Como Web | Outros pcaps de fora: na categoria | Macro-F1 no teste com teto |
|---|---|---|---|---|---|---|---|---|---|
| 0 (publicada) | `BenignTraffic2.pcap` | 31.032 | 1,73% (1,65% a 1,87%) | 0,77% (0,72% a 0,86%) | 0,61% (0,59% a 0,65%) | 0,03% (0,03% a 0,04%) | 0,31% (0,30% a 0,32%) | `DDoS-SYN_Flood1.pcap` 99,97% (99,97% a 99,97%); `DoS-SYN_Flood1.pcap` 99,92% (99,92% a 99,92%) | 82,20% (82,09% a 82,27%) |
| 1 | `BenignTraffic.pcap` | 36.228 | 38,51% (38,21% a 38,84%) | 5,49% (5,28% a 5,63%) | 32,40% (32,21% a 32,65%) | 0,55% (0,53% a 0,57%) | 0,05% (0,05% a 0,06%) | `DDoS-SYN_Flood.pcap` 99,98% (99,98% a 99,98%); `DoS-SYN_Flood.pcap` 99,84% (99,82% a 99,86%) | 77,49% (77,26% a 77,63%) |
| 2 | `BenignTraffic1.pcap` | 29.549 | 1,48% (1,39% a 1,56%) | 0,63% (0,59% a 0,68%) | 0,57% (0,56% a 0,60%) | 0,06% (0,06% a 0,07%) | 0,21% (0,18% a 0,24%) | `DDoS-SYN_Flood1.pcap` 99,97% (99,97% a 99,97%); `DoS-SYN_Flood1.pcap` 99,92% (99,92% a 99,92%) | 82,13% (82,04% a 82,29%) |

Somando as janelas dos 3 pcaps benignos, cada um com o modelo que não o viu, 15,42% (15,36% a 15,53%) viram ataque. O pior pcap benigno de fora, por semente, fica em 38,51% (38,21% a 38,84%).

**O que os números mostram.** O alarme falso do pcap benigno de fora vai de 1,48% (`BenignTraffic1.pcap`) a 38,51% (`BenignTraffic.pcap`), conforme o pcap que fica fora do treino. O número publicado é o de uma das rotações.

## d. Tráfego de fundo dos pcaps de ataque

**O que foi feito.** As janelas que a regra de rótulo descarta, sem nenhum quadro de um MAC atacante, estão gravadas à parte desde a versão 2 da regeração (`descartadas/`). O modelo da divisão por tempo classificou todas elas. Cada janela fica na parte de treino ou na de teste do seu pcap pelo mesmo corte da divisão: o modelo nunca viu nenhuma delas, mas as da parte de treino são do mesmo trecho de captura das janelas com que ele treinou. Nos SYN, o pcap de fora é todo teste e o outro, todo treino.

| Pcap | Categoria | Fundo / janelas | Treino: janelas | Treino: como ataque | Treino: na categoria do pcap | Teste: janelas | Teste: como ataque | Teste: na categoria do pcap | Ataque mais previsto no teste |
|---|---|---|---|---|---|---|---|---|---|
| `VulnerabilityScan.pcap` | Recon | 18.496 / 37.332 | 12.171 | 66,9% (66,8% a 66,9%) | 65,6% (65,5% a 65,7%) | 6.325 | 80,8% (80,6% a 80,9%) | 79,6% (79,4% a 79,7%) | Recon |
| `MITM-ArpSpoofing.pcap` | Spoofing | 16.571 / 24.765 | 13.006 | 99,7% (99,6% a 99,8%) | 99,6% (99,5% a 99,7%) | 3.565 | 99,7% (99,6% a 99,8%) | 99,5% (99,3% a 99,6%) | Spoofing |
| `DNS_Spoofing.pcap` | Spoofing | 7.302 / 17.888 | 5.079 | 96,3% (94,7% a 97,7%) | 95,3% (93,7% a 96,7%) | 2.223 | 99,7% (99,6% a 99,7%) | 97,7% (97,6% a 97,8%) | Spoofing |
| `Recon-OSScan.pcap` | Recon | 5.738 / 9.825 | 4.188 | 31,5% (31,3% a 31,6%) | 27,9% (27,5% a 28,2%) | 1.550 | 51,7% (51,3% a 52,0%) | 47,0% (46,5% a 47,5%) | Recon |
| `Recon-PortScan.pcap` | Recon | 4.445 / 8.228 | 2.827 | 76,3% (75,9% a 76,8%) | 74,5% (74,1% a 74,7%) | 1.618 | 26,7% (26,5% a 26,9%) | 21,3% (21,1% a 21,5%) | Recon |
| `DDoS-SlowLoris.pcap` | DDoS+DoS | 1.681 / 23.391 | 1.179 | 17,5% (17,0% a 18,0%) | 11,0% (10,6% a 11,5%) | 502 | 4,4% (4,2% a 4,8%) | 3,4% (3,0% a 3,8%) | DDoS+DoS |
| `DDoS-ACK_Fragmentation.pcap` | DDoS+DoS | 527 / 24.984 | 64 | 10,9% (9,4% a 12,5%) | 6,8% (4,7% a 9,4%) | 463 | 6,6% (6,3% a 6,9%) | 4,6% (4,3% a 4,8%) | DDoS+DoS |
| `Mirai-greeth_flood.pcap` | Mirai | 493 / 33.501 | 400 | 87,7% (84,5% a 91,0%) | 82,9% (80,0% a 87,0%) | 93 | 75,3% (74,2% a 77,4%) | 69,9% (69,9% a 69,9%) | Mirai |
| `DDoS-TCP_Flood.pcap` | DDoS+DoS | 453 / 265.671 | 97 | 12,7% (12,4% a 13,4%) | 1,4% (1,0% a 2,1%) | 356 | 51,8% (50,0% a 53,4%) | 7,1% (6,7% a 7,3%) | Recon |
| `Recon-HostDiscovery.pcap` | Recon | 441 / 13.437 | 252 | 8,6% (8,3% a 8,7%) | 3,2% (3,2% a 3,2%) | 189 | 11,6% (10,1% a 12,7%) | 3,9% (2,6% a 5,3%) | DDoS+DoS |
| `DictionaryBruteForce.pcap` | BruteForce | 265 / 1.307 | 146 | 42,2% (40,4% a 43,2%) | 11,0% (10,3% a 11,6%) | 119 | 27,5% (26,1% a 29,4%) | 2,0% (1,7% a 2,5%) | Recon |
| `DDoS-SYN_Flood.pcap` | DDoS+DoS | 223 / 265.925 | 223 | 12,7% (11,2% a 13,5%) | 3,0% (2,2% a 3,6%) | 0 | - | - | nenhum |
| `DoS-HTTP_Flood1.pcap` | DDoS+DoS | 218 / 31.099 | 25 | 62,7% (60,0% a 64,0%) | 14,7% (12,0% a 16,0%) | 193 | 49,6% (49,2% a 49,7%) | 26,3% (25,4% a 26,9%) | DDoS+DoS |
| `DDoS-UDP_Flood.pcap` | DDoS+DoS | 206 / 266.503 | 206 | 65,7% (64,6% a 67,5%) | 21,4% (20,4% a 22,8%) | 0 | - | - | nenhum |
| `SqlInjection.pcap` | Web | 200 / 525 | 145 | 73,3% (71,0% a 75,2%) | 0,0% (0,0% a 0,0%) | 55 | 63,0% (61,8% a 63,6%) | 0,0% (0,0% a 0,0%) | Recon |
| `DDoS-HTTP_Flood-.pcap` | DDoS+DoS | 186 / 28.756 | 177 | 45,0% (42,9% a 47,5%) | 32,8% (29,9% a 35,0%) | 9 | 29,6% (22,2% a 44,4%) | 14,8% (11,1% a 22,2%) | DDoS+DoS |
| `CommandInjection.pcap` | Web | 164 / 541 | 79 | 52,7% (51,9% a 53,2%) | 34,6% (32,9% a 35,4%) | 85 | 98,4% (97,6% a 98,8%) | 1,2% (1,2% a 1,2%) | DDoS+DoS |
| `BrowserHijacking.pcap` | Web | 127 / 586 | 32 | 39,6% (34,4% a 50,0%) | 2,1% (0,0% a 3,1%) | 95 | 21,8% (20,0% a 23,2%) | 0,4% (0,0% a 1,1%) | DDoS+DoS |
| `DDoS-ICMP_Fragmentation.pcap` | DDoS+DoS | 118 / 20.597 | 108 | 23,1% (22,2% a 24,1%) | 17,9% (17,6% a 18,5%) | 10 | 63,3% (60,0% a 70,0%) | 30,0% (20,0% a 40,0%) | Recon |
| `Recon-PingSweep.pcap` | Recon | 113 / 227 | 63 | 45,5% (44,4% a 46,0%) | 42,3% (41,3% a 44,4%) | 50 | 22,0% (20,0% a 24,0%) | 16,0% (14,0% a 18,0%) | Recon |
| `DDoS-PSHACK_Flood.pcap` | DDoS+DoS | 94 / 267.712 | 81 | 22,6% (21,0% a 25,9%) | 14,4% (12,3% a 16,0%) | 13 | 41,0% (38,5% a 46,2%) | 30,8% (23,1% a 38,5%) | DDoS+DoS |
| `DDoS-RSTFINFlood.pcap` | DDoS+DoS | 90 / 266.832 | 84 | 8,3% (8,3% a 8,3%) | 4,4% (3,6% a 4,8%) | 6 | 0,0% (0,0% a 0,0%) | 0,0% (0,0% a 0,0%) | nenhum |
| `DoS-UDP_Flood.pcap` | DDoS+DoS | 85 / 166.738 | 74 | 53,2% (51,4% a 55,4%) | 30,6% (28,4% a 32,4%) | 11 | 48,5% (45,5% a 54,5%) | 27,3% (27,3% a 27,3%) | DDoS+DoS |
| `DoS-SYN_Flood1.pcap` | DDoS+DoS | 72 / 264.026 | 0 | - | - | 72 | 61,1% (58,3% a 63,9%) | 42,6% (41,7% a 43,1%) | DDoS+DoS |
| `XSS.pcap` | Web | 72 / 385 | 55 | 75,2% (74,5% a 76,4%) | 40,6% (38,2% a 43,6%) | 17 | 56,9% (52,9% a 58,8%) | 31,4% (29,4% a 35,3%) | Web |
| `Backdoor_Malware.pcap` | Web | 69 / 322 | 48 | 69,4% (66,7% a 70,8%) | 12,5% (10,4% a 14,6%) | 21 | 55,6% (52,4% a 57,1%) | 38,1% (38,1% a 38,1%) | Web |
| `DDoS-SYN_Flood1.pcap` | DDoS+DoS | 68 / 267.097 | 0 | - | - | 68 | 23,0% (22,1% a 23,5%) | 10,8% (10,3% a 11,8%) | DDoS+DoS |
| `DoS-TCP_Flood.pcap` | DDoS+DoS | 52 / 260.028 | 41 | 80,5% (80,5% a 80,5%) | 47,2% (46,3% a 48,8%) | 11 | 21,2% (18,2% a 27,3%) | 15,2% (9,1% a 18,2%) | DDoS+DoS |
| `DDoS-ICMP_Flood.pcap` | DDoS+DoS | 46 / 267.909 | 41 | 19,5% (17,1% a 24,4%) | 5,7% (4,9% a 7,3%) | 5 | 80,0% (80,0% a 80,0%) | 73,3% (60,0% a 80,0%) | DDoS+DoS |
| `DDoS-UDP_Fragmentation.pcap` | DDoS+DoS | 45 / 22.439 | 21 | 41,3% (38,1% a 42,9%) | 36,5% (33,3% a 38,1%) | 24 | 29,2% (29,2% a 29,2%) | 25,0% (20,8% a 29,2%) | DDoS+DoS |
| `DDoS-SynonymousIP_Flood.pcap` | DDoS+DoS | 26 / 268.525 | 17 | 11,8% (11,8% a 11,8%) | 11,8% (11,8% a 11,8%) | 9 | 14,8% (11,1% a 22,2%) | 0,0% (0,0% a 0,0%) | Recon |
| `Uploading_Attack.pcap` | Web | 20 / 126 | 13 | 76,9% (69,2% a 84,6%) | 35,9% (30,8% a 46,2%) | 7 | 61,9% (57,1% a 71,4%) | 14,3% (14,3% a 14,3%) | Spoofing |
| `Mirai-udpplain.pcap` | Mirai | 16 / 36.389 | 14 | 40,5% (35,7% a 50,0%) | 0,0% (0,0% a 0,0%) | 2 | 100,0% (100,0% a 100,0%) | 0,0% (0,0% a 0,0%) | DDoS+DoS |
| `DoS-SYN_Flood.pcap` | DDoS+DoS | 10 / 262.586 | 10 | 40,0% (30,0% a 50,0%) | 30,0% (20,0% a 40,0%) | 0 | - | - | nenhum |

Juntando os pcaps, na parte de teste 72,28% (72,20% a 72,38%) das janelas de fundo viram ataque, e na de treino, 75,22% (75,01% a 75,39%). No pcap benigno de fora da divisão publicada, 1,73% (1,65% a 1,87%).

Com o limiar da rodada g, na parte de teste e na semente principal: argmax: 72,38%; t = 0,55: 73,84%; t = 0,65: 67,83%; t = 0,75: 60,51%.

Quantos quadros do atacante há na janela, na parte de teste e na semente principal: a fração na categoria do pcap, com as janelas entre parênteses. A coluna 0 é o fundo.

| Categoria | 0 (fundo) | 1 | 2 a 5 | 6 a 20 | 21 a 50 | 51 a 100 |
|---|---|---|---|---|---|---|
| DDoS+DoS | 10% (1.752) | 15% (254) | 15% (844) | 43% (833) | 63% (1.544) | 100% (210.898) |
| Mirai | 68% (95) | 0% (3) | 10% (41) | 15% (149) | 12% (16) | 100% (24.249) |
| Recon | 63% (9.732) | 62% (541) | 86% (6.057) | 91% (1.731) | 97% (274) | 95% (2.379) |
| Spoofing | 99% (5.788) | 99% (966) | 99% (2.595) | 100% (1.446) | 100% (1.851) | 97% (149) |
| Web | 6% (280) | 14% (35) | 11% (123) | 53% (256) | 46% (39) | 8% (12) |
| BruteForce | 2% (119) | 0% (2) | 0% (82) | 56% (45) | 90% (58) | 22% (86) |

Entre os pcaps com ao menos 100 janelas de fundo na parte de teste, as maiores frações na categoria do próprio pcap são as de `MITM-ArpSpoofing.pcap` (99,5% de 3.565), `DNS_Spoofing.pcap` (97,7% de 2.223), `VulnerabilityScan.pcap` (79,6% de 6.325) e `Recon-OSScan.pcap` (47,0% de 1.550).

**O que os números mostram.** A coluna "na categoria do pcap" é a fração do fundo que o modelo põe na categoria do ataque daquela captura, sem nenhum quadro do atacante na janela. Onde ela fica perto do recall das janelas com atacante, a categoria acompanha a captura, e não o ataque. Parte do fundo pode conter efeito do ataque, então a fração de fundo classificada como ataque é uma estimativa pessimista do alarme falso durante um ataque.

## e. Pcap inteiro fora do treino

**O que foi feito.** Para cada pcap da lista, o modelo foi treinado sem nenhuma janela dele, com o resto igual à divisão publicada, e classificou as janelas dele. "Dentro da captura" é o modelo da divisão publicada, que treinou com o começo do mesmo pcap, nas mesmas janelas de teste. Cada pcap de Recon e de Web é uma técnica diferente, então tirar o pcap tira também a técnica do treino; o pcap de BruteForce é o único da categoria, e sem ele a categoria some do treino.

| Pcap | Categoria | Janelas de teste | Na categoria, dentro da captura | Na categoria, pcap fora | Como ataque, dentro | Como ataque, pcap fora | Pcap inteiro fora: na categoria |
|---|---|---|---|---|---|---|---|
| `Recon-HostDiscovery.pcap` | Recon | 3.842 | 93,08% (92,92% a 93,21%) | 38,38% (38,03% a 39,02%) | 94,12% (94,04% a 94,22%) | 77,36% (75,85% a 78,79%) | 58,52% (58,32% a 58,83%) |
| `Recon-OSScan.pcap` | Recon | 1.397 | 76,88% (76,38% a 77,24%) | 73,01% (72,66% a 73,23%) | 85,54% (85,40% a 85,61%) | 84,82% (84,68% a 85,11%) | 74,72% (74,58% a 74,92%) |
| `Recon-PingSweep.pcap` | Recon | 18 | 53,70% (50,00% a 55,56%) | 51,85% (50,00% a 55,56%) | 53,70% (50,00% a 55,56%) | 51,85% (50,00% a 55,56%) | 55,26% (53,51% a 57,02%) |
| `Recon-PortScan.pcap` | Recon | 850 | 81,33% (81,06% a 81,53%) | 79,41% (79,06% a 80,00%) | 87,84% (87,41% a 88,24%) | 87,88% (87,76% a 88,00%) | 89,67% (89,53% a 89,88%) |
| `VulnerabilityScan.pcap` | Recon | 4.875 | 87,79% (87,61% a 87,98%) | 5,81% (5,48% a 6,01%) | 88,09% (87,90% a 88,27%) | 8,92% (8,64% a 9,39%) | 17,26% (17,17% a 17,38%) |
| `Backdoor_Malware.pcap` | Web | 76 | 55,26% (53,95% a 56,58%) | 48,68% (47,37% a 50,00%) | 82,89% (81,58% a 85,53%) | 81,58% (80,26% a 82,89%) | 49,14% (48,62% a 49,80%) |
| `BrowserHijacking.pcap` | Web | 81 | 13,99% (13,58% a 14,81%) | 2,47% (2,47% a 2,47%) | 40,33% (39,51% a 40,74%) | 30,45% (29,63% a 30,86%) | 5,88% (5,45% a 6,75%) |
| `CommandInjection.pcap` | Web | 77 | 35,06% (33,77% a 36,36%) | 26,41% (24,68% a 27,27%) | 94,37% (93,51% a 94,81%) | 90,04% (88,31% a 92,21%) | 49,51% (49,07% a 49,87%) |
| `SqlInjection.pcap` | Web | 102 | 1,63% (0,98% a 1,96%) | 0,00% (0,00% a 0,00%) | 90,85% (90,20% a 91,18%) | 92,16% (91,18% a 94,12%) | 0,00% (0,00% a 0,00%) |
| `Uploading_Attack.pcap` | Web | 31 | 79,57% (74,19% a 87,10%) | 76,34% (70,97% a 80,65%) | 92,47% (90,32% a 96,77%) | 91,40% (87,10% a 96,77%) | 75,79% (74,53% a 76,42%) |
| `XSS.pcap` | Web | 98 | 67,01% (66,33% a 68,37%) | 63,61% (60,20% a 67,35%) | 83,33% (81,63% a 84,69%) | 81,97% (79,59% a 84,69%) | 52,08% (51,44% a 52,40%) |
| `DNS_Spoofing.pcap` | Spoofing | 3.143 | 98,95% (98,92% a 98,98%) | 94,09% (93,13% a 94,62%) | 99,94% (99,90% a 99,97%) | 99,75% (99,62% a 99,84%) | 83,21% (83,02% a 83,42%) |
| `MITM-ArpSpoofing.pcap` | Spoofing | 3.864 | 99,81% (99,77% a 99,84%) | 99,28% (99,17% a 99,46%) | 99,95% (99,95% a 99,95%) | 99,60% (99,51% a 99,77%) | 98,70% (98,67% a 98,74%) |
| `Mirai-greeth_flood.pcap` | Mirai | 9.957 | 99,98% (99,97% a 99,98%) | 99,91% (99,89% a 99,92%) | 100,00% (99,99% a 100,00%) | 99,96% (99,96% a 99,96%) | 99,60% (99,59% a 99,62%) |
| `Mirai-greip_flood21.pcap` | Mirai | 3.586 | 100,00% (100,00% a 100,00%) | 100,00% (100,00% a 100,00%) | 100,00% (100,00% a 100,00%) | 100,00% (100,00% a 100,00%) | 99,97% (99,97% a 99,98%) |
| `Mirai-udpplain.pcap` | Mirai | 10.915 | 98,32% (98,31% a 98,34%) | 0,00% (0,00% a 0,00%) | 99,46% (99,44% a 99,47%) | 99,51% (99,47% a 99,55%) | 0,00% (0,00% a 0,00%) |
| `DictionaryBruteForce.pcap` | BruteForce | 273 | 34,80% (34,43% a 35,16%) | 0,00% (0,00% a 0,00%) | 89,13% (89,01% a 89,38%) | 76,43% (75,46% a 77,29%) | 0,00% (0,00% a 0,00%) |
| `DDoS-ICMP_Flood.pcap` | DDoS+DoS | 14.916 | 99,93% (99,89% a 99,96%) | 99,92% (99,89% a 99,95%) | 99,98% (99,97% a 99,99%) | 99,97% (99,95% a 99,98%) | 99,95% (99,95% a 99,95%) |
| `DDoS-SlowLoris.pcap` | DDoS+DoS | 6.515 | 83,39% (83,27% a 83,50%) | 57,78% (55,83% a 60,61%) | 86,66% (86,37% a 86,86%) | 77,62% (77,13% a 78,11%) | 67,36% (66,55% a 68,46%) |
| `DoS-HTTP_Flood1.pcap` | DDoS+DoS | 9.137 | 89,45% (89,33% a 89,55%) | 86,64% (86,51% a 86,76%) | 97,35% (97,24% a 97,52%) | 97,13% (97,02% a 97,29%) | 93,99% (93,81% a 94,15%) |
| `DoS-UDP_Flood.pcap` | DDoS+DoS | 14.988 | 99,88% (99,85% a 99,92%) | 56,81% (56,47% a 57,36%) | 99,98% (99,97% a 99,99%) | 99,94% (99,90% a 99,98%) | 63,29% (63,29% a 63,29%) |

Somando os pcaps de cada categoria, nas janelas de teste:

| Categoria | Pcaps | Recall dentro da captura | Recall com o pcap fora | Diferença |
|---|---|---|---|---|
| DDoS+DoS | 4 | 95,45% (95,41% a 95,47%) | 77,09% (76,91% a 77,38%) | -18,36 p.p., acima do ruído |
| Mirai | 3 | 99,24% (99,24% a 99,25%) | 55,34% (55,33% a 55,34%) | -43,91 p.p., acima do ruído |
| Recon | 5 | 87,70% (87,65% a 87,77%) | 31,53% (31,42% a 31,68%) | -56,17 p.p., acima do ruído |
| Spoofing | 2 | 99,42% (99,41% a 99,44%) | 96,95% (96,46% a 97,25%) | -2,47 p.p., acima do ruído |
| Web | 6 | 37,06% (36,99% a 37,20%) | 31,25% (30,54% a 32,47%) | -5,81 p.p., acima do ruído |
| BruteForce | 1 | 34,80% (34,43% a 35,16%) | 0,00% (0,00% a 0,00%) | -34,80 p.p., acima do ruído |

**O que os números mostram.** O recall dentro da captura mede o reconhecimento de um trecho seguinte da mesma captura; o recall com o pcap fora mede o reconhecimento de uma captura que o modelo não viu. A distância entre os dois, por categoria, está na última coluna. Fora BruteForce, as maiores quedas por pcap são em `Mirai-udpplain.pcap` (-98,32 p.p.), `VulnerabilityScan.pcap` (-81,98 p.p.), `Recon-HostDiscovery.pcap` (-54,69 p.p.) e `DoS-UDP_Flood.pcap` (-43,07 p.p.).

## f. Atalhos da captura

### Tamanho dos quadros

**O que foi feito.** Em todas as janelas mantidas, a fração com algum quadro menor que 60 bytes (`Min`), que é o quadro sem o preenchimento do Ethernet, e com algum quadro maior que 1.514 bytes (`Max`), que só existe quando a captura é feita na máquina que envia, com segmentação feita pela placa de rede. Os dois dependem de como a captura foi gravada, e não do ataque.

| Categoria | Janelas | Com quadro menor que 60 bytes | Com quadro maior que 1.514 bytes |
|---|---|---|---|
| DDoS+DoS | 3.236.618 | 0,00% | 1,43% |
| Mirai | 81.336 | 1,43% | 0,59% |
| Recon | 39.816 | 0,00% | 27,86% |
| Spoofing | 18.780 | 84,16% | 0,00% |
| Web | 1.833 | 0,00% | 38,68% |
| BruteForce | 1.042 | 0,00% | 32,92% |
| Benign | 96.809 | 0,00% | 87,84% |

Os pcaps com algum quadro menor que 60 bytes, e os benignos:

| Pcap | Categoria | Janelas | Com quadro menor que 60 bytes | Com quadro maior que 1.514 bytes |
|---|---|---|---|---|
| `BenignTraffic.pcap` | Benign | 36.228 | 0,00% | 79,72% |
| `BenignTraffic1.pcap` | Benign | 29.549 | 0,00% | 92,97% |
| `BenignTraffic2.pcap` | Benign | 31.032 | 0,00% | 92,44% |
| `DNS_Spoofing.pcap` | Spoofing | 10.586 | 84,72% | 0,00% |
| `MITM-ArpSpoofing.pcap` | Spoofing | 8.194 | 83,45% | 0,00% |
| `Mirai-greip_flood21.pcap` | Mirai | 11.955 | 9,71% | 0,00% |

### TTL

**Ablação.** O mesmo treino, nas mesmas sementes, sem a coluna `Time_To_Live`.

| Medida | 39 features | Sem `Time_To_Live` | Diferença |
|---|---|---|---|
| Macro-F1 | 82,20% (82,09% a 82,27%) | 81,91% (81,82% a 82,01%) | -0,29 p.p., acima do ruído |
| Benigno classificado como ataque | 1,72% (1,62% a 1,86%) | 1,86% (1,70% a 1,97%) | +0,15 p.p., sem diferença |
| Recall DDoS+DoS | 98,87% (98,85% a 98,88%) | 98,71% (98,66% a 98,78%) | -0,16 p.p., acima do ruído |
| Recall Mirai | 99,24% (99,24% a 99,25%) | 99,23% (99,22% a 99,24%) | -0,02 p.p., sem diferença |
| Recall Recon | 87,70% (87,65% a 87,77%) | 86,39% (86,22% a 86,55%) | -1,31 p.p., acima do ruído |
| Recall Spoofing | 99,42% (99,41% a 99,44%) | 99,43% (99,40% a 99,47%) | +0,01 p.p., sem diferença |
| Recall Web | 37,06% (36,99% a 37,20%) | 37,49% (36,56% a 38,49%) | +0,43 p.p., sem diferença |
| Recall BruteForce | 34,80% (34,43% a 35,16%) | 34,68% (34,43% a 34,80%) | -0,12 p.p., sem diferença |
| Pcap benigno de fora (`BenignTraffic2.pcap`) como ataque | 1,73% (1,65% a 1,87%) | 1,85% (1,79% a 1,89%) | +0,12 p.p., sem diferença |

**Janelas benignas de TTL baixo.** As janelas de `BenignTraffic2.pcap`, que o modelo da divisão publicada não viu, pelo TTL médio da janela, e as mesmas janelas com o TTL trocado por um valor fixo:

| TTL médio da janela | Janelas | Como ataque |
|---|---|---|
| até 64 | 183 | 9,3% (8,7% a 9,8%) |
| 64 a 70 | 180 | 11,1% (10,0% a 12,2%) |
| 70 a 75 | 312 | 6,2% (5,4% a 7,4%) |
| 75 a 90 | 2.217 | 4,0% (3,7% a 4,3%) |
| acima de 90 | 28.140 | 1,4% (1,3% a 1,5%) |

| TTL de todas as janelas trocado por | Como ataque |
|---|---|
| 64 | 36,9% (35,9% a 39,0%) |
| 70 | 19,1% (18,5% a 19,6%) |
| 80 | 1,6% (1,5% a 1,7%) |
| 100 | 1,8% (1,7% a 1,9%) |

### Importância por permutação

**O que foi feito.** No modelo da semente principal, cada feature das janelas de teste de uma categoria foi trocada pelo valor de uma janela de teste qualquer, 10 vezes, com até 3.000 janelas da categoria. A queda é a do recall, em pontos.

| Categoria | Recall de base (janelas) | Features que mais derrubam o recall (p.p.) |
|---|---|---|
| Web | 36,99% (465) | `IAT` 24,37; `Time_To_Live` 20,13; `Rate` 19,91; `ICMP` 8,30; `syn_flag_number` 3,35 |
| BruteForce | 35,16% (273) | `SSH` 33,99; `Time_To_Live` 2,60; `Rate` 2,27; `IAT` 1,83; `syn_flag_number` 1,10 |
| Recon | 87,67% (3.000) | `Time_To_Live` 7,57; `syn_flag_number` 4,24; `syn_count` 3,54; `Rate` 2,98; `IAT` 2,95 |
| Benign | 98,50% (3.000) | `Time_To_Live` 29,78; `HTTPS` 23,07; `HTTP` 6,37; `IAT` 4,18; `Rate` 3,86 |

No macro-F1, numa subamostra com até a mesma quantidade de janelas de cada categoria: `Min` 12,45; `SSH` 7,26; `Time_To_Live` 6,72; `HTTPS` 3,70; `IAT` 3,36; `Rate` 2,84 p.p. Pela redução de impureza, a medida que o relatório da regeração lista: `Time_To_Live` 10,6%; `Max` 10,1%; `Tot sum` 8,6%; `Tot size` 7,2%; `Min` 6,5%; `Std` 6,0%.

## g. Ponto de operação

### Limiar sobre a probabilidade de benigno

**O que foi feito.** Com as probabilidades do modelo da semente principal no teste, a regra: se 1 − P(Benign) ≥ t, a janela é ataque, na categoria de ataque mais provável; senão, é Benign. "Recall de ataque" é a fração das janelas de ataque postas em qualquer categoria de ataque. As duas últimas colunas aplicam a mesma regra ao fundo da parte de teste (rodada d) e ao pior pcap benigno de fora (rodada c).

| Limiar | Benigno como ataque | Recall de ataque | Ataque como benigno | Macro-F1 | Recall Recon | Recall Web | Recall BruteForce | Fundo de teste como ataque | `BenignTraffic.pcap` de fora como ataque |
|---|---|---|---|---|---|---|---|---|---|
| argmax (hoje) | 1,86% | 98,97% | 1,03% | 82,27% | 87,65% | 36,99% | 35,16% | 72,38% | 38,21% |
| 0,05 | 58,97% | 99,92% | 0,08% | 74,67% | 95,77% | 44,09% | 35,90% | 97,10% | 75,33% |
| 0,10 | 40,47% | 99,86% | 0,14% | 77,65% | 95,59% | 44,09% | 35,90% | 94,75% | 66,36% |
| 0,15 | 29,51% | 99,79% | 0,21% | 79,23% | 95,30% | 44,09% | 35,90% | 92,40% | 61,10% |
| 0,20 | 22,40% | 99,73% | 0,27% | 80,14% | 95,01% | 43,87% | 35,90% | 90,23% | 57,61% |
| 0,25 | 17,08% | 99,66% | 0,34% | 80,80% | 94,49% | 43,44% | 35,90% | 88,06% | 55,11% |
| 0,30 | 12,79% | 99,59% | 0,41% | 81,40% | 93,81% | 43,23% | 35,90% | 85,75% | 52,78% |
| 0,35 | 9,60% | 99,51% | 0,49% | 81,79% | 93,00% | 42,80% | 35,90% | 83,45% | 50,89% |
| 0,40 | 6,95% | 99,43% | 0,57% | 82,12% | 92,07% | 42,58% | 35,53% | 81,25% | 48,88% |
| 0,45 | 5,22% | 99,33% | 0,67% | 82,24% | 90,81% | 42,37% | 35,53% | 78,95% | 47,08% |
| 0,50 | 3,95% | 99,22% | 0,78% | 82,29% | 89,35% | 41,94% | 35,53% | 76,65% | 45,04% |
| 0,55 | 2,80% | 99,09% | 0,91% | 82,32% | 87,67% | 41,29% | 35,53% | 73,84% | 42,77% |
| 0,60 | 2,00% | 98,94% | 1,06% | 81,95% | 85,81% | 38,92% | 35,16% | 71,03% | 40,41% |
| 0,65 | 1,46% | 98,78% | 1,22% | 81,58% | 83,57% | 37,20% | 34,43% | 67,83% | 37,33% |
| 0,70 | 1,05% | 98,54% | 1,46% | 80,74% | 80,60% | 33,98% | 32,97% | 64,19% | 33,95% |
| 0,75 | 0,75% | 98,19% | 1,81% | 79,97% | 77,02% | 31,40% | 32,60% | 60,51% | 30,62% |
| 0,80 | 0,46% | 97,64% | 2,36% | 78,34% | 72,66% | 27,10% | 30,40% | 56,02% | 27,18% |
| 0,85 | 0,32% | 96,85% | 3,15% | 76,19% | 66,40% | 22,58% | 28,21% | 50,60% | 23,73% |
| 0,90 | 0,18% | 95,89% | 4,11% | 72,96% | 57,77% | 17,20% | 23,81% | 43,05% | 20,62% |
| 0,95 | 0,07% | 94,76% | 5,24% | 66,98% | 45,60% | 8,17% | 15,38% | 31,77% | 17,70% |

Pontos candidatos, o menor limiar que deixa o benigno classificado como ataque dentro de cada alvo:

- até 2,0%: t = 0,60, benigno como ataque 2,00%, recall de ataque 98,94%, macro-F1 81,95%, recall de Recon 85,81% e de Web 38,92%.
- até 1,0%: t = 0,75, benigno como ataque 0,75%, recall de ataque 98,19%, macro-F1 79,97%, recall de Recon 77,02% e de Web 31,40%.
- até 0,5%: t = 0,80, benigno como ataque 0,46%, recall de ataque 97,64%, macro-F1 78,34%, recall de Recon 72,66% e de Web 27,10%.

O argmax de hoje não é t = 0,5: ele dá Benign sempre que Benign é a classe mais provável, mesmo abaixo de 0,5. Os candidatos foram escolhidos no próprio teste, cujo benigno é um pcap só; a escolha final do limiar precisa sair de uma parte de validação, e não do teste.

### N janelas seguidas

**O que foi feito.** Um alarme dispara quando N janelas seguidas são classificadas como ataque; a sequência que continua não dispara outro. No pcap benigno de fora, a conta é sobre o pcap inteiro, e o tempo é a soma da duração das janelas. Em cada pcap de ataque, a sequência é o trecho de teste inteiro, com as janelas com e sem o atacante na ordem do arquivo, como o extrator as entregaria; o tempo até o alarme conta do começo do trecho. A semente é a principal, e a coluna da rotação usa o modelo daquela rotação.

| N | Alarmes em `BenignTraffic2.pcap` | Alarmes em `BenignTraffic.pcap` (rotação 1) | Alarmes em `BenignTraffic1.pcap` (rotação 2) | Pcaps de ataque com alarme no trecho de teste | Janelas até o alarme (mediana) | Segundos até o alarme (mediana) | Segundos até o alarme (maior) |
|---|---|---|---|---|---|---|---|
| 1 | 486 (61,1 por hora) | 5184 (565,8 por hora) | 360 (50,2 por hora) | 33 de 33 | 1 | 0,04 | 8,6 |
| 2 | 64 (8,0 por hora) | 1487 (162,3 por hora) | 67 (9,3 por hora) | 33 de 33 | 2 | 0,15 | 20,2 |
| 3 | 14 (1,8 por hora) | 787 (85,9 por hora) | 24 (3,3 por hora) | 33 de 33 | 3 | 0,21 | 30,8 |
| 5 | 4 (0,5 por hora) | 369 (40,3 por hora) | 3 (0,4 por hora) | 33 de 33 | 5 | 0,24 | 92,9 |

## h. Intervalos de confiança das classes raras

**O que foi feito.** No teste da semente principal: o intervalo de Wilson de 95%, que trata as janelas como independentes; o intervalo por blocos de 10 janelas vizinhas do mesmo pcap, com 5.000 reamostragens, porque janelas vizinhas erram juntas; a correlação do acerto entre uma janela e a seguinte; e o tamanho efetivo n(1 − r)/(1 + r).

| Categoria | Janelas de teste | Recall | Wilson | Por blocos | Autocorrelação | n efetivo | Precisão (previstas) | Wilson da precisão | Recall entre as sementes |
|---|---|---|---|---|---|---|---|---|---|
| Web | 465 | 37,0% | 32,7% a 41,5% | 31,1% a 43,1% | 0,42 | 190 | 64,7% (266) | 58,7% a 70,2% | 37,0% a 37,2% |
| BruteForce | 273 | 35,2% | 29,7% a 41,0% | 19,2% a 52,0% | 0,90 | 15 | 98,0% (98) | 92,9% a 99,4% | 34,4% a 35,2% |
| Recon | 10.982 | 87,7% | 87,0% a 88,3% | 86,6% a 88,7% | 0,32 | 5.693 | 86,9% (11.079) | 86,2% a 87,5% | 87,4% a 87,8% |
| Spoofing | 7.007 | 99,4% | 99,2% a 99,6% | 99,0% a 99,7% | 0,46 | 2.590 | 99,5% (7.004) | 99,3% a 99,6% | 99,4% a 99,4% |

Recall de Web por pcap, com o intervalo de Wilson: `Backdoor_Malware.pcap` 55,3% de 76 (44,1% a 65,9%); `BrowserHijacking.pcap` 13,6% de 81 (7,8% a 22,7%); `CommandInjection.pcap` 36,4% de 77 (26,5% a 47,5%); `SqlInjection.pcap` 1,0% de 102 (0,2% a 5,3%); `Uploading_Attack.pcap` 74,2% de 31 (56,8% a 86,3%); `XSS.pcap` 68,4% de 98 (58,6% a 76,7%).

**O que os números mostram.** Quando a autocorrelação é alta, o tamanho efetivo é uma fração das janelas de teste e o intervalo por blocos é bem mais largo que o de Wilson; é ele que vale para comparar duas configurações. A precisão de uma categoria com poucas previsões vem de poucas janelas.

## i. Custo

**O que foi feito.** O modelo salvo foi lido num processo novo, três vezes, para medir o tempo e a memória; a latência é de uma janela isolada, com um núcleo, em 500 janelas diferentes do teste, depois de uma de aquecimento. A vazão é a do extrator de janela de 100 com os endereços, lendo o pcap inteiro. Os tempos são desta máquina, dividida com outros processos, e mudam de uma execução para outra.

| Medida | Valor |
|---|---|
| Arquivo do modelo | 184,5 MB, 1.537.434 nós, profundidade média 44,9 e máxima 53 |
| Importar o scikit-learn e o joblib, num processo novo | 0,66 s |
| Ler o modelo | 0,07 s, com o arquivo no cache do sistema |
| Memória do processo | 160 MB antes de ler o modelo e 534 MB depois |
| Uma janela, `predict`, um núcleo | mediana 1,63 ms, p95 1,73 ms, p99 1,80 ms |
| Uma janela, `predict_proba` | mediana 1,63 ms, p95 1,77 ms, p99 1,89 ms |
| Lote de 1.000 janelas | 15,4 ms |
| Extrator de janela de 100 em `Recon-PortScan.pcap` | 831.856 pacotes em 5,0 s: 167.199 pacotes/s e 1.654 janelas/s |

Quanto tempo uma janela de 100 quadros leva para fechar (`Number` / `Rate`), em segundos, na amostra da semente principal:

| Categoria | Mediana | P90 | P99 |
|---|---|---|---|
| DDoS+DoS | 0,005 | 0,090 | 0,624 |
| Mirai | 0,019 | 0,045 | 0,129 |
| Recon | 1,257 | 2,882 | 4,547 |
| Spoofing | 0,531 | 3,005 | 4,358 |
| Web | 2,543 | 4,204 | 64,880 |
| BruteForce | 1,481 | 3,070 | 4,837 |
| Benign | 0,789 | 1,790 | 2,911 |

O Random Forest de 50 árvores, na mesma divisão e na mesma semente:

| Variante | Arquivo | Nós | Latência (mediana) | Lote de 1.000 | Macro-F1 | Benigno como ataque | Recall Recon | Recall Web | Recall BruteForce | Pcap benigno de fora nas rotações: como ataque |
|---|---|---|---|---|---|---|---|---|---|---|
| 100 árvores (o do sistema) | 184,5 MB | 1.537.434 | 1,63 ms | 15,4 ms | 82,27% | 1,86% | 87,65% | 36,99% | 35,16% | 38,21%; 1,56% |
| 50 árvores | 92,4 MB | 769.780 | 0,83 ms | 6,1 ms | 82,35% | 1,92% | 87,30% | 37,42% | 35,53% | 37,73%; 1,52% |

## Como os números foram obtidos

- Comando: `python -m codigo.classificador.rodadas --nucleos 4`, a partir da raiz do repositório, depois de `python -m codigo.classificador.regerar`.
- Dados: `dados/processed/regerado/janela_100/`, 72 arquivos (os CSVs de rótulo e as partes de `descartadas/`), com o SHA-256 de cada um em `manifesto_rodadas.json`. Manifesto da regeração `experimentos/resultados/manifesto_regeracao.json`, SHA-256 `750f7b95ac998784f8fea98139a189a319069bdbcfe791aec51579e7b88713bf`; extrator com SHA-256 `d3c32142f46c9202bcc439ca49bb45238425004ebacec384bbd51deb82bade7d` e opções nenhuma.
- Modelo salvo: `rf_regerado_janela_100.joblib`, SHA-256 `b67e9013e67acbc680c2d9312550b5e792f81665b4c755052ae84ecf23aa3986`.
- Treinos: `RandomForestClassifier` do scikit-learn com 100 árvores e os demais parâmetros padrão, 4 núcleos (o modelo não depende disso), teto de 50.000 linhas por rótulo e corte de 70% das janelas de cada pcap, as mesmas funções de `treinar_regerado`. Predição com um núcleo, em ordem fixa.
- Os números das tabelas são arredondados; os valores completos, com as contagens, estão no manifesto, e as
  tabelas em CSV começam com `rodadas_`.
- Tempo desta execução, na máquina em que rodou: 14,8 s. Os treinos já guardados em `dados/processed/rodadas/` são reaproveitados e não entram nessa conta; somados, os treinos de que os números saem levaram 890,8 s.
- Com as mesmas entradas e as mesmas sementes, os números saem iguais. Só mudam a data e os tempos.

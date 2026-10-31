# Ponto de operação: regra e alarme escolhidos na validação

Gerado por `python -m codigo.classificador.ponto_de_operacao` em 29/10/2026, com Python 3.11.2, scikit-learn 1.9.1, pandas 3.0.6 e numpy 2.4.6.

A decisão da equipe: a regra de decisão da janela é escolhida numa parte de validação, nunca no teste. Concorrem a categoria mais provável (argmax) e o limiar, em que a janela é ataque se 1 − P(Benign) ≥ t, na categoria de ataque mais provável, e senão é Benign. Um incidente só abre com 4 janelas de ataque seguidas, na ordem do pcap. Os pontos candidatos de `rodadas_de_teste.md` (rodada g) saíram do próprio teste e não são usados aqui.

**Validação.** Dentro da parte de treino de cada pcap (os primeiros 70% das janelas), as últimas 15% dessas janelas, por tempo, são a validação, e o resto é o treino reduzido. Nos rótulos com um pcap inteiro no teste, a validação são as últimas 15% de cada pcap de treino. O teste é o mesmo das rodadas. Na configuração com o fundo no treino, o fundo da validação também fica fora do treino reduzido.

**Regra.** O modelo treinado no treino reduzido, com a mesma amostra e a mesma semente, classifica todas as janelas da validação: as dos pcaps benignos e as com o atacante dos pcaps de ataque. Os candidatos são o argmax e os limiares de 0,01 a 1,00, de 0,01 em 0,01. Entre os que deixam no máximo 1% das janelas benignas da validação como ataque, vence o de maior recall de ataque na validação; no empate, o de menos benigno como ataque. O melhor limiar é o que venceria entre os limiares, e fica nas tabelas para comparação com o argmax. Nas rotações do pcap benigno de fora, cada rotação escolhe a sua regra na sua validação: a validação da rotação 0 tem janelas do pcap que a rotação 1 deixa de fora.

**Teste.** O modelo treinado no treino inteiro, o mesmo treino do corte por tempo das rodadas, com as três regras: o argmax, o melhor limiar e o ponto de operação, que é a regra que venceu na validação da sua semente e rotação. Pela regra de adoção aplicada em `rodadas_normalizadas.md`, a vencedora é a configuração 5 (as três condições são atendidas); a configuração 0 entra para comparação.

Cada configuração foi medida com as sementes 42, 1 e 2, que definem o teto e o Random Forest. Os valores são a média das sementes, com o menor e o maior entre parênteses. As diferenças são pareadas como em `rodadas_normalizadas.md`: mesma semente e mesmas janelas, com a variância por reamostragem de blocos de 10 janelas vizinhas somada à variância entre as sementes. A diferença só conta quando o intervalo de 95% não contém o zero; senão, é "sem diferença". Nas tabelas, † marca a diferença entre o melhor limiar e o argmax que conta, e * a diferença para a configuração 0, as duas no ponto de operação, que conta.

## Resumo

- Configuração 5: na validação da semente 42 venceu o argmax (rotação 0: argmax nas 3 sementes; melhor limiar 0,61; 0,59; 0,61), com N = 4. No ponto de operação, no corte por tempo, macro-F1 75,6% (75,4% a 75,7%) e benigno como ataque 0,85% (0,80% a 0,94%) por janela; no `BenignTraffic2.pcap` inteiro, 0,91% (0,89% a 0,93%) das janelas como ataque, e alarmes com 4 janelas seguidas, 1,3 (1 a 2) (0,2 (0,1 a 0,3) por hora); pior pcap benigno de fora (`BenignTraffic.pcap`), 6,0% (5,8% a 6,3%); fundo virando ataque, 13,3% (13,2% a 13,3%); pcaps de ataque com alarme no trecho de teste, 32 (31 a 32) de 33.
- Configuração 0: na validação da semente 42 venceu o limiar t = 0,68 (rotação 0: limiar 0,68; limiar 0,67; limiar 0,68; melhor limiar 0,68; 0,67; 0,68), com N = 4. No ponto de operação, no corte por tempo, macro-F1 81,3% (81,1% a 81,4%) e benigno como ataque 1,14% (1,04% a 1,21%) por janela; no `BenignTraffic2.pcap` inteiro, 1,14% (1,07% a 1,19%) das janelas como ataque, e alarmes com 4 janelas seguidas, 6,7 (5 a 8) (0,8 (0,6 a 1,0) por hora); pior pcap benigno de fora (`BenignTraffic.pcap`), 36,1% (36,0% a 36,1%); fundo virando ataque, 65,9% (65,7% a 66,2%); pcaps de ataque com alarme no trecho de teste, 33 de 33.

## A regra escolhida na validação

Em cada configuração, rotação e semente: as janelas da validação, o que o argmax e o melhor limiar fazem com elas (benigno classificado como ataque e recall de ataque, a fração das janelas com o atacante postas em alguma categoria de ataque) e a regra que venceu. Só concorre o candidato com no máximo 1% das benignas como ataque.

| Configuração | Rotação | Janelas benignas | Janelas de ataque | Argmax: benigno como ataque | Argmax: recall de ataque | Melhor limiar (por semente) | Limiar: benigno como ataque | Limiar: recall de ataque | Regra escolhida |
|---|---|---|---|---|---|---|---|---|---|
| 5 | 0 (`BenignTraffic2.pcap` de fora) | 9.866 | 321.428 | 0,77% (0,76% a 0,79%) | 99,55% (99,55% a 99,55%) | 0,61; 0,59; 0,61 | 0,97% (0,95% a 0,98%) | 99,51% (99,50% a 99,53%) | argmax nas 3 sementes |
| 5 | 1 (`BenignTraffic.pcap` de fora) | 9.087 | 321.841 | 0,45% (0,41% a 0,48%) | 99,56% (99,56% a 99,57%) | 0,53; 0,52; 0,53 | 0,94% (0,89% a 0,96%) | 99,62% (99,61% a 99,62%) | limiar 0,53; limiar 0,52; limiar 0,53 |
| 5 | 2 (`BenignTraffic1.pcap` de fora) | 10.089 | 321.428 | 0,75% (0,70% a 0,80%) | 99,55% (99,54% a 99,56%) | 0,59; 0,59; 0,60 | 0,97% (0,95% a 0,98%) | 99,52% (99,51% a 99,53%) | argmax nas 3 sementes |
| 0 | 0 (`BenignTraffic2.pcap` de fora) | 9.866 | 321.428 | 1,39% (1,34% a 1,45%) | 99,83% (99,83% a 99,83%) | 0,68; 0,67; 0,68 | 0,97% (0,93% a 0,99%) | 99,79% (99,79% a 99,79%) | limiar 0,68; limiar 0,67; limiar 0,68 |
| 0 | 1 (`BenignTraffic.pcap` de fora) | 9.087 | 321.841 | 1,25% (1,22% a 1,27%) | 99,88% (99,87% a 99,88%) | 0,67; 0,68; 0,67 | 0,95% (0,94% a 0,98%) | 99,86% (99,86% a 99,86%) | limiar 0,67; limiar 0,68; limiar 0,67 |
| 0 | 2 (`BenignTraffic1.pcap` de fora) | 10.089 | 321.428 | 1,38% (1,34% a 1,43%) | 99,83% (99,82% a 99,83%) | 0,68; 0,69; 0,69 | 0,95% (0,91% a 0,98%) | 99,78% (99,77% a 99,79%) | limiar 0,68; limiar 0,69; limiar 0,69 |

Na validação da rotação 0, a regra escolhida e as 4 janelas seguidas no resto da validação:

- Configuração 5, rotação 0, na regra escolhida em cada semente: recall na validação DDoS+DoS 99,8% (99,8% a 99,8%); Mirai 100,0%; Recon 80,4% (80,0% a 80,9%); Spoofing 78,4% (78,2% a 78,5%); Web 42,2% (41,5% a 42,6%); BruteForce 72,3% (71,4% a 73,1%); fundo da validação como ataque 12,4% (12,3% a 12,6%); alarmes com 4 janelas seguidas nos trechos benignos da validação (2,5 h), 0; pcaps de ataque com alarme no trecho de validação, 31 de 33 (sem alarme em alguma semente: `Recon-PingSweep.pcap` e `SqlInjection.pcap`).
- Configuração 0, rotação 0, na regra escolhida em cada semente: recall na validação DDoS+DoS 99,8% (99,8% a 99,8%); Mirai 100,0%; Recon 86,5% (86,2% a 86,7%); Spoofing 99,9% (99,9% a 100,0%); Web 46,5% (46,2% a 47,2%); BruteForce 76,2% (75,6% a 76,5%); fundo da validação como ataque 61,4% (61,1% a 61,8%); alarmes com 4 janelas seguidas nos trechos benignos da validação (2,5 h), 0; pcaps de ataque com alarme no trecho de validação, 32 de 33 (sem alarme em alguma semente: `Recon-PingSweep.pcap`).

## No teste: corte por tempo

As janelas de teste da divisão publicada (o fim de cada pcap e o pcap inteiro de fora nos rótulos de vários pcaps), com o mesmo modelo nas três regras; a coluna do ponto de operação repete a da regra que venceu na validação de cada semente. Janelas de teste por categoria, na semente principal: DDoS+DoS 214.373, Mirai 24.458, Recon 10.982, Spoofing 7.007, Web 465, BruteForce 273, Benign 16.008.

| Medida | Configuração 5, argmax | Configuração 5, melhor limiar | Configuração 5, ponto de operação | Configuração 0, argmax | Configuração 0, melhor limiar | Configuração 0, ponto de operação |
|---|---|---|---|---|---|---|
| Macro-F1 | 75,6% (75,4% a 75,7%) | 74,2% (74,0% a 74,6%) † | 75,6% (75,4% a 75,7%) * | 82,2% (82,1% a 82,3%) | 81,3% (81,1% a 81,4%) † | 81,3% (81,1% a 81,4%) |
| Acurácia | 96,1% (96,0% a 96,2%) | 95,8% (95,8% a 95,8%) † | 96,1% (96,0% a 96,2%) * | 98,3% (98,3% a 98,3%) | 98,0% (98,0% a 98,0%) † | 98,0% (98,0% a 98,0%) |
| Benigno classificado como ataque | 0,9% (0,8% a 0,9%) | 1,0% (0,9% a 1,1%) † | 0,9% (0,8% a 0,9%) * | 1,7% (1,6% a 1,9%) | 1,1% (1,0% a 1,2%) † | 1,1% (1,0% a 1,2%) |
| Ataque classificado como benigno | 3,6% (3,5% a 3,7%) | 3,9% (3,9% a 3,9%) † | 3,6% (3,5% a 3,7%) * | 1,0% (1,0% a 1,0%) | 1,3% (1,3% a 1,4%) † | 1,3% (1,3% a 1,4%) |
| Recall DDoS+DoS | 98,4% (98,3% a 98,4%) | 98,4% (98,3% a 98,4%) | 98,4% (98,3% a 98,4%) * | 98,9% (98,8% a 98,9%) | 98,8% (98,8% a 98,8%) † | 98,8% (98,8% a 98,8%) |
| Recall Mirai | 99,2% (99,2% a 99,2%) | 99,2% (99,2% a 99,2%) | 99,2% (99,2% a 99,2%) | 99,2% (99,2% a 99,3%) | 99,2% (99,2% a 99,3%) | 99,2% (99,2% a 99,3%) |
| Recall Recon | 55,0% (54,9% a 55,2%) | 50,4% (50,0% a 51,3%) † | 55,0% (54,9% a 55,2%) * | 87,7% (87,7% a 87,8%) | 82,1% (81,8% a 82,6%) † | 82,1% (81,8% a 82,6%) |
| Recall Spoofing | 79,9% (79,6% a 80,1%) | 73,3% (72,4% a 74,8%) † | 79,9% (79,6% a 80,1%) * | 99,4% (99,4% a 99,4%) | 99,4% (99,4% a 99,4%) | 99,4% (99,4% a 99,4%) |
| Recall Web | 35,1% (34,4% a 35,7%) | 37,1% (36,8% a 37,4%) † | 35,1% (34,4% a 35,7%) | 37,1% (37,0% a 37,2%) | 36,1% (35,9% a 36,3%) | 36,1% (35,9% a 36,3%) |
| Recall BruteForce | 34,4% (34,1% a 34,8%) | 35,0% (34,1% a 36,3%) | 34,4% (34,1% a 34,8%) | 34,8% (34,4% a 35,2%) | 33,7% (33,0% a 34,1%) | 33,7% (33,0% a 34,1%) |
| Recall Benign | 99,1% (99,1% a 99,2%) | 99,0% (98,9% a 99,1%) † | 99,1% (99,1% a 99,2%) * | 98,3% (98,1% a 98,4%) | 98,9% (98,8% a 99,0%) † | 98,9% (98,8% a 99,0%) |
| Precisão DDoS+DoS | 99,8% (99,8% a 99,8%) | 99,8% (99,8% a 99,8%) | 99,8% (99,8% a 99,8%) * | 99,8% (99,8% a 99,8%) | 99,8% (99,8% a 99,8%) † | 99,8% (99,8% a 99,8%) |
| Precisão Mirai | 100,0% (100,0% a 100,0%) | 100,0% (100,0% a 100,0%) | 100,0% (100,0% a 100,0%) | 100,0% (100,0% a 100,0%) | 100,0% (100,0% a 100,0%) | 100,0% (100,0% a 100,0%) |
| Precisão Recon | 85,7% (85,2% a 86,2%) | 83,8% (83,5% a 84,3%) † | 85,7% (85,2% a 86,2%) * | 87,0% (86,8% a 87,4%) | 86,9% (86,6% a 87,3%) | 86,9% (86,6% a 87,3%) |
| Precisão Spoofing | 99,9% (99,8% a 99,9%) | 99,8% (99,8% a 99,9%) | 99,9% (99,8% a 99,9%) * | 99,5% (99,5% a 99,5%) | 99,5% (99,5% a 99,5%) | 99,5% (99,5% a 99,5%) |
| Precisão Web | 67,4% (66,9% a 68,4%) | 62,0% (60,6% a 63,8%) † | 67,4% (66,9% a 68,4%) | 63,5% (62,1% a 64,7%) | 65,0% (63,3% a 66,9%) | 65,0% (63,3% a 66,9%) |
| Precisão BruteForce | 98,6% (97,9% a 99,0%) | 97,0% (95,0% a 100,0%) | 98,6% (97,9% a 99,0%) | 98,6% (98,0% a 99,0%) | 97,5% (96,9% a 97,9%) | 97,5% (96,9% a 97,9%) |
| Precisão Benign | 63,3% (62,8% a 63,6%) | 61,2% (61,0% a 61,4%) † | 63,3% (62,8% a 63,6%) * | 85,5% (85,4% a 85,6%) | 82,0% (81,7% a 82,4%) † | 82,0% (81,7% a 82,4%) |
| F1 DDoS+DoS | 99,1% (99,0% a 99,1%) | 99,1% (99,0% a 99,1%) | 99,1% (99,0% a 99,1%) * | 99,3% (99,3% a 99,3%) | 99,3% (99,3% a 99,3%) † | 99,3% (99,3% a 99,3%) |
| F1 Mirai | 99,6% (99,6% a 99,6%) | 99,6% (99,6% a 99,6%) | 99,6% (99,6% a 99,6%) | 99,6% (99,6% a 99,6%) | 99,6% (99,6% a 99,6%) | 99,6% (99,6% a 99,6%) |
| F1 Recon | 67,0% (66,8% a 67,2%) | 63,0% (62,7% a 63,5%) † | 67,0% (66,8% a 67,2%) * | 87,4% (87,3% a 87,5%) | 84,4% (84,3% a 84,6%) † | 84,4% (84,3% a 84,6%) |
| F1 Spoofing | 88,8% (88,6% a 88,9%) | 84,6% (83,9% a 85,5%) † | 88,8% (88,6% a 88,9%) * | 99,4% (99,4% a 99,5%) | 99,4% (99,4% a 99,5%) | 99,4% (99,4% a 99,5%) |
| F1 Web | 46,2% (45,8% a 46,6%) | 46,4% (46,2% a 46,7%) | 46,2% (45,8% a 46,6%) | 46,8% (46,4% a 47,1%) | 46,4% (46,2% a 46,9%) | 46,4% (46,2% a 46,9%) |
| F1 BruteForce | 51,0% (50,5% a 51,5%) | 51,5% (50,8% a 52,7%) | 51,0% (50,5% a 51,5%) | 51,4% (51,1% a 51,8%) | 50,1% (49,3% a 50,5%) | 50,1% (49,3% a 50,5%) |
| F1 Benign | 77,3% (76,9% a 77,5%) | 75,6% (75,5% a 75,8%) † | 77,3% (76,9% a 77,5%) * | 91,5% (91,4% a 91,5%) | 89,7% (89,5% a 89,9%) † | 89,7% (89,5% a 89,9%) |

## Benigno de fora: por janela e por alarme

Cada pcap benigno inteiro, com o modelo da rotação que o deixa fora do treino e a regra escolhida na validação dessa rotação: a fração das janelas classificada como ataque e os alarmes com 4 janelas de ataque seguidas, na ordem do pcap, com o argmax, com o melhor limiar e no ponto de operação. A hora é a soma da duração das janelas do pcap.

| Configuração | Pcap de fora | Janelas | Regra escolhida | Como ataque, argmax | Como ataque, melhor limiar | Como ataque, ponto de operação | Alarmes, argmax | Alarmes, melhor limiar | Alarmes, ponto de operação | Alarmes por hora, ponto de operação |
|---|---|---|---|---|---|---|---|---|---|---|
| 5 | `BenignTraffic2.pcap` | 31.032 | argmax nas 3 sementes | 0,9% (0,9% a 0,9%) | 1,1% (1,0% a 1,1%) † | 0,9% (0,9% a 0,9%) * | 1,3 (1 a 2) | 3,3 (3 a 4) | 1,3 (1 a 2) | 0,2 (0,1 a 0,3) |
| 5 | `BenignTraffic.pcap` | 36.228 | limiar 0,53; limiar 0,52; limiar 0,53 | 5,4% (5,3% a 5,4%) | 6,0% (5,8% a 6,3%) † | 6,0% (5,8% a 6,3%) * | 40,7 (37 a 45) | 41,7 (39 a 44) | 41,7 (39 a 44) | 4,5 (4,3 a 4,8) |
| 5 | `BenignTraffic1.pcap` | 29.549 | argmax nas 3 sementes | 0,8% (0,8% a 0,8%) | 0,9% (0,9% a 1,0%) † | 0,8% (0,8% a 0,8%) * | 1,3 (1 a 2) | 2,7 (2 a 3) | 1,3 (1 a 2) | 0,2 (0,1 a 0,3) |
| 0 | `BenignTraffic2.pcap` | 31.032 | limiar 0,68; limiar 0,67; limiar 0,68 | 1,7% (1,7% a 1,9%) | 1,1% (1,1% a 1,2%) † | 1,1% (1,1% a 1,2%) | 7,3 (6 a 9) | 6,7 (5 a 8) | 6,7 (5 a 8) | 0,8 (0,6 a 1,0) |
| 0 | `BenignTraffic.pcap` | 36.228 | limiar 0,67; limiar 0,68; limiar 0,67 | 38,5% (38,2% a 38,8%) | 36,1% (36,0% a 36,1%) † | 36,1% (36,0% a 36,1%) | 486,7 (484 a 491) | 467,0 (456 a 478) | 467,0 (456 a 478) | 51,0 (49,8 a 52,2) |
| 0 | `BenignTraffic1.pcap` | 29.549 | limiar 0,68; limiar 0,69; limiar 0,69 | 1,5% (1,4% a 1,6%) | 1,0% (0,9% a 1,2%) † | 1,0% (0,9% a 1,2%) | 7,3 (6 a 9) | 5,3 (5 a 6) | 5,3 (5 a 6) | 0,7 (0,7 a 0,8) |

Pior pcap benigno de fora, no ponto de operação: configuração 5, `BenignTraffic.pcap` com 6,0% (5,8% a 6,3%); configuração 0, `BenignTraffic.pcap` com 36,1% (36,0% a 36,1%).

## Fundo virando ataque

As janelas sem nenhum quadro do atacante na parte de teste dos pcaps de ataque, classificadas como algum ataque:

| Configuração | Janelas de fundo no teste | Argmax | Melhor limiar | Ponto de operação |
|---|---|---|---|---|
| 5 | 17.766 | 13,3% (13,2% a 13,3%) | 10,2% (9,9% a 10,8%) † | 13,3% (13,2% a 13,3%) * |
| 0 | 17.766 | 72,3% (72,2% a 72,4%) | 65,9% (65,7% a 66,2%) † | 65,9% (65,7% a 66,2%) |

## Pcaps de ataque no trecho de teste

Em cada pcap de ataque com parte de teste, a sequência de todas as janelas do trecho de teste, com e sem o atacante, na ordem do arquivo, como o extrator as entregaria. O tempo até o alarme conta do começo do trecho, pela soma da duração das janelas. O alarme é o de 4 janelas de ataque seguidas.

| Configuração | Regra | Pcaps com alarme | Janelas até o primeiro alarme (mediana) | Segundos até o primeiro alarme (mediana) | Segundos até o primeiro alarme (maior) |
|---|---|---|---|---|---|
| 5 | argmax | 32 (31 a 32) de 33 | 4 | 0,20 (0,18 a 0,20) | 150,7 |
| 5 | melhor limiar | 32 de 33 | 4 | 0,20 | 1.730,6 (150,7 a 2.961,5) |
| 5 | ponto de operação | 32 (31 a 32) de 33 | 4 | 0,20 (0,18 a 0,20) | 150,7 |
| 0 | argmax | 33 de 33 | 4 | 0,23 | 91,6 (90,2 a 92,3) |
| 0 | melhor limiar | 33 de 33 | 4 | 0,23 | 92,3 |
| 0 | ponto de operação | 33 de 33 | 4 | 0,23 | 92,3 |

Pcaps sem alarme no ponto de operação em alguma semente: configuração 5: `BrowserHijacking.pcap` e `Recon-PingSweep.pcap`.

## Quais diferenças contam

A diferença com o intervalo de 95% entre parênteses:

- Configuração 5, melhor limiar contra argmax: macro-F1 (-1,33 p.p., de -1,95 a -0,70), acurácia (-0,35 p.p., de -0,45 a -0,26), benigno como ataque no corte por tempo (+0,17 p.p., de +0,01 a +0,33), ataque como benigno (+0,33 p.p., de +0,20 a +0,46), recall de Recon (-4,57 p.p., de -5,36 a -3,78), recall de Spoofing (-6,57 p.p., de -8,53 a -4,62), recall de Web (+1,94 p.p., de +0,60 a +3,27), recall de Benign (-0,17 p.p., de -0,33 a -0,01), `BenignTraffic2.pcap` de fora como ataque (+0,16 p.p., de +0,02 a +0,29), `BenignTraffic.pcap` de fora como ataque (+0,62 p.p., de +0,26 a +0,99), `BenignTraffic1.pcap` de fora como ataque (+0,15 p.p., de +0,07 a +0,22) e fundo virando ataque (-3,05 p.p., de -3,72 a -2,38). Sem diferença: recall de DDoS+DoS, recall de Mirai e recall de BruteForce.
- Configuração 0, melhor limiar contra argmax: macro-F1 (-0,92 p.p., de -1,32 a -0,53), acurácia (-0,24 p.p., de -0,27 a -0,21), benigno como ataque no corte por tempo (-0,57 p.p., de -0,75 a -0,39), ataque como benigno (+0,31 p.p., de +0,28 a +0,35), recall de DDoS+DoS (-0,06 p.p., de -0,07 a -0,05), recall de Recon (-5,58 p.p., de -6,18 a -4,97), recall de Benign (+0,57 p.p., de +0,39 a +0,75), `BenignTraffic2.pcap` de fora como ataque (-0,59 p.p., de -0,74 a -0,44), `BenignTraffic.pcap` de fora como ataque (-2,44 p.p., de -2,84 a -2,04), `BenignTraffic1.pcap` de fora como ataque (-0,44 p.p., de -0,54 a -0,35) e fundo virando ataque (-6,41 p.p., de -6,96 a -5,87). Sem diferença: recall de Mirai, recall de Spoofing, recall de Web e recall de BruteForce.
- Configuração 5 contra a 0, as duas no ponto de operação: macro-F1 (-5,71 p.p., de -6,30 a -5,12), acurácia (-1,92 p.p., de -2,03 a -1,80), benigno como ataque no corte por tempo (-0,29 p.p., de -0,47 a -0,11), ataque como benigno (+2,23 p.p., de +2,08 a +2,37), recall de DDoS+DoS (-0,44 p.p., de -0,55 a -0,32), recall de Recon (-27,10 p.p., de -28,08 a -26,13), recall de Spoofing (-19,52 p.p., de -21,30 a -17,74), recall de Benign (+0,29 p.p., de +0,11 a +0,47), `BenignTraffic2.pcap` de fora como ataque (-0,23 p.p., de -0,38 a -0,09), `BenignTraffic.pcap` de fora como ataque (-30,08 p.p., de -31,04 a -29,12), `BenignTraffic1.pcap` de fora como ataque (-0,24 p.p., de -0,38 a -0,10) e fundo virando ataque (-52,61 p.p., de -53,81 a -51,40). Sem diferença: recall de Mirai, recall de Web e recall de BruteForce.

## Conferência

- Configuração 5: em 9 de 9 treinos inteiros, as predições do argmax conferidas com as do mesmo treino guardado das rodadas (o corte por tempo, o fundo e o pcap benigno de fora) diferem em 0 janelas.
- Configuração 0: em 9 de 9 treinos inteiros, as predições do argmax conferidas com as do mesmo treino guardado das rodadas (o corte por tempo, o fundo e o pcap benigno de fora) diferem em 0 janelas.

## Os modelos salvos

Os modelos que `codigo.classificador.treinar_regerado` salva, com o ponto de operação num JSON ao lado, conferidos contra o treino inteiro da semente principal, no corte por tempo: o do sistema (configuração 5) e o de referência, de 10/10 (configuração 0, `--sem-fundo`). `codigo.classificador.operacao` lê o JSON, recusa o de outro modelo e aplica a regra, o argmax ou o limiar, a uma janela (`PontoDeOperacao.categoria`, `Vigia`) e a uma sequência (`PontoDeOperacao.aplicar`). A pasta `modelos/` fica fora do git.

| Configuração | Modelo | SHA-256 | Predições diferentes do retreino (argmax, melhor limiar e ponto) | Regra escolhida aqui | Regra no JSON | Confere |
|---|---|---|---|---|---|---|
| 5 | `rf_regerado_janela_100.joblib` | `422fb3b4ca198039…` | 0 e 0 e 0 | argmax, N = 4 | argmax, N = 4 | sim |
| 0 | `rf_regerado_janela_100_sem_fundo.joblib` | `44b0b970599a0062…` | 0 e 0 e 0 | limiar 0,68, N = 4 | limiar 0,68, N = 4 | sim |

## Como os números foram obtidos

- Comando: `python -m codigo.classificador.ponto_de_operacao --nucleos 4`, a partir da raiz do repositório.
- Dados: `dados/processed/regerado/janela_100/`, 72 arquivos, com o SHA-256 de cada um em `manifesto_ponto_de_operacao.json`; manifesto da regeração `experimentos/resultados/manifesto_regeracao.json`, SHA-256 `2d8ed9c489f21f2e8ed0b8f1e312e974c820013ae020eaaf6b7ff4996dfbf7c3`.
- Regra de adoção lida de `experimentos/resultados/manifesto_rodadas_normalizadas.json`, SHA-256 `0f467f05ca65f9f1de07f73d1733dc49e9733cf4989f366a97a0f089566523c9`.
- Treinos: `RandomForestClassifier` com 100 árvores e os demais parâmetros padrão, teto de 50.000 linhas por rótulo, as funções de `rodadas` e `treinar_regerado`; dois treinos por semente e rotação, o reduzido e o inteiro. Predição com um núcleo, em ordem fixa.
- As tabelas em CSV começam com `ponto_de_operacao_`; os valores completos, com as contagens, estão no manifesto.
- Tempo desta execução, na máquina em que rodou: 29,1 s. Os treinos já guardados em `dados/processed/ponto_de_operacao/` são reaproveitados e não entram nessa conta; somados, os treinos de que os números saem levaram 499,1 s.
- Código: o SHA-256 de cada módulo de que os números saem (`rodadas.py`, `preparar.py`, `treinar.py`, `avaliar.py`, `treinar_regerado.py`, `regerar.py`, `mapeamento.py`, `extrator.py`, `ponto_de_operacao.py` e `operacao.py`) está no manifesto e entra na chave dos treinos guardados; commit `e0fe37c72e0b`.
- Memória: pico de 2,3 GB no processo, o necessário para reproduzir com a mesma quantidade de núcleos.
- Com as mesmas entradas, o mesmo código e as mesmas sementes, os números saem iguais. Só mudam a data e os
  tempos.

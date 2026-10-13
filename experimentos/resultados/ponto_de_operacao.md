# Ponto de operação: limiar e alarme escolhidos na validação

Gerado por `python -m codigo.classificador.ponto_de_operacao` em 13/10/2026, com Python 3.11.2, scikit-learn 1.9.1, pandas 3.0.6 e numpy 2.4.6.

A decisão da equipe: o limiar e a regra de janelas seguidas são escolhidos numa parte de validação, nunca no teste. A regra: a janela é ataque se 1 − P(Benign) ≥ t, na categoria de ataque mais provável; senão, é Benign. Um incidente só abre com 3 janelas de ataque seguidas, na ordem do pcap. Os pontos candidatos de `rodadas_de_teste.md` (rodada g) saíram do próprio teste e não são usados aqui.

**Validação.** Dentro da parte de treino de cada pcap (os primeiros 70% das janelas), as últimas 15% dessas janelas, por tempo, são a validação, e o resto é o treino reduzido. Nos rótulos com um pcap inteiro no teste, a validação são as últimas 15% de cada pcap de treino. O teste é o mesmo das rodadas. Na configuração com o fundo no treino, o fundo da validação também fica fora do treino reduzido.

**Limiar.** O modelo treinado no treino reduzido, com a mesma amostra e a mesma semente, classifica todas as janelas da validação. O limiar t é o menor da grade de 0,01 a 1,00, de 0,01 em 0,01, que deixa no máximo 1% das janelas dos pcaps benignos da validação como ataque. Nas rotações do pcap benigno de fora, cada rotação escolhe o seu t na sua validação: a validação da rotação 0 tem janelas do pcap que a rotação 1 deixa de fora.

**Teste.** O modelo treinado no treino inteiro, o mesmo treino do corte por tempo das rodadas, com o t da sua semente e rotação. As colunas "argmax" são o mesmo modelo com a categoria mais provável, a regra de hoje. Pela regra de adoção aplicada em `rodadas_normalizadas.md`, a vencedora é a configuração 5 (as três condições são atendidas); a configuração 0 entra para comparação.

Cada configuração foi medida com as sementes 42, 1 e 2, que definem o teto e o Random Forest. Os valores são a média das sementes, com o menor e o maior entre parênteses. As diferenças são pareadas como em `rodadas_normalizadas.md`: mesma semente e mesmas janelas, com a variância por reamostragem de blocos de 10 janelas vizinhas somada à variância entre as sementes. A diferença só conta quando o intervalo de 95% não contém o zero; senão, é "sem diferença". Nas tabelas, † marca a diferença entre o limiar e o argmax que conta, e * a diferença para a configuração 0 no limiar que conta.

## Resumo

- Configuração 5: t = 0,61 na semente 42 (0,61; 0,59; 0,61 nas sementes 42, 1 e 2), N = 3. No corte por tempo, macro-F1 74,2% (74,0% a 74,6%) e benigno como ataque 1,02% (0,94% a 1,09%) por janela; no `BenignTraffic2.pcap` inteiro, 1,07% (0,99% a 1,15%) das janelas como ataque e 8,7 (7 a 12) alarmes (1,1 (0,9 a 1,5) por hora); pior pcap benigno de fora (`BenignTraffic.pcap`), 6,0% (5,8% a 6,3%); fundo virando ataque, 10,2% (9,9% a 10,8%); pcaps de ataque com alarme no trecho de teste, 32 de 33.
- Configuração 0: t = 0,68 na semente 42 (0,68; 0,67; 0,68 nas sementes 42, 1 e 2), N = 3. No corte por tempo, macro-F1 81,3% (81,1% a 81,4%) e benigno como ataque 1,14% (1,04% a 1,21%) por janela; no `BenignTraffic2.pcap` inteiro, 1,14% (1,07% a 1,19%) das janelas como ataque e 12,7 (11 a 15) alarmes (1,6 (1,4 a 1,9) por hora); pior pcap benigno de fora (`BenignTraffic.pcap`), 36,1% (36,0% a 36,1%); fundo virando ataque, 65,9% (65,7% a 66,2%); pcaps de ataque com alarme no trecho de teste, 33 de 33.

## O limiar escolhido na validação

Em cada configuração, rotação e semente: as janelas dos pcaps benignos na validação, o t escolhido em cada semente, a fração dessas janelas que o t deixa como ataque e a que o argmax deixaria.

| Configuração | Rotação | Janelas benignas na validação | t (por semente) | Benigno da validação como ataque, no t | Com o argmax |
|---|---|---|---|---|---|
| 5 | 0 (`BenignTraffic2.pcap` de fora) | 9.866 | 0,61; 0,59; 0,61 | 0,97% (0,95% a 0,98%) | 0,77% (0,76% a 0,79%) |
| 5 | 1 (`BenignTraffic.pcap` de fora) | 9.087 | 0,53; 0,52; 0,53 | 0,94% (0,89% a 0,96%) | 0,45% (0,41% a 0,48%) |
| 5 | 2 (`BenignTraffic1.pcap` de fora) | 10.089 | 0,59; 0,59; 0,60 | 0,97% (0,95% a 0,98%) | 0,75% (0,70% a 0,80%) |
| 0 | 0 (`BenignTraffic2.pcap` de fora) | 9.866 | 0,68; 0,67; 0,68 | 0,97% (0,93% a 0,99%) | 1,39% (1,34% a 1,45%) |
| 0 | 1 (`BenignTraffic.pcap` de fora) | 9.087 | 0,67; 0,68; 0,67 | 0,95% (0,94% a 0,98%) | 1,25% (1,22% a 1,27%) |
| 0 | 2 (`BenignTraffic1.pcap` de fora) | 10.089 | 0,68; 0,69; 0,69 | 0,95% (0,91% a 0,98%) | 1,38% (1,34% a 1,43%) |

Na validação da rotação 0, a regra inteira (o t e as 3 janelas seguidas) no resto da validação:

- Configuração 5, rotação 0, no t de cada semente: recall na validação DDoS+DoS 99,8% (99,8% a 99,8%); Mirai 100,0%; Recon 78,1% (77,8% a 78,6%); Spoofing 75,0% (74,1% a 76,2%); Web 43,6% (42,1% a 45,1%); BruteForce 73,7% (72,3% a 74,8%); fundo da validação como ataque 8,5% (8,1% a 9,0%); nos trechos benignos da validação (2,5 h), 1,3 (1 a 2) alarmes com 3 janelas seguidas; pcaps de ataque com alarme no trecho de validação, 32 de 33 (sem alarme em alguma semente: `SqlInjection.pcap`).
- Configuração 0, rotação 0, no t de cada semente: recall na validação DDoS+DoS 99,8% (99,8% a 99,8%); Mirai 100,0%; Recon 86,5% (86,2% a 86,7%); Spoofing 99,9% (99,9% a 100,0%); Web 46,5% (46,2% a 47,2%); BruteForce 76,2% (75,6% a 76,5%); fundo da validação como ataque 61,4% (61,1% a 61,8%); nos trechos benignos da validação (2,5 h), 0,7 (0 a 1) alarmes com 3 janelas seguidas; pcaps de ataque com alarme no trecho de validação, 33 de 33.

## No teste: corte por tempo

As janelas de teste da divisão publicada (o fim de cada pcap e o pcap inteiro de fora nos rótulos de vários pcaps), com o mesmo modelo nas duas regras. Janelas de teste por categoria, na semente principal: DDoS+DoS 214.373, Mirai 24.458, Recon 10.982, Spoofing 7.007, Web 465, BruteForce 273, Benign 16.008.

| Medida | Configuração 5, argmax (hoje) | Configuração 5, limiar | Configuração 0, argmax (hoje) | Configuração 0, limiar |
|---|---|---|---|---|
| Macro-F1 | 75,6% (75,4% a 75,7%) | 74,2% (74,0% a 74,6%) †* | 82,2% (82,1% a 82,3%) | 81,3% (81,1% a 81,4%) † |
| Acurácia | 96,1% (96,0% a 96,2%) | 95,8% (95,8% a 95,8%) †* | 98,3% (98,3% a 98,3%) | 98,0% (98,0% a 98,0%) † |
| Benigno classificado como ataque | 0,9% (0,8% a 0,9%) | 1,0% (0,9% a 1,1%) † | 1,7% (1,6% a 1,9%) | 1,1% (1,0% a 1,2%) † |
| Ataque classificado como benigno | 3,6% (3,5% a 3,7%) | 3,9% (3,9% a 3,9%) †* | 1,0% (1,0% a 1,0%) | 1,3% (1,3% a 1,4%) † |
| Recall DDoS+DoS | 98,4% (98,3% a 98,4%) | 98,4% (98,3% a 98,4%) * | 98,9% (98,8% a 98,9%) | 98,8% (98,8% a 98,8%) † |
| Recall Mirai | 99,2% (99,2% a 99,2%) | 99,2% (99,2% a 99,2%) | 99,2% (99,2% a 99,3%) | 99,2% (99,2% a 99,3%) |
| Recall Recon | 55,0% (54,9% a 55,2%) | 50,4% (50,0% a 51,3%) †* | 87,7% (87,7% a 87,8%) | 82,1% (81,8% a 82,6%) † |
| Recall Spoofing | 79,9% (79,6% a 80,1%) | 73,3% (72,4% a 74,8%) †* | 99,4% (99,4% a 99,4%) | 99,4% (99,4% a 99,4%) |
| Recall Web | 35,1% (34,4% a 35,7%) | 37,1% (36,8% a 37,4%) † | 37,1% (37,0% a 37,2%) | 36,1% (35,9% a 36,3%) |
| Recall BruteForce | 34,4% (34,1% a 34,8%) | 35,0% (34,1% a 36,3%) | 34,8% (34,4% a 35,2%) | 33,7% (33,0% a 34,1%) |
| Recall Benign | 99,1% (99,1% a 99,2%) | 99,0% (98,9% a 99,1%) † | 98,3% (98,1% a 98,4%) | 98,9% (98,8% a 99,0%) † |
| Precisão DDoS+DoS | 99,8% (99,8% a 99,8%) | 99,8% (99,8% a 99,8%) * | 99,8% (99,8% a 99,8%) | 99,8% (99,8% a 99,8%) † |
| Precisão Mirai | 100,0% (100,0% a 100,0%) | 100,0% (100,0% a 100,0%) | 100,0% (100,0% a 100,0%) | 100,0% (100,0% a 100,0%) |
| Precisão Recon | 85,7% (85,2% a 86,2%) | 83,8% (83,5% a 84,3%) †* | 87,0% (86,8% a 87,4%) | 86,9% (86,6% a 87,3%) |
| Precisão Spoofing | 99,9% (99,8% a 99,9%) | 99,8% (99,8% a 99,9%) * | 99,5% (99,5% a 99,5%) | 99,5% (99,5% a 99,5%) |
| Precisão Web | 67,4% (66,9% a 68,4%) | 62,0% (60,6% a 63,8%) † | 63,5% (62,1% a 64,7%) | 65,0% (63,3% a 66,9%) |
| Precisão BruteForce | 98,6% (97,9% a 99,0%) | 97,0% (95,0% a 100,0%) | 98,6% (98,0% a 99,0%) | 97,5% (96,9% a 97,9%) |
| Precisão Benign | 63,3% (62,8% a 63,6%) | 61,2% (61,0% a 61,4%) †* | 85,5% (85,4% a 85,6%) | 82,0% (81,7% a 82,4%) † |
| F1 DDoS+DoS | 99,1% (99,0% a 99,1%) | 99,1% (99,0% a 99,1%) * | 99,3% (99,3% a 99,3%) | 99,3% (99,3% a 99,3%) † |
| F1 Mirai | 99,6% (99,6% a 99,6%) | 99,6% (99,6% a 99,6%) | 99,6% (99,6% a 99,6%) | 99,6% (99,6% a 99,6%) |
| F1 Recon | 67,0% (66,8% a 67,2%) | 63,0% (62,7% a 63,5%) †* | 87,4% (87,3% a 87,5%) | 84,4% (84,3% a 84,6%) † |
| F1 Spoofing | 88,8% (88,6% a 88,9%) | 84,6% (83,9% a 85,5%) †* | 99,4% (99,4% a 99,5%) | 99,4% (99,4% a 99,5%) |
| F1 Web | 46,2% (45,8% a 46,6%) | 46,4% (46,2% a 46,7%) | 46,8% (46,4% a 47,1%) | 46,4% (46,2% a 46,9%) |
| F1 BruteForce | 51,0% (50,5% a 51,5%) | 51,5% (50,8% a 52,7%) | 51,4% (51,1% a 51,8%) | 50,1% (49,3% a 50,5%) |
| F1 Benign | 77,3% (76,9% a 77,5%) | 75,6% (75,5% a 75,8%) †* | 91,5% (91,4% a 91,5%) | 89,7% (89,5% a 89,9%) † |

## Benigno de fora: por janela e por alarme

Cada pcap benigno inteiro, com o modelo da rotação que o deixa fora do treino e o t escolhido na validação dessa rotação: a fração das janelas classificada como ataque e os alarmes com 3 janelas de ataque seguidas, na ordem do pcap. A hora é a soma da duração das janelas do pcap.

| Configuração | Pcap de fora | Janelas | t (por semente) | Como ataque, argmax | Como ataque, limiar | Alarmes com 3 seguidas, argmax | Alarmes com 3 seguidas, limiar | Alarmes por hora, limiar |
|---|---|---|---|---|---|---|---|---|
| 5 | `BenignTraffic2.pcap` | 31.032 | 0,61; 0,59; 0,61 | 0,9% (0,9% a 0,9%) | 1,1% (1,0% a 1,1%) † | 4,3 (4 a 5) | 8,7 (7 a 12) | 1,1 (0,9 a 1,5) |
| 5 | `BenignTraffic.pcap` | 36.228 | 0,53; 0,52; 0,53 | 5,4% (5,3% a 5,4%) | 6,0% (5,8% a 6,3%) †* | 120,7 (118 a 125) | 124,0 (116 a 139) | 13,5 (12,7 a 15,2) |
| 5 | `BenignTraffic1.pcap` | 29.549 | 0,59; 0,59; 0,60 | 0,8% (0,8% a 0,8%) | 0,9% (0,9% a 1,0%) † | 6,0 (4 a 7) | 7,0 (5 a 9) | 1,0 (0,7 a 1,3) |
| 0 | `BenignTraffic2.pcap` | 31.032 | 0,68; 0,67; 0,68 | 1,7% (1,7% a 1,9%) | 1,1% (1,1% a 1,2%) † | 15,0 (14 a 16) | 12,7 (11 a 15) | 1,6 (1,4 a 1,9) |
| 0 | `BenignTraffic.pcap` | 36.228 | 0,67; 0,68; 0,67 | 38,5% (38,2% a 38,8%) | 36,1% (36,0% a 36,1%) † | 789,3 (787 a 793) | 712,0 (698 a 737) | 77,7 (76,2 a 80,4) |
| 0 | `BenignTraffic1.pcap` | 29.549 | 0,68; 0,69; 0,69 | 1,5% (1,4% a 1,6%) | 1,0% (0,9% a 1,2%) † | 21,0 (19 a 24) | 14,0 (12 a 17) | 2,0 (1,7 a 2,4) |

Pior pcap benigno de fora, no limiar: configuração 5, `BenignTraffic.pcap` com 6,0% (5,8% a 6,3%); configuração 0, `BenignTraffic.pcap` com 36,1% (36,0% a 36,1%).

## Fundo virando ataque

As janelas sem nenhum quadro do atacante na parte de teste dos pcaps de ataque, classificadas como algum ataque:

| Configuração | Janelas de fundo no teste | Argmax | Limiar |
|---|---|---|---|
| 5 | 17.766 | 13,3% (13,2% a 13,3%) | 10,2% (9,9% a 10,8%) †* |
| 0 | 17.766 | 72,3% (72,2% a 72,4%) | 65,9% (65,7% a 66,2%) † |

## Pcaps de ataque no trecho de teste

Em cada pcap de ataque com parte de teste, a sequência de todas as janelas do trecho de teste, com e sem o atacante, na ordem do arquivo, como o extrator as entregaria. O tempo até o alarme conta do começo do trecho, pela soma da duração das janelas. O alarme é o de 3 janelas de ataque seguidas.

| Configuração | Regra | Pcaps com alarme | Janelas até o primeiro alarme (mediana) | Segundos até o primeiro alarme (mediana) | Segundos até o primeiro alarme (maior) |
|---|---|---|---|---|---|
| 5 | argmax (hoje) | 32 (31 a 32) de 33 | 3 | 0,15 (0,11 a 0,16) | 150,7 |
| 5 | limiar | 32 de 33 | 3 | 0,16 | 150,7 |
| 0 | argmax (hoje) | 33 de 33 | 3 | 0,21 | 49,2 (30,8 a 86,0) |
| 0 | limiar | 33 de 33 | 3 | 0,21 | 30,8 |

Pcaps sem alarme no limiar em alguma semente: configuração 5: `Recon-PingSweep.pcap`.

## Quais diferenças contam

A diferença com o intervalo de 95% entre parênteses:

- Configuração 5, limiar contra argmax: macro-F1 (-1,33 p.p., de -1,95 a -0,70), acurácia (-0,35 p.p., de -0,45 a -0,26), benigno como ataque no corte por tempo (+0,17 p.p., de +0,01 a +0,33), ataque como benigno (+0,33 p.p., de +0,20 a +0,46), recall de Recon (-4,57 p.p., de -5,36 a -3,78), recall de Spoofing (-6,57 p.p., de -8,53 a -4,62), recall de Web (+1,94 p.p., de +0,60 a +3,27), recall de Benign (-0,17 p.p., de -0,33 a -0,01), `BenignTraffic2.pcap` de fora como ataque (+0,16 p.p., de +0,02 a +0,29), `BenignTraffic.pcap` de fora como ataque (+0,62 p.p., de +0,26 a +0,99), `BenignTraffic1.pcap` de fora como ataque (+0,15 p.p., de +0,07 a +0,22) e fundo virando ataque (-3,05 p.p., de -3,72 a -2,38). Sem diferença: recall de DDoS+DoS, recall de Mirai e recall de BruteForce.
- Configuração 0, limiar contra argmax: macro-F1 (-0,92 p.p., de -1,32 a -0,53), acurácia (-0,24 p.p., de -0,27 a -0,21), benigno como ataque no corte por tempo (-0,57 p.p., de -0,75 a -0,39), ataque como benigno (+0,31 p.p., de +0,28 a +0,35), recall de DDoS+DoS (-0,06 p.p., de -0,07 a -0,05), recall de Recon (-5,58 p.p., de -6,18 a -4,97), recall de Benign (+0,57 p.p., de +0,39 a +0,75), `BenignTraffic2.pcap` de fora como ataque (-0,59 p.p., de -0,74 a -0,44), `BenignTraffic.pcap` de fora como ataque (-2,44 p.p., de -2,84 a -2,04), `BenignTraffic1.pcap` de fora como ataque (-0,44 p.p., de -0,54 a -0,35) e fundo virando ataque (-6,41 p.p., de -6,96 a -5,87). Sem diferença: recall de Mirai, recall de Spoofing, recall de Web e recall de BruteForce.
- Configuração 5 contra a 0, as duas no limiar: macro-F1 (-7,04 p.p., de -7,66 a -6,42), acurácia (-2,27 p.p., de -2,34 a -2,20), ataque como benigno (+2,56 p.p., de +2,48 a +2,63), recall de DDoS+DoS (-0,43 p.p., de -0,52 a -0,34), recall de Recon (-31,67 p.p., de -32,66 a -30,69), recall de Spoofing (-26,09 p.p., de -28,48 a -23,70), `BenignTraffic.pcap` de fora como ataque (-30,08 p.p., de -31,04 a -29,12) e fundo virando ataque (-55,66 p.p., de -56,83 a -54,49). Sem diferença: benigno como ataque no corte por tempo, recall de Mirai, recall de Web, recall de BruteForce, recall de Benign, `BenignTraffic2.pcap` de fora como ataque e `BenignTraffic1.pcap` de fora como ataque.

## Conferência

- Configuração 5: em 9 de 9 treinos inteiros, as predições do argmax conferidas com as do mesmo treino guardado das rodadas (o corte por tempo, o fundo e o pcap benigno de fora) diferem em 0 janelas.
- Configuração 0: em 9 de 9 treinos inteiros, as predições do argmax conferidas com as do mesmo treino guardado das rodadas (o corte por tempo, o fundo e o pcap benigno de fora) diferem em 0 janelas.

## Os modelos salvos

Os modelos que `codigo.classificador.treinar_regerado` salva, com o ponto de operação num JSON ao lado, conferidos contra o treino inteiro da semente principal, no corte por tempo: o do sistema (configuração 5) e o de referência, de 10/10 (configuração 0, `--sem-fundo`). `codigo.classificador.operacao` lê o JSON, recusa o de outro modelo e aplica a regra a uma janela (`PontoDeOperacao.categoria`, `Vigia`) e a uma sequência (`PontoDeOperacao.aplicar`). A pasta `modelos/` fica fora do git.

| Configuração | Modelo | SHA-256 | Predições diferentes do retreino (argmax e limiar) | t e N escolhidos aqui | t e N no JSON | Confere |
|---|---|---|---|---|---|---|
| 5 | `rf_regerado_janela_100.joblib` | `422fb3b4ca198039…` | 0 e 0 | 0,61 e 3 | 0,61 e 3 | sim |
| 0 | `rf_regerado_janela_100_sem_fundo.joblib` | `44b0b970599a0062…` | 0 e 0 | 0,68 e 3 | 0,68 e 3 | sim |

## Como os números foram obtidos

- Comando: `python -m codigo.classificador.ponto_de_operacao --nucleos 4`, a partir da raiz do repositório.
- Dados: `dados/processed/regerado/janela_100/`, 72 arquivos, com o SHA-256 de cada um em `manifesto_ponto_de_operacao.json`; manifesto da regeração `experimentos/resultados/manifesto_regeracao.json`, SHA-256 `2d8ed9c489f21f2e8ed0b8f1e312e974c820013ae020eaaf6b7ff4996dfbf7c3`.
- Regra de adoção lida de `experimentos/resultados/manifesto_rodadas_normalizadas.json`, SHA-256 `570f6f17ca3ffb023c4dd08824eb39c6176101f03721766cef49682a877a12bf`.
- Treinos: `RandomForestClassifier` com 100 árvores e os demais parâmetros padrão, teto de 50.000 linhas por rótulo, as funções de `rodadas` e `treinar_regerado`; dois treinos por semente e rotação, o reduzido e o inteiro. Predição com um núcleo, em ordem fixa.
- As tabelas em CSV começam com `ponto_de_operacao_`; os valores completos, com as contagens, estão no manifesto.
- Tempo desta execução, na máquina em que rodou: 504,1 s. Os treinos já guardados em `dados/processed/ponto_de_operacao/` são reaproveitados e não entram nessa conta; somados, os treinos de que os números saem levaram 405,3 s.
- Código: o SHA-256 de cada módulo de que os números saem (`rodadas.py`, `preparar.py`, `treinar.py`, `avaliar.py`, `treinar_regerado.py`, `regerar.py`, `mapeamento.py`, `extrator.py`, `ponto_de_operacao.py` e `operacao.py`) está no manifesto e entra na chave dos treinos guardados; commit `ffedd52315c2`, com alterações ainda fora dele.
- Memória: pico de 2,5 GB no processo, o necessário para reproduzir com a mesma quantidade de núcleos.
- Com as mesmas entradas, o mesmo código e as mesmas sementes, os números saem iguais. Só mudam a data e os
  tempos.

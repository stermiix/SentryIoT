# Teste direto do atalho da janela

Gerado por `python -m codigo.classificador.janela` em 05/10/2026, com Python 3.11.2, scikit-learn 1.9.1, pandas 3.0.6, numpy 2.4.6 e dpkt 1.9.8.

## A pergunta

O CICIoT2023 (Neto et al., 2023) agrega os quadros em janelas de 100 nas classes de DDoS, DoS e Mirai
e de 10 nas demais. O treino exploratório mostrou que, mesmo sem as seis colunas que dependem da
janela, o modelo ainda põe mais de 99,8% das linhas de teste no grupo de janela certo
(`treino_exploratorio.md`). Na operação o extrator usa uma janela só para todo o tráfego. A pergunta
deste teste é o que acontece com uma captura agregada com a janela que o modelo não viu naquela
classe:

- o modelo reconhece um flood agregado em janelas de 10?
- o modelo reconhece uma varredura ou uma força bruta agregadas em janelas de 100?

## O experimento

**Modelos.** Random Forest de 7 categorias, com DDoS e DoS fundidas, treinado nas 1.030.783 linhas de treino do sorteio estratificado da amostra, com semente 42 e 100 árvores. São 4 modelos: com as 39 features ou com 33, sem as seis colunas que dependem da janela (`Number`, `Tot sum`, `ack_count`, `syn_count`, `fin_count` e `rst_count`), e com a priori da amostra ou a natural. São as mesmas configurações do treino exploratório. A tabela traz as medidas de cada modelo na parte de teste da amostra, para comparar com as daquele relatório.

| Modelo | Features | Priori de treino | Acurácia no teste da amostra | Recall de DDoS+DoS no teste da amostra | Recall de Mirai no teste da amostra | Recall de Recon no teste da amostra | Recall de BruteForce no teste da amostra |
|---|---|---|---|---|---|---|---|
| `f39_estratificada_c7` | 39 | da amostra | 93,81% | 99,98% | 99,66% | 91,56% | 33,55% |
| `f39_estratificada_c7_natural` | 39 | natural | 92,07% | 99,96% | 99,70% | 76,83% | 12,98% |
| `f33_estratificada_c7` | 33 | da amostra | 93,67% | 99,86% | 99,61% | 91,40% | 32,91% |
| `f33_estratificada_c7_natural` | 33 | natural | 91,82% | 99,72% | 99,63% | 76,25% | 12,26% |

**Capturas.** 5 pcaps do dataset, os mesmos da calibração do extrator. Cada um foi lido inteiro pelo extrator (`codigo/captura/extrator.py`), em leitura contínua, como na operação, sem o fatiamento em pedaços de 10 MB com que os autores geraram os CSVs oficiais. Cada pcap foi extraído duas vezes, com janela de 10 e com janela de 100.

| Captura | Rótulo | Categoria esperada | Janela do dataset | Tamanho (MB) | Pacotes | Quadros IPv4 e ARP | Janelas de 10 | Janelas de 100 |
|---|---|---|---|---|---|---|---|---|
| `DDoS-HTTP_Flood-.pcap` | `DDoS-HTTP_Flood` | DDoS+DoS | 100 | 610,9 | 2.881.005 | 2.875.590 | 287.559 | 28.756 |
| `DoS-HTTP_Flood1.pcap` | `DoS-HTTP_Flood` | DDoS+DoS | 100 | 1.491,7 | 3.114.983 | 3.109.872 | 310.988 | 31.099 |
| `Mirai-greip_flood21.pcap` | `Mirai-greip_flood` | Mirai | 100 | 704,5 | 1.196.296 | 1.195.447 | 119.545 | 11.955 |
| `Recon-PortScan.pcap` | `Recon-PortScan` | Recon | 10 | 201,0 | 831.856 | 822.771 | 82.278 | 8.228 |
| `DictionaryBruteForce.pcap` | `DictionaryBruteForce` | BruteForce | 10 | 39,1 | 133.138 | 130.632 | 13.064 | 1.307 |

**Condições.** A janela com que o dataset agrega a classe da captura é o **controle**. A outra é o
**teste**: janela de 10 nas três capturas de flood, e de 100 na de varredura e na de força bruta.

**Medida.** Para cada captura, janela e modelo, a categoria prevista de cada janela e a fração das
janelas na categoria esperada. Todas as janelas de uma captura levam o rótulo do ataque capturado. O que
interessa é quanto a fração muda do controle para o teste, mais do que o valor de cada um.

## Ressalvas

Valem para todas as tabelas, e por isso vêm antes dos números.

**1. O controle contém dados parecidos com os de treino.** As linhas oficiais destes pcaps fazem parte
do dataset de onde saiu a amostra de treino. A extração contínua do controle não é o CSV oficial, porque
sem o fatiamento as janelas se alinham de outra forma depois do primeiro pedaço, mas parte das janelas
sai igual. A tabela conta as janelas com as 39 features idênticas às de uma linha de treino, em 32 bits,
e quantas delas repetem uma linha de treino do mesmo rótulo da captura. Por isso o valor do controle não
é uma medida em dado novo. O teste é a outra janela.

| Captura | Controle: idênticas a uma linha de treino | das quais, do mesmo rótulo | Teste: idênticas a uma linha de treino | das quais, do mesmo rótulo |
|---|---|---|---|---|
| `DDoS-HTTP_Flood-.pcap` | 424 de 28.756 (1,47%) | 417 | 5.605 de 287.559 (1,95%) | 0 |
| `DoS-HTTP_Flood1.pcap` | 1.023 de 31.099 (3,29%) | 1.019 | 29.405 de 310.988 (9,46%) | 0 |
| `Mirai-greip_flood21.pcap` | 110 de 11.955 (0,92%) | 110 | 2 de 119.545 (0,00%) | 2 |
| `Recon-PortScan.pcap` | 6.958 de 82.278 (8,46%) | 6.465 | 0 de 8.228 (0,00%) | 0 |
| `DictionaryBruteForce.pcap` | 2.929 de 13.064 (22,42%) | 2.924 | 0 de 1.307 (0,00%) | 0 |

Os rótulos que a amostra de treino dá aos vetores que se repetem na condição de teste. A janela conta
uma vez em cada rótulo que o vetor dela tem no treino:

- `DDoS-HTTP_Flood-.pcap`, janela de 10: `Recon-PortScan` (4.785 janelas), `Recon-OSScan` (4.121 janelas), `BenignTraffic` (71 janelas) e mais 8 rótulos.
- `DoS-HTTP_Flood1.pcap`, janela de 10: `Recon-PortScan` (27.605 janelas), `Recon-OSScan` (26.387 janelas), `VulnerabilityScan` (150 janelas) e mais 8 rótulos.
- `Mirai-greip_flood21.pcap`, janela de 10: `Mirai-greip_flood` (2 janelas).

**2. O rótulo é da captura, e não da janela.** Todas as janelas de um pcap levam o rótulo do ataque, mas
as janelas juntam quadros seguidos de todos os dispositivos da rede, e parte delas pode conter só tráfego de
fundo de outros dispositivos. É uma hipótese levantada na revisão e registrada no `ROADMAP.md`, ainda sem
medida versionada. Por isso o valor absoluto do controle não é 100%, e a leitura é pela diferença entre as
duas janelas da mesma captura.

**3. São 5 capturas.** Uma ou duas por categoria: 2 de DDoS+DoS, 1 de Mirai, 1 de Recon e 1 de BruteForce. Não há captura de tráfego benigno, nem de Spoofing, nem de Web. Este teste não é uma avaliação das 34 classes, e nada nele mede o alarme falso sobre tráfego benigno.

**4. Uma semente.** Os modelos são os da semente 42. O teste não foi repetido com outras sementes, e por isso não diz quanto de uma diferença pequena é ruído.

**5. O relatório não recomenda uma saída.** Ele entrega os números e diz, para cada saída em avaliação, o
que ela ganharia ou perderia segundo eles.

## Tabela principal

Fração das janelas de cada captura que o modelo põe na categoria esperada. Em cada captura, a primeira
linha é o controle e a segunda é o teste.

| Captura | Categoria esperada | Janela | Condição | Janelas | 39 features, priori da amostra | 39 features, priori natural | 33 features, priori da amostra | 33 features, priori natural |
|---|---|---|---|---|---|---|---|---|
| `DDoS-HTTP_Flood-.pcap` | DDoS+DoS | 100 | controle | 28.756 | 100,00% | 99,89% | 99,79% | 99,49% |
| `DDoS-HTTP_Flood-.pcap` | DDoS+DoS | 10 | teste | 287.559 | 0,20% | 0,52% | 70,40% | 69,71% |
| `DoS-HTTP_Flood1.pcap` | DDoS+DoS | 100 | controle | 31.099 | 100,00% | 100,00% | 98,76% | 98,21% |
| `DoS-HTTP_Flood1.pcap` | DDoS+DoS | 10 | teste | 310.988 | 0,04% | 1,33% | 57,16% | 54,93% |
| `Mirai-greip_flood21.pcap` | Mirai | 100 | controle | 11.955 | 100,00% | 100,00% | 100,00% | 100,00% |
| `Mirai-greip_flood21.pcap` | Mirai | 10 | teste | 119.545 | 97,92% | 98,22% | 99,90% | 99,92% |
| `Recon-PortScan.pcap` | Recon | 10 | controle | 82.278 | 92,66% | 77,46% | 92,29% | 76,64% |
| `Recon-PortScan.pcap` | Recon | 100 | teste | 8.228 | 0,00% | 0,00% | 16,27% | 17,79% |
| `DictionaryBruteForce.pcap` | BruteForce | 10 | controle | 13.064 | 48,94% | 13,56% | 48,46% | 12,70% |
| `DictionaryBruteForce.pcap` | BruteForce | 100 | teste | 1.307 | 0,00% | 0,00% | 2,98% | 0,38% |

### Quanto muda

A fração do teste menos a do controle, em pontos percentuais.

| Captura | Janela | 39 features, priori da amostra | 39 features, priori natural | 33 features, priori da amostra | 33 features, priori natural |
|---|---|---|---|---|---|
| `DDoS-HTTP_Flood-.pcap` | de 100 para 10 | -99,80 | -99,37 | -29,39 | -29,78 |
| `DoS-HTTP_Flood1.pcap` | de 100 para 10 | -99,96 | -98,67 | -41,60 | -43,29 |
| `Mirai-greip_flood21.pcap` | de 100 para 10 | -2,08 | -1,78 | -0,10 | -0,08 |
| `Recon-PortScan.pcap` | de 10 para 100 | -92,66 | -77,46 | -76,02 | -58,84 |
| `DictionaryBruteForce.pcap` | de 10 para 100 | -48,94 | -13,56 | -45,48 | -12,32 |

## Para onde vão as janelas

A distribuição das categorias previstas, como fração das janelas de cada captura. Uma tabela por modelo.

### `f39_estratificada_c7`: 39 features, priori da amostra

| Captura | Janela | Condição | DDoS+DoS | Mirai | Recon | Spoofing | Web | BruteForce | Benign |
|---|---|---|---|---|---|---|---|---|---|
| `DDoS-HTTP_Flood-.pcap` | 100 | controle | 100,00% | 0,00% | 0,00% | 0,00% | 0,00% | 0,00% | 0,00% |
| `DDoS-HTTP_Flood-.pcap` | 10 | teste | 0,20% | 0,00% | 83,77% | 2,18% | 12,75% | 0,14% | 0,97% |
| `DoS-HTTP_Flood1.pcap` | 100 | controle | 100,00% | 0,00% | 0,00% | 0,00% | 0,00% | 0,00% | 0,00% |
| `DoS-HTTP_Flood1.pcap` | 10 | teste | 0,04% | 0,00% | 84,35% | 2,01% | 12,41% | 0,10% | 1,09% |
| `Mirai-greip_flood21.pcap` | 100 | controle | 0,00% | 100,00% | 0,00% | 0,00% | 0,00% | 0,00% | 0,00% |
| `Mirai-greip_flood21.pcap` | 10 | teste | 0,00% | 97,92% | 0,05% | 2,03% | 0,00% | 0,00% | 0,00% |
| `Recon-PortScan.pcap` | 10 | controle | 0,00% | 0,00% | 92,66% | 1,10% | 0,56% | 0,36% | 5,32% |
| `Recon-PortScan.pcap` | 100 | teste | 99,99% | 0,01% | 0,00% | 0,00% | 0,00% | 0,00% | 0,00% |
| `DictionaryBruteForce.pcap` | 10 | controle | 0,00% | 0,00% | 41,96% | 2,42% | 1,63% | 48,94% | 5,04% |
| `DictionaryBruteForce.pcap` | 100 | teste | 98,93% | 1,07% | 0,00% | 0,00% | 0,00% | 0,00% | 0,00% |

### `f39_estratificada_c7_natural`: 39 features, priori natural

| Captura | Janela | Condição | DDoS+DoS | Mirai | Recon | Spoofing | Web | BruteForce | Benign |
|---|---|---|---|---|---|---|---|---|---|
| `DDoS-HTTP_Flood-.pcap` | 100 | controle | 99,89% | 0,11% | 0,00% | 0,00% | 0,00% | 0,00% | 0,00% |
| `DDoS-HTTP_Flood-.pcap` | 10 | teste | 0,52% | 0,00% | 93,67% | 1,05% | 0,91% | 0,00% | 3,85% |
| `DoS-HTTP_Flood1.pcap` | 100 | controle | 100,00% | 0,00% | 0,00% | 0,00% | 0,00% | 0,00% | 0,00% |
| `DoS-HTTP_Flood1.pcap` | 10 | teste | 1,33% | 0,00% | 84,55% | 2,44% | 3,52% | 0,00% | 8,16% |
| `Mirai-greip_flood21.pcap` | 100 | controle | 0,00% | 100,00% | 0,00% | 0,00% | 0,00% | 0,00% | 0,00% |
| `Mirai-greip_flood21.pcap` | 10 | teste | 0,00% | 98,22% | 0,03% | 1,75% | 0,00% | 0,00% | 0,00% |
| `Recon-PortScan.pcap` | 10 | controle | 0,00% | 0,00% | 77,46% | 1,90% | 0,01% | 0,00% | 20,63% |
| `Recon-PortScan.pcap` | 100 | teste | 99,95% | 0,05% | 0,00% | 0,00% | 0,00% | 0,00% | 0,00% |
| `DictionaryBruteForce.pcap` | 10 | controle | 0,00% | 0,00% | 47,16% | 5,04% | 0,01% | 13,56% | 34,23% |
| `DictionaryBruteForce.pcap` | 100 | teste | 88,98% | 11,02% | 0,00% | 0,00% | 0,00% | 0,00% | 0,00% |

### `f33_estratificada_c7`: 33 features, priori da amostra

| Captura | Janela | Condição | DDoS+DoS | Mirai | Recon | Spoofing | Web | BruteForce | Benign |
|---|---|---|---|---|---|---|---|---|---|
| `DDoS-HTTP_Flood-.pcap` | 100 | controle | 99,79% | 0,00% | 0,19% | 0,01% | 0,00% | 0,00% | 0,00% |
| `DDoS-HTTP_Flood-.pcap` | 10 | teste | 70,40% | 0,00% | 24,23% | 0,85% | 3,82% | 0,03% | 0,67% |
| `DoS-HTTP_Flood1.pcap` | 100 | controle | 98,76% | 0,00% | 1,22% | 0,01% | 0,01% | 0,00% | 0,00% |
| `DoS-HTTP_Flood1.pcap` | 10 | teste | 57,16% | 0,00% | 35,05% | 1,12% | 5,88% | 0,03% | 0,77% |
| `Mirai-greip_flood21.pcap` | 100 | controle | 0,00% | 100,00% | 0,00% | 0,00% | 0,00% | 0,00% | 0,00% |
| `Mirai-greip_flood21.pcap` | 10 | teste | 0,00% | 99,90% | 0,02% | 0,08% | 0,00% | 0,00% | 0,00% |
| `Recon-PortScan.pcap` | 10 | controle | 0,63% | 0,00% | 92,29% | 1,10% | 0,50% | 0,33% | 5,15% |
| `Recon-PortScan.pcap` | 100 | teste | 83,64% | 0,00% | 16,27% | 0,04% | 0,01% | 0,00% | 0,04% |
| `DictionaryBruteForce.pcap` | 10 | controle | 0,03% | 0,00% | 42,64% | 2,30% | 1,57% | 48,46% | 4,99% |
| `DictionaryBruteForce.pcap` | 100 | teste | 95,64% | 0,69% | 0,61% | 0,00% | 0,00% | 2,98% | 0,08% |

### `f33_estratificada_c7_natural`: 33 features, priori natural

| Captura | Janela | Condição | DDoS+DoS | Mirai | Recon | Spoofing | Web | BruteForce | Benign |
|---|---|---|---|---|---|---|---|---|---|
| `DDoS-HTTP_Flood-.pcap` | 100 | controle | 99,49% | 0,05% | 0,36% | 0,02% | 0,00% | 0,00% | 0,07% |
| `DDoS-HTTP_Flood-.pcap` | 10 | teste | 69,71% | 0,03% | 26,43% | 0,89% | 0,52% | 0,00% | 2,43% |
| `DoS-HTTP_Flood1.pcap` | 100 | controle | 98,21% | 0,00% | 1,72% | 0,03% | 0,01% | 0,00% | 0,03% |
| `DoS-HTTP_Flood1.pcap` | 10 | teste | 54,93% | 0,00% | 34,02% | 1,42% | 2,76% | 0,00% | 6,87% |
| `Mirai-greip_flood21.pcap` | 100 | controle | 0,00% | 100,00% | 0,00% | 0,00% | 0,00% | 0,00% | 0,00% |
| `Mirai-greip_flood21.pcap` | 10 | teste | 0,00% | 99,92% | 0,01% | 0,07% | 0,00% | 0,00% | 0,00% |
| `Recon-PortScan.pcap` | 10 | controle | 0,76% | 0,00% | 76,64% | 1,95% | 0,01% | 0,00% | 20,64% |
| `Recon-PortScan.pcap` | 100 | teste | 81,39% | 0,01% | 17,79% | 0,11% | 0,00% | 0,00% | 0,69% |
| `DictionaryBruteForce.pcap` | 10 | controle | 0,36% | 0,00% | 47,38% | 4,93% | 0,00% | 12,70% | 34,63% |
| `DictionaryBruteForce.pcap` | 100 | teste | 86,99% | 7,57% | 1,84% | 0,08% | 0,00% | 0,38% | 3,14% |

## O que os números dizem sobre cada saída em avaliação

Só o que cada saída ganharia ou perderia segundo as tabelas acima. As faixas vão do menor ao maior valor
entre os modelos: os 4 no controle e, no teste, os de cada conjunto de features (2 com 39 e 2 com 33), que diferem pela priori de treino. As ressalvas do começo valem para tudo o que segue.

### Janela única de 10 na operação

Com o extrator fixo em 10, as classes que o dataset agrega em 10 chegam ao modelo como no treino, e as que ele agrega em 100 chegam na condição de teste.

- Ficam no controle: `Recon-PortScan.pcap`, com 76,64% a 92,66% das janelas em Recon conforme o modelo; `DictionaryBruteForce.pcap`, com 12,70% a 48,94% das janelas em BruteForce conforme o modelo.
- Passam à condição de teste:
  - `DDoS-HTTP_Flood-.pcap`: com a janela de 100, 99,49% a 100,00% das janelas ficam em DDoS+DoS. Com a de 10, 0,20% a 0,52% com as 39 features (diferença de -99,80 a -99,37 p.p.) e 69,71% a 70,40% com as 33 features (diferença de -29,78 a -29,39 p.p.). A categoria mais prevista com a janela de 10 é Recon (83,77% a 93,67% das janelas) com as 39 features e DDoS+DoS (69,71% a 70,40% das janelas) com as 33 features.
  - `DoS-HTTP_Flood1.pcap`: com a janela de 100, 98,21% a 100,00% das janelas ficam em DDoS+DoS. Com a de 10, 0,04% a 1,33% com as 39 features (diferença de -99,96 a -98,67 p.p.) e 54,93% a 57,16% com as 33 features (diferença de -43,29 a -41,60 p.p.). A categoria mais prevista com a janela de 10 é Recon (84,35% a 84,55% das janelas) com as 39 features e DDoS+DoS (54,93% a 57,16% das janelas) com as 33 features.
  - `Mirai-greip_flood21.pcap`: com a janela de 100, 100,00% das janelas ficam em Mirai. Com a de 10, 97,92% a 98,22% com as 39 features (diferença de -2,08 a -1,78 p.p.) e 99,90% a 99,92% com as 33 features (diferença de -0,10 a -0,08 p.p.). A categoria mais prevista com a janela de 10 é Mirai (97,92% a 98,22% das janelas) com as 39 features e Mirai (99,90% a 99,92% das janelas) com as 33 features.
- Fora desta medida: o tráfego benigno e as categorias de ataque sem captura (Spoofing e Web), que o dataset já agrega em 10. Para eles continuam valendo as medidas do treino exploratório.

### Janela única de 100 na operação

Com o extrator fixo em 100, as classes que o dataset agrega em 100 chegam ao modelo como no treino, e as que ele agrega em 10 chegam na condição de teste.

- Ficam no controle: `DDoS-HTTP_Flood-.pcap`, com 99,49% a 100,00% das janelas em DDoS+DoS conforme o modelo; `DoS-HTTP_Flood1.pcap`, com 98,21% a 100,00% das janelas em DDoS+DoS conforme o modelo; `Mirai-greip_flood21.pcap`, com 100,00% das janelas em Mirai.
- Passam à condição de teste:
  - `Recon-PortScan.pcap`: com a janela de 10, 76,64% a 92,66% das janelas ficam em Recon. Com a de 100, 0,00% com as 39 features (diferença de -92,66 a -77,46 p.p.) e 16,27% a 17,79% com as 33 features (diferença de -76,02 a -58,84 p.p.). A categoria mais prevista com a janela de 100 é DDoS+DoS (99,95% a 99,99% das janelas) com as 39 features e DDoS+DoS (81,39% a 83,64% das janelas) com as 33 features.
  - `DictionaryBruteForce.pcap`: com a janela de 10, 12,70% a 48,94% das janelas ficam em BruteForce. Com a de 100, 0,00% com as 39 features (diferença de -48,94 a -13,56 p.p.) e 0,38% a 2,98% com as 33 features (diferença de -45,48 a -12,32 p.p.). A categoria mais prevista com a janela de 100 é DDoS+DoS (88,98% a 98,93% das janelas) com as 39 features e DDoS+DoS (86,99% a 95,64% das janelas) com as 33 features.
- Uma janela de 100 leva dez vezes mais quadros para fechar: `Recon-PortScan.pcap` dá 8.228 janelas de 100, contra 82.278 de 10; `DictionaryBruteForce.pcap` dá 1.307 janelas de 100, contra 13.064 de 10.
- Fora desta medida: o tráfego benigno e as categorias de ataque sem captura (Spoofing e Web), agregados em 100. Nenhum dos pcaps é dessas classes, e o alarme falso sobre tráfego benigno em janelas de 100 fica sem número.

### Janelas regeradas dos pcaps

Nesta saída o treino muda: as janelas de todas as classes seriam geradas de novo, a partir dos pcaps, com
um tamanho só, e treino e operação passariam a usar a mesma janela.

- Este teste não treina com janelas regeradas, e por isso não mede o que a saída entregaria. Ele mede o descompasso que ela teria de fechar, que é a diferença do controle para o teste, aqui na faixa entre os 4 modelos: `DDoS-HTTP_Flood-.pcap`, agregado em 10, de -99,80 a -29,39 p.p.; `DoS-HTTP_Flood1.pcap`, agregado em 10, de -99,96 a -41,60 p.p.; `Mirai-greip_flood21.pcap`, agregado em 10, de -2,08 a -0,08 p.p.; `Recon-PortScan.pcap`, agregado em 100, de -92,66 a -58,84 p.p.; `DictionaryBruteForce.pcap`, agregado em 100, de -48,94 a -12,32 p.p.
- O extrator leu os 5 pcaps inteiros com as duas janelas, em 121,4 s no total, e as extrações são as que a regeração usaria para estas capturas.
- Com janela de 100, as classes hoje agregadas em 10 ficam com cerca de um décimo das linhas: `Recon-PortScan.pcap` passa de 82.278 linhas para 8.228; `DictionaryBruteForce.pcap` passa de 13.064 linhas para 1.307.
- A regeração depende de ter o pcap de cada classe. Aqui são 5 pcaps, de 34 classes, com 3,0 GB somados.
- Fora desta medida: o desempenho de um modelo treinado com janelas regeradas, com qualquer das duas janelas.

### Limitação declarada

Nesta saída o treino e a extração ficam como estão, e o artigo declara o descompasso.

- O que haveria a declarar é o que este teste mediu. Da janela do dataset para a outra, a fração das janelas na categoria esperada muda, na faixa entre os 4 modelos: `DDoS-HTTP_Flood-.pcap`, agregado em 10, de -99,80 a -29,39 p.p.; `DoS-HTTP_Flood1.pcap`, agregado em 10, de -99,96 a -41,60 p.p.; `Mirai-greip_flood21.pcap`, agregado em 10, de -2,08 a -0,08 p.p.; `Recon-PortScan.pcap`, agregado em 100, de -92,66 a -58,84 p.p.; `DictionaryBruteForce.pcap`, agregado em 100, de -48,94 a -12,32 p.p.
- A declaração teria de trazer também os limites da medida: 5 capturas, uma semente e um controle em que 0,92% a 22,38% das janelas, conforme a captura, repetem uma linha de treino do mesmo rótulo.
- A saída não mexe no treino nem na extração: o descompasso medido nestas capturas fica como está.

O relatório não recomenda nenhuma das saídas.

## Como os números foram obtidos

- Comando: `python -m codigo.classificador.janela`, a partir da raiz do repositório. Ele refaz a extração, o treino, a pontuação e este relatório. Semente 42 na divisão e nos modelos.
- Amostra: `dados/processed/amostra.csv.gz`, com SHA-256 do CSV descomprimido `f23c098dc10faf3f857a473f8c793fc2642098d9046f11cbc76d83e20e505b8f`, conferido com `manifesto_amostra.json` antes de treinar.
- Modelos: `RandomForestClassifier` do scikit-learn com os parâmetros padrão, 100 árvores e sem `StandardScaler`, treinados com 4 núcleos. A quantidade de núcleos muda o tempo, e não o modelo. Na priori natural, o `sample_weight` de cada linha de treino é a contagem do rótulo no conjunto completo dividida pela contagem dele no treino, como no treino exploratório.
- Predição: votos das árvores somados em ordem fixa, com um núcleo, para a mesma entrada dar sempre a
  mesma resposta.
- Extração: `codigo.captura.extrator.extrair` sobre o arquivo inteiro. Das 10 extrações, 9 terminam em uma janela incompleta, a última do arquivo, que entra na conta como as outras.
- Pcaps, com o tamanho e o SHA-256 de cada um:
  - `DDoS-HTTP_Flood-.pcap`: 610.856.427 bytes, `299c6f2180b3cf94ebb14e3e5aa5afe16ff51eac232f7f2c61a4384443eb7387`
  - `DoS-HTTP_Flood1.pcap`: 1.491.704.312 bytes, `2b7df8fce78461e435952e39cb2e33c445b137fa08ee7429d97fde6d93032d40`
  - `Mirai-greip_flood21.pcap`: 704.513.741 bytes, `5a77e5c663c31759d7834047bd85197dfd51f2cb7dcc22bfe0a8d1dbf1973742`
  - `Recon-PortScan.pcap`: 200.950.957 bytes, `e13368bdc571a6ec53f8dd9e5491137dd0656c9d997bd62b323e957722bd4fc1`
  - `DictionaryBruteForce.pcap`: 39.130.622 bytes, `09ad3cfabd139b950da3078fec0f0fd196fe36cd82237d898035437f4c69161b`
- Tempo, na máquina em que rodou: 121,4 s de extração, 109,4 s de treino e 24,3 s de pontuação, em 255,7 s no total.
- `teste_da_janela.csv` tem uma linha por captura, janela, modelo e categoria prevista. `manifesto_teste_da_janela.json` traz os mesmos números, as contagens de cada extração e as medidas de cada modelo na parte de teste da amostra.
- Com a mesma amostra, os mesmos pcaps e a mesma semente, a tabela sai idêntica. Só mudam a data e os tempos.
- Conferência por outro caminho: extrair uma captura com `python -m codigo.captura.extrator --janela N`,
  treinar o modelo com `python -m codigo.classificador.treinar --alvo 7` e pontuar com
  `python -m codigo.classificador.avaliar MODELO --csv CAPTURA.csv --rotulo ROTULO`. O recall da categoria
  esperada é a fração da tabela principal.

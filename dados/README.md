# Dados — como montar o ambiente

O dataset **não é versionado no git**: o `MERGED_CSV` tem 8,7 GB, e os 38 pcaps usados na
regeração somam cerca de 46 GB. O repositório guarda o código e as decisões; os dados são uma
dependência que se instala, na mesma lógica do `node_modules`.

Este arquivo é a receita. Seguindo ele, qualquer integrante chega ao mesmo ponto.

## De onde vem

**CICIoT2023** — Canadian Institute for Cybersecurity (UNB).

- **Fonte oficial:** <http://cicresearch.ca/IOTDataset/CIC_IOT_Dataset2023/>
  (exige preencher um formulário de cadastro antes de liberar os arquivos)

A pasta do grupo no Google Drive deixou de ser usada em 04/10/2026, porque o conjunto é pesado
demais para manter lá. Cada pessoa baixa da fonte oficial só o que a sua tarefa pede:

| Para | O que baixar | Tamanho |
|---|---|---|
| Rodar os testes (`pytest`) | Nada. Os testes que dependem do dataset são pulados | 0 |
| Regerar os dados de treino e treinar o classificador | Os pcaps, ao menos um por classe (ver "Regeração dos dados de treino") | de 3 MB a 2 GB por pcap |
| Treinar na amostra do `MERGED_CSV` (treino exploratório) | `MERGED_CSV/` | 8,7 GB |
| Recalibrar o extrator (opcional) | O pcap do ataque e a pasta de CSV por ataque correspondente | de 39 MB a 1,5 GB por pcap |
| Refazer a calibração de conjunto (opcional) | Os 38 pcaps e o `MERGED_CSV/` | cerca de 46 GB e 8,7 GB |

Não usar re-uploads de terceiros (Kaggle e afins): não dá para citar a origem no artigo e não há
garantia de que o conteúdo bate com o oficial.

## Onde colocar

A pasta `CICIoT2023/` vai na **raiz do repositório**, irmã de `codigo/` e `artigo/`.
Já está no `.gitignore`.

```
TCC/CICIoT2023/
├── MERGED_CSV/                  <- o conjunto oficial em CSV (63 arquivos, 8,7 GB), usado na
│                                   exploração e no treino exploratório
├── <34 pastas, uma por ataque>/ <- CSVs por ataque, sem rótulo. OPCIONAIS: só servem para
│                                   recalibrar o extrator (a calibração já foi feita)
├── *.pcap                       <- os pcaps, de um a três por classe, de onde os dados de treino
│                                   são regerados (ver "Regeração dos dados de treino")
├── pcap2csv/                    <- o extrator DOS AUTORES (código de referência)
├── example.ipynb                <- notebook de ML dos autores (ler as ressalvas abaixo)
├── tools/                       <- notas das ferramentas usadas
├── README.pdf  README_CSV.pdf
```

---

## O conjunto oficial em CSV: `MERGED_CSV/`

**Desde 10/10/2026 não é a fonte do treino do sistema**, que usa os dados regerados dos pcaps (ver
"Regeração dos dados de treino a partir dos pcaps"). O `MERGED_CSV` serve à exploração e ao
treino exploratório. São 63 arquivos, cerca de 45,0 milhões de linhas no total, 8,7 GB.

- **40 colunas: as 39 features + `Label`** (com L maiúsculo).
- As 39 features são **idênticas** às dos CSVs por ataque e às que o `pcap2csv` produz,
  conferido coluna por coluna. É a base para treino e operação usarem os mesmos números, com a
  ressalva do tamanho da janela (ver "Janela de 10 ou de 100 pacotes").
- Já vem mesclado entre ataques e embaralhado: cada arquivo contém linhas de todas as 34 classes.

**Por que 63 arquivos e não um só:** é saída do PySpark (cada trabalhador grava a sua parte), e
8,7 GB num arquivo único seria inabrível. Cada pedaço tem cerca de 140 MB e cabe na memória.

**Nove arquivos oficiais estão truncados** (`Merged42`, `Merged44` e `Merged46` a `Merged52`):
terminam no meio de uma linha, e os dois últimos têm só 44 MB e 14 MB. A cópia tem 45.019.234 linhas
completas, e em quase todas as classes faltam cerca de 4,3% das linhas que os CSVs por ataque
trazem. As proporções entre as classes não mudam, porque o conjunto é embaralhado. Três CSVs por
ataque de `DoS-UDP_Flood` (7, 8 e 9) têm o mesmo defeito. O corte está nos arquivos da fonte
oficial: em 04/10/2026 os doze foram baixados de novo e vieram idênticos, byte a byte, aos que já
tínhamos. A linha incompleta de cada um fica fora das contagens e da amostra. Os números estão em
`experimentos/resultados/exploracao.md`.

**Cada arquivo é representativo do conjunto todo** (contagem feita à mão em 05/09/2026, sem
script versionado):

| | Linhas | DDOS-ICMP | BENIGN | BruteForce | PortScan |
|---|---|---|---|---|---|
| Merged01 | 712.311 | 15,25% | 2,33% | 204 | 1.251 |
| Merged32 | 704.067 | 15,24% | 2,34% | 193 | 1.205 |
| Merged63 | 428.161 | 15,33% | 2,38% | 116 | 726 |

### Como amostrar para o treino exploratório

8,7 GB não cabem na memória, e o treino exploratório precisa de tudo junto. A estratégia:

**percorrer os 63 arquivos guardando TODAS as linhas das classes raras e só uma fatia das
classes gigantes** (um teto de 50 mil por classe). Isso derruba de 45,0 milhões para 1.288.479
linhas e ataca o desbalanceamento ao mesmo tempo.

Nas classes raras, usar os 63 arquivos faz diferença real: `DICTIONARYBRUTEFORCE` sai de 204
exemplos (1 arquivo) para 12.522 (63 arquivos).

⚠ O script de amostragem **precisa ficar versionado, com semente fixa**, e a estratégia precisa
ir para a metodologia do artigo. Sem isso o resultado não é reproduzível.

    python -m codigo.classificador.amostrar

O comando grava `dados/processed/amostra.csv.gz`, que fica fora do git, e o manifesto
`experimentos/resultados/manifesto_amostra.json`, que é versionado: semente, teto, contagem por
classe e hash da amostra. Com os mesmos arquivos de entrada, a amostra sai idêntica a cada execução.

### Armadilha dos rótulos

No `MERGED_CSV` os rótulos vêm **em maiúsculas** (`DDOS-ICMP_FLOOD`), mas o dicionário de
agrupamento do notebook dos autores usa a grafia normal (`DDoS-ICMP_Flood`). Aplicar o dicionário
direto não casa com nada e zera tudo em silêncio. **Normalizar antes.**

Pôr o dicionário em maiúsculas também não resolve: o tráfego benigno aparece como `BENIGN` no
`MERGED_CSV`, e não como `BENIGNTRAFFIC`. A normalização está em
`codigo/classificador/mapeamento.py`, que recusa qualquer rótulo fora das 34 classes.

---

## Decisões já tomadas

**Os dados de treino são regerados a partir dos pcaps, em janela única e com o rótulo pelo
atacante** (10/10/2026). O `MERGED_CSV` fica como referência e como fonte do treino exploratório.
O motivo e a receita estão em "Regeração dos dados de treino", abaixo.

**O modelo do sistema treina com o tráfego de fundo da parte de treino como benigno e decide pelo
ponto de operação escolhido na validação** (13/10/2026). As janelas sem nenhum quadro do atacante
que ficam na parte de treino de cada pcap de ataque entram no treino como `Benign`. A regra de
decisão da janela é escolhida numa parte de validação, entre a categoria mais provável (argmax) e o
limiar sobre 1 − P(Benign); no modelo do sistema, venceu o argmax. O incidente só abre com 3
janelas de ataque seguidas. O treino de 10/10, sem o fundo, fica como referência.
Detalhes em "O treino", abaixo, e os motivos no `ROADMAP.md`.

**Usamos as 39 features do `MERGED_CSV`.** Treino e operação partem do mesmo conjunto de colunas,
e o extrator reproduz os valores oficiais nos cinco pcaps calibrados, com janela de 10 e de 100;
a calibração de conjunto confirma o cálculo nos 38 pcaps (ver "Calibração do extrator"). A
leitura é de arquivo pcap; a captura ao vivo ainda não foi entregue. (Havia uma versão de 46
features; as 7 extras não saem do código publicado pelos autores, porque as linhas que as
calculariam estão comentadas no `Feature_extraction.py`, linhas 132 e 171. Por isso ela foi
descartada.)

**Classificamos em 7 categorias, não em 34 variantes** (decisão de 04/10/2026). O ponto de
partida é o `dict_7classes` do `example.ipynb` (célula 14), o agrupamento oficial dos autores, que
tem 8 categorias contando o tráfego benigno; aqui, DDoS e DoS viram uma categoria só. As 39
features descrevem os pacotes, e não quantas máquinas atacam: 29,5% das linhas do `MERGED_CSV`
têm o vetor igual ao de uma linha de outra categoria, quase sempre o mesmo flood rotulado como
DDoS e como DoS. A separação entre os dois sai da quantidade de IPs de origem do incidente, fora
do modelo. Os agentes não precisam da variante exata: a mitigação de um `DDoS-ICMP_Flood` e a de
um `DDoS-UDP_Flood` são a mesma.

**Não gastar semanas no classificador.** O benchmark dos autores põe o RF entre os dois melhores
modelos, com a rede neural. Seguimos essa escolha sem reproduzir o resultado deles, porque o
código do treino do RF não foi publicado (ver a seção seguinte): a contribuição do trabalho é a
camada MCP com os agentes.

---

## O `example.ipynb` — usar com cuidado

Serve como referência de estrutura e como citação, **não como código para rodar**. Três problemas
verificados no arquivo:

1. **Ele não treina Random Forest.** O `RandomForestClassifier` é importado (células 15 e 20) e
   nunca instanciado — só roda `LogisticRegression`. O RF do artigo não foi publicado.
2. **O laço de treino está errado.** Chamar `.fit()` repetidamente no scikit-learn **não acumula**
   — cada chamada descarta o aprendizado anterior. O laço treina só no último arquivo da lista.
   Mesmo problema com o `scaler.fit()` dentro do laço.
3. **As métricas estão com os argumentos invertidos** (`recall_score(y_pred, y_test)`). A ordem
   certa é `(y_test, y_pred)`; invertido, o que ele chama de recall é precisão e vice-versa.

O que aproveitar dele: os dicionários `dict_7classes` e `dict_2classes`, e a estrutura de avaliação.

**Não usar `StandardScaler` com Random Forest.** Árvores não ligam para escala, e sem scaler o
número que sai do extrator entra direto no modelo — um artefato a menos para versionar e sincronizar.

---

## Calibração do extrator

O `pcap2csv/` é o extrator dos autores e serve de referência. O nosso fica em
`codigo/captura/extrator.py` e é conferido pelo `codigo/captura/calibrar.py`, que compara a saída
com os CSVs oficiais e grava o resultado em `experimentos/resultados/calibracao.md`.

    python -m codigo.captura.calibrar

Como o CSV oficial é gerado (lido no código dos autores, confirmado nos cinco pcaps calibrados e
descrito no artigo do dataset):

1. O pcap é fatiado com `tcpdump`, em pedaços de 10 MB.
2. Cada pedaço é processado sozinho. Só entram quadros Ethernet de tipo IPv4 ou ARP.
3. Os quadros mantidos são agregados em janelas de quadros consecutivos, e não em janelas de
   tempo. O código publicado traz a janela fixa em 10 (`Feature_extraction.py`, linha 475,
   `n_rows = 10`), mas os autores usaram 100 nas classes de flood. Ver a seção seguinte.
   A última janela de cada pedaço pode ficar incompleta, o que aparece na coluna `Number`.
4. Os CSVs dos pedaços são juntados sem ordem definida. Por isso a ordem das linhas do CSV oficial
   não é cronológica, e a comparação é feita bloco a bloco.

Stack real dos autores (de `tools/`, do código e do artigo): `tcpdump` captura e fatia, `dpkt` faz
o parsing, `mergecap` junta capturas e `PySpark` junta os CSVs. O Scapy é importado pelo código,
mas não contribui para nenhuma das 39 colunas.

**Resultado da calibração** (04/10/2026, detalhes em `experimentos/resultados/calibracao.md`):

| Arquivo | Janela | Pacotes | Quadros IPv4 e ARP | Linhas no CSV oficial | Linhas reproduzidas |
|---|---|---|---|---|---|
| `DictionaryBruteForce.pcap` | 10 | 133.138 | 130.632 | 13.064 | 13.064 |
| `Recon-PortScan.pcap` | 10 | 831.856 | 822.771 | 82.284 | 82.284 |
| `DDoS-HTTP_Flood-.pcap` | 100 | 2.881.005 | 2.875.590 | 28.790 | 28.790 |
| `DoS-HTTP_Flood1.pcap` | 100 | 3.114.983 | 3.109.872 | 31.175 | 31.175 |
| `Mirai-greip_flood21.pcap` | 100 | 1.196.296 | 1.195.447 | 11.991 | 11.991 |

A diferença entre pacotes e quadros mantidos vem do filtro: IPv6, STP e outros tipos de quadro
ficam de fora. A soma da coluna `Number` do CSV oficial é igual à contagem de quadros IPv4 e ARP
nos cinco pcaps.

A janela de 100 foi calibrada em 04/10/2026 com um pcap de cada família que a usa: DDoS, DoS e
Mirai. O calibrador lê o tamanho da janela do próprio CSV oficial, então basta acrescentar um
pcap à pasta do dataset para conferir outra classe.

O pcap de Mirai declara no cabeçalho um limite de captura de 1500 bytes e traz quadros maiores.
A libpcap, usada pelo `tcpdump` com que os autores fatiam o arquivo, entrega esses quadros
cortados no limite. O extrator faz o mesmo, e só assim as linhas oficiais são reproduzidas.

**Calibração de conjunto** (11/10/2026, detalhes em
`experimentos/resultados/calibracao_conjunto.md`). Os CSVs por ataque não estão mais na nossa
cópia do dataset, e a calibração acima cobre só os cinco pcaps que tinham o seu. A de conjunto
confere os 38 pcaps contra o `MERGED_CSV` inteiro: cada pcap é extraído como os autores
extraíram, em pedaços de 10 MB e com a janela da classe, e cada linha nossa é procurada entre as
linhas do mesmo rótulo no `MERGED_CSV`, com os 39 valores iguais até cerca de 9 algarismos
significativos. A prova de que o cálculo é o dos autores é a cobertura: em 15 rótulos, toda
linha do `MERGED_CSV` tem par entre as nossas, e uma divergência do extrator em qualquer janela
deles deixaria uma linha sem par. Do nosso lado, entre 95,53% e 99,00% das linhas de cada pcap
têm par; o que falta vem dos arquivos truncados na fonte oficial. Nos floods e no benigno a
cobertura do rótulo é baixa porque temos uma ou duas partes de capturas maiores: 20 dos 38 pcaps
têm cerca de 2.048.000.000 bytes, o tamanho em que o `tcpdump -C 2048` corta o arquivo.

    python -m codigo.captura.calibrar_conjunto --dataset CICIoT2023 --processos 3

O índice do `MERGED_CSV` chega a cerca de 4,3 GB de memória, e a execução completa levou 27
minutos. Os dados intermediários ficam em `dados/processed/calibracao_conjunto`, fora do git, e
são reaproveitados enquanto os arquivos e o código que os gera não mudarem.

**O quadro como no fio.** O extrator tem duas opções, desligadas por padrão, que medem o tamanho
do quadro como ele passa no fio, e não como a máquina que capturou o gravou: `--preencher` conta
como 60 bytes o quadro menor que isso, gravado sem o preenchimento do Ethernet, e `--limitar`
conta como 1.514 bytes o quadro maior, que só existe com segmentação feita pela placa da máquina
que capturou. No CICIoT2023, `DNS_Spoofing.pcap`, `MITM-ArpSpoofing.pcap` e
`Mirai-greip_flood21.pcap` têm quadros menores que 60 bytes, e 35 dos 38 pcaps têm quadros
maiores que 1.514. As duas opções ficam desligadas na calibração, que reproduz os autores, e no
modelo do sistema: a comparação com elas ligadas está em
`experimentos/resultados/rodadas_normalizadas.md` e não foi adotada; o artefato de captura fica
como limitação declarada (`ROADMAP.md`, decisão de 13/10/2026).

**Avisos da extração.** No fim, a linha de comando do extrator diz quantos quadros ficaram fora
do filtro, por tipo, e avisa em dois casos que mudam os números: quando a maior parte dos quadros
fora tem etiqueta de VLAN (802.1Q ou 802.1ad), que o código dos autores também descarta, e quando
a captura gravou pacotes com menos bytes que o quadro original (limite de captura curto), o que
deixa as colunas de tamanho menores do que no treino. Nos dois casos a correção é na captura:
espelhar a porta sem a VLAN, ou capturar o quadro inteiro, com `tcpdump -s 0`.

---

## Janela de 10 ou de 100 pacotes

O tamanho da janela muda conforme a classe. Está no artigo do dataset (Neto et al., 2023) e foi
medido nos 63 arquivos do `MERGED_CSV` pela coluna `Number`:

| Categorias | Janela | Linhas com a janela completa |
|---|---|---|
| DDoS, DoS, Mirai (19 classes) | 100 pacotes | 99,1% a 99,9% |
| Benign, Recon, Spoofing, Web, BruteForce (15 classes) | 10 pacotes | 99,9% ou mais |

As linhas restantes são a última janela de cada pedaço de 10 MB, que fica incompleta.

Consequências para o projeto:

- **Atalho no treino.** A coluna `Number` sozinha separa as classes de flood das demais. As
  colunas `Tot sum`, `ack_count`, `syn_count`, `fin_count` e `rst_count` são o produto de outra
  coluna por `Number` (conferido em todas as linhas do `MERGED_CSV`), então carregam
  o mesmo atalho. O modelo pode aprender o tamanho da janela em vez do comportamento do tráfego,
  e as métricas das classes de flood saem infladas.
- **Descompasso na operação.** O extrator não conhece a classe antes de classificar, então usa
  uma janela só. Com 10, um flood real chega com números que o modelo só viu em classes que não
  são flood. Com 100, acontece o inverso com o tráfego benigno e as varreduras.
- **O que sobra depois de tirar essas colunas.** `Min`, `Max` e `Std` ainda variam com o tamanho
  da janela, e as médias de uma janela de 100 têm passos de 0,01, contra 0,1 na de 10.

Saídas que foram avaliadas:

1. Remover `Number`, `Tot sum` e as quatro contagens. `Tot sum` e as contagens são o produto de
   uma coluna que fica por `Number`; o que sai é a leitura direta do tamanho da janela. No treino
   exploratório isso custou menos de 0,3 ponto de acurácia e não eliminou o atalho: sem as seis
   colunas o modelo ainda separa os dois grupos de janela em mais de 99,8% das linhas de teste.
2. Regerar as janelas de todas as classes a partir dos pcaps, com um tamanho só. Deixa as classes
   raras com menos linhas na janela de 100, mas é a única saída em que treino e operação usam a
   mesma janela.
3. Manter como está e declarar a limitação no artigo.

A decisão, em 10/10/2026, foi a segunda: ver "Regeração dos dados de treino".

O extrator aceita qualquer tamanho de janela. Desde 19/10/2026 o padrão é 100, a do sistema; para
comparar com o CSV oficial nas classes de janela de 10, use `--janela 10` na linha de comando ou
`Extrator(janela=10)` no código.

O teste direto, com cinco pcaps extraídos nas duas janelas e pontuados pelo modelo de 7
categorias, está em `experimentos/resultados/teste_da_janela.md`. Para refazê-lo:

    python -m codigo.classificador.janela

Duas outras diferenças entre o artigo do dataset e os arquivos publicados, para não citar errado:

- A Tabela 4 do artigo lista 47 atributos, e os CSVs trazem 39. Faltam `ts`, `flow duration`,
  `Srate`, `Drate`, `urg count`, `Magnitude`, `Radius`, `Covariance` e `Weight`, e há `IGMP`, que
  a tabela não lista.
- `Variance`, que o artigo define como razão entre as variâncias dos pacotes de entrada e de
  saída, nos arquivos é a variância amostral do tamanho dos quadros (igual a `Std` ao quadrado).

---

## Regeração dos dados de treino a partir dos pcaps

**Por quê.** Dois problemas medidos no `MERGED_CSV` oficial. O modelo treinado nele aprende o
tamanho da janela em vez do comportamento do tráfego: extraído com a outra janela, um flood vira
Recon e uma varredura de portas vira flood, e tirar as seis colunas ligadas à janela não resolve
(`experimentos/resultados/teste_da_janela.md`). E o rótulo oficial é dado ao arquivo inteiro: nos
pcaps de varredura, força bruta, Web e spoofing, entre 33% e 87% das janelas de 10 quadros não
têm nenhum quadro do atacante (`experimentos/resultados/janelas_sem_atacante.md`). Por isso os
dados de treino são gerados de novo, a partir dos pcaps, com o nosso extrator (decisão de
10/10/2026 no `ROADMAP.md`).

**Os atacantes.** São os sete Raspberry Pi da Tabela 1 do artigo do dataset, identificados pelo
MAC (`codigo/classificador/atacantes.py`). A lista foi confirmada nos pcaps pela contagem de
quadros por MAC: os sete atacam no Mirai e em quase todos os pcaps de DDoS (em
`DDoS-SYN_Flood.pcap`, `dc:a6:32:c9:e5:a4` fica abaixo de 1% dos quadros), e só
`dc:a6:32:dc:27:d5` nos demais, com `dc:a6:32:c9:e5:a4` em volume menor nos ataques Web. Os outros
Raspberry Pi da rede são vítimas. O MAC `dc:a6:32:dc:27:d5` também aparece em cerca de 1% dos
quadros dos pcaps benignos, e 27,1% das janelas de 100 desses pcaps (5,5% das de 10) têm ao
menos um quadro de um MAC da lista: o dispositivo que ataca gera tráfego comum, e a regra de
rótulo não usa a lista nos pcaps benignos.

**A regra de rótulo.** O rótulo de cada pcap vem do nome do arquivo, sem o sufixo numérico
(`DoS-HTTP_Flood1.pcap` é `DoS-HTTP_Flood`); nome que não casa com nenhum dos 34 rótulos é
recusado. Num pcap benigno, toda janela é `BenignTraffic`. Num pcap de ataque, a janela recebe o
rótulo do arquivo se contém um quadro com MAC de atacante na origem ou no destino, e é descartada
se não contém. A regeração não muda o rótulo da janela descartada: ela fica à parte, em
`descartadas/`. Quem decide o que fazer com ela é o treino. Desde 13/10/2026, o treino do sistema
põe como `Benign` as descartadas da parte de treino de cada pcap de ataque e deixa as da parte de
teste fora do teste; até então elas ficavam fora do treino, porque o tráfego de fundo de uma
captura de ataque pode conter efeito do ataque, e o treino de referência (`--sem-fundo`) continua
assim.

**A receita**, a partir da raiz do repositório, com os pcaps em `CICIoT2023/`:

    python -m codigo.classificador.atacantes          # confirma os MACs e mede as janelas sem atacante
    python -m codigo.classificador.regerar            # extrai, rotula e grava os CSVs regerados
    python -m codigo.classificador.treinar_regerado --nucleos 4               # o modelo do sistema, com a regra e o N
    python -m codigo.classificador.treinar_regerado --sem-fundo --nucleos 4   # o modelo de 10/10, como referência
    python -m codigo.classificador.rodadas --nucleos 4            # rodadas de teste do modelo de 10/10
    python -m codigo.classificador.rodadas --capturas --nucleos 4 # comparação das configurações 0 a 5
    python -m codigo.classificador.ponto_de_operacao --nucleos 4  # ponto de operação nas configurações 0 e 5

Os dois primeiros aceitam `--dataset` para apontar outra pasta de pcaps; `treinar_regerado` lê o
manifesto da regeração (`--manifesto-da-regeracao`) e os CSVs regerados (`--destino`). As rodadas
usam o modelo de referência, e por isso o treino com `--sem-fundo` vem antes delas; o ponto de
operação confere os dois modelos salvos contra o próprio retreino. Os dois primeiros
guardam no manifesto o tamanho e a data de modificação de cada pcap, e numa execução seguinte só
leem os pcaps novos ou alterados; um pcap que sumiu da pasta sai da saída. O manifesto da
regeração guarda também o SHA-256 do extrator, as opções com que ele mediu os quadros e a versão
da regra, e uma mudança em qualquer um deles faz ler todos os pcaps de novo. Quando chegar um pcap
novo, basta rodar os comandos de novo. Os pcaps grandes levam de um a quatro minutos cada um,
conforme a quantidade de pacotes.

`regerar` aceita ainda `--processos` (quantos pcaps ler ao mesmo tempo, cada um num processo),
`--refazer` (ler todos os pcaps de novo, sem reaproveitar as partes) e as opções do extrator
`--preencher` e `--limitar`. A comparação com o quadro como no fio regera os pcaps em outras
pastas e roda as rodadas com `--capturas`:

    python -m codigo.classificador.regerar --janelas 100 --preencher --destino dados/processed/regerado_preenchido --saida experimentos/resultados/regeracao_preenchido
    python -m codigo.classificador.regerar --janelas 100 --preencher --limitar --destino dados/processed/regerado_preenchido_limitado --saida experimentos/resultados/regeracao_preenchido_limitado
    python -m codigo.classificador.rodadas --capturas --nucleos 4

**O que sai.** `dados/processed/regerado/janela_<W>/<rotulo>.csv.gz`, fora do git, com as 39
features, `Label`, o arquivo de origem, o índice da janela no arquivo, a quantidade de IPs de
origem e de destino distintos, se havia atacante, quantos quadros da janela têm um MAC atacante
na origem ou no destino (`quadros_atacante`) e quantos MACs atacantes distintos aparecem nela
(`macs_atacante`). O arquivo de cada rótulo é a junção das partes de cada pcap (`partes/`), e por
isso um pcap novo entra sem refazer os outros. As janelas descartadas, sem nenhum quadro do
atacante, ficam à parte, com as mesmas colunas e o rótulo do arquivo, em
`descartadas/<pcap>.csv.gz`: as da parte de treino entram no treino do sistema como `Benign`, e
todas servem para medir o que o modelo faz com o tráfego de fundo das capturas de ataque. O manifesto
`experimentos/resultados/manifesto_regeracao.json`, versionado, registra o hash e o tamanho de
cada pcap e as janelas extraídas, mantidas e descartadas, por janela.

**O treino.** O modelo do sistema tem janela de 100 (decisão de 10/10/2026), 7 categorias, com
DDoS e DoS juntos, e as 39 features, com teto de 50.000 linhas por rótulo e semente 42, como no
treino exploratório. Treino e teste são divididos por tempo: dentro de cada pcap, as primeiras 70%
das janelas vão para o treino e as últimas 30% para o teste, para não deixar janelas vizinhas dos
dois lados; um rótulo com mais de um pcap tem o último arquivo, pelo sufixo numérico do nome,
inteiro no teste. As janelas de fundo da parte de treino de cada pcap de ataque entram no treino
como `Benign` (40.966 janelas). O ponto de operação sai de uma parte de validação: as últimas 15%
da parte de treino de cada pcap, por tempo. Um modelo treinado no resto classifica as janelas da
validação, e concorrem a categoria mais provável (argmax) e os limiares t sobre 1 − P(Benign), de
0,01 em 0,01; entre os que deixam no máximo 1% das janelas benignas da validação como ataque, vence
o de maior recall de ataque. No modelo do sistema venceu o argmax. O modelo salvo é o do treino
inteiro, em `modelos/rf_regerado_janela_100.joblib`, com a regra e o N num JSON ao lado
(`rf_regerado_janela_100.ponto_de_operacao.json`); `codigo/classificador/operacao.py` lê o JSON,
recusa o de outro modelo e aplica a regra, o argmax ou o limiar, a uma janela e a uma sequência de
janelas. As medidas, com o argmax e com o melhor limiar, lado a lado, estão em
`experimentos/resultados/regeracao.md`.

O treino de 10/10, sem o fundo e com as duas janelas, de 10 e de 100, fica como referência:
`--sem-fundo` o refaz em `regeracao_sem_fundo.md`, com `_sem_fundo` no nome de tudo o que grava,
e guarda as rodadas parciais anteriores aos 34 rótulos. A comparação das duas janelas que levou à
de 100 está nesse relatório.

Os controles do modelo do sistema estão em `rodadas_normalizadas.md` (a configuração 5 contra o
modelo de 10/10, com três sementes: corte por tempo, rotação do pcap benigno de fora, tráfego de
fundo e pcap inteiro fora do treino) e em `ponto_de_operacao.md` (o ponto de operação por janela e
por alarme). Os demais controles, medidos no modelo de 10/10, estão em `rodadas_de_teste.md`:
cinco sementes, atalhos da captura, intervalos de confiança das classes raras e custo.

---

## Sobre as classes

34 classes no total. Confirmado no conjunto completo: **não existe classe de exfiltração de dados**,
e por isso o trabalho segue sem esse cenário, em decisão com o orientador de 10/10/2026 (ver
`ROADMAP.md`). E as classes dos nossos cenários são muito desiguais — `DICTIONARYBRUTEFORCE` é 0,03%
dos dados.

Consequência para as métricas: **relatar recall por classe, nunca só acurácia.** DDoS e DoS somam
89,5% das linhas, e só a categoria DDoS tem 72,3%: um modelo que respondesse "DDoS" para tudo
acertaria 72,3% e seria inútil. Quando formos mal numa classe rara, dizer isso no artigo com o
número de amostras ao lado.

---

## Mapa completo de arquivos

Tudo que existe hoje e tudo que vamos criar. Quem for começar numa frente, procure a sua seção.

### O que já existe — dataset e código de referência (não versionado)

```
CICIoT2023/
├── MERGED_CSV/                      63 arquivos, 8,7 GB: referência, exploração e treino exploratório
│   └── Merged01.csv … Merged63.csv  39 features + Label, embaralhado
│
├── *.pcap                           De um a três pcaps por classe, baixados da fonte oficial.
│                                      O nome é o rótulo, às vezes com um sufixo numérico
│                                      (`DoS-HTTP_Flood1.pcap`, `BenignTraffic1.pcap`). São a
│                                      fonte dos dados de treino regerados e da calibração.
│
├── <34 pastas por ataque>/          CSVs de 39 features SEM rótulo. Opcionais: só a
│                                      recalibração do extrator precisa delas.
│   ├── DictionaryBruteForce/          Servem de gabarito da calibração:
│   ├── Recon-PortScan/                é com eles que se compara a saída
│   ├── DDoS-ICMP_Flood/               do nosso extrator.
│   └── …
│
├── pcap2csv/                        O EXTRATOR DOS AUTORES, usado como referência
│   ├── Feature_extraction.py          27 KB, o principal. n_rows = 10 na linha 475
│   ├── Generating_dataset.py          orquestra: fatia com tcpdump e paraleliza
│   ├── Communication_features.py      features de Wi-Fi e Zigbee
│   ├── Connectivity_features.py       features de conexão, tempo e flags
│   ├── Dynamic_features.py            magnitude, raio, covariância (COMENTADAS no uso)
│   ├── Layered_features.py            features por camada (L1 a L4)
│   ├── Supporting_functions.py        auxiliares: protocolo, fluxo, flags
│   └── output/ split_temp/ csv_files/ pastas de trabalho do script
│
├── example.ipynb                    notebook de ML dos autores — REFERÊNCIA, tem 3 bugs
├── tools/                           notas das ferramentas: dpkt, tcpdump, mergecap, PySpark
├── README.pdf                       documentação geral do dataset
└── README_CSV.pdf                   documentação da parte de CSVs
```

### No repositório (versionado): o que existe e o que falta criar

As linhas marcadas com **(a criar)** ainda não existem.

**Frente de captura** — `codigo/captura/`

| Arquivo | O que faz |
|---|---|
| `extrator.py` | Lê um pcap, de arquivo ou de fluxo, e produz as 39 features a cada janela de quadros IPv4 ou ARP. O tamanho da janela vem de `--janela`, e o sistema usa 100 (decisão de 10/10/2026). `--preencher` e `--limitar`, desligadas por padrão, aproximam o tamanho do quadro do que passa no fio (preenchimento até 60 bytes e teto de 1.514). A medição não depende da origem dos quadros, o que deixa caminho para captura ao vivo |
| `calibrar.py` | Refaz o fatiamento de 10 MB, roda o extrator e compara com o CSV oficial, bloco a bloco, nas 39 colunas. Gera `experimentos/resultados/calibracao.md` |
| `calibrar_conjunto.py` | Confere os 38 pcaps contra o `MERGED_CSV` inteiro, linha a linha dentro de cada rótulo, e compara a leitura contínua com a fatiada. Gera `experimentos/resultados/calibracao_conjunto.md`, as tabelas e o manifesto |

**Frente de dados e classificador** — `codigo/classificador/`

| Arquivo | O que faz |
|---|---|
| `mapeamento.py` | Os 34 rótulos na grafia dos autores, a normalização da grafia (o `MERGED_CSV` usa MAIÚSCULAS e `BENIGN`) e o agrupamento em 8 categorias e em ataque ou benigno, igual ao `dict_7classes` e ao `dict_2classes` |
| `amostrar.py` | Para o treino exploratório: percorre os 63 arquivos do `MERGED_CSV` em fluxo, guarda todas as linhas das classes raras e sorteia no máximo 50.000 das demais. **Semente fixa.** Grava `dados/processed/amostra.csv.gz`, com as 39 features, `Label` e `Categoria`, e o manifesto da amostra |
| `explorar.py` | Lê o `MERGED_CSV` inteiro e gera `experimentos/resultados/exploracao.md` |
| `preparar.py` | Lê a amostra, escolhe as features (as 39, ou 33 sem as que dependem da janela) e o alvo (34 classes, 8 categorias, 7 com DDoS e DoS fundidas, ou ataque e benigno) e separa treino e teste, por sorteio estratificado de linhas, por grupos de vetores idênticos ou, nos dados regerados, por tempo dentro de cada pcap. **Semente fixa** |
| `treinar.py` | No treino exploratório, treina o Random Forest com os parâmetros padrão do scikit-learn e salva o modelo em `modelos/`, fora do git, com as features, o alvo e a divisão usados. Sem `StandardScaler` |
| `avaliar.py` | Acurácia, macro-F1, precisão, recall e F1 por classe, matriz de confusão, taxa de falso positivo, teto, importância das features, tempo de inferência e tamanho do modelo. Mede na distribuição da amostra e reponderado para a do conjunto completo. Também pontua um CSV de fora com as 39 colunas e o rótulo conhecido, como a saída do extrator |
| `experimento.py` | Roda o treino exploratório: execuções que combinam features, divisão, alvo e proporção das classes no treino, com três sementes. Grava o relatório, as tabelas, as matrizes de confusão e o manifesto do experimento |
| `janela.py` | Roda o teste direto do atalho da janela: extrai cinco pcaps com janela de 10 e de 100, em leitura contínua, treina os quatro modelos de 7 categorias (39 ou 33 features, priori da amostra ou natural), pontua cada extração e grava o relatório, a tabela e o manifesto do teste |
| `atacantes.py` | Os MACs dos sete Raspberry Pi atacantes, o rótulo lido do nome do pcap e a medida das janelas sem atacante: lê cada pcap uma vez, conta os quadros por MAC e, com janela de 10 e de 100, as janelas sem nenhum quadro de atacante. Grava `janelas_sem_atacante.md`, as tabelas e o manifesto; numa execução seguinte só lê os pcaps novos ou alterados |
| `regerar.py` | Regera os dados de treino: para cada pcap e cada janela, extrai as features com endereços, decide o rótulo da janela (benigno no pcap benigno; o rótulo do arquivo só na janela com atacante, senão descarta) e grava `dados/processed/regerado/janela_<W>/<rotulo>.csv.gz`, com as descartadas à parte em `descartadas/`. O manifesto guarda hash, tamanho e as janelas extraídas, mantidas e descartadas de cada pcap, o SHA-256 do extrator, as opções e a versão da regra; só os pcaps novos ou alterados são lidos de novo |
| `treinar_regerado.py` | Treina o modelo do sistema nos dados regerados: janela de 100, 7 categorias, teto de 50.000 linhas por rótulo, divisão por tempo, as 39 features e o fundo da parte de treino como `Benign`; escolhe a regra na validação, salva o modelo em `modelos/`, fora do git, com a regra e o N num JSON ao lado, e grava `regeracao.md`, as métricas, as matrizes de confusão e o manifesto. Com `--sem-fundo`, refaz o treino de 10/10 como referência (`regeracao_sem_fundo.md`) |
| `operacao.py` | A regra do ponto de operação, para o sistema usar: a categoria de uma janela pelas probabilidades do modelo, pelo argmax ou pelo limiar, os incidentes de uma sequência de janelas com N seguidas, a `Vigia`, que aplica a regra janela a janela, a escolha da regra na validação e a leitura e gravação do JSON ao lado do modelo. Só depende do numpy |
| `rodadas.py` | Roda os controles do modelo de 10/10 (sementes, rotação do pcap benigno de fora, tráfego de fundo, pcap fora do treino, atalhos da captura, limiar, intervalos e custo) e grava `rodadas_de_teste.md`; com `--capturas`, compara as configurações 0 a 5 (o quadro como no fio e o fundo no treino) e grava `rodadas_normalizadas.md`, com a regra de adoção da configuração 5. `rodadas_relatorio.py` monta os dois relatórios a partir dos manifestos |
| `ponto_de_operacao.py` | Mede o ponto de operação nas configurações 0 e 5, com três sementes e as três rotações do pcap benigno de fora: a regra escolhida na validação, as medidas no teste com o argmax, o melhor limiar e a regra escolhida, os alarmes com `operacao.SEGUIDAS` janelas seguidas (4 desde 28/10), o fundo virando ataque e as diferenças pareadas; confere os modelos salvos por `treinar_regerado`. Grava `ponto_de_operacao.md` (montado por `ponto_de_operacao_relatorio.py`), as tabelas e o manifesto |

**Frente de MCP e agentes** — `codigo/mcp/` e `codigo/agente/`

| Arquivo | O que faz |
|---|---|
| `mcp/README.md` | Por onde começar na frente de agentes: como subir o stub, ligar um cliente MCP, chamar cada tool, aprovar pelo terminal e ler o log de eventos |
| `mcp/tipos.py` | Os tipos do contrato, numa fonte só: o que cada uma das dez tools recebe e devolve e o formato de cada linha do log de eventos |
| `mcp/contrato.json` | O mesmo contrato em JSON Schema, gerado de `tipos.py`. Um teste falha se os dois divergirem. É ele que destrava as duas frentes em paralelo |
| `mcp/acoes.py` | O catálogo de ações, as ações novas, a política de risco, os rótulos neutros, o resumo do incidente e o ambiente simulado, com desfazer |
| `mcp/politica.toml` | Os limites da política de risco, que a equipe ajusta sem mexer no código |
| `mcp/base.py` | A leitura da base de mitigações e a busca usada por `pesquisar_solucoes`. A base é o levantamento da equipe em `agente/recomendacoes/`, com a ação do catálogo e a fonte de cada medida |
| `mcp/eventos.py` | Gravação e leitura do log de eventos, que a interface web lê |
| `mcp/cenarios.py` | Os quatro incidentes de exemplo do stub, com números ilustrativos: flood, força bruta, varredura de portas e falso positivo |
| `mcp/stub.py` | O servidor MCP: responde às dez tools com os quatro cenários de exemplo ou, com `--cenarios`, com os incidentes reais de um pcap gravados pelo reprodutor. Nesse modo de reprodução, é o servidor da PoC (decisão de 2026-10-25) |
| `mcp/aprovar.py` | O comando de terminal com que a pessoa aprova, rejeita ou promove uma proposta de ação, e marca um incidente como já resolvido |
| `mcp/roteiro.py` | Gera `mcp/exemplos/incidente_flood.jsonl`, o log de exemplo de um incidente inteiro, usado nos testes do MCP e da interface web |
| `mcp/exemplos/` | O log de exemplo e o seu README, que explica o incidente passo a passo |
| `agente/skills/` | As instruções dos três agentes, uma skill por pasta: triagem do alerta, coordenação do incidente, análise por categoria, recomendação de mitigação e execução da ação. Cada skill é o prompt de sistema do agente, e o agente de decisão junta as três dele, com a coordenação primeiro (decisão de 2026-10-25) |
| `agente/recomendacoes/` | Levantamento de mitigações por categoria, com as fontes |
| `agente/pedidos.py` | Os pedidos aos modelos no formato de `chat/completions`, montados sem chamar ninguém: o prompt de sistema vem da skill do agente, e as tools são as da linha dele |
| `agente/laco.py` | O laço ReAct de um agente: o modelo pede tools, o laço as executa e devolve o resultado, com limites de voltas, chamadas repetidas e tamanho, e um motivo claro de parada |
| `agente/cliente_mcp.py` | O cliente do servidor MCP de um agente: abre o stub por stdio só com as tools da linha dele |
| `agente/registro.py` | O que o laço grava no log: um `llm_chamada` por chamada ao modelo e um `agente_concluido` por agente |
| `agente/agentes.py` | O orquestrador em código: triagem, veredito sem endereço, decisão, espera da aprovação no log, execução e verificação do efeito, em três configurações (`local`, `nuvem`, `hibrida`). Roda com `python -m codigo.agente --incidente inc-0001 --log <log> --configuracao hibrida` |
| `agente/aprovador.py` | O aprovador automático dos experimentos e a conferência de cada proposta contra o gabarito (`experimentos/gabarito_da_recomendacao.toml`): aprova a proposta de risco alto que o gabarito aceita, rejeita as demais, inclusive a ação nova, e grava a decisão no log como a de uma pessoa (`aprovador-automatico`). O papel do alvo vem dos IPs dos atacantes do dataset |
| `agente/experimento.py` | O executor dos experimentos ponta a ponta: `preparar` reproduz os pcaps e monta o conjunto de incidentes, com a verdade de campo (os IPs dos atacantes do dataset e se o incidente é verdadeiro); `rodar` roda os agentes em cada configuração e repetição, com o aprovador automático, e retoma de onde parou; `consolidar` gera `avaliacao_agentes.csv` e `custo_latencia.csv`. Roda em Linux ou macOS (`preparar` usa o `resource`, que o Windows não tem) |
| `agente/teste_tool_poisoning.py` | **(a criar)** O experimento de segurança do MCP: uma tool com descrição envenenada, para medir se o agente cai |

**Frente do reprodutor de tráfego** (`codigo/reprodutor/`)

| Arquivo | O que faz |
|---|---|
| `reprodutor.py` | Leva um pcap pelo extrator, pelo modelo do sistema e pela política de acionamento, que reúne as janelas do mesmo ataque num incidente só (primeira versão, decisão de 2026-10-19), e grava os incidentes no log de eventos do contrato, com os cenários ao lado para o servidor MCP atender |
| `__main__.py` | A linha de comando: `python -m codigo.reprodutor <pcap>`, com `--so-teste` para só o trecho fora do treino e os parâmetros da política. O log vai para `dados/eventos/reproducoes/`, fora do git |
| `avaliar.py` | Roda o reprodutor nos 38 pcaps e confere os incidentes com os MACs dos atacantes. Gera `experimentos/resultados/reproducao_dos_pcaps.md` e o manifesto |
| `custo.py` | Mede o custo do modelo do sistema na operação, num núcleo: a latência de uma janela isolada no trecho de teste de um pcap por categoria, o lote de 1.000 janelas, a vazão do extrator e do reprodutor e a memória. Gera `experimentos/resultados/custo_do_modelo_do_sistema.md` e o manifesto (`nice -n 10 python -m codigo.reprodutor.custo`) |
| `regras.py` | Compara regras de alarme do modelo do sistema, sem retreino, fora do CICIoT2023 (a casa, o IoT-23 e o CICIoMT2024) e no trecho de teste do próprio CICIoT2023: extrai cada pcap uma vez e passa as janelas pela política de acionamento com cada regra; mede também, por janela, o teste publicado do CICIoT2023. Gera `experimentos/resultados/testes_fora_do_ciciot2023.md` e o manifesto (`python -m codigo.reprodutor.regras`; pcaps em `dados/raw/iot23/` e `dados/raw/ciciomt2024/`) |
| `referencia_benigno.json` | A mediana de cada feature no tráfego benigno do treino, mostrada ao lado das features principais do incidente |

**Backend da interface** (`codigo/api/`)

| Arquivo | O que faz |
|---|---|
| `README.md` | Como configurar e subir o servidor, e o que cada rota recebe e devolve |
| `servidor.py` | As rotas: o chat com o modelo, as skills como prompts e a simulação com um pcap |
| `simulacao.py` | A simulação: o pcap enviado pela tela passa pelo reprodutor e chega até a porta do modelo da triagem, sem chamada. Grava em `dados/eventos/simulacoes/`, fora do git |
| `configuracao.py`, `provedor.py`, `prompts.py` | A leitura do `.env`, o cliente de `chat/completions` e a leitura das skills |

**Resultados** — `experimentos/`

| Arquivo | O que faz |
|---|---|
| `resultados/calibracao.md` | O relatório da calibração: o que bateu, o que divergiu e quanto |
| `resultados/calibracao_conjunto.md` | A calibração dos 38 pcaps contra o `MERGED_CSV`: fração das nossas linhas com par, cobertura de cada rótulo, linhas sem par, leitura contínua contra fatiada e a captura de cada pcap. `calibracao_conjunto_pcaps.csv` e `calibracao_conjunto_rotulos.csv` trazem as tabelas; `manifesto_calibracao_conjunto.json`, tudo |
| `resultados/exploracao.md` | A exploração do `MERGED_CSV` completo: linhas por classe e por categoria, janela por classe, valores vazios e infinitos, colunas redundantes e linhas repetidas |
| `resultados/manifesto_amostra.json` | O registro da amostra: semente, teto, contagem por classe no conjunto e na amostra, hash dos arquivos lidos e hash da amostra |
| `resultados/treino_exploratorio.md` | O relatório do treino exploratório: as execuções, as medidas por classe, a importância das features, o custo e o que os números dizem sobre as decisões em aberto |
| `resultados/manifesto_treino_exploratorio.json` | O registro do experimento: semente, parâmetros, versões, hash da amostra, as duas divisões e todos os números de cada execução |
| `resultados/metricas_classificador.csv` | Precisão, recall, F1, suporte e taxa de falso positivo por classe, em formato longo: uma linha por execução, distribuição e classe |
| `resultados/importancia_features.csv` | Importância de cada feature em cada execução, em formato longo |
| `resultados/matrizes_confusao/` | O que o modelo confunde com o quê, em CSV. Dois arquivos por execução: a matriz do alvo e a que abre a classe real nos 34 rótulos |
| `resultados/teste_da_janela.md` | O relatório do teste direto do atalho da janela: a fração das janelas de cada pcap na categoria esperada, com a janela do dataset e com a outra, a distribuição das previsões e o que os números dizem sobre cada saída em avaliação |
| `resultados/teste_da_janela.csv` | Os números do teste da janela, em formato longo: uma linha por captura, janela, modelo e categoria prevista |
| `resultados/manifesto_teste_da_janela.json` | O registro do teste da janela: semente, parâmetros, versões, hash da amostra, tamanho e hash de cada pcap, as contagens de cada extração e todos os números |
| `resultados/janelas_sem_atacante.md` | A confirmação dos MACs dos atacantes em cada pcap e, por pcap e por janela, quantas janelas não têm nenhum quadro de atacante. `janelas_sem_atacante.csv` tem os números por pcap e janela; `janelas_sem_atacante_macs.csv`, as contagens por MAC; `manifesto_janelas_sem_atacante.json`, tudo, com hash e tamanho de cada pcap |
| `resultados/manifesto_regeracao.json` | O registro da regeração: regra de rótulo, colunas, e por pcap o hash, o tamanho e as janelas extraídas, mantidas e descartadas, por janela |
| `resultados/regeracao.md` | O relatório do treino do modelo do sistema: o que mudou em relação ao modelo de 10/10, os dados, a divisão, a escolha da regra na validação, as medidas por categoria com o argmax e com o melhor limiar, as duas matrizes de confusão, a fração de cada pcap na categoria esperada e os IPs de origem por janela em DDoS e DoS. `regeracao_metricas.csv` e `regeracao_por_arquivo.csv` trazem os números; `matrizes_confusao/regerado_janela_100.csv`, `_limiar.csv` e `_ponto.csv`, as matrizes do argmax, do melhor limiar e da regra escolhida; `manifesto_treino_regerado.json`, tudo |
| `resultados/regeracao_sem_fundo.md` | O treino de 10/10, de referência, nas duas janelas, com as rodadas parciais anteriores. Os arquivos dele levam `_sem_fundo` no nome |
| `resultados/rodadas_de_teste.md` | Os controles do modelo de 10/10, que continuam valendo como referência. As tabelas estão nos `rodadas_*.csv`, e tudo, em `manifesto_rodadas.json` |
| `resultados/rodadas_normalizadas.md` | A comparação entre o modelo de 10/10 e os treinos com o quadro normalizado e com o fundo como benigno, com a regra de adoção da configuração 5. As tabelas estão nos `rodadas_normalizadas_*.csv`, e tudo, em `manifesto_rodadas_normalizadas.json` |
| `resultados/ponto_de_operacao.md` | O ponto de operação nas configurações 5 e 0: a regra escolhida em cada semente e rotação, as medidas no teste com o argmax, o melhor limiar e a regra escolhida, os alarmes no pcap benigno de fora, o fundo, os pcaps de ataque que alarmam e a conferência dos modelos salvos. As tabelas estão nos `ponto_de_operacao_*.csv`, e tudo, em `manifesto_ponto_de_operacao.json` |
| `resultados/regeracao_preenchido/`, `resultados/regeracao_preenchido_limitado/` | Os manifestos das regerações com o quadro completado até 60 bytes e com o quadro como no fio |
| `resultados/reproducao_dos_pcaps.md` | Os 38 pcaps pelo reprodutor, com os incidentes conferidos com os MACs dos atacantes: janelas com atacante, origem e destino principais, categoria DDoS ou DoS, atraso de detecção, alarmes falsos nos pcaps benignos e o efeito de capturar os quadros como no fio. Tudo está em `manifesto_reproducao_dos_pcaps.json` |
| `resultados/custo_do_modelo_do_sistema.md` | O custo do modelo do sistema na operação: latência de uma janela, lote, vazão do extrator e do reprodutor, tempo de leitura e memória, com a máquina da medida. Tudo está em `manifesto_custo_do_modelo_do_sistema.json` |
| `resultados/avaliacao_agentes.csv` | **(a gerar)** A qualidade das recomendações: por rodada (incidente, configuração e repetição), se a ação é aceitável no alvo certo pelo gabarito por categoria, com o acerto da triagem ao lado (decisão de 2026-10-25). Sai de `python -m codigo.agente.experimento consolidar` |
| `resultados/custo_latencia.csv` | **(a gerar)** Tokens, tempo das chamadas aos modelos e custo por agente e por rodada, com o tempo da detecção e o dos agentes na linha de total. Sai do mesmo comando |
| `notebooks/` | Exploração livre. Nada que vá para o artigo nasce aqui sem virar script |

**Raiz do repositório**

| Arquivo | O que faz |
|---|---|
| `requirements.txt` | As dependências fixadas, para todo mundo rodar igual |
| `ruff.toml` | A configuração do `ruff`, o lint do CI |
| `.github/workflows/` | O CI (`ci.yml`: lint, testes, auditoria das dependências e build do frontend) e o CodeQL (`codeql.yml`) |
| `frontend/` | A interface web, com o seu próprio README |
| `.env.example` | Modelo das variáveis do provedor de LLM: endereço, chave, modelo e parâmetros de geração. O `.env` de verdade nunca entra no git |

### Ordem em que essas coisas nascem

1. `mcp/contrato.json` — destrava as duas frentes
2. `captura/extrator.py` e `captura/calibrar.py`, o caminho crítico; depois, `captura/calibrar_conjunto.py`
3. `classificador/mapeamento.py` → `explorar.py` e `amostrar.py` → `preparar.py` → `treinar.py` → `avaliar.py` → `experimento.py` → `janela.py` → `atacantes.py` → `regerar.py` → `treinar_regerado.py` → `rodadas.py` → `operacao.py` e `ponto_de_operacao.py`
4. `mcp/stub.py` (em paralelo a tudo, desde o contrato) → `reprodutor/`, cujos incidentes o stub atende com `--cenarios`
5. `agente/` — depois que o servidor responde
6. `experimentos/resultados/` — as tabelas vazias devem existir **antes** dos experimentos

## Ambiente Python

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest
```

Requer Python 3.11 ou mais novo. As versões ficam fixadas no `requirements.txt`.

## O que NUNCA vai para o git

`CICIoT2023/`, arquivos `.pcap`, CSVs grandes, modelos treinados (`.pkl`, `.joblib`), `.env` e o
log de eventos de uma execução (`dados/eventos/`).

## O que SEMPRE vai para o git

Código, o script de amostragem com semente fixa, a lista de features, a definição da divisão
treino/teste, métricas e tabelas (em `experimentos/resultados/`) e as decisões no `ROADMAP.md`.
Cuidado para não salvar resultado dentro de `dados/` — essa pasta é ignorada e eles sumiriam.

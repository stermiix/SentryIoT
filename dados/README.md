# Dados — como montar o ambiente

O dataset **não é versionado no git** (são ~17 GB). O repositório guarda o código e as decisões;
os dados são uma dependência que se instala — mesma lógica do `node_modules`.

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
| Treinar o classificador | `MERGED_CSV/` | 8,7 GB |
| Calibrar o extrator | O pcap do ataque e o CSV por ataque correspondente | de 39 MB a cerca de 0,6 GB por pcap |

Não usar re-uploads de terceiros (Kaggle e afins): não dá para citar a origem no artigo e não há
garantia de que o conteúdo bate com o oficial.

## Onde colocar

A pasta `CICIoT2023/` vai na **raiz do repositório**, irmã de `codigo/` e `artigo/`.
Já está no `.gitignore`.

```
TCC/CICIoT2023/
├── MERGED_CSV/                  <- O DATASET DE TREINO (63 arquivos, 8,7 GB)
├── <34 pastas, uma por ataque>/ <- CSVs por ataque, sem rótulo (usados na calibração)
├── DictionaryBruteForce.pcap    <- 39 MB, um dos pcaps da calibração
├── Recon-PortScan.pcap          <- 192 MB
├── DDoS-HTTP_Flood-.pcap        <- cerca de 0,6 GB (estimativa), a baixar: flood para a janela de 100
├── pcap2csv/                    <- o extrator DOS AUTORES (código de referência)
├── example.ipynb                <- notebook de ML dos autores (ler as ressalvas abaixo)
├── tools/                       <- notas das ferramentas usadas
├── README.pdf  README_CSV.pdf
```

---

## O dataset de treino: `MERGED_CSV/`

**É este que se usa para treinar.** 63 arquivos, cerca de 45,0 milhões de linhas no total, 8,7 GB.

- **40 colunas: as 39 features + `Label`** (com L maiúsculo).
- As 39 features são **idênticas** às dos CSVs por ataque e às que o `pcap2csv` produz,
  conferido coluna por coluna. É a base para treino e operação usarem os mesmos números, com a
  ressalva do tamanho da janela (ver "Janela de 10 ou de 100 pacotes").
- Já vem mesclado entre ataques e embaralhado: cada arquivo contém linhas de todas as 34 classes.

**Por que 63 arquivos e não um só:** é saída do PySpark (cada trabalhador grava a sua parte), e
8,7 GB num arquivo único seria inabrível. Cada pedaço tem ~137 MB e cabe na memória.

**Nove arquivos da nossa cópia estão truncados** (`Merged42`, `Merged44` e `Merged46` a `Merged52`):
terminam no meio de uma linha, e os dois últimos têm só 44 MB e 14 MB. A cópia tem 45.019.234 linhas
completas, e em quase todas as classes faltam cerca de 4,3% das linhas que os CSVs por ataque
trazem. As proporções entre as classes não mudam, porque o conjunto é embaralhado. Três CSVs por
ataque de `DoS-UDP_Flood` (7, 8 e 9) têm o mesmo defeito. Não foi possível conferir se o corte está
nos arquivos oficiais ou só na nossa cópia: quem baixar o dataset de novo deve comparar o tamanho
desses doze arquivos. Os números estão em `experimentos/resultados/exploracao.md`.

**Cada arquivo é representativo do conjunto todo** (verificado em 05/09/2026):

| | Linhas | DDOS-ICMP | BENIGN | BruteForce | PortScan |
|---|---|---|---|---|---|
| Merged01 | 712.311 | 15,25% | 2,33% | 204 | 1.251 |
| Merged32 | 704.067 | 15,24% | 2,34% | 193 | 1.205 |
| Merged63 | 428.161 | 15,33% | 2,38% | 116 | 726 |

### Como amostrar para treinar

8,7 GB não cabem na memória, e Random Forest precisa de tudo junto. A estratégia:

**percorrer os 63 arquivos guardando TODAS as linhas das classes raras e só uma fatia das
classes gigantes** (um teto de 50 mil por classe). Isso derruba de 45,0 milhões para 1.288.479
linhas e ataca o desbalanceamento ao mesmo tempo.

Nas classes raras, usar os 63 arquivos faz diferença real: `DICTIONARYBRUTEFORCE` sai de 204
exemplos (1 arquivo) para ~12 mil (63 arquivos).

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

**Usamos as 39 features do `MERGED_CSV`.** Treino e operação partem do mesmo conjunto de colunas,
e o extrator reproduz os valores oficiais nas classes já calibradas, que usam janela de 10. A
leitura é de arquivo pcap; a captura ao vivo ainda não foi entregue. (Havia uma versão de 46
features; as 7 extras não saem do código publicado pelos autores, porque as linhas que as
calculariam estão comentadas no `Feature_extraction.py`, linhas 132 e 171. Por isso ela foi
descartada.)

**Classificamos em 8 categorias, não em 34 variantes.** O F1 é bem melhor, e os agentes não
precisam da variante exata — a mitigação de um `DDoS-ICMP_Flood` e de um `DDoS-UDP_Flood` é a
mesma. Usar o `dict_7classes` do `example.ipynb` (célula 14) tal como está: agrupamento oficial
dos autores, citável.

**Não gastar semanas no classificador.** Os autores já publicaram o benchmark (RF entre os dois
melhores, com a rede neural). Reproduzir e seguir — a contribuição do trabalho é a camada
MCP + agentes.

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

Como o CSV oficial é gerado (lido no código dos autores, confirmado nos dois pcaps e descrito no
artigo do dataset):

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

**Resultado da calibração** (03/10/2026, detalhes em `experimentos/resultados/calibracao.md`):

| Arquivo | Pacotes | Quadros IPv4 e ARP | Linhas no CSV oficial | Linhas reproduzidas |
|---|---|---|---|---|
| `DictionaryBruteForce.pcap` | 133.138 | 130.632 | 13.064 | 13.064 |
| `Recon-PortScan.pcap` | 831.856 | 822.771 | 82.284 | 82.284 |

A diferença entre pacotes e quadros mantidos (1,88% e 1,09%) vem do filtro: IPv6, STP e outros
tipos de quadro ficam de fora. A soma da coluna `Number` do CSV oficial é igual à contagem de
quadros IPv4 e ARP nos dois pcaps.

Os dois pcaps disponíveis são de classes com janela de 10. A janela de 100 ainda não foi
calibrada, porque não temos pcap de nenhuma classe de flood. O calibrador lê o tamanho da janela
do próprio CSV oficial, então basta acrescentar o pcap à pasta do dataset.

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

Saídas em avaliação, a decidir antes do treino:

1. Remover `Number`, `Tot sum` e as quatro contagens. Não se perde informação, porque elas são
   função de colunas que ficam. Reduz o atalho, mas não o elimina.
2. Uniformizar em 100, reagrupando as classes de janela 10 a partir dos CSVs por ataque. É o mais
   correto e pode ser conferido com o nosso extrator nos dois pcaps, mas deixa as classes raras
   com dez vezes menos linhas.
3. Manter como está e declarar a limitação no artigo.

O extrator aceita qualquer tamanho de janela: `--janela 100` na linha de comando ou
`Extrator(janela=100)` no código.

Duas outras diferenças entre o artigo do dataset e os arquivos publicados, para não citar errado:

- A Tabela 4 do artigo lista 47 atributos, e os CSVs trazem 39. Faltam `ts`, `flow duration`,
  `Srate`, `Drate`, `urg count`, `Magnitude`, `Radius`, `Covariance` e `Weight`, e há `IGMP`, que
  a tabela não lista.
- `Variance`, que o artigo define como razão entre as variâncias dos pacotes de entrada e de
  saída, nos arquivos é a variância amostral do tamanho dos quadros (igual a `Std` ao quadrado).

---

## Sobre as classes

34 classes no total. Confirmado no conjunto completo: **não existe classe de exfiltração de dados**.
E as classes dos nossos cenários são muito desiguais — `DICTIONARYBRUTEFORCE` é 0,03% dos dados.
Decisão pendente com o orientador (ver `ROADMAP.md`).

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
├── MERGED_CSV/                      63 arquivos, 8,7 GB — O DATASET DE TREINO
│   └── Merged01.csv … Merged63.csv  39 features + Label, embaralhado
│
├── DictionaryBruteForce.pcap        39 MB, pcap da calibração
├── Recon-PortScan.pcap              192 MB — segundo pcap, para conferência
│
├── <34 pastas por ataque>/          CSVs de 39 features SEM rótulo.
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

### O que vamos criar — no repositório (versionado)

**Frente de captura** — `codigo/captura/`

| Arquivo | O que faz |
|---|---|
| `extrator.py` | Lê um pcap, de arquivo ou de fluxo, e produz as 39 features a cada janela de quadros IPv4 ou ARP (10 por padrão). A medição não depende da origem dos quadros, o que deixa caminho para captura ao vivo |
| `calibrar.py` | Refaz o fatiamento de 10 MB, roda o extrator e compara com o CSV oficial, bloco a bloco, nas 39 colunas. Gera `experimentos/resultados/calibracao.md` |

**Frente de dados e classificador** — `codigo/classificador/`

| Arquivo | O que faz |
|---|---|
| `mapeamento.py` | Os 34 rótulos na grafia dos autores, a normalização da grafia (o `MERGED_CSV` usa MAIÚSCULAS e `BENIGN`) e o agrupamento em 8 categorias e em ataque ou benigno, igual ao `dict_7classes` e ao `dict_2classes` |
| `amostrar.py` | Percorre os 63 arquivos do `MERGED_CSV` em fluxo, guarda todas as linhas das classes raras e sorteia no máximo 50.000 das demais. **Semente fixa.** Grava `dados/processed/amostra.csv.gz`, com as 39 features, `Label` e `Categoria`, e o manifesto da amostra |
| `explorar.py` | Lê o `MERGED_CSV` inteiro e gera `experimentos/resultados/exploracao.md` |
| `preparar.py` | Aplica o agrupamento em 8 categorias e separa treino e teste. Grava a divisão usada |
| `treinar.py` | Treina o Random Forest e salva o modelo. Sem `StandardScaler` |
| `avaliar.py` | Recall por classe, matriz de confusão, taxa de falso positivo, importância das features, tempo de inferência e tamanho do modelo |

**Frente de MCP e agentes** — `codigo/mcp/` e `codigo/agente/`

| Arquivo | O que faz |
|---|---|
| `mcp/README.md` | Por onde começar na frente de agentes: como subir o stub, ligar um cliente MCP, chamar cada tool, aprovar pelo terminal e ler o log de eventos |
| `mcp/tipos.py` | Os tipos do contrato, numa fonte só: o que cada uma das nove tools recebe e devolve e o formato de cada linha do log de eventos |
| `mcp/contrato.json` | O mesmo contrato em JSON Schema, gerado de `tipos.py`. Um teste falha se os dois divergirem. É ele que destrava as duas frentes em paralelo |
| `mcp/acoes.py` | O catálogo de ações, as ações novas, a política de risco e o ambiente simulado, com desfazer |
| `mcp/politica.toml` | Os limites da política de risco, que a equipe ajusta sem mexer no código |
| `mcp/base.py` | A leitura da base local de documentos e a busca usada por `pesquisar_solucoes` |
| `mcp/base_provisoria/` | Os documentos da base local. Conteúdo provisório do stub, a substituir pelo levantamento de mitigações da equipe |
| `mcp/eventos.py` | Gravação e leitura do log de eventos, que a interface web lê |
| `mcp/cenarios.py` | Os quatro incidentes de exemplo do stub, com números ilustrativos: flood, força bruta, varredura de portas e falso positivo |
| `mcp/stub.py` | O servidor MCP de mentira: responde às nove tools com os cenários, para a frente de agentes trabalhar antes de o modelo existir |
| `mcp/aprovar.py` | O comando de terminal com que a pessoa aprova, rejeita ou promove uma proposta de ação |
| `mcp/roteiro.py` | Gera `mcp/exemplos/incidente_flood.jsonl`, o log de exemplo de um incidente inteiro, insumo do modo replay da interface web |
| `mcp/servidor.py` | O servidor MCP de verdade, que expõe o classificador pelas mesmas tools do contrato |
| `agente/agentes.py` | O sistema multiagente: triagem, decisão e execução |
| `agente/prompts/` | Os prompts de cada agente, em arquivos separados |
| `agente/acionamento.py` | A política de acionamento: agrega, deduplica e decide quando vale chamar a LLM. Sem isso, um DDoS gera milhares de chamadas por segundo |
| `agente/teste_tool_poisoning.py` | O experimento de segurança do MCP: uma tool com descrição envenenada, para medir se o agente cai |

**Resultados** — `experimentos/`

| Arquivo | O que faz |
|---|---|
| `resultados/calibracao.md` | O relatório da calibração: o que bateu, o que divergiu e quanto |
| `resultados/exploracao.md` | A exploração do `MERGED_CSV` completo: linhas por classe e por categoria, janela por classe, valores vazios e infinitos, colunas redundantes e linhas repetidas |
| `resultados/manifesto_amostra.json` | O registro da amostra: semente, teto, contagem por classe no conjunto e na amostra, hash dos arquivos lidos e hash da amostra |
| `resultados/metricas_classificador.csv` | Recall, precisão e F1 por classe |
| `resultados/matriz_confusao.png` | O que o modelo confunde com o quê |
| `resultados/avaliacao_agentes.csv` | A qualidade das recomendações — **a tabela que ainda não tem métrica definida** |
| `resultados/custo_latencia.csv` | Tokens e tempo de resposta por alerta |
| `notebooks/` | Exploração livre. Nada que vá para o artigo nasce aqui sem virar script |

**Raiz do repositório**

| Arquivo | O que faz |
|---|---|
| `requirements.txt` | As dependências fixadas, para todo mundo rodar igual |
| `.env.example` | Modelo das variáveis de ambiente (chave da LLM). O `.env` de verdade nunca entra no git |

### Ordem em que essas coisas nascem

1. `mcp/contrato.json` — destrava as duas frentes
2. `captura/extrator.py` e `captura/calibrar.py` — caminho crítico
3. `classificador/mapeamento.py` → `explorar.py` e `amostrar.py` → `preparar.py` → `treinar.py` → `avaliar.py`
4. `mcp/stub.py` (em paralelo a tudo, desde o contrato) → `mcp/servidor.py`
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

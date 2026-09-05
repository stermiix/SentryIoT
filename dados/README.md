# Dados — como montar o ambiente

O dataset **não é versionado no git** (são ~17 GB). O repositório guarda o código e as decisões;
os dados são uma dependência que se instala — mesma lógica do `node_modules`.

Este arquivo é a receita. Seguindo ele, qualquer integrante chega ao mesmo ponto.

## De onde vem

**CICIoT2023** — Canadian Institute for Cybersecurity (UNB).

- **Atalho (recomendado):** pasta do grupo no Google Drive, já baixada e organizada —
  <https://drive.google.com/drive/folders/1_7z8FdOGWJy4btkNhMS7gWv6abKyzoW6?usp=sharing>
- **Fonte oficial:** <http://cicresearch.ca/IOTDataset/CIC_IOT_Dataset2023/>
  (exige preencher um formulário de cadastro antes de liberar os arquivos)

Não usar re-uploads de terceiros (Kaggle e afins): não dá para citar a origem no artigo e não há
garantia de que o conteúdo bate com o oficial.

## Onde colocar

A pasta `CICIoT2023/` vai na **raiz do repositório**, irmã de `codigo/` e `artigo/`.
Já está no `.gitignore`.

```
TCC/CICIoT2023/
├── MERGED_CSV/                  <- O DATASET DE TREINO (63 arquivos, 8,7 GB)
├── <34 pastas, uma por ataque>/ <- CSVs por ataque, sem rótulo (usados na calibração)
├── DictionaryBruteForce.pcap    <- 38 MB — o pcap da calibração
├── Recon-PortScan.pcap          <- 192 MB
├── pcap2csv/                    <- o extrator DOS AUTORES (código de referência)
├── example.ipynb                <- notebook de ML dos autores (ler as ressalvas abaixo)
├── tools/                       <- notas das ferramentas usadas
├── README.pdf  README_CSV.pdf
```

---

## O dataset de treino: `MERGED_CSV/`

**É este que se usa para treinar.** 63 arquivos, ~44,5 milhões de linhas no total, 8,7 GB.

- **40 colunas: as 39 features + `Label`** (com L maiúsculo).
- As 39 features são **idênticas** às dos CSVs por ataque e às que o `pcap2csv` produz —
  conferido coluna por coluna. É isso que garante que treino e operação usem os mesmos números.
- Já vem mesclado entre ataques e embaralhado: cada arquivo contém linhas de todas as 34 classes.

**Por que 63 arquivos e não um só:** é saída do PySpark (cada trabalhador grava a sua parte), e
8,7 GB num arquivo único seria inabrível. Cada pedaço tem ~137 MB e cabe na memória.

**Cada arquivo é representativo do conjunto todo** (verificado em 05/09/2026):

| | Linhas | DDOS-ICMP | BENIGN | BruteForce | PortScan |
|---|---|---|---|---|---|
| Merged01 | 712.311 | 15,25% | 2,33% | 204 | 1.251 |
| Merged32 | 704.067 | 15,24% | 2,34% | 193 | 1.205 |
| Merged63 | 428.161 | 15,33% | 2,38% | 116 | 726 |

### Como amostrar para treinar

8,7 GB não cabem na memória, e Random Forest precisa de tudo junto. A estratégia:

**percorrer os 63 arquivos guardando TODAS as linhas das classes raras e só uma fatia das
classes gigantes** (um teto de ~50 mil por classe, por exemplo). Isso derruba de 44 milhões para
cerca de 1 milhão de linhas e ataca o desbalanceamento ao mesmo tempo.

Nas classes raras, usar os 63 arquivos faz diferença real: `DICTIONARYBRUTEFORCE` sai de 204
exemplos (1 arquivo) para ~12 mil (63 arquivos).

⚠ O script de amostragem **precisa ficar versionado, com semente fixa**, e a estratégia precisa
ir para a metodologia do artigo. Sem isso o resultado não é reproduzível.

### Armadilha dos rótulos

No `MERGED_CSV` os rótulos vêm **em maiúsculas** (`DDOS-ICMP_FLOOD`), mas o dicionário de
agrupamento do notebook dos autores usa a grafia normal (`DDoS-ICMP_Flood`). Aplicar o dicionário
direto não casa com nada e zera tudo em silêncio. **Normalizar antes.**

---

## Decisões já tomadas

**Usamos as 39 features do `MERGED_CSV`.** Treino e operação usam exatamente o mesmo conjunto de
números, e o extrator consegue reproduzi-los ao vivo. (Havia uma versão de 46 features; as 7
extras não saem do código publicado pelos autores — as linhas que as calculariam estão comentadas
no `Feature_extraction.py`, linhas 132 e 171. Por isso ela foi descartada.)

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

O `pcap2csv/` é o extrator dos autores. A sequência:

1. Rodar o original no `DictionaryBruteForce.pcap` → confirmar que reproduz o CSV oficial (controle)
2. Adaptar para ler de uma interface de rede ao vivo (o trabalho de verdade — o código atual é só
   para arquivo e usa `rdpcap()`, que carrega o pcap inteiro na memória)
3. Rodar a versão adaptada no mesmo pcap → confirmar que os números não mudaram (**a calibração
   que vale**)

Parâmetro-chave: `Feature_extraction.py`, linha 477, `n_rows = 10` — cada linha do CSV resume
**10 pacotes consecutivos**, não uma janela de tempo. Confirma-se pela coluna `Number`.

Stack real dos autores (de `tools/` e do código): `tcpdump` captura e fatia, **`dpkt`** faz o
parsing, `mergecap` junta capturas, `PySpark` junta os CSVs. **O Scapy só é usado para Zigbee e
Bluetooth** — não para o tráfego IP.

**Alvos de verificação** (medidos em 03/09/2026):

| Arquivo | Pacotes | Linhas no CSV oficial | Pacotes/10 |
|---|---|---|---|
| `DictionaryBruteForce.pcap` | 133.138 | 13.064 | 13.313 |
| `Recon-PortScan.pcap` | 831.856 | 82.284 | 83.185 |

A diferença de 1–2% para menos é esperada: há um `except: continue` no laço principal que descarta
pacotes que o `dpkt` não interpreta.

---

## Sobre as classes

34 classes no total. Confirmado no conjunto completo: **não existe classe de exfiltração de dados**.
E as classes dos nossos cenários são muito desiguais — `DICTIONARYBRUTEFORCE` é 0,03% dos dados.
Decisão pendente com o orientador (ver `ROADMAP.md`).

Consequência para as métricas: **relatar recall por classe, nunca só acurácia.** Com 78% de
DDoS/DoS, um modelo que respondesse "DDoS" para tudo acertaria 78% e seria inútil. Quando formos
mal numa classe rara, dizer isso no artigo com o número de amostras ao lado.

---

## Mapa completo de arquivos

Tudo que existe hoje e tudo que vamos criar. Quem for começar numa frente, procure a sua seção.

### O que já existe — dataset e código de referência (não versionado)

```
CICIoT2023/
├── MERGED_CSV/                      63 arquivos, 8,7 GB — O DATASET DE TREINO
│   └── Merged01.csv … Merged63.csv  39 features + Label, embaralhado
│
├── DictionaryBruteForce.pcap        38 MB  — pcap da calibração (use este)
├── Recon-PortScan.pcap              192 MB — segundo pcap, para conferência
│
├── <34 pastas por ataque>/          CSVs de 39 features SEM rótulo.
│   ├── DictionaryBruteForce/          Servem de gabarito da calibração:
│   ├── Recon-PortScan/                é com eles que se compara a saída
│   ├── DDoS-ICMP_Flood/               do nosso extrator.
│   └── …
│
├── pcap2csv/                        O EXTRATOR DOS AUTORES — base do nosso
│   ├── Feature_extraction.py          27 KB, o principal. n_rows = 10 na linha 477
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
| `extrator.py` | O extrator adaptado do `pcap2csv`. Lê de arquivo **ou de interface de rede ao vivo** e produz as 39 features a cada 10 pacotes |
| `calibrar.py` | Roda o extrator no `DictionaryBruteForce.pcap` e compara com o CSV oficial. Confere contagem de linhas (alvo: ~13.064), nomes e ordem das colunas, e valores linha a linha |

**Frente de dados e classificador** — `codigo/classificador/`

| Arquivo | O que faz |
|---|---|
| `mapeamento.py` | O `dict_7classes` dos autores, com os rótulos normalizados (o `MERGED_CSV` usa MAIÚSCULAS) |
| `amostrar.py` | Percorre os 63 arquivos do `MERGED_CSV`, guarda todas as linhas das classes raras e limita as gigantes. **Semente fixa.** Gera o conjunto de treino |
| `preparar.py` | Aplica o agrupamento em 8 categorias e separa treino e teste. Grava a divisão usada |
| `treinar.py` | Treina o Random Forest e salva o modelo. Sem `StandardScaler` |
| `avaliar.py` | Recall por classe, matriz de confusão, taxa de falso positivo, importância das features, tempo de inferência e tamanho do modelo |

**Frente de MCP e agentes** — `codigo/mcp/` e `codigo/agente/`

| Arquivo | O que faz |
|---|---|
| `mcp/contrato.json` | O contrato da tool: o que o classificador recebe e devolve. **Primeiro artefato a existir** — é ele que destrava as duas frentes em paralelo |
| `mcp/stub.py` | Devolve predições falsas no formato do contrato, para a frente de agentes trabalhar antes de o modelo existir |
| `mcp/servidor.py` | O servidor MCP de verdade, expondo o classificador como tool |
| `agente/agentes.py` | O sistema multiagente: triagem, contexto e mitigação |
| `agente/prompts/` | Os prompts de cada agente, em arquivos separados |
| `agente/acionamento.py` | A política de acionamento: agrega, deduplica e decide quando vale chamar a LLM. Sem isso, um DDoS gera milhares de chamadas por segundo |
| `agente/teste_tool_poisoning.py` | O experimento de segurança do MCP: uma tool com descrição envenenada, para medir se o agente cai |

**Resultados** — `experimentos/`

| Arquivo | O que faz |
|---|---|
| `resultados/calibracao.md` | O relatório da calibração: o que bateu, o que divergiu e quanto |
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
3. `classificador/amostrar.py` → `preparar.py` → `treinar.py` → `avaliar.py`
4. `mcp/stub.py` (em paralelo a tudo, desde o contrato) → `mcp/servidor.py`
5. `agente/` — depois que o servidor responde
6. `experimentos/resultados/` — as tabelas vazias devem existir **antes** dos experimentos

## Ambiente Python

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install dpkt scapy pandas scikit-learn numpy tqdm
```

## O que NUNCA vai para o git

`CICIoT2023/`, arquivos `.pcap`, CSVs grandes, modelos treinados (`.pkl`, `.joblib`) e `.env`.

## O que SEMPRE vai para o git

Código, o script de amostragem com semente fixa, a lista de features, a definição da divisão
treino/teste, métricas e tabelas (em `experimentos/resultados/`) e as decisões no `ROADMAP.md`.
Cuidado para não salvar resultado dentro de `dados/` — essa pasta é ignorada e eles sumiriam.

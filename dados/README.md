# Dados — como montar o ambiente

O dataset **não é versionado no git** (são ~8,6 GB). O repositório guarda o código e as
decisões; os dados são uma dependência que se instala — mesma lógica do `node_modules`.

Este arquivo é a receita. Seguindo ele, qualquer integrante chega exatamente ao mesmo ponto.

## De onde vem

**CICIoT2023** — Canadian Institute for Cybersecurity (UNB).

- **Atalho (recomendado):** pasta compartilhada do grupo no Google Drive, já com tudo baixado e
  organizado — <https://drive.google.com/drive/folders/1_7z8FdOGWJy4btkNhMS7gWv6abKyzoW6?usp=sharing>
- **Fonte oficial:** <http://cicresearch.ca/IOTDataset/CIC_IOT_Dataset2023/>
  (exige preencher um formulário de cadastro antes de liberar os arquivos)

Não usar re-uploads de terceiros (Kaggle e afins): não dá para citar a origem no artigo e não há
garantia de que o conteúdo bate com o oficial.

## Onde colocar

Baixe e coloque a pasta `CICIoT2023/` na **raiz do repositório** (irmã de `codigo/` e `artigo/`).
Ela já está no `.gitignore`.

```
TCC/
├── CICIoT2023/              <- colocar aqui (~8,6 GB, fora do git)
│   ├── <34 pastas: 33 ataques + Benign_Final>/
│   │   └── <Classe>.pcap.csv        # CSV de 39 features
│   ├── DictionaryBruteForce.pcap    # 38 MB  — usado na calibração
│   ├── Recon-PortScan.pcap          # 192 MB
│   ├── pcap2csv/                    # código de extração DOS AUTORES
│   ├── tools/                       # notas das ferramentas usadas
│   ├── README.pdf
│   └── README_CSV.pdf
├── codigo/
├── dados/                   <- este README; dados derivados ficam fora do git
└── experimentos/resultados/ <- métricas e artefatos pequenos VÃO para o git
```

## Fatos importantes sobre o dataset

Levantados em 03/09/2026 lendo o código dos autores. Poupam muita descoberta repetida.

**Existem dois níveis de CSV, e a diferença importa muito:**

| | Por ataque (o que temos) | Consolidado "ML-ready" |
|---|---|---|
| Colunas | **39** | não verificado — não temos os arquivos |
| Coluna de rótulo | **não tem** | tem (`label`) |
| Organização | uma pasta por classe | combinado e embaralhado |
| Arquivo | `<Classe>/<Classe>.pcap.csv` | conjunto separado, não baixado |
| Gerado pelo código publicado | **sim** | não |

As 39 colunas foram conferidas em 04/09/2026 direto no código e nos arquivos:
`Feature_extraction.py` declara `columns` com 40 nomes (linha 19), e a linha 519 remove `ts`
antes de salvar — sobram exatamente as 39 do cabeçalho dos CSVs.

**Não existe coluna de rótulo nos CSVs por ataque.** `grep -rn "label" pcap2csv/*.py` não retorna
nada: quem gera o rótulo é o nome da pasta. O pré-processamento precisa injetá-lo.

O que o código calcula mas **não** emite (verificado por leitura): `flow_duration`, `srate` e
`drate` (linhas 358–361), `urg_count` (linha 332), e o bloco de features dinâmicas
(`magnite, radius, correlation, covaraince, var_ratio, weight`) que está comentado nas linhas
132 e 171, além de `Covariance` na linha 513. Quantas dessas entram no consolidado e qual é a
contagem exata dele **não dá para afirmar com o material local** — os PDFs não trazem a lista de
features em texto e o conjunto consolidado não foi baixado. Não citar "46 features" no artigo sem
conferir na fonte oficial.

➡ **Decisão do projeto: usamos os CSVs de 39 features.** Só assim a calibração do nosso extrator
é verificável contra o oficial. Custo aceito: menos comparabilidade direta com baselines da
literatura, que costumam usar a versão consolidada. Isso é justificado no artigo.

**A janela de agregação é de 10 pacotes, não de tempo.**
`Feature_extraction.py`, linha 477: `n_rows = 10`. Cada linha do CSV resume 10 pacotes
consecutivos — dá para confirmar pela coluna `Number`, que vale 10 em todas as linhas.

**A stack real dos autores** (de `tools/` e do código): `tcpdump` captura e fatia o pcap em
pedaços de 10 MB, **`dpkt`** faz o parsing dos pacotes, `mergecap` (Wireshark) junta capturas,
`PySpark` junta os CSVs. O **Scapy só é usado para Zigbee e Bluetooth** — não para o tráfego IP.
Por isso nosso extrator usa `dpkt`, seguindo a referência.

**São 34 pastas de classe: 33 ataques + 1 de tráfego benigno** (`Benign_Final`), agrupados pelo
`README.pdf` oficial em 7 categorias. Contagem medida em 04/09/2026 sobre os 309 CSVs,
**46.776.697 amostras** no total:

| Categoria | Classes | Amostras | % |
|---|---:|---:|---:|
| DDoS | 12 | 33.984.450 | 72,65% |
| DoS | 4 | 7.845.117 | 16,77% |
| Mirai | 3 | 2.634.054 | 5,63% |
| Benigno | 1 | 1.098.191 | 2,35% |
| Recon | 5 | 690.534 | 1,48% |
| Spoofing | 2 | 486.458 | 1,04% |
| Web-based | 6 | 24.829 | 0,053% |
| Brute Force | 1 | 13.064 | 0,028% |

**Não existe classe de exfiltração de dados** — nenhuma das 33. E o brute force tem uma variante
só (`DictionaryBruteForce`, 13.064 amostras). A PoC promete 4 cenários e o dataset cobre 3, com 1
deles frágil. Decisão pendente com o orientador (ver `ROADMAP.md`).

**O desbalanceamento é extremo:** `DDoS-ICMP_Flood` (7.200.501) contra `Uploading_Attack` (1.252)
dá 5.751:1, e DDoS+DoS somam 89,4% de tudo. Consequência prática: acurácia global vai passar de
99% sem significar nada. Reportar métricas por classe e macro-F1, nunca só a acurácia.

**Cuidado com o split:** cada linha agrega 10 pacotes consecutivos do mesmo pcap, então linhas
vizinhas são correlacionadas. Embaralhar linhas antes de dividir treino/teste vaza informação e
infla o resultado. A divisão tem que ser por arquivo.

**Verificação de integridade** (rodada em 03/09/2026 — os números devem bater):

| Arquivo | Pacotes | Linhas no CSV oficial | Pacotes/10 |
|---|---|---|---|
| `DictionaryBruteForce.pcap` | 133.138 | 13.064 | 13.313 |
| `Recon-PortScan.pcap` | 831.856 | 82.284 | 83.185 |

A diferença de 1–2% para menos é esperada: o extrator descarta pacotes que o `dpkt` não consegue
interpretar (há um `except: continue` no laço principal). Se o seu extrator chegar nessa mesma
faixa, o entendimento do pipeline está correto.

## Ambiente Python

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install dpkt scapy pandas scikit-learn numpy tqdm
```

## O que NUNCA vai para o git

Datasets (`CICIoT2023/`), `.pcap`, `.csv` grandes, modelos treinados (`.pkl`, `.joblib`) e `.env`.

## O que SEMPRE vai para o git

Código, a lista de features selecionadas, a definição da divisão treino/teste, métricas e tabelas
de resultado (em `experimentos/resultados/`) e as decisões registradas no `ROADMAP.md`.
Cuidado para não salvar resultado dentro de `dados/` — essa pasta é ignorada e eles sumiriam.

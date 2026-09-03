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
│   ├── <uma pasta por classe de ataque>/
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

| | Por ataque | Consolidado |
|---|---|---|
| Features | **39** | 46 |
| Arquivo | `<Classe>/<Classe>.pcap.csv` | versão "ML-ready" |
| Gerado pelo código publicado | **sim** | não |

As 7 features a mais do consolidado (`flow_duration`, `Duration`, `Srate`, `Drate`, `urg_count`,
`Magnitue`, `Radius`, `Covariance`, `Weight`) vêm de uma etapa que os autores **não publicaram** —
no `Feature_extraction.py` as linhas que as calculariam estão comentadas (132 e 171).

➡ **Decisão do projeto: usamos os CSVs de 39 features.** Só assim a calibração do nosso extrator
é verificável contra o oficial. Custo aceito: menos comparabilidade direta com baselines da
literatura, que costumam usar a versão de 46. Isso é justificado no artigo.

**A janela de agregação é de 10 pacotes, não de tempo.**
`Feature_extraction.py`, linha 477: `n_rows = 10`. Cada linha do CSV resume 10 pacotes
consecutivos — dá para confirmar pela coluna `Number`, que vale 10 em todas as linhas.

**A stack real dos autores** (de `tools/` e do código): `tcpdump` captura e fatia o pcap em
pedaços de 10 MB, **`dpkt`** faz o parsing dos pacotes, `mergecap` (Wireshark) junta capturas,
`PySpark` junta os CSVs. O **Scapy só é usado para Zigbee e Bluetooth** — não para o tráfego IP.
Por isso nosso extrator usa `dpkt`, seguindo a referência.

**Não existe classe de exfiltração de dados** — são 34 classes, nenhuma delas. E o brute force é
raríssimo: `DictionaryBruteForce` tem 0,027% das amostras. Decisão pendente com o orientador
(ver `ROADMAP.md`).

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

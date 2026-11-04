# Referências

Bibliografia e material de apoio do SentryIoT.

Material de origem, na pasta-mãe `RoadMap_TCC/` (fora deste repositório):
`Artigo_TCC1.pdf`, `Poster_TCC1.pdf`, `EditalTCC_2026_2-V1.pdf`, `PROFESSOR.md`.

## Fontes do trabalho

- **Dataset CICIoT2023 (página oficial, pcaps, CSVs e código dos autores):**
  <https://cicresearch.ca/IOTDataset/CIC_IOT_Dataset2023/>
- **Artigo do dataset:** Neto et al. (2023), *Sensors* 23(13), 5941, DOI 10.3390/s23135941.
- **Repositório do projeto:** <https://github.com/stermiix/SentryIoT>

## Referências do artigo

A lista fica em `artigo/latex/referencias.bib`, no formato do abntex2cite; o que ainda falta
conferir na fonte leva CONFERIR no campo `note`. Fontes conferidas em 11/10/2026.

Conferido em 26/10/2026: Doménech et al. (2025) no PDF; os resumos de Neto, Engelen, Liu, Greshake,
Radosevich e Halloran, Hou, Kelly e Zhang; a publicação em anais de Greshake et al. (AISec 2023) e
de Yao et al. (ICLR 2023); e as páginas da Darktrace, da Netskope e da Vectra. Ramkumar et al.
ficou de fora: o texto completo é pago e não foi possível confirmar que ele filtra por MAC.

### Notas de conferência por fonte

Vieram do antigo `artigo/esqueleto.md`, que saiu do repositório em 03/11/2026 (fica no histórico
do git). Dizem o que foi lido de cada fonte e o cuidado ao citá-la.

- **Neto et al. (2023):** artigo do CICIoT2023, revisado por pares (*Sensors*). Conferido em
  26/10/2026 no resumo, via Crossref, porque o site da MDPI bloqueou a leitura: 33 ataques, 105
  dispositivos IoT, sete categorias (DDoS, DoS, Recon, Web-based, brute force, spoofing e Mirai),
  todos executados por dispositivos IoT maliciosos contra outros dispositivos IoT. Conferido em
  03/11/2026 no texto completo, pelo Europe PMC (PMC10346235): a seção 4 (*Feature Extraction and
  Data Description*) lista numa tabela as 47 features, de `ts` a `Weight`, e documenta as janelas
  de 10 pacotes (Backdoor Malware, Benign Traffic, ..., XSS) e de 100 pacotes (DDoS, DoS e Mirai),
  com a média dos valores de cada janela; o motivo dado é reduzir a diferença de volume entre as
  classes (o exemplo deles é DDoS e CommandInjection). Doménech et al. (2025) confirmam. Os pcaps e
  o código de extração vêm da página oficial do dataset (CANADIAN INSTITUTE FOR CYBERSECURITY,
  2023).
- **Doménech et al. (2025):** revisado por pares (*Internet of Things*, Elsevier), conferido no
  PDF em 26/10/2026. (a) A seção 3 documenta a janela de 100 pacotes para DDoS, DoS e Mirai e de
  10 para o resto, nos dois datasets (CICIoT2023 e CICIoMT2024). (b) A seção 5.1.1 recomenda janela
  uniforme para todos os tipos de tráfego, mas como crítica ao CICIoMT2024, que repete o esquema do
  CICIoT2023; ao citar, dizer isso, e não que a recomendação é sobre o CICIoT2023. (c) A queda de
  até 66,87% de F1 (Random Forest, 5 classes, experimento 2) vale **só** treinando no CICIoT2023 e
  testando no CICIoMT2024, e não nos dois sentidos, como o resumo do artigo sugere. (d) Critica
  métricas ponderadas em dataset desbalanceado e recomenda a média sem peso, o que apoia o uso de
  macro-F1 e de métricas por classe (seções 2.2 e 4.1.3 do artigo deles).
- **Engelen, Rimmer e Joosen (2021) e Liu et al. (2022):** revisados por pares (IEEE SPW e IEEE
  CNS). Só os resumos foram lidos, via Semantic Scholar, em 26/10/2026. Engelen et al. apontam
  problemas de geração de tráfego, construção de fluxos, extração de features e rotulagem no
  CICIDS2017, com mais de 20% do tráfego reconstruído ou rerrotulado; Liu et al. relatam erros na
  orquestração dos ataques, nas features, na documentação e nos rótulos do CIC-IDS-2017 e do
  CSE-CIC-IDS-2018.
- **Greshake et al. (2023):** lido por inteiro no arXiv. A publicação em anais (16th ACM Workshop
  on Artificial Intelligence and Security, AISec, junto do CCS '23, Copenhague, p. 79-90, DOI
  10.1145/3605764.3623985) vem do Crossref; o PDF dos anais não foi aberto.
- **Yao et al. (2023), ReAct:** o arXiv diz que a versão 3 é a final do ICLR 2023 (11ª edição,
  Kigali, 1 a 5 de maio, confirmado em iclr.cc). A página do OpenReview não abriu, e por isso a
  referência aponta para o arXiv.
- **Radosevich e Halloran (2025) e Hou et al. (2026):** introdução e seções principais lidas.
- **Darktrace, Netskope, Vectra AI e Kelly, Glavin e Barrett (2021):** pedidos pela banca do TCC I,
  com menção curta e sem análise detalhada. Páginas abertas em 26/10/2026: a da Darktrace é um blog
  de 18/11/2024; a da Netskope, um comunicado de 25/07/2023; a da Vectra, um comunicado de
  12/10/2022 republicado no Dark Reading.
- **Zhang et al. (2026):** *preprint* de 23/09/2026, e só o resumo foi lido. A lista de autores é
  longa, e por isso a referência usa "et al.".
- **Ramkumar et al.:** fora da lista. O candidato achado, sem confirmação de que é o trabalho da
  lista original ("2024"), é RAMKUMAR, K. et al. *Diagnosing unknown attacks in smart homes using
  abductive reasoning*, IEEE Transactions on Software Engineering, 2025, DOI
  10.1109/TSE.2025.3610540; o resumo só diz que usa o CICIoT2023 e o IoT-23 como referência.

## Pedido da banca do TCC I

Darktrace, Netskope, Vectra AI e o ataque *Denial of Wallet* (DoW): uma fonte citável para cada,
já incluída na lista do artigo. No texto, viram menção curta, sem análise detalhada.

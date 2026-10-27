# Comparação com o baseline publicado do Random Forest (Neto et al., 2023)

Relatório escrito à mão, sem script: os números publicados vêm do artigo, e os nossos, dos
relatórios gerados que cada linha cita.

**Fonte dos números publicados.** NETO, E. C. P. et al. CICIoT2023: a real-time dataset and
benchmark for large-scale attacks in IoT environment. *Sensors*, v. 23, n. 13, 5941, 2023. DOI
10.3390/s23135941. Lido em 27/10/2026 na versão do PubMed Central
(<https://pmc.ncbi.nlm.nih.gov/articles/PMC10346235/>): Tabela 6 (resultados dos modelos), Tabela 4
(features) e seções 4 e 5 (janelas e protocolo).

## 1. O que o artigo publica

Random Forest da Tabela 6, em três cenários. Os valores do artigo têm nove casas; aqui, em
percentual com duas.

| Cenário | Acurácia | Recall | Precisão | F1 |
|---|---|---|---|---|
| 2 classes (ataque ou benigno) | 99,68% | 96,52% | 96,54% | 96,53% |
| 8 classes (7 categorias e benigno) | 99,44% | 91,00% | 70,54% | 71,93% |
| 34 classes (33 ataques e benigno) | 99,16% | 83,16% | 70,45% | 71,40% |

O protocolo, nas palavras do artigo:
- a divisão é de 80% para o treino e 20% para o teste, com os dados normalizados pelo
  `StandardScaler` antes do treino (seção 5);
- a única feature retirada é o timestamp, "since it does not illustrate the network behavior"
  (seção 4);
- as janelas são de 100 pacotes em DDoS, DoS e Mirai e de 10 nas demais classes (seção 4).

O artigo não diz se recall, precisão e F1 são médias macro, micro ou ponderadas. O F1 bem abaixo
da acurácia sugere média macro, mas isso não está escrito.

## 2. Os nossos números mais próximos

Random Forest do scikit-learn sobre a amostra do `MERGED_CSV`, com as 39 colunas públicas, sorteio
estratificado de 80% para treino e 20% para teste, semente 42 (`treino_exploratorio.md`, tabela
"As 16 execuções"). Cada célula traz o valor na amostra de teste e, depois da barra, o reponderado
para a distribuição natural do dataset completo.

| Cenário | Execução | Priori de treino | Acurácia | Macro-F1 |
|---|---|---|---|---|
| 2 classes | `f39_estratificada_c2` | amostra | 97,06% / 98,66% | 76,49% / 80,27% |
| 2 classes | `f39_estratificada_c2_natural` | natural | 95,56% / 99,26% | 78,19% / 91,66% |
| 8 classes | `f39_estratificada_c8` | amostra | 84,55% / 82,66% | 72,21% / 67,01% |
| 8 classes | `f39_estratificada_c8_natural` | natural | 82,40% / 84,28% | 64,52% / 66,27% |
| 34 classes | `f39_estratificada_c34` | amostra | 74,07% / 75,07% | 62,83% / 58,76% |
| 34 classes | `f39_estratificada_c34_natural` | natural | 72,10% / 77,16% | 58,62% / 59,63% |

As execuções de 34 classes usam 25 árvores, e as demais, 100 (`treino_exploratorio.md`, "Custo de
cada execução"). O modelo do sistema não entra nesta comparação: ele é treinado nos dados
regerados dos pcaps, em janela única de 100 quadros e em 7 categorias, e os resultados dele estão
em `ponto_de_operacao.md`.

## 3. Por que os números não batem

**Os arquivos públicos têm 39 colunas, e o modelo do artigo usou 46.** A Tabela 4 lista 47
features. Sem o timestamp, o modelo do artigo recebeu 46. Os CSVs públicos e o nosso extrator
(`codigo/captura/extrator.py`, `COLUNAS`) têm 39:
- faltam oito: `flow duration`, `Srate`, `Drate`, `urg count`, `Magnitude`, `Radius`,
  `Covariance` e `Weight`;
- o `Duration` do artigo é o TTL ("Time-to-Live (ttl)", na Tabela 4), que nos arquivos públicos se
  chama `Time_To_Live`;
- o indicador `IGMP` é coluna dos arquivos públicos, e no artigo só aparece na descrição de
  `Protocol Type`.

Daí 46 − 8 + 1 = 39. Cinco das oito que faltam (`Srate`, `Drate`, `Magnitude`, `Radius` e
`Covariance`) separam o tráfego que entra do que sai do fluxo, e `Weight` multiplica as duas
contagens.

**Com as 39 colunas, o acerto em 8 categorias tem teto de 92,87%.** No `MERGED_CSV`, 29,49% das
linhas têm o vetor das 39 features igual ao de uma linha de outra categoria. Quem só vê essas
colunas dá a mesma resposta a todas essas linhas, e no conjunto completo, na proporção natural, o
acerto não passa de 92,87% (`exploracao.md`, seção 8). O teto cai quando o conjunto cresce. A
amostra inteira, de 1.288.479 linhas, já tem teto de 96,22%, e um teste de 20% do conjunto completo
teria cerca de 9 milhões. Os 99,44% publicados para 8 classes ficam acima desses dois valores: não
são alcançáveis com as 39 colunas públicas. O artigo não mede o efeito de cada coluna, e por isso a
diferença é coerente com as oito colunas que faltam, sem que isso esteja provado. O teto em 2 e em
34 classes não foi calculado.

**O protocolo também é outro.** As principais diferenças:
- o artigo divide o conjunto completo; nós dividimos uma amostra com teto de 50.000 linhas por
  rótulo e reponderamos as medidas;
- o artigo normaliza as features, o que não muda o Random Forest;
- o tipo de média das medidas do artigo não é conhecido;
- o notebook publicado pelos autores não treina o Random Forest, então não há código do artigo para
  repetir.

## 4. Como o artigo usa isto

O artigo não compara os números. Ele diz que o Random Forest está entre os melhores modelos do
benchmark dos autores, e explica por que os números não se comparam: as colunas públicas e o teto de
92,87% (seção 3.4 do `artigo/esqueleto.md`).

## 5. As outras partes da tarefa

- **Importância das features:** já medida, por Bernardo.
  - Por redução média de impureza no treino exploratório: `importancia_features.csv` e
    `treino_exploratorio.md`, "Importância das features".
  - No modelo de janela de 100 dos dados regerados: `regeracao.md`, em que as três primeiras são
    `Time_To_Live`, `Max` e `Tot sum`.
  - Por permutação, no modelo de 10/10: `rodadas_de_teste.md`, "Importância por permutação".
- **Ajuste enxuto de hiperparâmetros para reduzir o modelo do sistema (365,6 MB):** não feito. O
  treino precisa dos dados regerados (`dados/processed/regerado`), que ficam fora do git e não
  estão na máquina de quem escreveu este relatório. Fica pendente para quem tem os dados rodar,
  medindo tamanho em disco, tempo por janela e a Tabela 1 do artigo antes e depois.

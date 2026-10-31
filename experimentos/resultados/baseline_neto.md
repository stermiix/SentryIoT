# Comparação com o baseline publicado do Random Forest (Neto et al., 2023)

Relatório escrito à mão, sem script: os números publicados vêm do artigo, e os nossos, dos
relatórios gerados que cada linha cita. As poucas contas feitas aqui sobre tabelas do artigo podem
ser refeitas com o que está na seção 6, "Como conferir".

**Fonte dos números publicados.** NETO, E. C. P.; DADKHAH, S.; FERREIRA, R.; ZOHOURIAN, A.; LU,
R.; GHORBANI, A. A. CICIoT2023: a real-time dataset and benchmark for large-scale attacks in IoT
environment. **Sensors**, v. 23, n. 13, 5941, 2023. DOI: 10.3390/s23135941. Lido em 27/10/2026 e
conferido de novo em 30/10/2026 na versão do PubMed Central
(<https://pmc.ncbi.nlm.nih.gov/articles/PMC10346235/>): Tabela 3 (linhas por categoria), Tabela 4
(features), Tabela 5 (estatísticas de cada feature), Tabela 6 (resultados dos modelos), Tabela 8
(matriz de confusão do Random Forest em 8 classes) e seções 4 e 5 (janelas e protocolo). O notebook
citado é o `example.ipynb` que os autores distribuem com o dataset.

## 1. O que o artigo publica

Random Forest da Tabela 6, em três cenários. Os valores do artigo têm nove casas; aqui, em
percentual com duas. As colunas de recall e de precisão saíram trocadas no artigo, e a tabela as
traz com o nome impresso e o que de fato medem (ver adiante).

| Cenário | Acurácia | "Recall" impresso (é a precisão macro) | "Precision" impresso (é o recall macro) | F1 macro |
|---|---|---|---|---|
| 2 classes (ataque ou benigno) | 99,68% | 96,52% | 96,54% | 96,53% |
| 8 classes (7 categorias e benigno) | 99,44% | 91,00% | 70,54% | 71,93% |
| 34 classes (33 ataques e benigno) | 99,16% | 83,16% | 70,45% | 71,40% |

Nos três cenários, o Random Forest tem a maior acurácia e o maior F1 dos cinco modelos da Tabela 6.

O protocolo, segundo o artigo:
- a divisão é de 80% para o treino e 20% para o teste, com os dados normalizados pelo
  `StandardScaler` antes do treino (seção 5);
- a única feature retirada é o timestamp, "since it does not illustrate the network behavior"
  (seção 4);
- as janelas são de 100 pacotes em DDoS, DoS e Mirai e de 10 nas demais classes (seção 4).

O artigo não informa os hiperparâmetros do Random Forest, nem o número de árvores.

**Média macro, com precisão e recall trocados.** O artigo não diz como as medidas se agregam
quando há várias classes. O notebook dos autores responde: nos três cenários, ele chama
`recall_score(y_pred, y_test, average='macro')` e `precision_score(y_pred, y_test,
average='macro')` (`example.ipynb`, células 12, 17 e 22, contando a partir de 0). A média é macro, e
os argumentos estão na ordem inversa da que o scikit-learn espera, `(y_true, y_pred)`. Com a ordem
trocada, o que sai como recall é a precisão, e vice-versa; acurácia e F1 não mudam. A matriz de
confusão do Random Forest em 8 classes (Tabela 8) confirma a troca:

| Medida | Calculada da Tabela 8 | Impressa na Tabela 6 |
|---|---|---|
| Acurácia | 99,44% | 99,44% |
| Precisão macro | 91,74% | 91,00% (coluna "Recall") |
| Recall macro | 70,57% | 70,54% (coluna "Precision") |
| F1 macro (média dos F1 de cada classe) | 71,96% | 71,93% |
| F1 ponderado | 99,40% | não publicado |

O F1 macro bate com o impresso, e o ponderado não. A precisão difere em 0,74 ponto, e as outras
medidas, em menos de 0,05; o artigo não explica a diferença.

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

Três grupos de causas: os arquivos públicos são outra versão dos dados, as 39 colunas deles impõem
um teto em 8 categorias, e o protocolo é outro. A evidência mais direta de que a distância vem dos
dados é a do par DDoS e DoS.

**Os arquivos públicos são outra versão dos dados, e não só com menos colunas.**

- **Colunas.** A Tabela 4 lista 47 features. Sem o timestamp, o modelo do artigo recebeu 46. Os
  CSVs públicos e o nosso extrator (`codigo/captura/extrator.py`, `COLUNAS`) têm 39. Faltam oito:
  `flow duration`, `Srate`, `Drate`, `urg count`, `Magnitude`, `Radius`, `Covariance` e `Weight`.
  O `Duration` do artigo é o TTL ("Time-to-Live (ttl)", na Tabela 4), que nos arquivos públicos se
  chama `Time_To_Live`, e o indicador `IGMP` é coluna dos arquivos públicos, mas no artigo só
  aparece na descrição de `Protocol Type`. Daí 46 − 8 + 1 = 39.
- **Duas das oito quase não trazem informação nova.** Na Tabela 5 do artigo, `Srate` tem as mesmas
  estatísticas de `Rate` (média, desvio, mínimo, quartis e máximo), e `Drate` é zero até o percentil
  75, com máximo de 29,7. `Magnitude`, `Radius` e `Covariance` separam, no fluxo, o tráfego que
  entra do que sai, e `Weight` multiplica as contagens das duas direções.
- **Colunas de mesmo nome em outra escala.** A Tabela 5 do artigo e a faixa de valores dos arquivos
  públicos (`exploracao.md`, seções 6 e 7) não descrevem os mesmos dados:

  | Coluna | Tabela 5 do artigo | `MERGED_CSV` |
  |---|---|---|
  | `IAT` | média de 83.182.525,9 e máximo de 167.639.436 | de −0,017818 a 78.612,0 |
  | `Number` | de 1 a 15, com mediana de 9,5 | de 1 a 100 |
  | `Header_Length` | até 9.907.147,75, com percentil 75 de 280,555 | de 0 a 60 |
  | `Variance` | de 0 a 1, definida como razão entre as variâncias dos pacotes de entrada e de saída (Tabela 4) | até 135.848.458, igual a `Std` ao quadrado em todas as linhas |

- **Outras contagens de linhas.** A Tabela 3 do artigo soma 46.686.579 linhas, e o `MERGED_CSV`
  tem 45.019.234 (`exploracao.md`, seção 2). Recon tem 354.565 linhas no artigo e 661.121 nos
  arquivos públicos; nas outras sete categorias, os arquivos públicos têm de 4,15% a 4,27% menos
  linhas que o artigo.

Por isso o teto e o treino exploratório medem os arquivos públicos, e não os dados em que o artigo
mediu, que não estão disponíveis.

**Com as 39 colunas, o acerto em 8 categorias no conjunto completo tem teto de 92,87%.** No
`MERGED_CSV`, 29,49% das linhas têm o vetor das 39 features igual ao de uma linha de outra
categoria. Quem só vê essas colunas dá a mesma resposta a linhas de vetor igual, e no conjunto
completo, na proporção natural, o acerto não passa de 92,87% (`exploracao.md`, seção 8). O teto vale
para o conjunto em que é calculado e fica mais alto num conjunto menor: reponderado para a proporção
natural, é 96,22% na amostra de 1.288.479 linhas e 98,27% nas 257.696 linhas de teste de
`f39_estratificada_c8` (`treino_exploratorio.md`, "Limite da acurácia reponderada"). A amostra não é
um sorteio do conjunto completo, porque guarda no máximo 50.000 linhas de cada rótulo, e por isso
96,22% não é o teto de um teste sorteado de 20% do conjunto completo; esse teto não foi calculado.
O valor que se compara com a acurácia do artigo é outro: num sorteio de linhas do conjunto
completo, como o do artigo, a acurácia no teste estima a acurácia no conjunto completo, e o limite
esperado dela nestes arquivos é o teto do conjunto completo, 92,87% (mesma seção). Os 99,44%
publicados para 8 classes ficam 6,57 pontos acima. O teto em 2 e em 34 classes não foi calculado.

**A evidência mais direta: DDoS e DoS.** Nos arquivos públicos, quase toda a distância em 8
categorias está nesse par. Dos 3.209.716 erros da regra do teto no conjunto completo, 2.399.296 são
linhas de DoS e 806.209, de DDoS (`exploracao.md`, seção 8). No treino exploratório, 91,8% dos erros
reponderados do modelo de 8 categorias (`f39_estratificada_c8`) são trocas entre DDoS e DoS; sem
contá-las, a acurácia reponderada iria de 82,66% a 98,59%. Com a priori natural, juntar as duas
categorias leva a acurácia reponderada de 84,28% (`f39_estratificada_c8_natural`) a 99,10%
(`f39_estratificada_c7_natural`), perto dos 99,44% do artigo (`treino_exploratorio.md`, "DDoS e DoS"
e "As 16 execuções"). No artigo, as trocas entre DDoS e DoS são 1.645 dos 57.507 erros da Tabela 8,
2,9%, e o recall de DoS é de 99,93%. Os dados em que o artigo mediu separavam DDoS de DoS; nos
arquivos públicos, boa parte das linhas das duas categorias não se separa. O artigo não mede o
efeito de cada coluna, e por isso não se sabe qual diferença da versão dos dados explica a
separação.

**O protocolo também é outro.**
- **Divisão.** O artigo divide o conjunto completo, combinado e embaralhado (seção 5); nós dividimos
  uma amostra com teto de 50.000 linhas por rótulo e reponderamos as medidas.
- **Tamanho do treino.** O texto do artigo fala em 80% das 46.686.579 linhas, cerca de 37 milhões;
  a matriz da Tabela 8 soma 10.340.161 linhas de teste, 22,1% do total, e não 20%. Nos dois casos, o
  treino do artigo tem mais de 30 vezes as 1.030.783 linhas do nosso (`treino_exploratorio.md`,
  "Divisões entre treino e teste"). O efeito dessa diferença não foi medido.
- **Hiperparâmetros e número de árvores.** Os do artigo não são conhecidos. Os nossos são os padrão
  do scikit-learn 1.9.1, sem busca de hiperparâmetros, com 100 árvores, e 25 em 34 classes, porque a
  floresta de 100 árvores não caberia na memória da máquina usada (`treino_exploratorio.md`, "Custo
  de cada execução" e "Como os números foram obtidos"). A comparação em 34 classes é a mais fraca
  das três.
- **Priori de treino.** O artigo treina na proporção natural das classes. As nossas execuções com
  `_natural` no nome fazem o mesmo, por peso de linha; as outras treinam na proporção da amostra.
- **Medidas.** As do artigo são macro, com precisão e recall trocados (seção 1); as nossas usam a
  ordem certa dos argumentos. Acurácia e F1 não mudam com a troca, e são essas as medidas da
  tabela da seção 2.
- **Normalização.** O artigo normaliza as features, o que não muda o Random Forest: a árvore só
  compara valores de uma feature com limiares.
- **Código.** O notebook publicado pelos autores não treina o Random Forest: o
  `RandomForestClassifier` é importado nas células 15 e 20 e nunca instanciado, e só a regressão
  logística é treinada. Não há código do artigo para repetir.

## 4. Como o artigo do TCC usa isto

O artigo do TCC não compara os números do sistema com os da Tabela 6. A seção 3.4
(`artigo/latex/secoes/3-metodologia.tex`) cita o benchmark dos autores e explica, com os números
deste relatório, por que os resultados dele não se comparam com os do sistema: as colunas
públicas, os 29,49% de linhas que repetem o vetor de outra categoria e o teto de 92,87%, contra os
99,44% publicados.

## 5. As outras partes da tarefa

- **Importância das features:** já medida por Bernardo.
  - Por redução média de impureza no treino exploratório: `importancia_features.csv` e
    `treino_exploratorio.md`, "Importância das features".
  - No modelo de janela de 100 dos dados regerados: `regeracao.md`, em que as três primeiras são
    `Time_To_Live`, `Max` e `Tot sum`.
  - Por permutação, no modelo de 10/10: `rodadas_de_teste.md`, "Importância por permutação".
- **Ajuste enxuto de hiperparâmetros para reduzir o modelo do sistema (365,6 MB):** não feito. O
  treino precisa dos dados regerados (`dados/processed/regerado`), que ficam fora do git e não
  estão na máquina de quem escreveu este relatório. Fica pendente para quem tem os dados rodar o
  ajuste, medindo antes e depois o tamanho em disco, o tempo por janela e os números da Tabela 1
  do artigo do TCC.

## 6. Como conferir

**Números publicados.** Tabelas 3, 4, 5, 6 e 8 do artigo, no link do início. As medidas
calculadas da Tabela 8 (seções 1 e 3) saem da matriz, com a classe real nas linhas: a soma de cada
linha fica entre 21,9% e 22,8% das linhas da categoria na Tabela 3, e a das colunas não.

```python
import numpy as np

# Tabela 8 de Neto et al. (2023). Linhas: classe real; colunas: classe prevista.
# Ordem: Benign, BruteForce, DDoS, DoS, Mirai, Recon, Spoofing, Web.
m = np.array([
    [234929, 4, 24, 2, 4, 3192, 5159, 8],
    [1342, 169, 1, 0, 0, 844, 626, 1],
    [15, 0, 7525049, 557, 18, 339, 173, 0],
    [7, 0, 1088, 1790979, 34, 12, 47, 0],
    [5, 0, 603, 18, 582921, 100, 30, 0],
    [11565, 6, 1418, 11, 16, 60006, 5591, 17],
    [14618, 1, 18, 6, 11, 4743, 88371, 30],
    [1140, 1, 3, 1, 1, 1265, 2792, 230],
])
recall = np.diag(m) / m.sum(axis=1)
precisao = np.diag(m) / m.sum(axis=0)
f1 = 2 * precisao * recall / (precisao + recall)
erros = m.sum() - np.trace(m)
print("acurácia", np.trace(m) / m.sum())                        # 0,9944
print("precisão macro", precisao.mean())                        # 0,9174
print("recall macro", recall.mean())                            # 0,7057
print("F1 macro", f1.mean())                                    # 0,7196
print("F1 ponderado", (f1 * m.sum(axis=1)).sum() / m.sum())     # 0,9940
print("trocas DDoS e DoS", m[2, 3] + m[3, 2], "de", erros)      # 1.645 de 57.507
print("recall de DoS", recall[3])                               # 0,9993
print("linhas de teste", m.sum())                               # 10.340.161
```

**Notebook dos autores.** `example.ipynb`, distribuído com o dataset: células 12, 17 e 22 para as
medidas, 15 e 20 para os modelos, contando a partir de 0.

**Colunas públicas.** A primeira linha de qualquer arquivo do `MERGED_CSV`
(`head -1 CICIoT2023/MERGED_CSV/Merged01.csv`) traz as 39 colunas e o `Label`; o extrator usa as
mesmas, em `COLUNAS` de `codigo/captura/extrator.py`.

**Nossos números.** Os dois relatórios citados são gerados, e os comandos precisam do `MERGED_CSV`
em `CICIoT2023/MERGED_CSV`, fora do git:
- `exploracao.md` (linhas, faixas de valores, linhas repetidas e teto de 92,87%):
  `python -m codigo.classificador.explorar`, que lê o `MERGED_CSV` inteiro;
- `treino_exploratorio.md` (as execuções da seção 2, as trocas entre DDoS e DoS e os tetos de
  96,22% e 98,27%): `python -m codigo.classificador.amostrar`, que grava a amostra em
  `dados/processed/amostra.csv.gz`, seguido de `python -m codigo.classificador.experimento`. Os
  valores completos ficam em `manifesto_treino_exploratorio.json` e `metricas_classificador.csv`.

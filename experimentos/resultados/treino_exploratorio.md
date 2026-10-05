# Treino exploratório do classificador

Gerado por `python -m codigo.classificador.experimento` em 04/10/2026, com Python 3.11.2, scikit-learn 1.9.1, pandas 3.0.6 e numpy 2.4.6.

Dez execuções do Random Forest sobre a amostra de treino do CICIoT2023 (Neto et al., 2023). Oito
combinam três escolhas que estão em aberto no `ROADMAP.md`: as colunas que dependem do tamanho da
janela, a divisão entre treino e teste e a separação entre DDoS e DoS. Duas servem de referência para
os cenários do artigo do dataset. O relatório traz os números e não recomenda nenhuma das saídas.

## Como ler os números

**Amostra e conjunto completo.** Todas as execuções usam a amostra de treino (`dados/processed/amostra.csv.gz`, 1.288.479 linhas), que limita as linhas de cada classe. Nela, DDoS e DoS somam 58,2% das linhas; no conjunto completo, de 45.019.234 linhas, somam 89,5%. Por isso cada medida aparece de duas formas:

- **na amostra**: calculada sobre as linhas de teste como elas são;
- **reponderada**: cada linha de teste pesa a quantidade de linhas do seu rótulo no conjunto completo
  dividida pela quantidade no teste, com as contagens de `manifesto_amostra.json`. É a estimativa da
  medida na distribuição original do dataset.

A ponderação altera só o cálculo da medida. O modelo é o mesmo nas duas formas e foi treinado com as
proporções da amostra.

O peso é por rótulo, entre os 34, e não por classe do alvo. O recall de um rótulo não muda com a ponderação. O de uma categoria que reúne vários rótulos muda, porque dentro dela os rótulos passam a pesar de outra forma. Na amostra, `DoS-HTTP_Flood` é 25,0% das linhas de DoS; no conjunto completo, 0,9%. A taxa de tráfego benigno classificado como ataque não muda, porque o tráfego benigno é um rótulo só.

**Vetor idêntico.** Duas linhas têm o mesmo vetor quando são iguais em todas as features da execução, depois da conversão para ponto flutuante de 32 bits, que é como o scikit-learn as entrega às árvores. A amostra tem 1.140.373 vetores distintos com as 39 features e 1.140.354 com as 33. Com as 39, 206.815 linhas (16,05%) repetem o vetor de outra linha. No conjunto completo são 58,78% (`exploracao.md`): a amostra guarda uma fração pequena das classes grandes, e a maior parte das repetições delas fica de fora.

**Teto.** É um limite por coincidência exata de vetores, calculado nas linhas de teste de cada execução. Quem só vê as features dá a mesma resposta a todas as linhas com o mesmo vetor. A regra que mais acerta responde, em cada vetor, a classe de maior peso, e as linhas das outras classes são erro certo. A acurácia dessa regra é a maior possível naquelas linhas, e é com ela que a acurácia do modelo na mesma execução se compara. O teto depende do tamanho e da mistura de classes do conjunto em que é medido: com mais linhas, mais vetores se repetem com classes diferentes. Por isso ele muda com a divisão. No sorteio de linhas, parte das repetições de um vetor fica no treino e não entra na conta. O teto que a exploração mediu vale para o conjunto completo, na proporção natural das classes, e não é o limite destas execuções.

**Recall na regra do teto.** As tabelas por classe trazem o recall de cada classe na regra que dá o teto. Ele não é um limite por classe: a regra maximiza o acerto global, e outra regra pode acertar mais numa classe e menos em outra. No empate entre classes num vetor, a regra fica com a primeira na ordem das tabelas.

**Valores vazios e infinitos.** 49 linhas da amostra têm `Std` e `Variance` vazios ou `Rate` infinito. Elas são mantidas. O infinito entra como vazio, e o Random Forest do scikit-learn trata o vazio sem imputação.

**Uma semente.** Cada execução foi feita uma vez, com a semente 42 na divisão e no modelo. Diferenças pequenas entre execuções podem vir do sorteio, e não da escolha comparada. Para repetir com outro sorteio: `python -m codigo.classificador.experimento --semente N --saida OUTRA_PASTA`.

## Divisões entre treino e teste

As duas divisões reservam 20% das linhas para o teste e são as mesmas em todas as execuções que as usam, quaisquer que sejam as features e o alvo.

- **Sorteio estratificado**: sorteio de linhas com a mesma fração de cada um dos 34 rótulos no teste.
  É o método dos autores do dataset.
- **Divisão por grupos**: todas as linhas com o mesmo vetor nas 33 features ficam do mesmo lado. Linhas
  iguais nas 39 também são iguais nas 33, então nenhum vetor aparece no treino e no teste, com
  qualquer dos dois conjuntos de features. O sorteio dos grupos é estratificado pelo rótulo mais
  frequente de cada grupo.

| Divisão | Linhas de treino | Linhas de teste | Linhas de teste com vetor que está no treino, 39 features | Idem, 33 features |
|---|---|---|---|---|
| sorteio estratificado | 1.030.783 | 257.696 | 38.934 (15,11%) | 38.939 (15,11%) |
| divisão por grupos | 1.030.491 | 257.988 | 0 (0,00%) | 0 (0,00%) |

O hash das linhas de teste de cada divisão está no manifesto do experimento.

## As 10 execuções

Medidas globais nas linhas de teste. Em cada par de colunas, a primeira é na amostra e a segunda é
reponderada para a distribuição original.

| Execução | Features | Divisão | Alvo | Acurácia na amostra | Acurácia reponderada | Macro-F1 na amostra | Macro-F1 reponderado | F1 ponderado na amostra | F1 ponderado reponderado | Teto na amostra | Teto reponderado |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `f39_estratificada_c8` | 39 | sorteio estratificado | 8 categorias | 84,55% | 82,66% | 72,21% | 67,01% | 84,01% | 83,01% | 98,82% | 98,27% |
| `f39_estratificada_c7` | 39 | sorteio estratificado | 7 categorias | 93,81% | 98,58% | 74,11% | 69,96% | 93,41% | 98,58% | 99,96% | 99,99% |
| `f39_grupos_c8` | 39 | divisão por grupos | 8 categorias | 84,62% | 82,79% | 72,37% | 67,21% | 84,08% | 83,11% | 97,64% | 96,24% |
| `f39_grupos_c7` | 39 | divisão por grupos | 7 categorias | 93,86% | 98,61% | 74,41% | 70,42% | 93,47% | 98,62% | 99,95% | 99,99% |
| `f33_estratificada_c8` | 33 | sorteio estratificado | 8 categorias | 84,37% | 82,61% | 71,82% | 66,67% | 83,82% | 82,96% | 98,82% | 98,27% |
| `f33_estratificada_c7` | 33 | sorteio estratificado | 7 categorias | 93,67% | 98,55% | 73,89% | 69,87% | 93,26% | 98,55% | 99,95% | 99,99% |
| `f33_grupos_c8` | 33 | divisão por grupos | 8 categorias | 84,36% | 82,70% | 71,94% | 66,95% | 83,80% | 83,01% | 97,64% | 96,24% |
| `f33_grupos_c7` | 33 | divisão por grupos | 7 categorias | 93,67% | 98,58% | 73,97% | 70,12% | 93,27% | 98,59% | 99,95% | 99,99% |
| `f39_estratificada_c34` | 39 | sorteio estratificado | 34 classes | 74,07% | 75,07% | 62,83% | 58,76% | 73,51% | 75,01% | 98,43% | 97,58% |
| `f39_estratificada_c2` | 39 | sorteio estratificado | ataque ou benigno | 97,06% | 98,66% | 76,49% | 80,27% | 96,77% | 98,43% | 99,99% | 100,00% |

Classes de interesse. Onde há dois valores, o primeiro é na amostra e o segundo é reponderado. O recall
do tráfego benigno e a taxa de benigno classificado como ataque são iguais nas duas distribuições.

| Execução | Recall de DDoS | Recall de DoS | Recall de DDoS+DoS | Recall de benigno | Benigno classificado como ataque | Ataque classificado como benigno |
|---|---|---|---|---|---|---|
| `f39_estratificada_c8` | 90,74% e 87,50% | 65,61% e 59,88% | não se aplica | 53,82% | 46,18% | 1,27% e 0,10% |
| `f39_estratificada_c7` | não se aplica | não se aplica | 99,98% e 99,99% | 53,62% | 46,38% | 1,27% e 0,10% |
| `f39_grupos_c8` | 90,86% e 87,72% | 65,38% e 59,59% | não se aplica | 54,96% | 45,04% | 1,29% e 0,10% |
| `f39_grupos_c7` | não se aplica | não se aplica | 99,98% e 99,99% | 54,92% | 45,08% | 1,30% e 0,10% |
| `f33_estratificada_c8` | 90,64% e 87,46% | 65,25% e 59,90% | não se aplica | 53,22% | 46,78% | 1,27% e 0,10% |
| `f33_estratificada_c7` | não se aplica | não se aplica | 99,86% e 99,98% | 52,78% | 47,22% | 1,27% e 0,10% |
| `f33_grupos_c8` | 90,82% e 87,75% | 64,63% e 59,08% | não se aplica | 54,31% | 45,69% | 1,29% e 0,10% |
| `f33_grupos_c7` | não se aplica | não se aplica | 99,85% e 99,98% | 54,49% | 45,51% | 1,29% e 0,10% |
| `f39_estratificada_c34` | não se aplica | não se aplica | não se aplica | 66,83% | 33,17% | 2,59% e 0,21% |
| `f39_estratificada_c2` | não se aplica | não se aplica | não se aplica | 45,36% | 54,64% | 0,85% e 0,07% |

Para onde vai o tráfego benigno nas execuções de 8 categorias, como fração das linhas benignas do teste:

| Classe prevista | `f39_estratificada_c8` | `f39_grupos_c8` | `f33_estratificada_c8` | `f33_grupos_c8` |
|---|---|---|---|---|
| DDoS | 0,00% | 0,00% | 0,05% | 0,01% |
| DoS | 0,00% | 0,00% | 0,00% | 0,02% |
| Mirai | 0,00% | 0,00% | 0,00% | 0,00% |
| Recon | 42,30% | 41,78% | 43,01% | 42,37% |
| Spoofing | 2,97% | 2,41% | 2,85% | 2,46% |
| Web | 0,62% | 0,50% | 0,56% | 0,52% |
| BruteForce | 0,29% | 0,35% | 0,31% | 0,31% |
| Benign | 53,82% | 54,96% | 53,22% | 54,31% |

Na amostra, o tráfego benigno é 3,9% das linhas, e as categorias de ataque com janela de 10 (Recon, Spoofing, Web e BruteForce) somam 26,3%. No conjunto completo são 2,3% e 2,6%.

As execuções de 34 classes e de ataque ou benigno servem de referência para os cenários do artigo do dataset (Neto et al., 2023). Os valores publicados não estão neste repositório e precisam ser conferidos no artigo antes de qualquer comparação. O artigo avalia na distribuição original, então a coluna comparável é a reponderada. A execução de 34 classes usa 25 árvores, e as demais usam 100 (ver "Custo de cada execução").

## Resultados por classe

Uma tabela para cada execução da grade. As colunas da esquerda são medidas na amostra, e as da direita
são reponderadas. "Falso positivo" é a fração das linhas das outras classes que o modelo pôs na classe.
"Recall na regra do teto" é o recall da classe na regra de maior acerto global, e não um limite da
classe (ver "Como ler os números"). As mesmas medidas, com as execuções de
referência, estão em `metricas_classificador.csv`, e as matrizes de confusão estão em `matrizes_confusao/`.

### `f39_estratificada_c8`: 39 features, sorteio estratificado, 8 categorias

| Classe | Linhas no teste | Precisão | Recall | F1 | Falso positivo | Recall na regra do teto | Precisão (repond.) | Recall (repond.) | F1 (repond.) | Falso positivo (repond.) | Recall na regra do teto (repond.) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| DDoS | 110.000 | 87,82% | 90,74% | 89,26% | 9,37% | 99,59% | 90,14% | 87,50% | 88,80% | 24,96% | 99,55% |
| DoS | 40.000 | 72,09% | 65,61% | 68,70% | 4,67% | 93,83% | 53,31% | 59,88% | 56,40% | 10,90% | 91,87% |
| Mirai | 30.000 | 99,94% | 99,66% | 99,80% | 0,01% | 100,00% | 99,82% | 99,66% | 99,74% | 0,01% | 100,00% |
| Recon | 40.432 | 77,84% | 91,63% | 84,18% | 4,85% | 99,87% | 54,48% | 92,61% | 68,60% | 1,15% | 99,86% |
| Spoofing | 20.000 | 93,06% | 86,38% | 89,59% | 0,54% | 99,91% | 89,85% | 86,33% | 88,05% | 0,10% | 99,90% |
| Web | 4.760 | 69,62% | 28,84% | 40,79% | 0,24% | 99,43% | 29,75% | 28,84% | 29,29% | 0,04% | 99,43% |
| BruteForce | 2.504 | 79,94% | 33,59% | 47,30% | 0,08% | 100,00% | 41,39% | 33,59% | 37,08% | 0,01% | 100,00% |
| Benign | 10.000 | 63,10% | 53,82% | 58,09% | 1,27% | 99,81% | 92,74% | 53,82% | 68,11% | 0,10% | 99,89% |

### `f39_estratificada_c7`: 39 features, sorteio estratificado, 7 categorias

| Classe | Linhas no teste | Precisão | Recall | F1 | Falso positivo | Recall na regra do teto | Precisão (repond.) | Recall (repond.) | F1 (repond.) | Falso positivo (repond.) | Recall na regra do teto (repond.) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| DDoS+DoS | 150.000 | 99,93% | 99,98% | 99,96% | 0,09% | 100,00% | 99,98% | 99,99% | 99,99% | 0,18% | 100,00% |
| Mirai | 30.000 | 99,96% | 99,66% | 99,81% | 0,01% | 100,00% | 99,87% | 99,66% | 99,76% | 0,01% | 100,00% |
| Recon | 40.432 | 77,80% | 91,56% | 84,12% | 4,86% | 99,87% | 54,38% | 92,52% | 68,50% | 1,16% | 99,86% |
| Spoofing | 20.000 | 93,08% | 86,48% | 89,66% | 0,54% | 99,91% | 89,89% | 86,45% | 88,14% | 0,10% | 99,90% |
| Web | 4.760 | 68,44% | 28,34% | 40,08% | 0,25% | 99,43% | 28,28% | 28,34% | 28,31% | 0,04% | 99,43% |
| BruteForce | 2.504 | 79,40% | 33,55% | 47,16% | 0,09% | 100,00% | 41,36% | 33,55% | 37,05% | 0,01% | 100,00% |
| Benign | 10.000 | 63,01% | 53,62% | 57,94% | 1,27% | 99,81% | 92,73% | 53,62% | 67,95% | 0,10% | 99,89% |

### `f39_grupos_c8`: 39 features, divisão por grupos, 8 categorias

| Classe | Linhas no teste | Precisão | Recall | F1 | Falso positivo | Recall na regra do teto | Precisão (repond.) | Recall (repond.) | F1 (repond.) | Falso positivo (repond.) | Recall na regra do teto (repond.) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| DDoS | 110.134 | 87,78% | 90,86% | 89,29% | 9,42% | 98,48% | 90,10% | 87,72% | 88,89% | 25,13% | 98,64% |
| DoS | 39.978 | 72,24% | 65,38% | 68,64% | 4,61% | 89,26% | 53,62% | 59,59% | 56,45% | 10,71% | 83,92% |
| Mirai | 30.012 | 99,93% | 99,63% | 99,78% | 0,01% | 100,00% | 99,87% | 99,62% | 99,75% | 0,01% | 100,00% |
| Recon | 40.433 | 77,96% | 91,54% | 84,21% | 4,81% | 99,86% | 54,74% | 92,41% | 68,75% | 1,14% | 99,85% |
| Spoofing | 20.166 | 93,47% | 86,70% | 89,96% | 0,51% | 99,95% | 90,92% | 86,70% | 88,76% | 0,09% | 99,95% |
| Web | 4.753 | 71,46% | 28,45% | 40,69% | 0,21% | 99,45% | 32,14% | 28,45% | 30,18% | 0,03% | 99,45% |
| BruteForce | 2.505 | 77,53% | 34,29% | 47,55% | 0,10% | 99,88% | 37,60% | 34,29% | 35,87% | 0,02% | 99,88% |
| Benign | 10.007 | 63,24% | 54,96% | 58,81% | 1,29% | 99,75% | 92,77% | 54,96% | 69,03% | 0,10% | 99,78% |

### `f39_grupos_c7`: 39 features, divisão por grupos, 7 categorias

| Classe | Linhas no teste | Precisão | Recall | F1 | Falso positivo | Recall na regra do teto | Precisão (repond.) | Recall (repond.) | F1 (repond.) | Falso positivo (repond.) | Recall na regra do teto (repond.) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| DDoS+DoS | 150.112 | 99,92% | 99,98% | 99,95% | 0,11% | 100,00% | 99,98% | 99,99% | 99,98% | 0,21% | 100,00% |
| Mirai | 30.012 | 99,93% | 99,61% | 99,77% | 0,01% | 100,00% | 99,89% | 99,60% | 99,75% | 0,01% | 100,00% |
| Recon | 40.433 | 77,92% | 91,51% | 84,17% | 4,82% | 99,86% | 54,78% | 92,41% | 68,79% | 1,14% | 99,85% |
| Spoofing | 20.166 | 93,40% | 86,58% | 89,86% | 0,52% | 99,95% | 90,54% | 86,58% | 88,52% | 0,09% | 99,95% |
| Web | 4.753 | 71,17% | 28,47% | 40,67% | 0,22% | 99,45% | 31,12% | 28,47% | 29,74% | 0,03% | 99,45% |
| BruteForce | 2.505 | 79,48% | 34,17% | 47,79% | 0,09% | 99,88% | 40,75% | 34,17% | 37,17% | 0,01% | 99,88% |
| Benign | 10.007 | 63,00% | 54,92% | 58,68% | 1,30% | 99,75% | 92,75% | 54,92% | 68,99% | 0,10% | 99,78% |

### `f33_estratificada_c8`: 33 features, sorteio estratificado, 8 categorias

| Classe | Linhas no teste | Precisão | Recall | F1 | Falso positivo | Recall na regra do teto | Precisão (repond.) | Recall (repond.) | F1 (repond.) | Falso positivo (repond.) | Recall na regra do teto (repond.) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| DDoS | 110.000 | 87,78% | 90,64% | 89,19% | 9,40% | 99,59% | 90,14% | 87,46% | 88,78% | 24,92% | 99,55% |
| DoS | 40.000 | 71,71% | 65,25% | 68,33% | 4,73% | 93,83% | 53,23% | 59,90% | 56,37% | 10,94% | 91,87% |
| Mirai | 30.000 | 99,94% | 99,61% | 99,77% | 0,01% | 100,00% | 99,87% | 99,61% | 99,74% | 0,01% | 100,00% |
| Recon | 40.432 | 77,32% | 91,44% | 83,79% | 4,99% | 99,87% | 53,84% | 92,49% | 68,06% | 1,18% | 99,86% |
| Spoofing | 20.000 | 93,04% | 86,38% | 89,58% | 0,54% | 99,91% | 89,55% | 86,33% | 87,91% | 0,11% | 99,90% |
| Web | 4.760 | 69,58% | 28,07% | 40,00% | 0,23% | 99,43% | 29,86% | 28,06% | 28,93% | 0,03% | 99,43% |
| BruteForce | 2.504 | 79,13% | 32,71% | 46,28% | 0,08% | 100,00% | 39,97% | 32,71% | 35,98% | 0,01% | 100,00% |
| Benign | 10.000 | 62,82% | 53,22% | 57,62% | 1,27% | 99,81% | 92,63% | 53,22% | 67,60% | 0,10% | 99,89% |

### `f33_estratificada_c7`: 33 features, sorteio estratificado, 7 categorias

| Classe | Linhas no teste | Precisão | Recall | F1 | Falso positivo | Recall na regra do teto | Precisão (repond.) | Recall (repond.) | F1 (repond.) | Falso positivo (repond.) | Recall na regra do teto (repond.) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| DDoS+DoS | 150.000 | 99,84% | 99,86% | 99,85% | 0,23% | 100,00% | 99,97% | 99,98% | 99,98% | 0,22% | 100,00% |
| Mirai | 30.000 | 99,96% | 99,61% | 99,78% | 0,01% | 100,00% | 99,91% | 99,61% | 99,76% | 0,01% | 100,00% |
| Recon | 40.432 | 77,33% | 91,40% | 83,77% | 4,99% | 99,87% | 53,78% | 92,52% | 68,02% | 1,19% | 99,86% |
| Spoofing | 20.000 | 93,03% | 86,50% | 89,64% | 0,55% | 99,91% | 89,30% | 86,46% | 87,86% | 0,11% | 99,90% |
| Web | 4.760 | 69,87% | 28,26% | 40,24% | 0,23% | 99,43% | 30,29% | 28,25% | 29,24% | 0,03% | 99,43% |
| BruteForce | 2.504 | 80,00% | 32,91% | 46,63% | 0,08% | 100,00% | 42,32% | 32,91% | 37,02% | 0,01% | 100,00% |
| Benign | 10.000 | 62,62% | 52,78% | 57,28% | 1,27% | 99,81% | 92,62% | 52,78% | 67,24% | 0,10% | 99,89% |

### `f33_grupos_c8`: 33 features, divisão por grupos, 8 categorias

| Classe | Linhas no teste | Precisão | Recall | F1 | Falso positivo | Recall na regra do teto | Precisão (repond.) | Recall (repond.) | F1 (repond.) | Falso positivo (repond.) | Recall na regra do teto (repond.) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| DDoS | 110.134 | 87,63% | 90,82% | 89,20% | 9,55% | 98,48% | 90,00% | 87,75% | 88,86% | 25,42% | 98,64% |
| DoS | 39.978 | 71,76% | 64,63% | 68,01% | 4,67% | 89,26% | 53,47% | 59,08% | 56,14% | 10,68% | 83,92% |
| Mirai | 30.012 | 99,94% | 99,56% | 99,75% | 0,01% | 100,00% | 99,94% | 99,55% | 99,75% | 0,00% | 100,00% |
| Recon | 40.433 | 77,27% | 91,18% | 83,65% | 4,98% | 99,86% | 54,05% | 92,32% | 68,18% | 1,17% | 99,85% |
| Spoofing | 20.166 | 93,29% | 86,49% | 89,76% | 0,53% | 99,95% | 90,10% | 86,52% | 88,27% | 0,10% | 99,95% |
| Web | 4.753 | 71,24% | 27,73% | 39,92% | 0,21% | 99,45% | 31,48% | 27,74% | 29,49% | 0,03% | 99,45% |
| BruteForce | 2.505 | 80,15% | 33,21% | 46,97% | 0,08% | 99,88% | 40,25% | 33,21% | 36,40% | 0,01% | 99,88% |
| Benign | 10.007 | 62,88% | 54,31% | 58,28% | 1,29% | 99,75% | 92,73% | 54,31% | 68,50% | 0,10% | 99,78% |

### `f33_grupos_c7`: 33 features, divisão por grupos, 7 categorias

| Classe | Linhas no teste | Precisão | Recall | F1 | Falso positivo | Recall na regra do teto | Precisão (repond.) | Recall (repond.) | F1 (repond.) | Falso positivo (repond.) | Recall na regra do teto (repond.) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| DDoS+DoS | 150.112 | 99,80% | 99,85% | 99,82% | 0,28% | 100,00% | 99,97% | 99,98% | 99,97% | 0,25% | 100,00% |
| Mirai | 30.012 | 99,95% | 99,55% | 99,75% | 0,01% | 100,00% | 99,97% | 99,54% | 99,75% | 0,00% | 100,00% |
| Recon | 40.433 | 77,28% | 91,16% | 83,65% | 4,98% | 99,86% | 54,08% | 92,32% | 68,21% | 1,17% | 99,85% |
| Spoofing | 20.166 | 93,30% | 86,50% | 89,77% | 0,53% | 99,95% | 90,27% | 86,51% | 88,35% | 0,10% | 99,95% |
| Web | 4.753 | 72,37% | 27,60% | 39,96% | 0,20% | 99,45% | 33,77% | 27,61% | 30,38% | 0,03% | 99,45% |
| BruteForce | 2.505 | 79,13% | 32,85% | 46,43% | 0,08% | 99,88% | 38,59% | 32,85% | 35,49% | 0,01% | 99,88% |
| Benign | 10.007 | 62,96% | 54,49% | 58,42% | 1,29% | 99,75% | 92,77% | 54,49% | 68,66% | 0,10% | 99,78% |

## Importância das features

Importância por redução média de impureza, a que o scikit-learn calcula no treino. As importâncias de
um modelo somam 100%. As features estão na ordem da primeira coluna, e as que dependem do tamanho da
janela estão marcadas. A tabela completa, com as execuções de referência, está em `importancia_features.csv`.

### Com 39 features

| Posição | Feature | `f39_estratificada_c8` | `f39_estratificada_c7` | `f39_grupos_c8` | `f39_grupos_c7` |
|---|---|---|---|---|---|
| 1 | `Tot sum` (janela) | 10,79% | 12,74% | 10,46% | 12,87% |
| 2 | `Rate` | 8,19% | 5,39% | 8,23% | 5,10% |
| 3 | `Number` (janela) | 7,56% | 11,28% | 8,20% | 11,97% |
| 4 | `Protocol Type` | 5,79% | 5,96% | 5,90% | 6,05% |
| 5 | `Max` | 5,65% | 6,61% | 6,18% | 6,60% |
| 6 | `Min` | 5,63% | 5,98% | 4,98% | 6,86% |
| 7 | `IAT` | 5,60% | 4,44% | 5,58% | 4,74% |
| 8 | `Tot size` | 5,14% | 6,44% | 5,27% | 6,12% |
| 9 | `AVG` | 4,70% | 5,65% | 4,74% | 5,25% |
| 10 | `Header_Length` | 4,36% | 3,04% | 4,58% | 3,08% |
| 11 | `Variance` | 4,31% | 3,77% | 4,09% | 4,53% |
| 12 | `Time_To_Live` | 4,27% | 4,39% | 4,08% | 4,64% |
| 13 | `Std` | 4,07% | 4,56% | 4,17% | 3,69% |
| 14 | `HTTPS` | 2,99% | 3,82% | 2,96% | 3,72% |
| 15 | `ack_count` (janela) | 2,69% | 2,90% | 2,80% | 2,35% |
| 16 | `ack_flag_number` | 2,44% | 2,19% | 2,37% | 2,13% |
| 17 | `psh_flag_number` | 1,86% | 1,07% | 1,97% | 0,94% |
| 18 | `syn_count` (janela) | 1,71% | 1,60% | 1,67% | 1,10% |
| 19 | `syn_flag_number` | 1,57% | 1,04% | 1,43% | 1,16% |
| 20 | `UDP` | 1,48% | 1,36% | 1,50% | 1,25% |
| 21 | `TCP` | 1,46% | 1,58% | 1,51% | 1,81% |
| 22 | `ICMP` | 1,15% | 0,47% | 0,89% | 0,26% |
| 23 | `HTTP` | 1,14% | 0,51% | 1,03% | 0,61% |
| 24 | `rst_count` (janela) | 1,04% | 0,40% | 0,94% | 0,42% |
| 25 | `fin_count` (janela) | 0,98% | 0,44% | 0,95% | 0,38% |
| 26 | `fin_flag_number` | 0,88% | 0,36% | 0,88% | 0,32% |
| 27 | `rst_flag_number` | 0,83% | 0,35% | 0,93% | 0,38% |
| 28 | `DNS` | 0,45% | 0,45% | 0,45% | 0,45% |
| 29 | `SSH` | 0,43% | 0,46% | 0,44% | 0,47% |
| 30 | `ARP` | 0,26% | 0,22% | 0,26% | 0,26% |
| 31 | `IPv` | 0,25% | 0,20% | 0,24% | 0,18% |
| 32 | `LLC` | 0,20% | 0,20% | 0,22% | 0,21% |
| 33 | `DHCP` | 0,06% | 0,05% | 0,06% | 0,05% |
| 34 | `ece_flag_number` | 0,02% | 0,02% | 0,02% | 0,02% |
| 35 | `IGMP` | 0,01% | 0,01% | 0,01% | 0,01% |
| 36 | `cwr_flag_number` | 0,01% | 0,01% | 0,01% | 0,01% |
| 37 | `IRC` | 0,01% | 0,01% | 0,01% | 0,01% |
| 38 | `SMTP` | 0,00% | 0,00% | 0,00% | 0,00% |
| 39 | `Telnet` | 0,00% | 0,00% | 0,00% | 0,00% |

### Com 33 features

| Posição | Feature | `f33_estratificada_c8` | `f33_estratificada_c7` | `f33_grupos_c8` | `f33_grupos_c7` |
|---|---|---|---|---|---|
| 1 | `Rate` | 9,66% | 8,18% | 9,59% | 8,60% |
| 2 | `IAT` | 8,33% | 7,97% | 8,13% | 7,70% |
| 3 | `Max` | 8,12% | 8,29% | 7,40% | 8,41% |
| 4 | `AVG` | 6,85% | 7,32% | 6,81% | 8,15% |
| 5 | `Time_To_Live` | 6,51% | 8,35% | 6,54% | 8,16% |
| 6 | `Header_Length` | 6,24% | 4,70% | 6,36% | 4,90% |
| 7 | `Tot size` | 6,15% | 7,98% | 6,46% | 7,59% |
| 8 | `Min` | 5,65% | 7,88% | 5,80% | 7,44% |
| 9 | `Std` | 5,16% | 4,79% | 4,99% | 4,56% |
| 10 | `Variance` | 4,76% | 5,13% | 5,32% | 5,20% |
| 11 | `Protocol Type` | 4,67% | 4,52% | 4,78% | 4,35% |
| 12 | `HTTPS` | 4,01% | 5,25% | 3,78% | 5,08% |
| 13 | `ack_flag_number` | 3,85% | 3,98% | 3,96% | 4,10% |
| 14 | `psh_flag_number` | 2,86% | 2,06% | 2,76% | 1,84% |
| 15 | `syn_flag_number` | 2,72% | 2,24% | 2,57% | 2,19% |
| 16 | `TCP` | 2,54% | 2,10% | 2,85% | 2,49% |
| 17 | `UDP` | 2,04% | 1,84% | 2,29% | 2,14% |
| 18 | `rst_flag_number` | 1,91% | 1,17% | 1,96% | 1,10% |
| 19 | `fin_flag_number` | 1,84% | 1,04% | 1,80% | 1,02% |
| 20 | `HTTP` | 1,75% | 1,50% | 1,62% | 1,25% |
| 21 | `ICMP` | 1,60% | 0,73% | 1,58% | 0,65% |
| 22 | `DNS` | 0,58% | 0,58% | 0,56% | 0,51% |
| 23 | `ARP` | 0,57% | 0,64% | 0,55% | 0,67% |
| 24 | `LLC` | 0,55% | 0,52% | 0,51% | 0,59% |
| 25 | `IPv` | 0,52% | 0,66% | 0,48% | 0,71% |
| 26 | `SSH` | 0,42% | 0,45% | 0,41% | 0,45% |
| 27 | `DHCP` | 0,06% | 0,06% | 0,07% | 0,06% |
| 28 | `ece_flag_number` | 0,02% | 0,03% | 0,02% | 0,03% |
| 29 | `IGMP` | 0,02% | 0,01% | 0,02% | 0,02% |
| 30 | `cwr_flag_number` | 0,01% | 0,02% | 0,01% | 0,01% |
| 31 | `IRC` | 0,01% | 0,01% | 0,01% | 0,01% |
| 32 | `SMTP` | 0,00% | 0,00% | 0,00% | 0,00% |
| 33 | `Telnet` | 0,00% | 0,00% | 0,00% | 0,00% |

## Custo de cada execução

Os tempos são da máquina em que o experimento rodou e mudam de uma execução para outra. O tempo de
inferência é a mediana de cinco classificações de um lote de 1.000 janelas. O tamanho do modelo é o do
arquivo gravado com `joblib`, sem compressão.

| Execução | Árvores | Treino (s) | Classificar o teste inteiro, um núcleo (s) | 1.000 janelas, um núcleo (ms) | 1.000 janelas, todos os núcleos (ms) | Modelo (MB) | Nós por árvore | Profundidade média |
|---|---|---|---|---|---|---|---|---|
| `f39_estratificada_c8` | 100 | 21,0 | 3,7 | 39,5 | 16,0 | 2.275,7 | 177.787 | 77,1 |
| `f39_estratificada_c7` | 100 | 18,5 | 1,7 | 15,5 | 16,0 | 1.252,0 | 104.327 | 58,5 |
| `f39_grupos_c8` | 100 | 22,4 | 3,0 | 29,3 | 13,2 | 2.277,6 | 177.931 | 76,1 |
| `f39_grupos_c7` | 100 | 17,8 | 1,6 | 15,2 | 16,2 | 1.252,9 | 104.407 | 58,6 |
| `f33_estratificada_c8` | 100 | 20,0 | 3,1 | 30,1 | 13,7 | 2.394,9 | 187.101 | 79,8 |
| `f33_estratificada_c7` | 100 | 18,8 | 1,9 | 18,1 | 16,1 | 1.360,3 | 113.352 | 57,3 |
| `f33_grupos_c8` | 100 | 20,7 | 3,1 | 30,3 | 16,0 | 2.397,0 | 187.263 | 77,4 |
| `f33_grupos_c7` | 100 | 18,9 | 1,9 | 18,1 | 15,6 | 1.359,4 | 113.278 | 56,9 |
| `f39_estratificada_c34` | 25 | 7,3 | 1,2 | 7,5 | 16,0 | 2.330,3 | 277.413 | 77,8 |
| `f39_estratificada_c2` | 100 | 16,2 | 1,1 | 11,8 | 13,6 | 433,6 | 54.199 | 57,0 |

A execução de 34 classes usa 25 árvores, e não 100. Com 34 classes cada nó guarda 34 contagens e as árvores têm mais nós, e a floresta de 100 árvores não caberia na memória da máquina usada. As medidas dessa execução não são diretamente comparáveis às das outras.

As predições usadas nas métricas somam os votos das árvores com um núcleo, em ordem fixa. Com vários
núcleos o scikit-learn soma na ordem em que as árvores terminam, e uma linha com duas classes
empatadas pode mudar de resposta de uma chamada para outra.

## O que os números dizem sobre cada decisão em aberto

Só o que mudou e quanto, sem recomendação. As diferenças são da segunda coluna menos a primeira, em
pontos percentuais. "Na amostra" é medido nas linhas de teste como elas são, e "reponderada" é a
estimativa na distribuição original do dataset.

### Janela de 10 ou de 100 pacotes

O que muda quando saem as seis colunas que dependem do tamanho da janela, com a divisão e o alvo fixos.

Acurácia:

| Divisão e alvo | Na amostra, 39 | Na amostra, 33 | Diferença (p.p.) | Reponderada, 39 | Reponderada, 33 | Diferença (p.p.) |
|---|---|---|---|---|---|---|
| sorteio estratificado, 8 categorias | 84,55% | 84,37% | -0,18 | 82,66% | 82,61% | -0,05 |
| sorteio estratificado, 7 categorias | 93,81% | 93,67% | -0,14 | 98,58% | 98,55% | -0,03 |
| divisão por grupos, 8 categorias | 84,62% | 84,36% | -0,26 | 82,79% | 82,70% | -0,09 |
| divisão por grupos, 7 categorias | 93,86% | 93,67% | -0,19 | 98,61% | 98,58% | -0,03 |

Macro-F1:

| Divisão e alvo | Na amostra, 39 | Na amostra, 33 | Diferença (p.p.) | Reponderada, 39 | Reponderada, 33 | Diferença (p.p.) |
|---|---|---|---|---|---|---|
| sorteio estratificado, 8 categorias | 72,21% | 71,82% | -0,39 | 67,01% | 66,67% | -0,34 |
| sorteio estratificado, 7 categorias | 74,11% | 73,89% | -0,22 | 69,96% | 69,87% | -0,08 |
| divisão por grupos, 8 categorias | 72,37% | 71,94% | -0,42 | 67,21% | 66,95% | -0,26 |
| divisão por grupos, 7 categorias | 74,41% | 73,97% | -0,44 | 70,42% | 70,12% | -0,30 |

Erros entre os dois grupos de janela, isto é, linha de DDoS, DoS ou Mirai (janela de 100) classificada
em categoria de janela de 10, ou o contrário, como fração das linhas de teste. Ao lado, o tráfego benigno
classificado como ataque:

| Divisão e alvo | Entre janelas na amostra, 39 | Entre janelas na amostra, 33 | Entre janelas reponderado, 39 | Entre janelas reponderado, 33 | Benigno como ataque, 39 | Benigno como ataque, 33 |
|---|---|---|---|---|---|---|
| sorteio estratificado, 8 categorias | 0,006% | 0,152% | 0,001% | 0,024% | 46,18% | 46,78% |
| sorteio estratificado, 7 categorias | 0,004% | 0,143% | 0,000% | 0,019% | 46,38% | 47,22% |
| divisão por grupos, 8 categorias | 0,005% | 0,170% | 0,002% | 0,029% | 45,04% | 45,69% |
| divisão por grupos, 7 categorias | 0,005% | 0,167% | 0,002% | 0,027% | 45,08% | 45,51% |

- Nas quatro execuções com 39 features, as seis colunas somam de 24,8% a 29,4% da importância, e `Number` fica entre a 2ª e a 3ª posição das 39.
- As seis colunas são função de colunas que ficam (`dados/README.md`), então as 33 guardam a mesma
  informação sobre o tráfego. O que sai é a leitura direta do tamanho da janela.
- Este experimento não mede o efeito de classificar tráfego agregado com uma janela diferente da do
  treino. Treino e teste vêm da mesma amostra, em que a janela acompanha a classe, com 39 ou com 33
  features. A medida direta é pontuar capturas processadas pelo extrator com outro tamanho de janela
  (`python -m codigo.classificador.avaliar MODELO --csv CAPTURA --rotulo ROTULO`).

### Divisão entre treino e teste

O que muda do sorteio estratificado de linhas para a divisão por grupos, com as features e o alvo fixos.
As duas divisões têm linhas de teste diferentes.

Acurácia:

| Features e alvo | Na amostra, sorteio | Na amostra, grupos | Diferença (p.p.) | Reponderada, sorteio | Reponderada, grupos | Diferença (p.p.) |
|---|---|---|---|---|---|---|
| 39 features, 8 categorias | 84,55% | 84,62% | +0,07 | 82,66% | 82,79% | +0,13 |
| 39 features, 7 categorias | 93,81% | 93,86% | +0,05 | 98,58% | 98,61% | +0,03 |
| 33 features, 8 categorias | 84,37% | 84,36% | -0,01 | 82,61% | 82,70% | +0,09 |
| 33 features, 7 categorias | 93,67% | 93,67% | 0,00 | 98,55% | 98,58% | +0,03 |

Macro-F1:

| Features e alvo | Na amostra, sorteio | Na amostra, grupos | Diferença (p.p.) | Reponderada, sorteio | Reponderada, grupos | Diferença (p.p.) |
|---|---|---|---|---|---|---|
| 39 features, 8 categorias | 72,21% | 72,37% | +0,15 | 67,01% | 67,21% | +0,20 |
| 39 features, 7 categorias | 74,11% | 74,41% | +0,31 | 69,96% | 70,42% | +0,46 |
| 33 features, 8 categorias | 71,82% | 71,94% | +0,12 | 66,67% | 66,95% | +0,28 |
| 33 features, 7 categorias | 73,89% | 73,97% | +0,09 | 69,87% | 70,12% | +0,24 |

Teto:

| Features e alvo | Na amostra, sorteio | Na amostra, grupos | Diferença (p.p.) | Reponderada, sorteio | Reponderada, grupos | Diferença (p.p.) |
|---|---|---|---|---|---|---|
| 39 features, 8 categorias | 98,82% | 97,64% | -1,18 | 98,27% | 96,24% | -2,03 |
| 39 features, 7 categorias | 99,96% | 99,95% | 0,00 | 99,99% | 99,99% | 0,00 |
| 33 features, 8 categorias | 98,82% | 97,64% | -1,18 | 98,27% | 96,24% | -2,03 |
| 33 features, 7 categorias | 99,95% | 99,95% | 0,00 | 99,99% | 99,99% | 0,00 |

- No sorteio estratificado, 38.934 das 257.696 linhas de teste (15,11%) têm o mesmo vetor de uma linha do treino, com as 39 features. Na divisão por grupos, nenhuma.
- Na amostra, 16,05% das linhas repetem o vetor de outra. No conjunto completo são 58,78%. A diferença entre as duas divisões medida aqui é a da amostra, com menos repetição do que haveria no dataset inteiro.
- O teto das duas divisões não mede a mesma coisa. Na divisão por grupos, todas as repetições de um
  vetor ficam do mesmo lado, e o teto conta os conflitos de classe inteiros. No sorteio de linhas, parte
  das repetições fica no treino, e o teto só conta os conflitos que caíram no teste.
- A divisão por grupos separa vetores idênticos. Ela não separa janelas vizinhas do mesmo pcap, que são
  parecidas sem ser iguais. A saída de dividir pelos CSVs por ataque, que preservam o arquivo de
  origem, não é medida aqui: a amostra vem do `MERGED_CSV`, que não guarda o arquivo de cada linha.

### DDoS e DoS

O que muda de 8 categorias para 7, com DDoS e DoS fundidas, com as features e a divisão fixas.

Acurácia:

| Features e divisão | Na amostra, 8 | Na amostra, 7 | Diferença (p.p.) | Reponderada, 8 | Reponderada, 7 | Diferença (p.p.) |
|---|---|---|---|---|---|---|
| 39 features, sorteio estratificado | 84,55% | 93,81% | +9,26 | 82,66% | 98,58% | +15,92 |
| 39 features, divisão por grupos | 84,62% | 93,86% | +9,23 | 82,79% | 98,61% | +15,82 |
| 33 features, sorteio estratificado | 84,37% | 93,67% | +9,30 | 82,61% | 98,55% | +15,94 |
| 33 features, divisão por grupos | 84,36% | 93,67% | +9,31 | 82,70% | 98,58% | +15,88 |

Teto:

| Features e divisão | Na amostra, 8 | Na amostra, 7 | Diferença (p.p.) | Reponderada, 8 | Reponderada, 7 | Diferença (p.p.) |
|---|---|---|---|---|---|---|
| 39 features, sorteio estratificado | 98,82% | 99,96% | +1,13 | 98,27% | 99,99% | +1,72 |
| 39 features, divisão por grupos | 97,64% | 99,95% | +2,31 | 96,24% | 99,99% | +3,75 |
| 33 features, sorteio estratificado | 98,82% | 99,95% | +1,13 | 98,27% | 99,99% | +1,72 |
| 33 features, divisão por grupos | 97,64% | 99,95% | +2,31 | 96,24% | 99,99% | +3,75 |

Recall das duas categorias e peso das trocas entre elas. Em cada célula, o primeiro valor é na amostra
e o segundo é reponderado. "Trocas" são as linhas de DDoS classificadas como DoS e as de DoS
classificadas como DDoS. A penúltima coluna conta essas trocas como acerto no modelo de 8 categorias, e
a última é o modelo treinado com 7.

| Features e divisão | Recall de DDoS, 8 categorias | Recall de DoS, 8 categorias | Recall de DDoS+DoS, 7 categorias | Trocas entre DDoS e DoS, como fração dos erros do modelo de 8 | Acurácia do modelo de 8 sem contar as trocas como erro | Acurácia do modelo de 7 |
|---|---|---|---|---|---|---|
| 39 features, sorteio estratificado | 90,74% e 87,50% | 65,61% e 59,88% | 99,98% e 99,99% | 60,0% e 91,8% | 93,83% e 98,59% | 93,81% e 98,58% |
| 39 features, divisão por grupos | 90,86% e 87,72% | 65,38% e 59,59% | 99,98% e 99,99% | 60,2% e 91,9% | 93,88% e 98,61% | 93,86% e 98,61% |
| 33 features, sorteio estratificado | 90,64% e 87,46% | 65,25% e 59,90% | 99,86% e 99,98% | 59,4% e 91,7% | 93,66% e 98,55% | 93,67% e 98,55% |
| 33 features, divisão por grupos | 90,82% e 87,75% | 64,63% e 59,08% | 99,85% e 99,98% | 59,5% e 91,8% | 93,66% e 98,58% | 93,67% e 98,58% |

Custo do modelo:

| Features e divisão | Modelo de 8 (MB) | Modelo de 7 (MB) | Nós por árvore, 8 | Nós por árvore, 7 | Treino de 8 (s) | Treino de 7 (s) |
|---|---|---|---|---|---|---|
| 39 features, sorteio estratificado | 2.275,7 | 1.252,0 | 177.787 | 104.327 | 21,0 | 18,5 |
| 39 features, divisão por grupos | 2.277,6 | 1.252,9 | 177.931 | 104.407 | 22,4 | 17,8 |
| 33 features, sorteio estratificado | 2.394,9 | 1.360,3 | 187.101 | 113.352 | 20,0 | 18,8 |
| 33 features, divisão por grupos | 2.397,0 | 1.359,4 | 187.263 | 113.278 | 20,7 | 18,9 |

- O macro-F1 de 8 categorias e o de 7 são médias sobre conjuntos de classes diferentes e não se comparam
  diretamente. Os dois estão na tabela das 10 execuções.
- Os tetos desta seção são os das linhas de teste de cada execução. O teto que a exploração mediu no
  conjunto completo vale para aquele conjunto, na proporção natural das classes, e não se compara com
  eles. Nenhum deles limita o recall de DoS: o recall de uma categoria depende da regra, e a regra do
  teto maximiza o acerto global.
- A terceira saída em análise, deixar o modelo dizer o tipo de flood e separar DDoS de DoS pela
  quantidade de origens no alerta, não é medida aqui: as 39 features não trazem endereços de origem.

## Como os números foram obtidos

- Comando: `python -m codigo.classificador.experimento`, a partir da raiz do repositório. Semente 42 na divisão e no modelo.
- Amostra: `dados/processed/amostra.csv.gz`, com SHA-256 do CSV descomprimido `f23c098dc10faf3f857a473f8c793fc2642098d9046f11cbc76d83e20e505b8f`, conferido com `manifesto_amostra.json` antes de treinar.
- Modelo: `RandomForestClassifier` do scikit-learn com os parâmetros padrão, 100 árvores, `n_jobs=-1` e sem `StandardScaler`. Não houve busca de hiperparâmetros.
- As métricas saem da matriz de confusão de cada execução. As reponderadas usam a matriz que abre a
  classe real nos 34 rótulos (`matrizes_confusao/*_por_rotulo.csv`) e as contagens do conjunto completo.
- A média macro é sobre as classes do alvo. Os percentuais das tabelas são arredondados, e os valores
  completos estão em `manifesto_treino_exploratorio.json`.
- `metricas_classificador.csv` tem uma linha por execução, distribuição e classe. A distribuição `amostra` é a medida
  nas linhas de teste, e `original` é a reponderada.
- Com a mesma amostra e a mesma semente, `metricas_classificador.csv`, `importancia_features.csv` e as matrizes saem idênticos.
  As medidas de tempo mudam a cada execução.

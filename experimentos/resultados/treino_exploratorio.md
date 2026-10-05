# Treino exploratório do classificador

Gerado por `python -m codigo.classificador.experimento` em 04/10/2026, com Python 3.11.2, scikit-learn 1.9.1, pandas 3.0.6 e numpy 2.4.6.

Execuções do Random Forest sobre a amostra de treino do CICIoT2023 (Neto et al., 2023). A grade
combina três escolhas que estão em aberto no `ROADMAP.md`: as colunas que dependem do tamanho da
janela, a divisão entre treino e teste e a separação entre DDoS e DoS. As combinações do sorteio
estratificado são treinadas também com a proporção natural das classes, porque a priori de treino muda
os resultados. As execuções de 34 classes e de ataque ou benigno servem de referência para os cenários
do artigo do dataset. O relatório traz os números e não recomenda nenhuma das saídas.

As tabelas são da semente 42. A grade e as execuções com a proporção natural foram repetidas com as sementes 7 e 2026, e as comparações entre escolhas trazem a faixa entre sementes.

## Como ler os números

**Amostra e conjunto completo.** Todas as execuções usam a amostra de treino (`dados/processed/amostra.csv.gz`, 1.288.479 linhas), que limita as linhas de cada classe. Nela, DDoS e DoS somam 58,2% das linhas; no conjunto completo, de 45.019.234 linhas, somam 89,5%. Por isso cada medida aparece de duas formas:

- **na amostra**: calculada sobre as linhas de teste como elas são;
- **reponderada**: cada linha de teste pesa a quantidade de linhas do seu rótulo no conjunto completo
  dividida pela quantidade no teste, com as contagens de `manifesto_amostra.json`. É a estimativa da
  medida na distribuição original do dataset.

A ponderação altera só o cálculo da medida. O modelo avaliado é o mesmo nas duas formas, e o que ele
aprendeu depende da priori de treino, descrita abaixo.

O peso é por rótulo, entre os 34, e não por classe do alvo. O recall de um rótulo não muda com a ponderação. O de uma categoria que reúne vários rótulos muda, porque dentro dela os rótulos passam a pesar de outra forma. Na amostra, `DoS-HTTP_Flood` é 25,0% das linhas de DoS; no conjunto completo, 0,9%. A taxa de tráfego benigno classificado como ataque não muda com a ponderação, porque o tráfego benigno é um rótulo só. Ela muda com a priori de treino.

**Priori de treino.** A amostra limita as linhas de cada rótulo, então o modelo treinado nela aprende uma proporção entre as classes que não é a do dataset. Entre o tráfego benigno e as categorias de ataque com janela de 10 (Recon, Spoofing, Web e BruteForce), a proporção é de 1 para 6,8 na amostra e de 1 para 1,1 no conjunto completo. A reponderação das medidas não corrige isso: ela muda o peso das linhas na avaliação, e não o que o modelo aprendeu. Por isso as combinações do sorteio estratificado e as execuções de referência são treinadas de duas formas:

- **proporções da amostra**: todas as linhas de treino pesam o mesmo. É a priori da amostra;
- **proporção natural**: cada linha de treino pesa a quantidade de linhas do seu rótulo no conjunto completo dividida pela quantidade no treino (`sample_weight`). É a priori natural. No scikit-learn 1.9.1, o peso é a chance de a linha entrar no sorteio com reposição que monta o conjunto de cada árvore: cada árvore recebe a mesma quantidade de linhas, na proporção das classes do conjunto completo.

As execuções com a priori natural têm `_natural` no nome. A divisão entre treino e teste, as linhas de
teste e a avaliação são as mesmas nas duas formas.

**Vetor idêntico.** Duas linhas têm o mesmo vetor quando são iguais em todas as features da execução, depois da conversão para ponto flutuante de 32 bits, que é como o scikit-learn as entrega às árvores. A amostra tem 1.140.373 vetores distintos com as 39 features e 1.140.354 com as 33. Com as 39, 206.815 linhas (16,05%) repetem o vetor de outra linha. No conjunto completo são 58,78% (`exploracao.md`, seção 8): a amostra guarda uma fração pequena das classes grandes, e a maior parte das repetições delas fica de fora.

**Teto.** É um limite por coincidência exata de vetores, calculado nas linhas de teste de cada execução. Quem só vê as features dá a mesma resposta a todas as linhas com o mesmo vetor. A regra que mais acerta responde, em cada vetor, a classe mais frequente, e as linhas das outras classes são erro certo. A acurácia dessa regra é a maior possível naquelas linhas, e é com ela que a acurácia na amostra da mesma execução se compara. O teto depende da mistura de classes do conjunto em que é medido e cai quando o conjunto cresce: com mais linhas, mais vetores se repetem com classes diferentes. Por isso ele muda com a divisão. No sorteio de linhas, parte das repetições de um vetor fica no treino e não entra na conta.

**Limite da acurácia reponderada.** No sorteio estratificado, a acurácia reponderada estima a acurácia do modelo no conjunto completo. O limite esperado dela é o teto do conjunto completo, e não o das linhas de teste: em 8 categorias, 92,87% com as 39 features (`exploracao.md`, seção 8). O teto reponderado de uma parte da amostra fica acima desse valor, porque o teto cai quando o conjunto cresce: em 8 categorias e com as 39 features, ele é 98,27% nas 257.696 linhas de teste de `f39_estratificada_c8` e 96,22% nas 1.288.479 linhas da amostra inteira, e o conjunto completo tem 45.019.234 linhas. Por isso as tabelas trazem o teto das linhas de teste sem reponderar, e o reponderado fica só no manifesto. A exploração não mediu o teto do conjunto completo em 7 categorias, em 34 classes nem no cenário de ataque ou benigno.

**Recall na regra do teto.** As tabelas por classe trazem o recall de cada classe na regra que dá o teto. Ele não é um limite por classe: a regra maximiza o acerto global, e outra regra pode acertar mais numa classe e menos em outra. No empate entre classes num vetor, a regra fica com a primeira na ordem das tabelas.

**Valores vazios e infinitos.** 49 linhas da amostra têm `Std` e `Variance` vazios ou `Rate` infinito. Elas são mantidas. O infinito entra como vazio, e o Random Forest do scikit-learn trata o vazio sem imputação.

**Sementes.** As tabelas trazem os valores da semente 42, usada na divisão e no modelo. A grade das três escolhas e as execuções com a priori natural foram repetidas com as sementes 7 e 2026, cada uma com outra divisão e outros modelos. A faixa entre sementes vai do menor ao maior valor das 3 sementes. Uma diferença entre duas escolhas que muda de sinal de uma comparação para outra não se distingue do ruído de semente. Uma diferença com o mesmo sinal em todas as comparações é consistente, e o tamanho dela é comparado com a maior variação de uma mesma execução entre sementes: o relatório a chama de pequena quando não chega a 2 vezes essa variação, e de muito acima do ruído a partir de 10 vezes. Com 3 sementes isso descreve a variação observada e não é um teste estatístico. As execuções de referência rodaram só com a semente 42.

## Divisões entre treino e teste

As duas divisões reservam 20% das linhas para o teste e são as mesmas em todas as execuções que as usam, quaisquer que sejam as features e o alvo.

- **Sorteio estratificado de linhas**: sorteio de linhas com a mesma fração de cada um dos 34 rótulos
  no teste. O notebook de exemplo dos autores do dataset divide de outra forma: por arquivo, com 80% dos
  CSVs no treino, na proporção natural das classes e sem estratificar.
- **Divisão por grupos**: todas as linhas com o mesmo vetor nas 33 features ficam do mesmo lado. Linhas
  iguais nas 39 também são iguais nas 33, então nenhum vetor aparece no treino e no teste, com
  qualquer dos dois conjuntos de features. O sorteio dos grupos é estratificado pelo rótulo mais
  frequente de cada grupo.

| Divisão | Linhas de treino | Linhas de teste | Linhas de teste com vetor que está no treino, 39 features | Idem, 33 features |
|---|---|---|---|---|
| sorteio estratificado | 1.030.783 | 257.696 | 38.934 (15,11%) | 38.939 (15,11%) |
| divisão por grupos | 1.030.491 | 257.988 | 0 (0,00%) | 0 (0,00%) |

A tabela é a da semente 42. O hash das linhas de teste de cada divisão está no manifesto do experimento, com as divisões das repetições.

## As 16 execuções

Medidas globais nas linhas de teste. Em cada par de colunas, a primeira é na amostra e a segunda é
reponderada para a distribuição original. A priori de treino é a da amostra ou a natural. O teto é o
das linhas de teste, sem reponderar, e se compara com a acurácia na amostra (ver "Como ler os números").

| Execução | Features | Divisão | Alvo | Priori de treino | Acurácia na amostra | Acurácia reponderada | Macro-F1 na amostra | Macro-F1 reponderado | F1 ponderado na amostra | F1 ponderado reponderado | Teto nas linhas de teste |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `f39_estratificada_c8` | 39 | sorteio estratificado | 8 categorias | amostra | 84,55% | 82,66% | 72,21% | 67,01% | 84,01% | 83,01% | 98,82% |
| `f39_estratificada_c7` | 39 | sorteio estratificado | 7 categorias | amostra | 93,81% | 98,58% | 74,11% | 69,96% | 93,41% | 98,58% | 99,96% |
| `f39_grupos_c8` | 39 | divisão por grupos | 8 categorias | amostra | 84,62% | 82,79% | 72,37% | 67,21% | 84,08% | 83,11% | 97,64% |
| `f39_grupos_c7` | 39 | divisão por grupos | 7 categorias | amostra | 93,86% | 98,61% | 74,41% | 70,42% | 93,47% | 98,62% | 99,95% |
| `f33_estratificada_c8` | 33 | sorteio estratificado | 8 categorias | amostra | 84,37% | 82,61% | 71,82% | 66,67% | 83,82% | 82,96% | 98,82% |
| `f33_estratificada_c7` | 33 | sorteio estratificado | 7 categorias | amostra | 93,67% | 98,55% | 73,89% | 69,87% | 93,26% | 98,55% | 99,95% |
| `f33_grupos_c8` | 33 | divisão por grupos | 8 categorias | amostra | 84,36% | 82,70% | 71,94% | 66,95% | 83,80% | 83,01% | 97,64% |
| `f33_grupos_c7` | 33 | divisão por grupos | 7 categorias | amostra | 93,67% | 98,58% | 73,97% | 70,12% | 93,27% | 98,59% | 99,95% |
| `f39_estratificada_c8_natural` | 39 | sorteio estratificado | 8 categorias | natural | 82,40% | 84,28% | 64,52% | 66,27% | 81,64% | 83,39% | 98,82% |
| `f39_estratificada_c7_natural` | 39 | sorteio estratificado | 7 categorias | natural | 92,07% | 99,10% | 65,99% | 69,75% | 91,85% | 99,08% | 99,96% |
| `f33_estratificada_c8_natural` | 33 | sorteio estratificado | 8 categorias | natural | 82,06% | 84,27% | 63,93% | 65,84% | 81,30% | 83,38% | 98,82% |
| `f33_estratificada_c7_natural` | 33 | sorteio estratificado | 7 categorias | natural | 91,82% | 99,08% | 65,65% | 69,50% | 91,61% | 99,07% | 99,95% |
| `f39_estratificada_c34` | 39 | sorteio estratificado | 34 classes | amostra | 74,07% | 75,07% | 62,83% | 58,76% | 73,51% | 75,01% | 98,43% |
| `f39_estratificada_c34_natural` | 39 | sorteio estratificado | 34 classes | natural | 72,10% | 77,16% | 58,62% | 59,63% | 70,84% | 76,49% | 98,43% |
| `f39_estratificada_c2` | 39 | sorteio estratificado | ataque ou benigno | amostra | 97,06% | 98,66% | 76,49% | 80,27% | 96,77% | 98,43% | 99,99% |
| `f39_estratificada_c2_natural` | 39 | sorteio estratificado | ataque ou benigno | natural | 95,56% | 99,26% | 78,19% | 91,66% | 96,14% | 99,25% | 99,99% |

Faixa de cada medida nas 3 sementes (42, 7 e 2026), do menor ao maior valor. As execuções de referência rodaram só com a semente 42.

| Execução | Acurácia na amostra | Acurácia reponderada | Macro-F1 na amostra | Macro-F1 reponderado | Benigno classificado como ataque |
|---|---|---|---|---|---|
| `f39_estratificada_c8` | 84,55% a 84,60% | 82,66% a 82,80% | 72,09% a 72,44% | 66,81% a 67,18% | 46,06% a 46,19% |
| `f39_estratificada_c7` | 93,78% a 93,81% | 98,58% a 98,59% | 74,08% a 74,38% | 69,89% a 70,21% | 46,22% a 46,38% |
| `f39_grupos_c8` | 84,54% a 84,62% | 82,68% a 82,79% | 72,10% a 72,37% | 67,05% a 67,21% | 45,04% a 45,76% |
| `f39_grupos_c7` | 93,81% a 93,86% | 98,59% a 98,61% | 74,20% a 74,41% | 70,26% a 70,42% | 45,08% a 45,98% |
| `f33_estratificada_c8` | 84,37% a 84,44% | 82,61% a 82,75% | 71,82% a 72,04% | 66,67% a 66,94% | 46,47% a 46,78% |
| `f33_estratificada_c7` | 93,61% a 93,67% | 98,55% a 98,56% | 73,89% a 74,04% | 69,76% a 69,93% | 46,71% a 47,22% |
| `f33_grupos_c8` | 84,36% a 84,39% | 82,67% a 82,70% | 71,76% a 71,94% | 66,72% a 66,95% | 45,69% a 46,67% |
| `f33_grupos_c7` | 93,65% a 93,67% | 98,57% a 98,59% | 73,88% a 73,97% | 69,84% a 70,21% | 45,51% a 46,35% |
| `f39_estratificada_c8_natural` | 82,33% a 82,45% | 84,28% a 84,46% | 64,52% a 64,56% | 66,27% a 66,37% | 13,87% a 14,43% |
| `f39_estratificada_c7_natural` | 92,02% a 92,09% | 99,10% a 99,12% | 65,93% a 66,08% | 69,73% a 69,89% | 14,14% a 14,48% |
| `f33_estratificada_c8_natural` | 82,06% a 82,17% | 84,27% a 84,44% | 63,93% a 64,23% | 65,84% a 66,12% | 14,14% a 14,42% |
| `f33_estratificada_c7_natural` | 91,76% a 91,86% | 99,07% a 99,09% | 65,59% a 65,66% | 69,41% a 69,51% | 14,28% a 14,42% |

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
| `f39_estratificada_c8_natural` | 93,60% e 92,79% | 55,00% e 44,04% | não se aplica | 85,57% | 14,43% | 5,03% e 0,41% |
| `f39_estratificada_c7_natural` | não se aplica | não se aplica | 99,96% e 99,99% | 85,52% | 14,48% | 5,07% e 0,42% |
| `f33_estratificada_c8_natural` | 93,27% e 92,78% | 54,58% e 44,09% | não se aplica | 85,86% | 14,14% | 5,17% e 0,43% |
| `f33_estratificada_c7_natural` | não se aplica | não se aplica | 99,72% e 99,97% | 85,72% | 14,28% | 5,14% e 0,42% |
| `f39_estratificada_c34` | não se aplica | não se aplica | não se aplica | 66,83% | 33,17% | 2,59% e 0,21% |
| `f39_estratificada_c34_natural` | não se aplica | não se aplica | não se aplica | 89,78% | 10,22% | 6,97% e 0,58% |
| `f39_estratificada_c2` | não se aplica | não se aplica | não se aplica | 45,36% | 54,64% | 0,85% e 0,07% |
| `f39_estratificada_c2_natural` | não se aplica | não se aplica | não se aplica | 81,41% | 18,59% | 3,87% e 0,31% |

Para onde vai o tráfego benigno nas execuções de 8 categorias, como fração das linhas benignas do teste:

| Classe prevista | `f39_estratificada_c8` | `f39_grupos_c8` | `f33_estratificada_c8` | `f33_grupos_c8` | `f39_estratificada_c8_natural` | `f33_estratificada_c8_natural` |
|---|---|---|---|---|---|---|
| DDoS | 0,00% | 0,00% | 0,05% | 0,01% | 0,00% | 0,00% |
| DoS | 0,00% | 0,00% | 0,00% | 0,02% | 0,00% | 0,00% |
| Mirai | 0,00% | 0,00% | 0,00% | 0,00% | 0,00% | 0,00% |
| Recon | 42,30% | 41,78% | 43,01% | 42,37% | 12,93% | 12,78% |
| Spoofing | 2,97% | 2,41% | 2,85% | 2,46% | 1,50% | 1,36% |
| Web | 0,62% | 0,50% | 0,56% | 0,52% | 0,00% | 0,00% |
| BruteForce | 0,29% | 0,35% | 0,31% | 0,31% | 0,00% | 0,00% |
| Benign | 53,82% | 54,96% | 53,22% | 54,31% | 85,57% | 85,86% |

Na amostra, o tráfego benigno é 3,9% das linhas, e as categorias de ataque com janela de 10 (Recon, Spoofing, Web e BruteForce) somam 26,3%. No conjunto completo são 2,3% e 2,6%. As execuções com `_natural` no nome foram treinadas com a proporção do conjunto completo (ver "Priori de treino").

As execuções de 34 classes e de ataque ou benigno servem de referência para os cenários do artigo do dataset (Neto et al., 2023). Os valores publicados não estão neste repositório e precisam ser conferidos no artigo antes de qualquer comparação. A comparação depende também do protocolo: o notebook de exemplo dos autores treina e avalia na proporção natural das classes, com divisão por arquivo, e aqui a priori de treino muda os resultados. Nenhuma coluna deste relatório repete esse protocolo. As execuções de 34 classes usam 25 árvores, e as demais usam 100 (ver "Custo de cada execução").

## Resultados por classe

Uma tabela para cada execução de 8 ou de 7 categorias. As colunas da esquerda são medidas na amostra, e as da direita
são reponderadas. "Falso positivo" é a fração das linhas das outras classes que o modelo pôs na classe.
"Recall na regra do teto" é o recall da classe na regra de maior acerto global nas linhas de teste,
sem reponderar, e não um limite da classe (ver "Como ler os números"). As mesmas medidas, com as execuções de
referência, estão em `metricas_classificador.csv`, e as matrizes de confusão estão em `matrizes_confusao/`.

### `f39_estratificada_c8`: 39 features, sorteio estratificado, 8 categorias, priori da amostra

| Classe | Linhas no teste | Precisão | Recall | F1 | Falso positivo | Recall na regra do teto | Precisão (repond.) | Recall (repond.) | F1 (repond.) | Falso positivo (repond.) |
|---|---|---|---|---|---|---|---|---|---|---|
| DDoS | 110.000 | 87,82% | 90,74% | 89,26% | 9,37% | 99,59% | 90,14% | 87,50% | 88,80% | 24,96% |
| DoS | 40.000 | 72,09% | 65,61% | 68,70% | 4,67% | 93,83% | 53,31% | 59,88% | 56,40% | 10,90% |
| Mirai | 30.000 | 99,94% | 99,66% | 99,80% | 0,01% | 100,00% | 99,82% | 99,66% | 99,74% | 0,01% |
| Recon | 40.432 | 77,84% | 91,63% | 84,18% | 4,85% | 99,87% | 54,48% | 92,61% | 68,60% | 1,15% |
| Spoofing | 20.000 | 93,06% | 86,38% | 89,59% | 0,54% | 99,91% | 89,85% | 86,33% | 88,05% | 0,10% |
| Web | 4.760 | 69,62% | 28,84% | 40,79% | 0,24% | 99,43% | 29,75% | 28,84% | 29,29% | 0,04% |
| BruteForce | 2.504 | 79,94% | 33,59% | 47,30% | 0,08% | 100,00% | 41,39% | 33,59% | 37,08% | 0,01% |
| Benign | 10.000 | 63,10% | 53,82% | 58,09% | 1,27% | 99,81% | 92,74% | 53,82% | 68,11% | 0,10% |

### `f39_estratificada_c7`: 39 features, sorteio estratificado, 7 categorias, priori da amostra

| Classe | Linhas no teste | Precisão | Recall | F1 | Falso positivo | Recall na regra do teto | Precisão (repond.) | Recall (repond.) | F1 (repond.) | Falso positivo (repond.) |
|---|---|---|---|---|---|---|---|---|---|---|
| DDoS+DoS | 150.000 | 99,93% | 99,98% | 99,96% | 0,09% | 100,00% | 99,98% | 99,99% | 99,99% | 0,18% |
| Mirai | 30.000 | 99,96% | 99,66% | 99,81% | 0,01% | 100,00% | 99,87% | 99,66% | 99,76% | 0,01% |
| Recon | 40.432 | 77,80% | 91,56% | 84,12% | 4,86% | 99,87% | 54,38% | 92,52% | 68,50% | 1,16% |
| Spoofing | 20.000 | 93,08% | 86,48% | 89,66% | 0,54% | 99,91% | 89,89% | 86,45% | 88,14% | 0,10% |
| Web | 4.760 | 68,44% | 28,34% | 40,08% | 0,25% | 99,43% | 28,28% | 28,34% | 28,31% | 0,04% |
| BruteForce | 2.504 | 79,40% | 33,55% | 47,16% | 0,09% | 100,00% | 41,36% | 33,55% | 37,05% | 0,01% |
| Benign | 10.000 | 63,01% | 53,62% | 57,94% | 1,27% | 99,81% | 92,73% | 53,62% | 67,95% | 0,10% |

### `f39_grupos_c8`: 39 features, divisão por grupos, 8 categorias, priori da amostra

| Classe | Linhas no teste | Precisão | Recall | F1 | Falso positivo | Recall na regra do teto | Precisão (repond.) | Recall (repond.) | F1 (repond.) | Falso positivo (repond.) |
|---|---|---|---|---|---|---|---|---|---|---|
| DDoS | 110.134 | 87,78% | 90,86% | 89,29% | 9,42% | 98,48% | 90,10% | 87,72% | 88,89% | 25,13% |
| DoS | 39.978 | 72,24% | 65,38% | 68,64% | 4,61% | 89,26% | 53,62% | 59,59% | 56,45% | 10,71% |
| Mirai | 30.012 | 99,93% | 99,63% | 99,78% | 0,01% | 100,00% | 99,87% | 99,62% | 99,75% | 0,01% |
| Recon | 40.433 | 77,96% | 91,54% | 84,21% | 4,81% | 99,86% | 54,74% | 92,41% | 68,75% | 1,14% |
| Spoofing | 20.166 | 93,47% | 86,70% | 89,96% | 0,51% | 99,95% | 90,92% | 86,70% | 88,76% | 0,09% |
| Web | 4.753 | 71,46% | 28,45% | 40,69% | 0,21% | 99,45% | 32,14% | 28,45% | 30,18% | 0,03% |
| BruteForce | 2.505 | 77,53% | 34,29% | 47,55% | 0,10% | 99,88% | 37,60% | 34,29% | 35,87% | 0,02% |
| Benign | 10.007 | 63,24% | 54,96% | 58,81% | 1,29% | 99,75% | 92,77% | 54,96% | 69,03% | 0,10% |

### `f39_grupos_c7`: 39 features, divisão por grupos, 7 categorias, priori da amostra

| Classe | Linhas no teste | Precisão | Recall | F1 | Falso positivo | Recall na regra do teto | Precisão (repond.) | Recall (repond.) | F1 (repond.) | Falso positivo (repond.) |
|---|---|---|---|---|---|---|---|---|---|---|
| DDoS+DoS | 150.112 | 99,92% | 99,98% | 99,95% | 0,11% | 100,00% | 99,98% | 99,99% | 99,98% | 0,21% |
| Mirai | 30.012 | 99,93% | 99,61% | 99,77% | 0,01% | 100,00% | 99,89% | 99,60% | 99,75% | 0,01% |
| Recon | 40.433 | 77,92% | 91,51% | 84,17% | 4,82% | 99,86% | 54,78% | 92,41% | 68,79% | 1,14% |
| Spoofing | 20.166 | 93,40% | 86,58% | 89,86% | 0,52% | 99,95% | 90,54% | 86,58% | 88,52% | 0,09% |
| Web | 4.753 | 71,17% | 28,47% | 40,67% | 0,22% | 99,45% | 31,12% | 28,47% | 29,74% | 0,03% |
| BruteForce | 2.505 | 79,48% | 34,17% | 47,79% | 0,09% | 99,88% | 40,75% | 34,17% | 37,17% | 0,01% |
| Benign | 10.007 | 63,00% | 54,92% | 58,68% | 1,30% | 99,75% | 92,75% | 54,92% | 68,99% | 0,10% |

### `f33_estratificada_c8`: 33 features, sorteio estratificado, 8 categorias, priori da amostra

| Classe | Linhas no teste | Precisão | Recall | F1 | Falso positivo | Recall na regra do teto | Precisão (repond.) | Recall (repond.) | F1 (repond.) | Falso positivo (repond.) |
|---|---|---|---|---|---|---|---|---|---|---|
| DDoS | 110.000 | 87,78% | 90,64% | 89,19% | 9,40% | 99,59% | 90,14% | 87,46% | 88,78% | 24,92% |
| DoS | 40.000 | 71,71% | 65,25% | 68,33% | 4,73% | 93,83% | 53,23% | 59,90% | 56,37% | 10,94% |
| Mirai | 30.000 | 99,94% | 99,61% | 99,77% | 0,01% | 100,00% | 99,87% | 99,61% | 99,74% | 0,01% |
| Recon | 40.432 | 77,32% | 91,44% | 83,79% | 4,99% | 99,87% | 53,84% | 92,49% | 68,06% | 1,18% |
| Spoofing | 20.000 | 93,04% | 86,38% | 89,58% | 0,54% | 99,91% | 89,55% | 86,33% | 87,91% | 0,11% |
| Web | 4.760 | 69,58% | 28,07% | 40,00% | 0,23% | 99,43% | 29,86% | 28,06% | 28,93% | 0,03% |
| BruteForce | 2.504 | 79,13% | 32,71% | 46,28% | 0,08% | 100,00% | 39,97% | 32,71% | 35,98% | 0,01% |
| Benign | 10.000 | 62,82% | 53,22% | 57,62% | 1,27% | 99,81% | 92,63% | 53,22% | 67,60% | 0,10% |

### `f33_estratificada_c7`: 33 features, sorteio estratificado, 7 categorias, priori da amostra

| Classe | Linhas no teste | Precisão | Recall | F1 | Falso positivo | Recall na regra do teto | Precisão (repond.) | Recall (repond.) | F1 (repond.) | Falso positivo (repond.) |
|---|---|---|---|---|---|---|---|---|---|---|
| DDoS+DoS | 150.000 | 99,84% | 99,86% | 99,85% | 0,23% | 100,00% | 99,97% | 99,98% | 99,98% | 0,22% |
| Mirai | 30.000 | 99,96% | 99,61% | 99,78% | 0,01% | 100,00% | 99,91% | 99,61% | 99,76% | 0,01% |
| Recon | 40.432 | 77,33% | 91,40% | 83,77% | 4,99% | 99,87% | 53,78% | 92,52% | 68,02% | 1,19% |
| Spoofing | 20.000 | 93,03% | 86,50% | 89,64% | 0,55% | 99,91% | 89,30% | 86,46% | 87,86% | 0,11% |
| Web | 4.760 | 69,87% | 28,26% | 40,24% | 0,23% | 99,43% | 30,29% | 28,25% | 29,24% | 0,03% |
| BruteForce | 2.504 | 80,00% | 32,91% | 46,63% | 0,08% | 100,00% | 42,32% | 32,91% | 37,02% | 0,01% |
| Benign | 10.000 | 62,62% | 52,78% | 57,28% | 1,27% | 99,81% | 92,62% | 52,78% | 67,24% | 0,10% |

### `f33_grupos_c8`: 33 features, divisão por grupos, 8 categorias, priori da amostra

| Classe | Linhas no teste | Precisão | Recall | F1 | Falso positivo | Recall na regra do teto | Precisão (repond.) | Recall (repond.) | F1 (repond.) | Falso positivo (repond.) |
|---|---|---|---|---|---|---|---|---|---|---|
| DDoS | 110.134 | 87,63% | 90,82% | 89,20% | 9,55% | 98,48% | 90,00% | 87,75% | 88,86% | 25,42% |
| DoS | 39.978 | 71,76% | 64,63% | 68,01% | 4,67% | 89,26% | 53,47% | 59,08% | 56,14% | 10,68% |
| Mirai | 30.012 | 99,94% | 99,56% | 99,75% | 0,01% | 100,00% | 99,94% | 99,55% | 99,75% | 0,00% |
| Recon | 40.433 | 77,27% | 91,18% | 83,65% | 4,98% | 99,86% | 54,05% | 92,32% | 68,18% | 1,17% |
| Spoofing | 20.166 | 93,29% | 86,49% | 89,76% | 0,53% | 99,95% | 90,10% | 86,52% | 88,27% | 0,10% |
| Web | 4.753 | 71,24% | 27,73% | 39,92% | 0,21% | 99,45% | 31,48% | 27,74% | 29,49% | 0,03% |
| BruteForce | 2.505 | 80,15% | 33,21% | 46,97% | 0,08% | 99,88% | 40,25% | 33,21% | 36,40% | 0,01% |
| Benign | 10.007 | 62,88% | 54,31% | 58,28% | 1,29% | 99,75% | 92,73% | 54,31% | 68,50% | 0,10% |

### `f33_grupos_c7`: 33 features, divisão por grupos, 7 categorias, priori da amostra

| Classe | Linhas no teste | Precisão | Recall | F1 | Falso positivo | Recall na regra do teto | Precisão (repond.) | Recall (repond.) | F1 (repond.) | Falso positivo (repond.) |
|---|---|---|---|---|---|---|---|---|---|---|
| DDoS+DoS | 150.112 | 99,80% | 99,85% | 99,82% | 0,28% | 100,00% | 99,97% | 99,98% | 99,97% | 0,25% |
| Mirai | 30.012 | 99,95% | 99,55% | 99,75% | 0,01% | 100,00% | 99,97% | 99,54% | 99,75% | 0,00% |
| Recon | 40.433 | 77,28% | 91,16% | 83,65% | 4,98% | 99,86% | 54,08% | 92,32% | 68,21% | 1,17% |
| Spoofing | 20.166 | 93,30% | 86,50% | 89,77% | 0,53% | 99,95% | 90,27% | 86,51% | 88,35% | 0,10% |
| Web | 4.753 | 72,37% | 27,60% | 39,96% | 0,20% | 99,45% | 33,77% | 27,61% | 30,38% | 0,03% |
| BruteForce | 2.505 | 79,13% | 32,85% | 46,43% | 0,08% | 99,88% | 38,59% | 32,85% | 35,49% | 0,01% |
| Benign | 10.007 | 62,96% | 54,49% | 58,42% | 1,29% | 99,75% | 92,77% | 54,49% | 68,66% | 0,10% |

### `f39_estratificada_c8_natural`: 39 features, sorteio estratificado, 8 categorias, priori natural

| Classe | Linhas no teste | Precisão | Recall | F1 | Falso positivo | Recall na regra do teto | Precisão (repond.) | Recall (repond.) | F1 (repond.) | Falso positivo (repond.) |
|---|---|---|---|---|---|---|---|---|---|---|
| DDoS | 110.000 | 85,08% | 93,60% | 89,14% | 12,22% | 99,59% | 87,43% | 92,79% | 90,03% | 34,76% |
| DoS | 40.000 | 75,88% | 55,00% | 63,78% | 3,21% | 93,83% | 59,30% | 44,04% | 50,54% | 6,28% |
| Mirai | 30.000 | 99,82% | 99,73% | 99,78% | 0,02% | 100,00% | 99,78% | 99,73% | 99,76% | 0,01% |
| Recon | 40.432 | 82,85% | 76,94% | 79,79% | 2,96% | 99,87% | 74,43% | 79,12% | 76,71% | 0,41% |
| Spoofing | 20.000 | 92,61% | 85,30% | 88,81% | 0,57% | 99,91% | 93,11% | 85,43% | 89,11% | 0,07% |
| Web | 4.760 | 99,01% | 8,38% | 15,46% | 0,00% | 99,43% | 97,20% | 8,38% | 15,43% | 0,00% |
| BruteForce | 2.504 | 100,00% | 13,78% | 24,22% | 0,00% | 100,00% | 100,00% | 13,78% | 24,22% | 0,00% |
| Benign | 10.000 | 40,74% | 85,57% | 55,20% | 5,03% | 99,81% | 83,23% | 85,57% | 84,38% | 0,41% |

### `f39_estratificada_c7_natural`: 39 features, sorteio estratificado, 7 categorias, priori natural

| Classe | Linhas no teste | Precisão | Recall | F1 | Falso positivo | Recall na regra do teto | Precisão (repond.) | Recall (repond.) | F1 (repond.) | Falso positivo (repond.) |
|---|---|---|---|---|---|---|---|---|---|---|
| DDoS+DoS | 150.000 | 99,94% | 99,96% | 99,95% | 0,08% | 100,00% | 99,98% | 99,99% | 99,99% | 0,16% |
| Mirai | 30.000 | 99,88% | 99,70% | 99,79% | 0,02% | 100,00% | 99,86% | 99,70% | 99,78% | 0,01% |
| Recon | 40.432 | 82,87% | 76,83% | 79,73% | 2,96% | 99,87% | 74,34% | 78,87% | 76,54% | 0,41% |
| Spoofing | 20.000 | 92,75% | 85,25% | 88,84% | 0,56% | 99,91% | 93,10% | 85,39% | 89,08% | 0,07% |
| Web | 4.760 | 98,78% | 8,49% | 15,63% | 0,00% | 99,43% | 95,88% | 8,49% | 15,59% | 0,00% |
| BruteForce | 2.504 | 100,00% | 12,98% | 22,98% | 0,00% | 100,00% | 100,00% | 12,98% | 22,98% | 0,00% |
| Benign | 10.000 | 40,51% | 85,52% | 54,98% | 5,07% | 99,81% | 83,06% | 85,52% | 84,27% | 0,42% |

### `f33_estratificada_c8_natural`: 33 features, sorteio estratificado, 8 categorias, priori natural

| Classe | Linhas no teste | Precisão | Recall | F1 | Falso positivo | Recall na regra do teto | Precisão (repond.) | Recall (repond.) | F1 (repond.) | Falso positivo (repond.) |
|---|---|---|---|---|---|---|---|---|---|---|
| DDoS | 110.000 | 85,04% | 93,27% | 88,96% | 12,22% | 99,59% | 87,45% | 92,78% | 90,03% | 34,71% |
| DoS | 40.000 | 75,19% | 54,58% | 63,25% | 3,31% | 93,83% | 59,30% | 44,09% | 50,58% | 6,29% |
| Mirai | 30.000 | 99,83% | 99,65% | 99,74% | 0,02% | 100,00% | 99,86% | 99,65% | 99,76% | 0,01% |
| Recon | 40.432 | 82,06% | 76,21% | 79,03% | 3,10% | 99,87% | 73,78% | 78,46% | 76,05% | 0,42% |
| Spoofing | 20.000 | 92,46% | 85,18% | 88,67% | 0,58% | 99,91% | 92,81% | 85,34% | 88,92% | 0,07% |
| Web | 4.760 | 97,77% | 8,28% | 15,26% | 0,00% | 99,43% | 95,72% | 8,28% | 15,23% | 0,00% |
| BruteForce | 2.504 | 100,00% | 12,26% | 21,84% | 0,00% | 100,00% | 100,00% | 12,26% | 21,84% | 0,00% |
| Benign | 10.000 | 40,15% | 85,86% | 54,72% | 5,17% | 99,81% | 82,84% | 85,86% | 84,32% | 0,43% |

### `f33_estratificada_c7_natural`: 33 features, sorteio estratificado, 7 categorias, priori natural

| Classe | Linhas no teste | Precisão | Recall | F1 | Falso positivo | Recall na regra do teto | Precisão (repond.) | Recall (repond.) | F1 (repond.) | Falso positivo (repond.) |
|---|---|---|---|---|---|---|---|---|---|---|
| DDoS+DoS | 150.000 | 99,80% | 99,72% | 99,76% | 0,28% | 100,00% | 99,98% | 99,97% | 99,97% | 0,21% |
| Mirai | 30.000 | 99,88% | 99,63% | 99,76% | 0,02% | 100,00% | 99,84% | 99,63% | 99,74% | 0,01% |
| Recon | 40.432 | 82,40% | 76,25% | 79,21% | 3,03% | 99,87% | 74,29% | 78,70% | 76,43% | 0,41% |
| Spoofing | 20.000 | 92,38% | 85,28% | 88,68% | 0,59% | 99,91% | 92,30% | 85,40% | 88,71% | 0,07% |
| Web | 4.760 | 98,77% | 8,42% | 15,52% | 0,00% | 99,43% | 96,94% | 8,42% | 15,50% | 0,00% |
| BruteForce | 2.504 | 100,00% | 12,26% | 21,84% | 0,00% | 100,00% | 100,00% | 12,26% | 21,84% | 0,00% |
| Benign | 10.000 | 40,24% | 85,72% | 54,77% | 5,14% | 99,81% | 82,98% | 85,72% | 84,33% | 0,42% |

## Importância das features

Importância por redução média de impureza, a que o scikit-learn calcula no treino. As importâncias de
um modelo somam 100%. As features estão na ordem da primeira coluna, e as que dependem do tamanho da
janela estão marcadas. A tabela completa, com as execuções de referência, está em `importancia_features.csv`.

### Com 39 features

| Posição | Feature | `f39_estratificada_c8` | `f39_estratificada_c7` | `f39_grupos_c8` | `f39_grupos_c7` | `f39_estratificada_c8_natural` | `f39_estratificada_c7_natural` |
|---|---|---|---|---|---|---|---|
| 1 | `Tot sum` (janela) | 10,79% | 12,74% | 10,46% | 12,87% | 7,06% | 12,05% |
| 2 | `Rate` | 8,19% | 5,39% | 8,23% | 5,10% | 15,32% | 4,46% |
| 3 | `Number` (janela) | 7,56% | 11,28% | 8,20% | 11,97% | 3,20% | 6,71% |
| 4 | `Protocol Type` | 5,79% | 5,96% | 5,90% | 6,05% | 5,10% | 6,02% |
| 5 | `Max` | 5,65% | 6,61% | 6,18% | 6,60% | 5,52% | 9,55% |
| 6 | `Min` | 5,63% | 5,98% | 4,98% | 6,86% | 3,49% | 5,78% |
| 7 | `IAT` | 5,60% | 4,44% | 5,58% | 4,74% | 7,88% | 4,65% |
| 8 | `Tot size` | 5,14% | 6,44% | 5,27% | 6,12% | 8,99% | 11,47% |
| 9 | `AVG` | 4,70% | 5,65% | 4,74% | 5,25% | 7,29% | 10,54% |
| 10 | `Header_Length` | 4,36% | 3,04% | 4,58% | 3,08% | 4,03% | 3,20% |
| 11 | `Variance` | 4,31% | 3,77% | 4,09% | 4,53% | 3,11% | 5,49% |
| 12 | `Time_To_Live` | 4,27% | 4,39% | 4,08% | 4,64% | 2,97% | 2,75% |
| 13 | `Std` | 4,07% | 4,56% | 4,17% | 3,69% | 3,45% | 5,61% |
| 14 | `HTTPS` | 2,99% | 3,82% | 2,96% | 3,72% | 1,83% | 2,37% |
| 15 | `ack_count` (janela) | 2,69% | 2,90% | 2,80% | 2,35% | 1,91% | 1,57% |
| 16 | `ack_flag_number` | 2,44% | 2,19% | 2,37% | 2,13% | 2,28% | 1,53% |
| 17 | `psh_flag_number` | 1,86% | 1,07% | 1,97% | 0,94% | 2,05% | 0,66% |
| 18 | `syn_count` (janela) | 1,71% | 1,60% | 1,67% | 1,10% | 1,57% | 0,55% |
| 19 | `syn_flag_number` | 1,57% | 1,04% | 1,43% | 1,16% | 1,27% | 0,48% |
| 20 | `UDP` | 1,48% | 1,36% | 1,50% | 1,25% | 1,87% | 0,81% |
| 21 | `TCP` | 1,46% | 1,58% | 1,51% | 1,81% | 1,73% | 1,23% |
| 22 | `ICMP` | 1,15% | 0,47% | 0,89% | 0,26% | 2,35% | 0,31% |
| 23 | `HTTP` | 1,14% | 0,51% | 1,03% | 0,61% | 0,70% | 0,30% |
| 24 | `rst_count` (janela) | 1,04% | 0,40% | 0,94% | 0,42% | 0,90% | 0,14% |
| 25 | `fin_count` (janela) | 0,98% | 0,44% | 0,95% | 0,38% | 0,78% | 0,21% |
| 26 | `fin_flag_number` | 0,88% | 0,36% | 0,88% | 0,32% | 1,25% | 0,22% |
| 27 | `rst_flag_number` | 0,83% | 0,35% | 0,93% | 0,38% | 1,09% | 0,14% |
| 28 | `DNS` | 0,45% | 0,45% | 0,45% | 0,45% | 0,26% | 0,34% |
| 29 | `SSH` | 0,43% | 0,46% | 0,44% | 0,47% | 0,06% | 0,05% |
| 30 | `ARP` | 0,26% | 0,22% | 0,26% | 0,26% | 0,18% | 0,27% |
| 31 | `IPv` | 0,25% | 0,20% | 0,24% | 0,18% | 0,20% | 0,34% |
| 32 | `LLC` | 0,20% | 0,20% | 0,22% | 0,21% | 0,19% | 0,18% |
| 33 | `DHCP` | 0,06% | 0,05% | 0,06% | 0,05% | 0,04% | 0,03% |
| 34 | `ece_flag_number` | 0,02% | 0,02% | 0,02% | 0,02% | 0,01% | 0,01% |
| 35 | `IGMP` | 0,01% | 0,01% | 0,01% | 0,01% | 0,01% | 0,01% |
| 36 | `cwr_flag_number` | 0,01% | 0,01% | 0,01% | 0,01% | 0,01% | 0,01% |
| 37 | `IRC` | 0,01% | 0,01% | 0,01% | 0,01% | 0,01% | 0,00% |
| 38 | `SMTP` | 0,00% | 0,00% | 0,00% | 0,00% | 0,01% | 0,00% |
| 39 | `Telnet` | 0,00% | 0,00% | 0,00% | 0,00% | 0,00% | 0,00% |

### Com 33 features

| Posição | Feature | `f33_estratificada_c8` | `f33_estratificada_c7` | `f33_grupos_c8` | `f33_grupos_c7` | `f33_estratificada_c8_natural` | `f33_estratificada_c7_natural` |
|---|---|---|---|---|---|---|---|
| 1 | `Rate` | 9,66% | 8,18% | 9,59% | 8,60% | 15,90% | 6,05% |
| 2 | `IAT` | 8,33% | 7,97% | 8,13% | 7,70% | 8,53% | 5,61% |
| 3 | `Max` | 8,12% | 8,29% | 7,40% | 8,41% | 7,64% | 11,55% |
| 4 | `AVG` | 6,85% | 7,32% | 6,81% | 8,15% | 9,65% | 13,11% |
| 5 | `Time_To_Live` | 6,51% | 8,35% | 6,54% | 8,16% | 3,60% | 3,62% |
| 6 | `Header_Length` | 6,24% | 4,70% | 6,36% | 4,90% | 4,72% | 4,43% |
| 7 | `Tot size` | 6,15% | 7,98% | 6,46% | 7,59% | 9,21% | 13,42% |
| 8 | `Min` | 5,65% | 7,88% | 5,80% | 7,44% | 4,77% | 8,44% |
| 9 | `Std` | 5,16% | 4,79% | 4,99% | 4,56% | 3,70% | 5,97% |
| 10 | `Variance` | 4,76% | 5,13% | 5,32% | 5,20% | 3,65% | 7,36% |
| 11 | `Protocol Type` | 4,67% | 4,52% | 4,78% | 4,35% | 4,14% | 4,82% |
| 12 | `HTTPS` | 4,01% | 5,25% | 3,78% | 5,08% | 2,37% | 3,59% |
| 13 | `ack_flag_number` | 3,85% | 3,98% | 3,96% | 4,10% | 3,40% | 2,94% |
| 14 | `psh_flag_number` | 2,86% | 2,06% | 2,76% | 1,84% | 2,78% | 1,17% |
| 15 | `syn_flag_number` | 2,72% | 2,24% | 2,57% | 2,19% | 2,67% | 0,98% |
| 16 | `TCP` | 2,54% | 2,10% | 2,85% | 2,49% | 2,25% | 1,82% |
| 17 | `UDP` | 2,04% | 1,84% | 2,29% | 2,14% | 2,18% | 1,02% |
| 18 | `rst_flag_number` | 1,91% | 1,17% | 1,96% | 1,10% | 2,22% | 0,41% |
| 19 | `fin_flag_number` | 1,84% | 1,04% | 1,80% | 1,02% | 1,81% | 0,53% |
| 20 | `HTTP` | 1,75% | 1,50% | 1,62% | 1,25% | 0,75% | 0,53% |
| 21 | `ICMP` | 1,60% | 0,73% | 1,58% | 0,65% | 2,68% | 0,51% |
| 22 | `DNS` | 0,58% | 0,58% | 0,56% | 0,51% | 0,34% | 0,53% |
| 23 | `ARP` | 0,57% | 0,64% | 0,55% | 0,67% | 0,30% | 0,44% |
| 24 | `LLC` | 0,55% | 0,52% | 0,51% | 0,59% | 0,30% | 0,52% |
| 25 | `IPv` | 0,52% | 0,66% | 0,48% | 0,71% | 0,28% | 0,49% |
| 26 | `SSH` | 0,42% | 0,45% | 0,41% | 0,45% | 0,06% | 0,06% |
| 27 | `DHCP` | 0,06% | 0,06% | 0,07% | 0,06% | 0,05% | 0,04% |
| 28 | `ece_flag_number` | 0,02% | 0,03% | 0,02% | 0,03% | 0,01% | 0,01% |
| 29 | `IGMP` | 0,02% | 0,01% | 0,02% | 0,02% | 0,01% | 0,01% |
| 30 | `cwr_flag_number` | 0,01% | 0,02% | 0,01% | 0,01% | 0,01% | 0,01% |
| 31 | `IRC` | 0,01% | 0,01% | 0,01% | 0,01% | 0,01% | 0,00% |
| 32 | `SMTP` | 0,00% | 0,00% | 0,00% | 0,00% | 0,01% | 0,00% |
| 33 | `Telnet` | 0,00% | 0,00% | 0,00% | 0,00% | 0,00% | 0,00% |

## Custo de cada execução

O tempo de inferência sai de duas formas. "1.000 janelas" é a mediana de cinco classificações de um
lote de 1.000 janelas. "Uma janela por chamada" é a mediana de 25 classificações de uma
janela sozinha, e é o caso da operação, em que cada janela é classificada assim que o extrator a
produz. O tamanho do modelo é o do arquivo gravado com `joblib`, sem compressão.

Os tempos não se comparam entre as linhas da tabela. Eles são da máquina em que o experimento rodou e
mudam de uma medida para outra com o mesmo modelo, conforme o que mais a máquina faz na hora. Servem
para a ordem de grandeza, e não para dizer que uma configuração é mais rápida do que outra.
Entre as repetições de uma mesma configuração nas 3 sementes, cujos modelos diferem em até 0,6% na quantidade de nós, o tempo por 1.000 janelas com um núcleo variou até 23% e o de uma janela por chamada, até 26%.

| Execução | Árvores | Treino (s) | Classificar o teste inteiro, um núcleo (s) | 1.000 janelas, um núcleo (ms) | 1.000 janelas, todos os núcleos (ms) | Uma janela por chamada, um núcleo (ms) | Modelo (MB) | Nós por árvore | Profundidade média |
|---|---|---|---|---|---|---|---|---|---|
| `f39_estratificada_c8` | 100 | 20,8 | 3,0 | 27,6 | 15,8 | 1,67 | 2.275,7 | 177.787 | 77,1 |
| `f39_estratificada_c7` | 100 | 17,5 | 1,6 | 14,1 | 16,0 | 1,84 | 1.252,0 | 104.327 | 58,5 |
| `f39_grupos_c8` | 100 | 20,9 | 3,0 | 29,2 | 15,8 | 1,66 | 2.277,6 | 177.931 | 76,1 |
| `f39_grupos_c7` | 100 | 17,9 | 1,6 | 15,1 | 16,0 | 1,64 | 1.252,9 | 104.407 | 58,6 |
| `f33_estratificada_c8` | 100 | 20,0 | 3,1 | 28,9 | 15,9 | 1,69 | 2.394,9 | 187.101 | 79,8 |
| `f33_estratificada_c7` | 100 | 19,0 | 1,9 | 17,6 | 15,6 | 1,66 | 1.360,3 | 113.352 | 57,3 |
| `f33_grupos_c8` | 100 | 19,9 | 3,1 | 30,4 | 16,0 | 1,69 | 2.397,0 | 187.263 | 77,4 |
| `f33_grupos_c7` | 100 | 18,9 | 1,9 | 19,0 | 16,0 | 1,66 | 1.359,4 | 113.278 | 56,9 |
| `f39_estratificada_c8_natural` | 100 | 18,6 | 2,4 | 21,6 | 16,1 | 1,71 | 1.258,8 | 97.699 | 76,6 |
| `f39_estratificada_c7_natural` | 100 | 15,4 | 1,2 | 9,6 | 15,9 | 1,61 | 274,8 | 22.210 | 50,9 |
| `f33_estratificada_c8_natural` | 100 | 17,8 | 3,3 | 23,1 | 13,7 | 1,68 | 1.294,5 | 100.487 | 76,2 |
| `f33_estratificada_c7_natural` | 100 | 19,0 | 1,8 | 14,4 | 13,6 | 2,04 | 305,6 | 24.778 | 50,6 |
| `f39_estratificada_c34` | 25 | 7,9 | 1,2 | 8,0 | 13,7 | 0,54 | 2.330,3 | 277.413 | 77,8 |
| `f39_estratificada_c34_natural` | 25 | 6,2 | 0,9 | 5,2 | 13,5 | 0,59 | 1.025,4 | 121.082 | 75,6 |
| `f39_estratificada_c2` | 100 | 14,5 | 1,0 | 8,4 | 12,7 | 1,72 | 433,6 | 54.199 | 57,0 |
| `f39_estratificada_c2_natural` | 100 | 13,5 | 0,8 | 7,5 | 12,9 | 1,97 | 148,2 | 17.483 | 49,4 |

As execuções de 34 classes usam 25 árvores, e não 100. Com 34 classes cada nó guarda 34 contagens e as árvores têm mais nós, e a floresta de 100 árvores não caberia na memória da máquina usada. As medidas dessas execuções não são diretamente comparáveis às das outras.

As predições usadas nas métricas somam os votos das árvores com um núcleo, em ordem fixa. Com vários
núcleos o scikit-learn soma na ordem em que as árvores terminam, e uma linha com duas classes
empatadas pode mudar de resposta de uma chamada para outra.

## O que os números dizem sobre cada decisão em aberto

Só o que mudou e quanto, sem recomendação. As diferenças são da segunda coluna menos a primeira, em
pontos percentuais. "Na amostra" é medido nas linhas de teste como elas são, e "reponderada" é a
estimativa na distribuição original do dataset. As três primeiras subseções usam as execuções
treinadas com as proporções da amostra. A quarta trata da priori de treino, uma escolha de método que
este experimento expôs.

Os valores das tabelas são da semente 42. A coluna de faixa e as frases que resumem cada comparação usam as 3 sementes (ver "Como ler os números").

### Janela de 10 ou de 100 pacotes

O que muda quando saem as seis colunas que dependem do tamanho da janela, com a divisão e o alvo fixos.

Acurácia:

| Divisão e alvo | Na amostra, 39 | Na amostra, 33 | Diferença (p.p.) | Faixa da diferença nas 3 sementes (p.p.) | Reponderada, 39 | Reponderada, 33 | Diferença (p.p.) | Faixa da diferença nas 3 sementes (p.p.) |
|---|---|---|---|---|---|---|---|---|
| sorteio estratificado, 8 categorias | 84,55% | 84,37% | -0,18 | -0,18 a -0,13 | 82,66% | 82,61% | -0,05 | -0,05 a -0,02 |
| sorteio estratificado, 7 categorias | 93,81% | 93,67% | -0,14 | -0,17 a -0,14 | 98,58% | 98,55% | -0,03 | -0,03 a -0,03 |
| divisão por grupos, 8 categorias | 84,62% | 84,36% | -0,26 | -0,26 a -0,16 | 82,79% | 82,70% | -0,09 | -0,09 a +0,01 |
| divisão por grupos, 7 categorias | 93,86% | 93,67% | -0,19 | -0,19 a -0,16 | 98,61% | 98,58% | -0,03 | -0,03 a -0,02 |

Macro-F1:

| Divisão e alvo | Na amostra, 39 | Na amostra, 33 | Diferença (p.p.) | Faixa da diferença nas 3 sementes (p.p.) | Reponderada, 39 | Reponderada, 33 | Diferença (p.p.) | Faixa da diferença nas 3 sementes (p.p.) |
|---|---|---|---|---|---|---|---|---|
| sorteio estratificado, 8 categorias | 72,21% | 71,82% | -0,39 | -0,40 a -0,27 | 67,01% | 66,67% | -0,34 | -0,34 a -0,11 |
| sorteio estratificado, 7 categorias | 74,11% | 73,89% | -0,22 | -0,34 a -0,19 | 69,96% | 69,87% | -0,08 | -0,28 a -0,08 |
| divisão por grupos, 8 categorias | 72,37% | 71,94% | -0,42 | -0,42 a -0,28 | 67,21% | 66,95% | -0,26 | -0,38 a -0,21 |
| divisão por grupos, 7 categorias | 74,41% | 73,97% | -0,44 | -0,44 a -0,25 | 70,42% | 70,12% | -0,30 | -0,42 a -0,09 |

Erros entre os dois grupos de janela, isto é, linha de DDoS, DoS ou Mirai (janela de 100) classificada
em categoria de janela de 10, ou o contrário, como fração das linhas de teste. Ao lado, o tráfego benigno
classificado como ataque. Valores da semente 42:

| Divisão e alvo | Entre janelas na amostra, 39 | Entre janelas na amostra, 33 | Entre janelas reponderado, 39 | Entre janelas reponderado, 33 | Benigno como ataque, 39 | Benigno como ataque, 33 |
|---|---|---|---|---|---|---|
| sorteio estratificado, 8 categorias | 0,006% | 0,152% | 0,001% | 0,024% | 46,18% | 46,78% |
| sorteio estratificado, 7 categorias | 0,004% | 0,143% | 0,000% | 0,019% | 46,38% | 47,22% |
| divisão por grupos, 8 categorias | 0,005% | 0,170% | 0,002% | 0,029% | 45,04% | 45,69% |
| divisão por grupos, 7 categorias | 0,005% | 0,167% | 0,002% | 0,027% | 45,08% | 45,51% |

- Acurácia, de 39 para 33 features, nas 12 comparações (4 pares de execuções, 3 sementes). Na amostra, a diferença vai de -0,26 a -0,13 p.p. e tem o mesmo sinal em todas as comparações; é pequena e consistente: a menor, de 0,13 p.p., não chega a 2 vezes a maior variação de uma mesma execução entre sementes (0,08 p.p.). Reponderada, vai de -0,09 a +0,01 p.p. e muda de sinal de uma comparação para outra: não se distingue do ruído de semente.
- Macro-F1, de 39 para 33 features, nas 12 comparações (4 pares de execuções, 3 sementes). Na amostra, a diferença vai de -0,44 a -0,19 p.p. e tem o mesmo sinal em todas as comparações; é pequena e consistente: a menor, de 0,19 p.p., não chega a 2 vezes a maior variação de uma mesma execução entre sementes (0,35 p.p.). Reponderada, vai de -0,42 a -0,08 p.p. e tem o mesmo sinal em todas as comparações; é pequena e consistente: a menor, de 0,08 p.p., não chega a 2 vezes a maior variação de uma mesma execução entre sementes (0,37 p.p.).
- Nas 12 execuções com 39 features e priori da amostra, contadas as 3 sementes, as seis colunas somam de 24,8% a 31,2% da importância, e `Number` fica entre a 1ª e a 3ª posição das 39.
- `Number` é a quantidade de quadros da janela e não é função das colunas que ficam. As outras cinco (`Tot sum`, `ack_count`, `syn_count`, `fin_count` e `rst_count`) são o produto de uma coluna que fica por `Number` (`exploracao.md`, seção 7). O que sai é a leitura direta do tamanho da janela.
- **Tirar as seis colunas não tira o atalho.** Sem elas, o modelo ainda põe de 99,82% a 99,86% das linhas de teste no grupo de janela certo (com as 39, de 99,99% a 100,00%), contadas as 3 sementes. As 33 features que ficam continuam variando com o tamanho da janela: `Min`, `Max` e `Std` dependem dele, e as médias de uma janela de 100 têm passos de 0,01, contra 0,1 na de 10 (`dados/README.md`). Como na amostra a janela acompanha a classe, o experimento não separa o que o modelo aprende do tráfego do que aprende da janela.
- Este experimento não mede o efeito de classificar tráfego agregado com uma janela diferente da do
  treino. Treino e teste vêm da mesma amostra, em que a janela acompanha a classe, com 39 ou com 33
  features. A medida direta é pontuar capturas processadas pelo extrator com outro tamanho de janela
  (`python -m codigo.classificador.avaliar MODELO --csv CAPTURA --rotulo ROTULO`).

### Divisão entre treino e teste

O que muda do sorteio estratificado de linhas para a divisão por grupos, com as features e o alvo fixos.
As duas divisões têm linhas de teste diferentes.

Acurácia:

| Features e alvo | Na amostra, sorteio | Na amostra, grupos | Diferença (p.p.) | Faixa da diferença nas 3 sementes (p.p.) | Reponderada, sorteio | Reponderada, grupos | Diferença (p.p.) | Faixa da diferença nas 3 sementes (p.p.) |
|---|---|---|---|---|---|---|---|---|
| 39 features, 8 categorias | 84,55% | 84,62% | +0,07 | -0,05 a +0,07 | 82,66% | 82,79% | +0,13 | -0,11 a +0,13 |
| 39 features, 7 categorias | 93,81% | 93,86% | +0,05 | 0,00 a +0,05 | 98,58% | 98,61% | +0,03 | 0,00 a +0,03 |
| 33 features, 8 categorias | 84,37% | 84,36% | -0,01 | -0,08 a -0,01 | 82,61% | 82,70% | +0,09 | -0,07 a +0,09 |
| 33 features, 7 categorias | 93,67% | 93,67% | 0,00 | -0,02 a +0,05 | 98,55% | 98,58% | +0,03 | +0,01 a +0,04 |

Macro-F1:

| Features e alvo | Na amostra, sorteio | Na amostra, grupos | Diferença (p.p.) | Faixa da diferença nas 3 sementes (p.p.) | Reponderada, sorteio | Reponderada, grupos | Diferença (p.p.) | Faixa da diferença nas 3 sementes (p.p.) |
|---|---|---|---|---|---|---|---|---|
| 39 features, 8 categorias | 72,21% | 72,37% | +0,15 | -0,29 a +0,15 | 67,01% | 67,21% | +0,20 | -0,13 a +0,29 |
| 39 features, 7 categorias | 74,11% | 74,41% | +0,31 | -0,17 a +0,31 | 69,96% | 70,42% | +0,46 | +0,05 a +0,46 |
| 33 features, 8 categorias | 71,82% | 71,94% | +0,12 | -0,18 a +0,12 | 66,67% | 66,95% | +0,28 | -0,10 a +0,28 |
| 33 features, 7 categorias | 73,89% | 73,97% | +0,09 | -0,16 a +0,09 | 69,87% | 70,12% | +0,24 | -0,09 a +0,45 |

Teto nas linhas de teste:

| Features e alvo | Teto, sorteio | Teto, grupos | Diferença (p.p.) | Faixa da diferença nas 3 sementes (p.p.) |
|---|---|---|---|---|
| 39 features, 8 categorias | 98,82% | 97,64% | -1,18 | -1,23 a -1,18 |
| 39 features, 7 categorias | 99,96% | 99,95% | 0,00 | -0,01 a 0,00 |
| 33 features, 8 categorias | 98,82% | 97,64% | -1,18 | -1,23 a -1,18 |
| 33 features, 7 categorias | 99,95% | 99,95% | 0,00 | -0,01 a 0,00 |

- Acurácia, do sorteio estratificado para a divisão por grupos, nas 12 comparações (4 pares de execuções, 3 sementes). Na amostra, a diferença vai de -0,08 a +0,07 p.p. e muda de sinal de uma comparação para outra: não se distingue do ruído de semente. Reponderada, vai de -0,11 a +0,13 p.p. e muda de sinal de uma comparação para outra: não se distingue do ruído de semente.
- Macro-F1, do sorteio estratificado para a divisão por grupos, nas 12 comparações (4 pares de execuções, 3 sementes). Na amostra, a diferença vai de -0,29 a +0,31 p.p. e muda de sinal de uma comparação para outra: não se distingue do ruído de semente. Reponderada, vai de -0,13 a +0,46 p.p. e muda de sinal de uma comparação para outra: não se distingue do ruído de semente.
- No sorteio estratificado da semente 42, 38.934 das 257.696 linhas de teste (15,11%) têm o mesmo vetor de uma linha do treino, com as 39 features. Na divisão por grupos, nenhuma.
- Na amostra, 16,05% das linhas repetem o vetor de outra. No conjunto completo são 58,78% (`exploracao.md`, seção 8). A diferença entre as duas divisões medida aqui é a da amostra, com menos repetição do que haveria no dataset inteiro.
- O teto das duas divisões não mede a mesma coisa. Na divisão por grupos, todas as repetições de um
  vetor ficam do mesmo lado, e o teto conta os conflitos de classe inteiros. No sorteio de linhas, parte
  das repetições fica no treino, e o teto só conta os conflitos que caíram no teste.
- A divisão por grupos separa vetores idênticos. Ela não separa janelas vizinhas do mesmo pcap, que são
  parecidas sem ser iguais. A saída de dividir pelos CSVs por ataque, que preservam o arquivo de
  origem, não é medida aqui: a amostra vem do `MERGED_CSV`, que não guarda o arquivo de cada linha.

### DDoS e DoS

O que muda de 8 categorias para 7, com DDoS e DoS fundidas, com as features e a divisão fixas.

Acurácia:

| Features e divisão | Na amostra, 8 | Na amostra, 7 | Diferença (p.p.) | Faixa da diferença nas 3 sementes (p.p.) | Reponderada, 8 | Reponderada, 7 | Diferença (p.p.) | Faixa da diferença nas 3 sementes (p.p.) |
|---|---|---|---|---|---|---|---|---|
| 39 features, sorteio estratificado | 84,55% | 93,81% | +9,26 | +9,18 a +9,26 | 82,66% | 98,58% | +15,92 | +15,78 a +15,92 |
| 39 features, divisão por grupos | 84,62% | 93,86% | +9,23 | +9,23 a +9,28 | 82,79% | 98,61% | +15,82 | +15,82 a +15,93 |
| 33 features, sorteio estratificado | 84,37% | 93,67% | +9,30 | +9,19 a +9,30 | 82,61% | 98,55% | +15,94 | +15,80 a +15,94 |
| 33 features, divisão por grupos | 84,36% | 93,67% | +9,31 | +9,26 a +9,31 | 82,70% | 98,58% | +15,88 | +15,88 a +15,89 |

Teto nas linhas de teste:

| Features e divisão | Teto, 8 | Teto, 7 | Diferença (p.p.) | Faixa da diferença nas 3 sementes (p.p.) |
|---|---|---|---|---|
| 39 features, sorteio estratificado | 98,82% | 99,96% | +1,13 | +1,08 a +1,13 |
| 39 features, divisão por grupos | 97,64% | 99,95% | +2,31 | +2,30 a +2,35 |
| 33 features, sorteio estratificado | 98,82% | 99,95% | +1,13 | +1,08 a +1,13 |
| 33 features, divisão por grupos | 97,64% | 99,95% | +2,31 | +2,30 a +2,35 |

Recall das duas categorias e peso das trocas entre elas. Em cada célula, o primeiro valor é na amostra
e o segundo é reponderado. "Trocas" são as linhas de DDoS classificadas como DoS e as de DoS
classificadas como DDoS. A penúltima coluna conta essas trocas como acerto no modelo de 8 categorias, e
a última é o modelo treinado com 7. Valores da semente 42.

| Features e divisão | Recall de DDoS, 8 categorias | Recall de DoS, 8 categorias | Recall de DDoS+DoS, 7 categorias | Trocas entre DDoS e DoS, como fração dos erros do modelo de 8 | Acurácia do modelo de 8 sem contar as trocas como erro | Acurácia do modelo de 7 |
|---|---|---|---|---|---|---|
| 39 features, sorteio estratificado | 90,74% e 87,50% | 65,61% e 59,88% | 99,98% e 99,99% | 60,0% e 91,8% | 93,83% e 98,59% | 93,81% e 98,58% |
| 39 features, divisão por grupos | 90,86% e 87,72% | 65,38% e 59,59% | 99,98% e 99,99% | 60,2% e 91,9% | 93,88% e 98,61% | 93,86% e 98,61% |
| 33 features, sorteio estratificado | 90,64% e 87,46% | 65,25% e 59,90% | 99,86% e 99,98% | 59,4% e 91,7% | 93,66% e 98,55% | 93,67% e 98,55% |
| 33 features, divisão por grupos | 90,82% e 87,75% | 64,63% e 59,08% | 99,85% e 99,98% | 59,5% e 91,8% | 93,66% e 98,58% | 93,67% e 98,58% |

Custo do modelo:

| Features e divisão | Modelo de 8 (MB) | Modelo de 7 (MB) | Nós por árvore, 8 | Nós por árvore, 7 | Treino de 8 (s) | Treino de 7 (s) |
|---|---|---|---|---|---|---|
| 39 features, sorteio estratificado | 2.275,7 | 1.252,0 | 177.787 | 104.327 | 20,8 | 17,5 |
| 39 features, divisão por grupos | 2.277,6 | 1.252,9 | 177.931 | 104.407 | 20,9 | 17,9 |
| 33 features, sorteio estratificado | 2.394,9 | 1.360,3 | 187.101 | 113.352 | 20,0 | 19,0 |
| 33 features, divisão por grupos | 2.397,0 | 1.359,4 | 187.263 | 113.278 | 19,9 | 18,9 |

- Acurácia, de 8 para 7 categorias, nas 12 comparações (4 pares de execuções, 3 sementes). Na amostra, a diferença vai de +9,18 a +9,31 p.p. e tem o mesmo sinal em todas as comparações; está muito acima do ruído de semente: a menor, de 9,18 p.p., é 114,6 vezes a maior variação de uma mesma execução entre sementes (0,08 p.p.). Reponderada, vai de +15,78 a +15,94 p.p. e tem o mesmo sinal em todas as comparações; está muito acima do ruído de semente: a menor, de 15,78 p.p., é 117,7 vezes a maior variação de uma mesma execução entre sementes (0,13 p.p.).
- O macro-F1 de 8 categorias e o de 7 são médias sobre conjuntos de classes diferentes e não se comparam
  diretamente. Os dois estão na tabela das execuções.
- Os tetos desta seção são os das linhas de teste de cada execução. No conjunto completo a diferença entre o teto de 8 e o de 7 categorias é bem maior do que a medida aqui: lá o teto de 8 categorias é 92,87% (`exploracao.md`, seção 8), e quase todo o erro mínimo está em linhas de DDoS e de DoS com o mesmo vetor, que a fusão deixa de contar como erro. O teto de 7 categorias do conjunto completo não foi calculado, e por isso essa diferença fica sem número aqui.
- Nenhum teto limita o recall de DoS: o recall de uma categoria depende da regra, e a regra do teto
  maximiza o acerto global.
- A terceira saída em análise, deixar o modelo dizer o tipo de flood e separar DDoS de DoS pela
  quantidade de origens no alerta, não é medida aqui: as 39 features não trazem endereços de origem.

### Priori de treino

O que muda das proporções da amostra para a proporção natural no treino, com as features, a divisão e o
alvo fixos. As duas execuções de cada par são avaliadas nas mesmas linhas de teste.

Tráfego benigno classificado como ataque, como fração das linhas benignas de teste. A medida é igual na
amostra e reponderada:

| Execução | Priori da amostra | Priori natural | Diferença (p.p.) | Faixa da diferença nas 3 sementes (p.p.) |
|---|---|---|---|---|
| `f39_estratificada_c8` | 46,18% | 14,43% | -31,75 | -32,32 a -31,71 |
| `f39_estratificada_c7` | 46,38% | 14,48% | -31,90 | -32,19 a -31,89 |
| `f33_estratificada_c8` | 46,78% | 14,14% | -32,64 | -32,64 a -32,05 |
| `f33_estratificada_c7` | 47,22% | 14,28% | -32,94 | -32,94 a -32,29 |
| `f39_estratificada_c34` | 33,17% | 10,22% | -22,95 | sem repetição |
| `f39_estratificada_c2` | 54,64% | 18,59% | -36,05 | sem repetição |

Ataque classificado como tráfego benigno, como fração das linhas de ataque de teste:

| Execução | Na amostra, priori da amostra | Na amostra, priori natural | Diferença (p.p.) | Faixa da diferença nas 3 sementes (p.p.) | Reponderada, priori da amostra | Reponderada, priori natural | Diferença (p.p.) | Faixa da diferença nas 3 sementes (p.p.) |
|---|---|---|---|---|---|---|---|---|
| `f39_estratificada_c8` | 1,27% | 5,03% | +3,75 | +3,75 a +3,78 | 0,10% | 0,41% | +0,31 | +0,31 a +0,31 |
| `f39_estratificada_c7` | 1,27% | 5,07% | +3,80 | +3,73 a +3,80 | 0,10% | 0,42% | +0,32 | +0,31 a +0,32 |
| `f33_estratificada_c8` | 1,27% | 5,17% | +3,90 | +3,81 a +3,90 | 0,10% | 0,43% | +0,32 | +0,32 a +0,32 |
| `f33_estratificada_c7` | 1,27% | 5,14% | +3,87 | +3,79 a +3,87 | 0,10% | 0,42% | +0,32 | +0,31 a +0,32 |
| `f39_estratificada_c34` | 2,59% | 6,97% | +4,38 | sem repetição | 0,21% | 0,58% | +0,37 | sem repetição |
| `f39_estratificada_c2` | 0,85% | 3,87% | +3,02 | sem repetição | 0,07% | 0,31% | +0,25 | sem repetição |

Acurácia:

| Execução | Na amostra, priori da amostra | Na amostra, priori natural | Diferença (p.p.) | Faixa da diferença nas 3 sementes (p.p.) | Reponderada, priori da amostra | Reponderada, priori natural | Diferença (p.p.) | Faixa da diferença nas 3 sementes (p.p.) |
|---|---|---|---|---|---|---|---|---|
| `f39_estratificada_c8` | 84,55% | 82,40% | -2,15 | -2,27 a -2,12 | 82,66% | 84,28% | +1,62 | +1,51 a +1,70 |
| `f39_estratificada_c7` | 93,81% | 92,07% | -1,74 | -1,76 a -1,72 | 98,58% | 99,10% | +0,52 | +0,52 a +0,53 |
| `f33_estratificada_c8` | 84,37% | 82,06% | -2,31 | -2,33 a -2,27 | 82,61% | 84,27% | +1,66 | +1,58 a +1,70 |
| `f33_estratificada_c7` | 93,67% | 91,82% | -1,84 | -1,85 a -1,81 | 98,55% | 99,08% | +0,53 | +0,52 a +0,53 |
| `f39_estratificada_c34` | 74,07% | 72,10% | -1,97 | sem repetição | 75,07% | 77,16% | +2,09 | sem repetição |
| `f39_estratificada_c2` | 97,06% | 95,56% | -1,50 | sem repetição | 98,66% | 99,26% | +0,60 | sem repetição |

Macro-F1:

| Execução | Na amostra, priori da amostra | Na amostra, priori natural | Diferença (p.p.) | Faixa da diferença nas 3 sementes (p.p.) | Reponderada, priori da amostra | Reponderada, priori natural | Diferença (p.p.) | Faixa da diferença nas 3 sementes (p.p.) |
|---|---|---|---|---|---|---|---|---|
| `f39_estratificada_c8` | 72,21% | 64,52% | -7,69 | -7,88 a -7,56 | 67,01% | 66,27% | -0,74 | -0,81 a -0,44 |
| `f39_estratificada_c7` | 74,11% | 65,99% | -8,12 | -8,29 a -8,12 | 69,96% | 69,75% | -0,21 | -0,32 a -0,16 |
| `f33_estratificada_c8` | 71,82% | 63,93% | -7,89 | -7,89 a -7,72 | 66,67% | 65,84% | -0,83 | -0,83 a -0,71 |
| `f33_estratificada_c7` | 73,89% | 65,65% | -8,24 | -8,38 a -8,24 | 69,87% | 69,50% | -0,37 | -0,42 a -0,35 |
| `f39_estratificada_c34` | 62,83% | 58,62% | -4,21 | sem repetição | 58,76% | 59,63% | +0,87 | sem repetição |
| `f39_estratificada_c2` | 76,49% | 78,19% | +1,70 | sem repetição | 80,27% | 91,66% | +11,39 | sem repetição |

Recall reponderado de cada classe nas execuções de 8 categorias, na semente 42:

| Classe | 39 features, priori da amostra | 39 features, priori natural | Diferença (p.p.) | 33 features, priori da amostra | 33 features, priori natural | Diferença (p.p.) |
|---|---|---|---|---|---|---|
| DDoS | 87,50% | 92,79% | +5,29 | 87,46% | 92,78% | +5,32 |
| DoS | 59,88% | 44,04% | -15,84 | 59,90% | 44,09% | -15,81 |
| Mirai | 99,66% | 99,73% | +0,07 | 99,61% | 99,65% | +0,04 |
| Recon | 92,61% | 79,12% | -13,49 | 92,49% | 78,46% | -14,04 |
| Spoofing | 86,33% | 85,43% | -0,90 | 86,33% | 85,34% | -0,99 |
| Web | 28,84% | 8,38% | -20,46 | 28,06% | 8,28% | -19,79 |
| BruteForce | 33,59% | 13,78% | -19,81 | 32,71% | 12,26% | -20,45 |
| Benign | 53,82% | 85,57% | +31,75 | 53,22% | 85,86% | +32,64 |

Recall reponderado de cada classe nas execuções de 7 categorias, na semente 42:

| Classe | 39 features, priori da amostra | 39 features, priori natural | Diferença (p.p.) | 33 features, priori da amostra | 33 features, priori natural | Diferença (p.p.) |
|---|---|---|---|---|---|---|
| DDoS+DoS | 99,99% | 99,99% | 0,00 | 99,98% | 99,97% | -0,01 |
| Mirai | 99,66% | 99,70% | +0,04 | 99,61% | 99,63% | +0,02 |
| Recon | 92,52% | 78,87% | -13,65 | 92,52% | 78,70% | -13,82 |
| Spoofing | 86,45% | 85,39% | -1,06 | 86,46% | 85,40% | -1,06 |
| Web | 28,34% | 8,49% | -19,85 | 28,25% | 8,42% | -19,83 |
| BruteForce | 33,55% | 12,98% | -20,57 | 32,91% | 12,26% | -20,65 |
| Benign | 53,62% | 85,52% | +31,90 | 52,78% | 85,72% | +32,94 |

- A taxa de tráfego benigno classificado como ataque e os recalls reponderados dependem da priori de treino. A reponderação corrige só a avaliação: o modelo treinado com as proporções da amostra continua com a priori da amostra.
- Com a priori da amostra, de 46,06% a 47,22% do tráfego benigno de teste é classificado como ataque nas execuções de 8 e de 7 categorias, contadas as 3 sementes. Com a priori natural, de 13,87% a 14,48%.
- Nas mesmas execuções, o ataque classificado como benigno, reponderado, é 0,10% com a priori da amostra e de 0,41% a 0,43% com a priori natural.
- O recall reponderado de Recon é de 92,16% a 92,61% com a priori da amostra e de 78,46% a 79,12% com a priori natural.
- Com a priori natural, cada árvore sorteia 1.030.783 linhas do treino, com reposição, na proporção do conjunto completo, e as categorias pequenas entram com poucas linhas: BruteForce com cerca de 287 linhas sorteadas, contra 10.018 linhas de treino na amostra; Web com cerca de 545 linhas sorteadas, contra 19.039 linhas de treino na amostra.
- O tamanho do modelo também muda com a priori, na semente 42: com 8 categorias, 2.275,7 e 2.394,9 MB com a priori da amostra e 1.258,8 e 1.294,5 MB com a priori natural; com 7 categorias, 1.252,0 e 1.360,3 MB com a priori da amostra e 274,8 e 305,6 MB com a priori natural. Os valores de cada alvo são os das execuções com 39 e com 33 features.
- Acurácia, da priori da amostra para a priori natural, nas 12 comparações (4 pares de execuções, 3 sementes). Na amostra, a diferença vai de -2,33 a -1,72 p.p. e tem o mesmo sinal em todas as comparações; está muito acima do ruído de semente: a menor, de 1,72 p.p., é 13,7 vezes a maior variação de uma mesma execução entre sementes (0,12 p.p.). Reponderada, vai de +0,52 a +1,70 p.p. e tem o mesmo sinal em todas as comparações; está acima do ruído de semente: a menor, de 0,52 p.p., é 2,9 vezes a maior variação de uma mesma execução entre sementes (0,18 p.p.).
- Macro-F1, da priori da amostra para a priori natural, nas 12 comparações (4 pares de execuções, 3 sementes). Na amostra, a diferença vai de -8,38 a -7,56 p.p. e tem o mesmo sinal em todas as comparações; está muito acima do ruído de semente: a menor, de 7,56 p.p., é 21,6 vezes a maior variação de uma mesma execução entre sementes (0,35 p.p.). Reponderada, vai de -0,83 a -0,16 p.p. e tem o mesmo sinal em todas as comparações; é pequena e consistente: a menor, de 0,16 p.p., não chega a 2 vezes a maior variação de uma mesma execução entre sementes (0,37 p.p.).
- A priori natural usada aqui é a proporção das classes no conjunto completo do dataset. A proporção do
  tráfego de uma rede em operação é outra e não é medida aqui.
- O relatório não recomenda nenhuma das duas. Os dois lados estão nas tabelas acima e, classe a classe, em
  "Resultados por classe".

## Como os números foram obtidos

- Comando: `python -m codigo.classificador.experimento`, a partir da raiz do repositório. Semente 42 na divisão e no modelo, e a grade repetida com as sementes 7 e 2026.
- Amostra: `dados/processed/amostra.csv.gz`, com SHA-256 do CSV descomprimido `f23c098dc10faf3f857a473f8c793fc2642098d9046f11cbc76d83e20e505b8f`, conferido com `manifesto_amostra.json` antes de treinar.
- Modelo: `RandomForestClassifier` do scikit-learn com os parâmetros padrão, 100 árvores, `n_jobs=-1` e sem `StandardScaler`. Não houve busca de hiperparâmetros.
- Priori de treino: sem pesos nas execuções com as proporções da amostra. Nas de proporção natural, o
  `sample_weight` de cada linha de treino é a contagem do rótulo no conjunto completo dividida pela
  contagem dele no treino, levada à média 1.
- As métricas saem da matriz de confusão de cada execução. As reponderadas usam a matriz que abre a
  classe real nos 34 rótulos (`matrizes_confusao/*_por_rotulo.csv`) e as contagens do conjunto completo.
- A média macro é sobre as classes do alvo. Os percentuais das tabelas são arredondados, e os valores
  completos estão em `manifesto_treino_exploratorio.json`.
- `metricas_classificador.csv` tem uma linha por execução, distribuição e classe. A distribuição `amostra` é a medida
  nas linhas de teste, e `original` é a reponderada.
- `metricas_classificador.csv`, `importancia_features.csv` e as matrizes trazem as execuções da semente 42. As
  repetições com as outras sementes estão em `manifesto_treino_exploratorio.json`, com as mesmas medidas.
- Com a mesma amostra e as mesmas sementes, `metricas_classificador.csv`, `importancia_features.csv` e as matrizes saem idênticos.
  As medidas de tempo mudam a cada execução.

# Roadmap: decisões do projeto

Registro das decisões importantes do TCC II: escopo, método, dados e prazos, com data e motivo.
O andamento das tarefas fica no painel de acompanhamento, não aqui. Mudança que é apenas de
tarefa (criar, reescrever, atribuir) não entra neste arquivo.

## Fases do cronograma

| Fase | Período | Foco |
|---|---|---|
| F0 — Fundação & Setup | até 31/08/2026 | GitHub, cadastro no Oriente, ambiente, datasets |
| F1 — Dados & Classificador | 01–20/09/2026 | requerimento no Portal, pré-processamento, features, treino e tuning do RF |
| F2 — Camada MCP + Agentes | 21/09–18/10/2026 | servidor MCP, sistema multiagente, testes de segurança do MCP |
| F3 — PoC end-to-end | 12–26/10/2026 | cenários de ataque, comparação isolado vs. integrado, métricas |
| F4 — Redação & Entrega | contínuo até 09/11/2026 | artigo, revisão do orientador, avaliadores, submissão |
| F5 — Banca & Fechamento | 10/11–07/12/2026 | slides, defesa, correções, entrega final |

Os períodos das fases 1 a 3 estão em revisão desde 04/10/2026 (ver "Decisões em aberto"). As
datas do edital, na Fase 4 e na Fase 5, não mudam.

## Decisões em aberto

| Desde | O que falta decidir | Saídas em análise |
|---|---|---|
| 2026-10-04 | **Novo calendário das fases 1 a 3.** A Fase 1 começou com atraso e a data de congelamento dos resultados deixou de valer | A equipe refaz os períodos, mantendo a submissão em 03–09/11 |
| 2026-10-04 | **DDoS e DoS com features idênticas.** No `MERGED_CSV`, 29,5% das linhas têm as 39 features iguais às de uma linha de outra categoria, quase sempre o mesmo flood rotulado como DDoS e como DoS. No conjunto completo e na proporção natural das classes, a coincidência exata de vetores limita o acerto em 8 categorias a 92,9%. Na regra que atinge esse acerto, o recall de DoS é de 69,0% e o de DDoS, 97,5% (`experimentos/resultados/exploracao.md`) | Manter as 8 categorias e declarar o teto, fundir DDoS e DoS numa categoria, ou deixar o modelo dizer o tipo de flood e separar DDoS de DoS pela quantidade de origens no alerta. Essa terceira saída é a preferida até aqui: o extrator já precisa guardar os endereços de origem para a resposta saber o que bloquear |
| 2026-10-04 | **Cópia local do dataset incompleta.** Nove arquivos do `MERGED_CSV` e três CSVs de `DoS-UDP_Flood` terminam no meio de uma linha, o que tira cerca de 4% das linhas, de forma parecida em todas as classes | Baixar esses arquivos de novo da fonte oficial e refazer a amostra e a exploração. Os números atuais valem como provisórios |
| 2026-10-04 | **Ferramenta de captura da rede** | Wireshark ou ferramenta equivalente. A captura gera o arquivo pcap que o extrator lê |
| 2026-10-03 | **Janela de 10 ou de 100 pacotes.** O dataset agrega em janelas de 100 nas classes de DDoS, DoS e Mirai e de 10 nas demais. A coluna `Number` sozinha separa os dois grupos, e na operação o extrator usa uma janela só | Retirar as colunas que dependem da janela e medir o atalho que sobra, uniformizar a janela ou declarar a limitação. Descritas em `dados/README.md`. Precisa sair antes do treino |
| 2026-10-03 | **Divisão entre treino e teste.** O `MERGED_CSV` vem embaralhado, sem o arquivo de origem de cada linha, e linhas vizinhas do mesmo pcap são correlacionadas. Além disso, 58,8% das linhas repetem as 39 features de outra linha, então sortear linhas põe exemplos idênticos no treino e no teste e infla o resultado | Retirar as linhas repetidas antes de dividir, dividir pelos CSVs por ataque, que preservam o arquivo, ou repetir a divisão aleatória dos autores e declarar a limitação |
| 2026-09-04 | **Dataset secundário.** O N-BaIoT deixou de ser o assumido | Bot-IoT e ToN-IoT, a avaliar quanto a exfiltração, pcap disponível e compatibilidade de features |
| 2026-09-03 | **Quarto cenário da PoC.** O CICIoT2023 não tem classe de exfiltração de dados, e a PoC promete esse cenário. Decisão com o orientador | Trocar o cenário por backdoor ou acesso não autorizado, coberto pela categoria Web-based, ou trazer o ToN-IoT para cobrir exfiltração |

## Decisões tomadas

| Data | Decisão | Motivo |
|---|---|---|
| 2026-10-04 | **Os agentes recebem o resumo do incidente, não o CSV.** O detalhe vem por tool, em fatias de até 20 janelas | Um flood gera milhares de linhas por minuto. Mandar tudo para a LLM custaria tokens demais, que é o risco de Denial of Wallet, e pioraria a resposta |
| 2026-10-04 | **A autonomia do executor é graduada pelo risco, e o catálogo de ações é uma base, não uma lista fechada.** Ação de risco baixo é executada sem aprovação. Ação de risco alto e toda ação nova, proposta pelo agente fora do catálogo, dependem de aprovação humana | O agente precisa de liberdade para pesquisar e propor outra saída quando a base não resolve. A aprovação humana do que é novo mantém o controle sobre o que o sistema aplica na rede |
| 2026-10-04 | **Os três agentes são triagem, decisão e execução.** O agente de triagem substitui o que era chamado de agente de detecção | Quem detecta é o Random Forest. O primeiro agente interpreta o alerta: confere a coerência, estima a gravidade e agrupa alertas do mesmo ataque |
| 2026-10-04 | **Na PoC, a resposta é executada de forma simulada, com aprovação humana e possibilidade de desfazer** | Mostra o fluxo completo de detecção e resposta sem depender de montar uma rede real em um mês. Se os impedimentos forem muitos, o foco pode mudar |
| 2026-10-04 | **O sistema terá uma interface web em `frontend/`,** que lê um log de eventos de formato fixo gravado pelo backend, com modo ao vivo e replay de uma execução gravada | O replay protege a demonstração na banca, porque não depende de internet nem da resposta da LLM na hora. O contador de janelas, incidentes e chamadas à LLM responde à pergunta sobre custo de tokens |
| 2026-10-04 | **A amostra de treino guarda todas as linhas das classes raras e até 50.000 das demais, com semente fixa (42).** São 1.288.479 linhas, registradas em `experimentos/resultados/manifesto_amostra.json` | As 45 milhões de linhas não cabem na memória, e o teto por classe reduz o desbalanceamento. Com semente e manifesto, a amostra pode ser refeita e conferida |
| 2026-10-04 | **A pasta do grupo no Google Drive deixa de ser usada.** Os dados vêm da fonte oficial, e cada pessoa baixa só o que a sua tarefa pede | O conjunto é pesado demais para manter no Drive |
| 2026-10-04 | **A data de congelamento dos resultados, prevista para 17/10, deixa de valer** | O extrator ficou pronto em 03/10 e o classificador ainda não foi treinado. Manter a data como referência não era realista |
| 2026-10-04 | **A captura continua prevista com ferramenta de rede; o `dpkt` substitui o Scapy só na extração das features** | O código dos autores do dataset lê os pacotes com `dpkt`. Reproduzi-lo é o que permite conferir os números contra o CSV oficial |
| 2026-10-03 | **O extrator lê arquivo pcap e reproduz o cálculo dos autores do dataset.** A captura em interface ao vivo fica para depois, como um adaptador sobre o mesmo núcleo | Captura ao vivo exige rede de teste e não pode ser conferida contra o CSV oficial. Na calibração, o extrator reproduziu todas as linhas dos cinco pcaps conferidos, nas 39 colunas, com janela de 10 e com janela de 100 (DDoS, DoS e Mirai) (`experimentos/resultados/calibracao.md`) |
| 2026-10-03 | **O treino parte do `MERGED_CSV`, que já traz a coluna `Label`** | Rotular pelo nome da pasta deixou de ser necessário. Resta normalizar a grafia dos rótulos |
| 2026-09-04 | **Classificar em 8 categorias, não nas 34 variantes** | O F1 cai muito com 34 classes, e os agentes não precisam da variante exata: a mitigação de um `DDoS-ICMP_Flood` e a de um `DDoS-UDP_Flood` são a mesma |
| 2026-09-04 | **Reproduzir o baseline publicado do Random Forest (Neto et al., 2023), sem investir semanas no classificador** | O benchmark dos autores já mostra o RF entre os dois melhores modelos. A contribuição do trabalho é a camada MCP com agentes |
| 2026-09-04 | **Relatar recall, precisão e F1 por classe e macro-F1, nunca só acurácia** | DDoS e DoS somam cerca de 89% das linhas, e a razão entre a maior e a menor classe passa de 5.000 para 1. Com esse desbalanceamento, a acurácia global fica alta mesmo com erro nas classes raras |
| 2026-09-04 | **Justificar o Random Forest também pela explicabilidade** | O RF permite saber quais features pesaram na decisão, e isso dá aos agentes material para a recomendação. Uma rede neural entregaria só rótulo e confiança |
| 2026-09-04 | **O N-BaIoT deixa de ser o dataset secundário assumido** | Cobre só Mirai e BASHLITE, não tem exfiltração, usa 115 features incompatíveis com as 39 e não distribui pcap |
| 2026-09-03 | **Treino e operação usam as mesmas 39 features do `MERGED_CSV`, calculadas pelo mesmo extrator** | Evita descompasso entre o que o modelo vê no treino e o que recebe na operação. A versão de 46 features foi descartada porque as 7 extras não saem do código publicado pelos autores |
| 2026-09-03 | **O sistema processa tráfego bruto (pcap), não apenas o CSV pré-processado** | Responde ao avaliador 2 do TCC I e torna real a camada de captura da arquitetura. Os pcaps vêm com o CICIoT2023, o que permite calibrar o extrator. Captura in loco foi descartada: inviável no prazo e sem rótulos |
| 2026-09-03 | **O artigo trata dos pontos pedidos pela banca do TCC I:** riscos de IA em nuvem, custo de tokens e alternativa on-premises; limites de NetFlow frente a pcap; e menção curta a Darktrace, Netskope, Vectra AI e Denial of Wallet | Recomendações da banca do TCC I |
| 2026-09-03 | **Projeto reposicionado de NIDS para NIDR (detecção e resposta), com arquitetura multiagente** | Recomendação da banca do TCC I, avaliadores 1 e 2 |
| 2026-09-03 | **O repositório SentryIoT é o local oficial do trabalho:** código, artigo, experimentos e reports | Separar o trabalho do painel de acompanhamento |

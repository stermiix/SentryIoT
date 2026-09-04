# Roadmap — ligação e histórico de mudanças

O painel de acompanhamento do TCC II fica no app em `../app/` (Node + Turso), compartilhado com a
equipe e o orientador. As tarefas vivem no banco Turso e só são editadas pela interface do painel.

Este arquivo é a ponte: tudo que acontece no repositório e muda o plano é anotado aqui primeiro,
com a ação correspondente no painel, e só depois aplicado na interface.

## Fases do cronograma (realinhado ao edital)

| Fase | Período | Foco |
|---|---|---|
| F0 — Fundação & Setup | até 31/08/2026 | GitHub, cadastro no Oriente, ambiente, datasets |
| F1 — Dados & Classificador | 01–20/09/2026 | requerimento no Portal, pré-processamento, features, treino e tuning do RF |
| F2 — Camada MCP + Agentes | 21/09–18/10/2026 | servidor MCP, sistema multiagente, testes de segurança do MCP |
| F3 — PoC end-to-end | 12–26/10/2026 | cenários de ataque, comparação isolado vs. integrado, métricas |
| F4 — Redação & Entrega | contínuo até 09/11/2026 | artigo, revisão do orientador, avaliadores, submissão |
| F5 — Banca & Fechamento | 10/11–07/12/2026 | slides, defesa, correções, entrega final |

## Como registrar uma mudança

Adicione uma linha no topo do histórico, com data, o que mudou, o motivo e a ação no painel.
Estado: `pendente` enquanto não foi aplicado na interface, `aplicado` depois.

| Data | Mudança | Motivo | Ação no painel | Estado |
|---|---|---|---|---|
| 2026-09-04 | **Classificar em 8 classes (categorias), não em 34 variantes** | O F1 cai muito com 34 classes; e os agentes não precisam da variante exata — a mitigação de um `DDoS-ICMP_Flood` e de um `DDoS-UDP_Flood` é a mesma. A categoria já basta para recomendar ação | Ajustar o texto da tarefa de treino da Fase 1 para explicitar 8 classes | pendente |
| 2026-09-04 | **Não investir semanas no classificador** — reproduzir o baseline publicado e seguir | Os autores do CICIoT2023 já publicaram o benchmark: RF ficou entre os dois melhores (com DNN). O classificador é problema resolvido; a contribuição do trabalho é a camada MCP + agentes. Reproduzir e citar Neto et al. (2023) na metodologia, deixando explícito o que é nosso | Reduzir a tarefa de grid search da Fase 1 de semanas para dias; realocar o tempo para a métrica da camada de agentes | pendente |
| 2026-09-04 | **Acrescentar o argumento da explicabilidade à justificativa do Random Forest** | Hoje o artigo defende o RF só por custo computacional. O argumento mais forte é outro: o RF permite saber *quais features pesaram* na decisão, e isso alimenta a camada de agentes com material para a recomendação ("flood: 36.847 pacotes/s, 100% ICMP, pacotes de 60 bytes"). Uma rede neural entregaria só rótulo e confiança. Fecha o argumento da "caixa-preta" levantado no referencial teórico | Criar tarefa na Fase 4: "Reescrever a justificativa da escolha do Random Forest incluindo explicabilidade e importância de features" | pendente |
| 2026-09-04 | Métricas: **relatar recall por classe, nunca só acurácia** | 78% do dataset é DDoS/DoS — um modelo que respondesse "DDoS" para tudo acertaria 78%. No benchmark dos autores a acurácia é alta mas o F1 fica em ~70% com 8 classes, o que revela erro nas classes raras (brute force: 319 amostras) | Refletir isso na tarefa de consolidação de métricas da Fase 3 | pendente |
| 2026-09-03 | Tarefa nova — **extrator de features com Scapy** sobre os PCAPs do CICIoT2023 | Peça que faltava entre a captura e o modelo: o classificador lê números, a rede entrega pacotes | Criar na Fase 1: "Implementar o extrator de features com Scapy sobre os PCAPs do CICIoT2023" | pendente |
| 2026-09-03 | Tarefa nova — **calibração do extrator** contra o CSV oficial | Prova de que o extrator funciona: mesmos pacotes devem gerar os mesmos números que os autores do dataset calcularam | Criar na Fase 1: "Calibrar o extrator comparando as features calculadas com o CSV oficial do CICIoT2023" | pendente |
| 2026-09-03 | Tarefa nova — **subconjunto de features reproduzíveis + retreino** | Em vez de reproduzir as 46 features, usar só as que o extrator calcula com segurança e retreinar o RF sobre elas: o mesmo código roda no treino e na execução, sem descompasso | Criar na Fase 1: "Definir o subconjunto de features reproduzíveis e retreinar o Random Forest apenas com elas" | pendente |
| 2026-09-03 | **Lacuna de exfiltração:** o CICIoT2023 não tem classe de exfiltração de dados, e a cobertura de brute force é de apenas 1 variante. A PoC promete 4 cenários e o dataset cobre 3, sendo 1 deles fraco | Verificado na taxonomia oficial (7 categorias, 33 ataques): DDoS, DoS, Recon, Web-based, Brute Force, Spoofing, Mirai — nenhuma de exfiltração. Um modelo não aprende a detectar um ataque do qual não tem exemplo | **Decisão com o orientador antes de codar.** Duas saídas: (a) trocar o 4º cenário por "backdoor / acesso não autorizado", coberto em Web-based; (b) trazer o ToN-IoT como secundário para cobrir exfiltração. Depois, ajustar o texto das tarefas da Fase 3 que citam "exfiltração de dados" | pendente |
| 2026-09-03 | Repositório `SentryIoT` criado e adotado como local oficial do trabalho (código, artigo, experimentos, reports) | Separar o trabalho do painel de acompanhamento | Marcar a tarefa "Criar repositório no GitHub (estrutura de pastas + README)" da Fase 0 como concluída, com responsável e semana | pendente |
| 2026-09-03 | Projeto reposicionado de NIDS para **NIDR** (detecção e resposta), com arquitetura **multiagente** | Recomendação da banca do TCC I (avaliadores 1 e 2) | Ajustar o texto das tarefas das fases 2 e 4 que ainda falam em "agente LLM"/"NIDS" para o enquadramento NIDR multiagente | pendente |
| 2026-09-03 | **DECIDIDO — Opção B:** o sistema processa tráfego bruto (PCAP), não apenas o CSV pré-processado. Descartadas a opção A (só CSV, deixaria Scapy/Wireshark sem função) e a C (captura in loco, inviável no prazo e sem rótulos) | Responde ao avaliador 2 com evidência e torna a camada de captura da Figura 1 real. Os PCAPs vêm junto com o CICIoT2023, o que permite calibrar o extrator contra o CSV oficial | Substituída pelas 3 tarefas novas da Fase 1 abaixo | aplicado |
| 2026-09-03 | Tópicos obrigatórios acrescentados ao artigo: riscos de IA em nuvem, custo de tokens e alternativa on-premises; limites de NetFlow vs. PCAP; Darktrace, Netskope, Vectra AI e Denial of Wallet | Recomendações da banca do TCC I | Criar tarefa na Fase 4: "Endereçar no artigo os pontos da banca (IA on-prem/tokens, NetFlow vs. PCAP, Darktrace/Netskope/Vectra, DoW)" | pendente |

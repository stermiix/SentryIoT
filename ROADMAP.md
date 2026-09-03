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
| 2026-09-03 | **Lacuna de exfiltração:** o CICIoT2023 não tem classe de exfiltração de dados, e a cobertura de brute force é de apenas 1 variante. A PoC promete 4 cenários e o dataset cobre 3, sendo 1 deles fraco | Verificado na taxonomia oficial (7 categorias, 33 ataques): DDoS, DoS, Recon, Web-based, Brute Force, Spoofing, Mirai — nenhuma de exfiltração. Um modelo não aprende a detectar um ataque do qual não tem exemplo | **Decisão com o orientador antes de codar.** Duas saídas: (a) trocar o 4º cenário por "backdoor / acesso não autorizado", coberto em Web-based; (b) trazer o ToN-IoT como secundário para cobrir exfiltração. Depois, ajustar o texto das tarefas da Fase 3 que citam "exfiltração de dados" | pendente |
| 2026-09-03 | Repositório `SentryIoT` criado e adotado como local oficial do trabalho (código, artigo, experimentos, reports) | Separar o trabalho do painel de acompanhamento | Marcar a tarefa "Criar repositório no GitHub (estrutura de pastas + README)" da Fase 0 como concluída, com responsável e semana | pendente |
| 2026-09-03 | Projeto reposicionado de NIDS para **NIDR** (detecção e resposta), com arquitetura **multiagente** | Recomendação da banca do TCC I (avaliadores 1 e 2) | Ajustar o texto das tarefas das fases 2 e 4 que ainda falam em "agente LLM"/"NIDS" para o enquadramento NIDR multiagente | pendente |
| 2026-09-03 | Ponto em aberto: definir se haverá **captura in loco** de tráfego IoT real ou apenas datasets — e, com isso, o papel de Scapy e Wireshark | Questionamento direto do avaliador 2; decide o conteúdo da Fase 1 e do artigo | Criar tarefa na Fase 1: "Decidir e documentar o escopo de captura (dataset vs. coleta in loco) e o papel de Scapy/Wireshark" | pendente |
| 2026-09-03 | Tópicos obrigatórios acrescentados ao artigo: riscos de IA em nuvem, custo de tokens e alternativa on-premises; limites de NetFlow vs. PCAP; Darktrace, Netskope, Vectra AI e Denial of Wallet | Recomendações da banca do TCC I | Criar tarefa na Fase 4: "Endereçar no artigo os pontos da banca (IA on-prem/tokens, NetFlow vs. PCAP, Darktrace/Netskope/Vectra, DoW)" | pendente |

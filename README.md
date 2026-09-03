# SentryIoT - MultiAgent NIDR

Sistema de detecção e resposta a intrusões (NIDR) em redes IoT, combinando classificação por Random Forest com um sistema multiagente LLM integrado via MCP.

TCC II — FCI Mackenzie, 2º semestre de 2026.
Equipe: Bernardo Souza Oliveira, Matheus Queiroz Gregorin, José Victor Roling e Pedro Henrique Cagnoni Guimarães.
Orientador: Prof. Rodrigo Cardoso Silva.

## Ideia

Um classificador Random Forest detecta anomalias no tráfego de rede IoT (datasets CICIoT2023 e
N-BaIoT). As predições são expostas por um **servidor MCP** e consumidas por um **sistema
multiagente LLM**, que correlaciona os alertas com vulnerabilidades conhecidas e devolve
recomendações de mitigação acionáveis — indo além da detecção, para a resposta.

A PoC cobre DDoS, port scan, brute force e exfiltração de dados, comparando a saída isolada do
classificador com a saída integrada (MCP + agentes) por acurácia, precisão, recall, F1-score e
taxa de falso positivo.

## Estrutura

| Pasta | Conteúdo |
|---|---|
| `artigo/` | texto do artigo (10–20 pág, template do Oriente) e figuras |
| `codigo/captura/` | coleta e parsing de tráfego (Scapy, PCAP) |
| `codigo/classificador/` | pré-processamento, features, treino e tuning do Random Forest |
| `codigo/mcp/` | servidor MCP que expõe as predições como tools |
| `codigo/agente/` | sistema multiagente LLM (loop ReAct, prompts) |
| `dados/` | datasets originais e tratados (não versionados) |
| `experimentos/` | notebooks de exploração e resultados/métricas |
| `referencias/` | bibliografia e material de apoio |
| `reports/` | reports semanais para o orientador (toda segunda-feira) |

## Documentos de apoio

- **`CLAUDE.md`** — contexto completo: escopo, correções da banca do TCC I, prazos do edital e
  regras de trabalho.
- **`ROADMAP.md`** — ligação com o painel de acompanhamento e histórico das mudanças de plano.

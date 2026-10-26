# Escolha do modelo local: qwen3.8-27b contra qwen3.8-27c

Teste de 25/10/2026, que decidiu o modelo local dos agentes (`ROADMAP.md`, decisão de 25/10). Os
dois modelos são servidos pelo mesmo servidor de inferência numa rede interna, compatível com a
API da OpenAI: o `qwen3.8-27b` é o Qwen3.8-27B normal, o mesmo publicado para o Ollama, e o
`qwen3.8-27c` é uma variante sem censura do mesmo modelo, cujo nome exato a equipe não conhece. O
servidor não mostra mais nada sobre eles: a lista de modelos traz só os nomes, os dois respondem
com a mesma identificação de versão, e a quantização não aparece.

## Como o teste foi feito

- Cada rodada subiu o servidor MCP em modo de reprodução (`python -m codigo.mcp.stub --cenarios`)
  sobre uma cópia do log do reprodutor e rodou um laço ReAct mínimo até a resposta final, com teto
  de 8 passos na triagem e 10 na decisão. O laço e o script do teste ficaram fora do repositório:
  dependem do servidor de inferência interno, e o laço dos agentes do sistema é a tarefa 44.
- Os parâmetros foram os do sistema: raciocínio desligado, temperatura 0, semente 7 e 2.048 tokens
  de saída, trocando só o modelo. Os dois modelos foram aquecidos com uma chamada descartada, e as
  rodadas correram em sequência.
- Os incidentes saíram do reprodutor em `DDoS-SYN_Flood1`, `Recon-PortScan`, `DictionaryBruteForce`,
  `XSS` e `BenignTraffic2`, mais o incidente de Spoofing aberto por 5.000 quadros do Wi-Fi de um
  notebook.
- **Triagem:** 12 incidentes × 2 modelos × 3 repetições. O certo é "coerente" quando a categoria do
  incidente é a do pcap e "duvidoso" ou "ruído" nos outros casos: 7 verdadeiros e 5 falsos.
- **Decisão, na configuração tudo local:** 9 incidentes, 3 por cenário, × 2 × 3, corrigidos pelo
  rascunho do gabarito da recomendação (`experimentos/gabarito_da_recomendacao.toml`, em revisão no
  PR 48), com a ação e o papel do alvo.

## Resultados

### Triagem

| Métrica | qwen3.8-27b | qwen3.8-27c |
|---|---|---|
| Acerto do rótulo | 15 de 36 (42%) | 24 de 36 (67%) |
| Nos incidentes verdadeiros | 6 de 21 | 21 de 21 |
| Nos incidentes falsos | 9 de 15 | 3 de 15 |
| Rodadas que pararam no teto de passos, sem rótulo | 18 de 36 | 0 de 36 |
| Tokens de entrada por rodada, mediana (p95) | 47.482 (241.737) | 17.248 (40.856) |
| Tempo por rodada, mediana (p95) | 26,2 s (56,3 s) | 17,2 s (25,3 s) |
| Erros de formato ou de tool | 0 em 183 chamadas | 0 em 89 chamadas |

O 27b entra em laço em 6 dos 12 incidentes, sempre nas 3 repetições: repete a mesma chamada de
`obter_janelas` com os mesmos argumentos até o teto. Quando responde, é o mais desconfiado dos dois.
O 27c sempre responde, mas aceitou como coerentes quase todos os falsos, inclusive o Spoofing do
notebook, com confiança 0,54.

### Decisão, na configuração tudo local

| Métrica | qwen3.8-27b | qwen3.8-27c |
|---|---|---|
| Proposta certa pelo gabarito | 27 de 27 | 27 de 27 |
| Ações propostas | `bloquear_ip` na origem 14, `limitar_taxa` no destino 9, `limitar_taxa` na origem 4 | `bloquear_ip` na origem 27 |
| Tokens de entrada por rodada, mediana | 21.112 | 21.113 |
| Tempo por rodada, mediana | 24,2 s | 26,2 s |
| Erros de formato ou de tool | 0 em 79 chamadas | 0 em 93 chamadas |

A bateria não separa os modelos, porque o gabarito aceita mais de uma ação por categoria. O 27c
sempre propõe bloquear a origem, que nesse dataset é sempre de risco alto, porque os atacantes estão
na rede local: toda proposta dele passa pela aprovação. O 27b limita a taxa em 13 de 27, e essa
ação roda sem aprovação.

Nenhuma das 126 rodadas teve letra fora do alfabeto latino no texto em português.

## Decisão

O modelo local é o `qwen3.8-27c`. Ele sempre chega a uma resposta, gasta cerca de um terço dos
tokens do 27b na triagem, é mais rápido e empata na decisão. A fraqueza dele, aceitar quase todo
alarme falso, motivou o limiar de confiança da triagem (`limiar_da_triagem.md`): com confiança
abaixo de 0,6, o veredito é duvidoso.

## Limitações do teste

- São poucos casos: 12 incidentes de triagem e 9 de decisão, de 5 pcaps e de uma captura.
- Com temperatura 0 e semente fixa, as repetições saíram iguais, salvo um caso de decisão do 27b:
  medem estabilidade, não variância.
- O gabarito da triagem pelo pcap pode ser contestado: um incidente "falso" pode ter janelas que de
  fato parecem da categoria.
- O laço ReAct do teste é o mínimo. Um laço que impeça a repetição da mesma chamada pode mudar os
  números do 27b, e vale repetir o teste quando o laço do sistema existir.
- A variante exata do 27c é desconhecida. Quem repetir o trabalho com o Qwen normal, o do Ollama,
  deve esperar o comportamento do 27b.

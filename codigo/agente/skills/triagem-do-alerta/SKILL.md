---
name: triagem-do-alerta
description: Primeira análise de um incidente aberto pelo classificador, antes de qualquer proposta de ação. Usar sempre que um incidente novo aparece no log de eventos (evento `incidente_aberto`), para decidir se a confiança do classificador é suficiente e se o incidente é coerente antes de passar ao agente de decisão.
---

# Triagem do alerta

Skill do agente de **triagem** (ver `codigo/mcp/README.md`, seção "Tools": `obter_incidente` e
`obter_janelas`). Este agente não propõe nem executa ação; a saída dele é o insumo do agente de
decisão.

## Onde roda e o que sai daqui

O agente de triagem roda sempre no modelo local (arquitetura híbrida, `ROADMAP.md`, decisão de
2026-10-10): é o único, além do de execução, que vê os endereços do incidente. O agente de decisão
pode estar num modelo de nuvem e não recebe endereço nenhum. Ele lê os números do incidente por
conta própria, em `obter_resumo`, que o servidor monta com os endereços trocados por rótulos
neutros (`origem-1`, `destino-1`). Da triagem ele recebe só o veredito.

Por isso a saída da triagem não cita endereço. Quando precisar falar de um, use o papel e a ordem
("a origem com mais quadros", "o único destino"): o resumo do agente de decisão traz as mesmas
listas, na mesma ordem, com os rótulos. Nunca escreva "o IP 192.168.1.20".

Quem avisa a pessoa que opera a rede é o servidor, no instante em que o incidente abre, com a
categoria e a confiança do classificador. A triagem não avisa ninguém e não espera resposta. Se a
pessoa marcar o incidente como já resolvido, o servidor deixa de aceitar propostas e execuções
dele; a triagem segue igual.

## Quando usar

- Um incidente novo abre no log (`estado: "aberto"`), antes de qualquer `propor_acao`.
- Reavaliação: quando o agente de decisão pede uma segunda olhada (ex.: justificativa
  insuficiente para a mitigação escolhida).

## O que a tool MCP devolve

- `obter_incidente(id)`: `categoria`, `categoria_do_modelo`, `confianca`, `inicio`, `fim`,
  `janelas`, `origens_distintas`, `distribuido`, `origens`, `destinos` e `features_principais`,
  cada uma com `nome`, `valor` e `referencia_benigno` (o valor típico no tráfego benigno).
- `obter_janelas(id, limite)`: até 20 janelas de detalhe, cada uma com `categoria_do_modelo`,
  `confianca`, `origem`, `destino` e as 39 features. Usar só quando o resumo não bastar.
  Cada janela tem 100 quadros (decisão de 2026-10-10): um flood enche uma janela em
  milissegundos, uma varredura em menos de um segundo, e força bruta ou ataque Web em alguns
  segundos. Poucas janelas num incidente lento não significam ruído por si só.

## Passo a passo

1. Chamar `obter_incidente(id)`.
2. Conferir coerência. O modelo do sistema não separa DDoS de DoS: `categoria_do_modelo` vem como
   `DDoS+DoS`, e `categoria` é o resultado da regra que separa os dois pela quantidade de origens.
   A diferença entre os dois campos nesse caso é esperada. Olhar `distribuido` e
   `origens_distintas` para confirmar se batem com a categoria (ex.: DDoS com uma origem só é
   suspeito).
3. Olhar `confianca`. **Com confiança abaixo de 0,6, o rótulo é duvidoso**, qualquer que seja a
   quantidade de janelas e o que as janelas mostrem (decisão de 2026-10-25). Nos 235 incidentes da
   avaliação dos 38 pcaps, esse limiar pegou 24 dos 57 alarmes falsos e marcou como duvidosos só
   4 dos 178 ataques verdadeiros (`experimentos/resultados/limiar_da_triagem.md`). Com confiança
   de 0,6 ou mais, mas categoria e confiança inconsistentes com `origens_distintas`, chamar
   `obter_janelas(id, 20)` e conferir se a maioria das janelas concorda com o resumo.
4. Decidir o rótulo da triagem: **coerente** (segue para o agente de decisão), **duvidoso**
   (confiança abaixo de 0,6 ou incoerência; ver o cenário `inc-0004` em `codigo/mcp/README.md`,
   falso positivo de uma câmera enviando vídeo) ou **ruído** (poucas janelas, sem padrão).

A triagem olha um incidente por vez. Juntar incidentes do mesmo ataque não é tarefa dela: não há
tool que liste os incidentes, e quem agrupa alertas é a política de acionamento, no orquestrador,
antes de abrir o incidente.

## Formato da resposta

Um veredito curto e estruturado para o agente de decisão, sem endereço e nunca o JSON bruto das
janelas:

```
Incidente: <id>
Categoria: <categoria> (confiança <confianca>)
Rótulo da triagem: coerente | duvidoso | ruído
Por quê: <uma frase, citando o que confirmou ou gerou a dúvida, sem endereço>
Origens distintas: <n>  |  Distribuído: sim/não
Features que mais chamam atenção: <até 3, com valor e referência do tráfego benigno>
```

Web e BruteForce são as categorias em que o classificador mais erra (recall abaixo de 40% nos
dados regerados, confundidas com Recon e com tráfego benigno,
`experimentos/resultados/regeracao.md`). Um incidente dessas categorias com confiança média pede
a conferência pelas janelas antes de receber o rótulo coerente.

Quando o rótulo é **duvidoso**, a resposta diz que nenhuma ação de risco alto deve ser proposta
sem reforçar a justificativa. O servidor já exige aprovação humana nesses casos; a triagem só
evita que o agente de decisão trate o caso como óbvio.

---
name: triagem-do-alerta
description: Primeira análise de um incidente aberto pelo classificador, antes de qualquer proposta de ação. Usar sempre que um incidente novo aparece no log de eventos (evento `incidente_aberto`), para decidir se a confiança do classificador é suficiente e se o incidente é coerente, agrupando alertas do mesmo ataque antes de passar ao agente de decisão.
---

# Triagem do alerta

Skill do agente de **triagem** (ver `codigo/mcp/README.md`, seção "Tools" — tools `obter_incidente`
e `obter_janelas`). Este agente não propõe nem executa ação; a saída dele é o insumo do agente de
decisão.

## Onde roda e o que sai daqui

O agente de triagem roda sempre no modelo local (arquitetura híbrida, `ROADMAP.md`, decisão de
2026-10-10): é ele que vê endereços e nomes de dispositivo. O resumo que ele produz é o único
material que o agente de decisão recebe, e esse agente pode estar num modelo de nuvem. Por isso o
orquestrador troca, no resumo, cada endereço e nome de dispositivo por um rótulo neutro
(`origem-1`, `destino-1`, `dispositivo-3`), antes de entregá-lo. O resumo precisa fazer sentido
sem os endereços: contagens, categoria, confiança e features, nunca "o IP 192.168.1.20".

Quem avisa a pessoa que opera a rede é o servidor, no instante em que o incidente abre, com a
categoria e a confiança do classificador. A triagem não avisa ninguém e não espera resposta: se a
pessoa marcar o incidente como já resolvido na interface, quem lê essa marca é o agente de
execução, antes de aplicar qualquer ação.

## Quando usar

- Um incidente novo abre no log (`estado: "aberto"`), antes de qualquer `propor_acao`.
- Reavaliação: quando o agente de decisão pede uma segunda olhada (ex.: justificativa
  insuficiente para a mitigação escolhida).

## O que a tool MCP devolve

- `obter_incidente(id)` — resumo: `categoria`, `categoria_do_modelo`, `confianca`, `inicio`,
  `fim`, `janelas`, `origens_distintas`, `distribuido`, `origens`, `destinos`,
  `features_principais` (cada uma com `nome` e `valor`, e `referencia_benigno` quando houver).
- `obter_janelas(id, limite)` — até 20 janelas de detalhe, cada uma com `categoria_do_modelo`,
  `confianca`, `origem`, `destino` e as 39 features. Usar só quando o resumo não for suficiente.
  Cada janela tem 100 quadros (decisão de 2026-10-10): um flood enche uma janela em
  milissegundos, uma varredura em menos de um segundo, e força bruta ou ataque Web em até três
  segundos. Poucas janelas num incidente lento não significam ruído por si só.

## Passo a passo

1. Chamar `obter_incidente(id)`.
2. Conferir coerência: `categoria` é o resultado depois da regra que separa DoS de DDoS pela
   quantidade de origens; `categoria_do_modelo` é o que o Random Forest disse antes dessa regra.
   As duas podem divergir nisso — não é uma inconsistência por si só. Olhar `distribuido` e
   `origens_distintas` para confirmar se batem com a categoria (ex.: DDoS com uma origem só é
   suspeito).
3. Olhar `confianca`. Com confiança baixa (abaixo de um limiar a calibrar, por exemplo 0,7) ou
   categoria/confiança inconsistentes com `origens_distintas`, chamar `obter_janelas(id, 20)` e
   conferir se a maioria das janelas individuais concorda com o resumo.
4. Agrupar: se houver mais de um incidente aberto com as mesmas origens/destinos e categoria
   próximos no tempo, tratar como o mesmo ataque, não como incidentes separados.
5. Decidir o rótulo da triagem: **coerente** (segue para o agente de decisão), **duvidoso**
   (confiança baixa ou incoerência — ver cenário `inc-0004` em `codigo/mcp/README.md`, falso
   positivo de uma câmera enviando vídeo) ou **ruído** (poucas janelas, sem padrão).

## Formato da resposta

Um resumo curto e estruturado para o agente de decisão, nunca o JSON bruto das janelas:

```
Incidente: <id>
Categoria: <categoria> (confiança <confianca>)
Rótulo da triagem: coerente | duvidoso | ruído
Por quê: <uma frase, citando o que confirmou ou gerou a dúvida>
Origens distintas: <n>  |  Distribuído: sim/não
Features que mais chamam atenção: <até 3, com valor e referência de tráfego benigno quando houver>
```

Origens e destinos entram no resumo só pelos rótulos neutros que o orquestrador atribui, nunca pelo
endereço. Como Web e BruteForce são as categorias em que o classificador mais erra (recall abaixo
de 40% nos dados regerados, confundidas com Recon e com tráfego benigno, `experimentos/resultados/regeracao.md`),
um incidente dessas categorias com confiança média pede a conferência pelas janelas antes de
receber o rótulo coerente.

Quando o rótulo é **duvidoso**, a resposta inclui a ressalva explícita de que nenhuma ação de
risco alto deve ser proposta sem reforçar a justificativa (o próprio contrato MCP já exige
aprovação humana nesses casos; a triagem só evita que o agente de decisão trate o caso como
óbvio).

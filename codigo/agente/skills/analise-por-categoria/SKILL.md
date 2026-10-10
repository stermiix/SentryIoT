---
name: analise-por-categoria
description: Interpreta o padrão do ataque dentro da categoria já triada (DDoS, DoS, Mirai, Recon, Spoofing, Web ou BruteForce), usando as features do incidente para entender o que está acontecendo antes de escolher uma mitigação. Usar depois da triagem-do-alerta e antes da recomendacao-de-mitigacao, sempre que o rótulo da triagem for "coerente".
---

# Análise por categoria de ataque

Skill do agente de **decisão** (ver `codigo/mcp/README.md`), primeira metade do trabalho dele:
entender o ataque antes de recomendar o que fazer. A segunda metade é a skill
`recomendacao-de-mitigacao`.

## Quando usar

- Depois que a `triagem-do-alerta` devolve um rótulo **coerente** para o incidente.
- Não usar sozinha em incidente **duvidoso**: nesse caso a análise serve só para apoiar a decisão
  de pedir mais dados ou escalar para aprovação humana, nunca para propor ação de risco alto.

## O que a tool MCP devolve (reaproveita a chamada da triagem)

- `obter_incidente(id)` — já traz `features_principais`, cada uma com `nome` (uma das 39 colunas
  do extrator) e `valor`, e `referencia_benigno` quando existir uma referência de tráfego normal
  para comparar.
- `obter_janelas(id, limite)` — usar quando `features_principais` não for suficiente para
  confirmar o padrão (limite de 20 janelas por chamada).

## Passo a passo (o que olhar em cada categoria)

- **DDoS / DoS**: `Rate` muito acima da referência de benigno, `syn_count`/`ack_count` altos,
  `origens_distintas` (DDoS tem muitas; DoS poucas — a separação exata já vem pronta em
  `categoria`, não precisa ser recalculada aqui). Confirmar se o padrão é volumétrico (Rate) ou
  de exaustão de recursos (contagem de flags).
- **Mirai**: portas e protocolos típicos de botnet IoT (ver `Protocol Type`, indicadores de
  porta), muitas vezes com múltiplos destinos.
- **Recon**: variação de porta de destino ao longo das janelas (varredura), `Time_To_Live`
  estável, poucas origens.
- **Spoofing**: inconsistência entre endereço de origem declarado e padrão de resposta —
  normalmente aparece como `confianca` mais baixa na triagem; checar se o destino coincide com
  um dispositivo protegido (política em `codigo/mcp/politica.toml`).
- **Web**: indicadores de porta HTTP/HTTPS, com `Rate` mais baixo que DDoS/DoS — risco de
  confundir com tráfego legítimo de alto volume; comparar sempre com `referencia_benigno`.
- **BruteForce**: muitas janelas seguidas com a mesma origem e destino, `Rate` moderado,
  característico de tentativa repetida (ex.: SSH) — ver cenário `inc-0002` em
  `codigo/mcp/README.md`.

## Formato da resposta

Entrada para a skill `recomendacao-de-mitigacao`, não para o humano diretamente:

```
Incidente: <id>  |  Categoria: <categoria>
Padrão observado: <1–2 frases, o que no tráfego caracteriza esse ataque específico>
Features que sustentam a leitura: <nome: valor (referência benigno: x), até 3>
Urgência percebida: baixa | média | alta
```

"Urgência percebida" não é o risco da ação (isso é calculado pelo contrato MCP em
`propor_acao`), é só um sinal para a próxima skill priorizar entre mitigações equivalentes.

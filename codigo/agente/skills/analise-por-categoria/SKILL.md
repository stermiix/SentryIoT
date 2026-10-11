---
name: analise-por-categoria
description: Interpreta o padrão do ataque dentro da categoria já triada (DDoS, DoS, Mirai, Recon, Spoofing, Web ou BruteForce), usando as features do incidente para entender o que está acontecendo antes de escolher uma mitigação. Usar depois da triagem-do-alerta e antes da recomendacao-de-mitigacao, sempre que o rótulo da triagem for "coerente".
---

# Análise por categoria de ataque

Skill do agente de **decisão** (ver `codigo/mcp/README.md`), primeira metade do trabalho dele:
entender o ataque antes de recomendar o que fazer. A segunda metade é a skill
`recomendacao-de-mitigacao`.

## Onde roda e o que chega aqui

O agente de decisão é o único que pode rodar num modelo de fronteira pela nuvem (arquitetura
híbrida, `ROADMAP.md`, decisão de 2026-10-10). Nada identificável da rede chega a ele: os
endereços e nomes de dispositivo do incidente vêm trocados por rótulos neutros (`origem-1`,
`destino-1`, `dispositivo-3`) pelo orquestrador, e a análise trabalha com esses rótulos, as
contagens, a confiança e as features. Não há o que "descobrir" por trás de um rótulo, e a análise
não deve tentar. Na configuração toda local, os dados chegam do mesmo jeito, para o fluxo ser o
mesmo nas três configurações comparadas no artigo.

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

As 39 features descrevem uma janela de 100 quadros (decisão de 2026-10-10): não há porta nem
endereço entre elas. O que existe de camada de aplicação são os indicadores de protocolo
(`HTTP`, `HTTPS`, `DNS`, `Telnet`, `SSH`, `TCP`, `UDP`, `ICMP`, `ARP` e os demais), que dizem a
fração da janela em cada protocolo. Quando a análise precisar de "em quais portas", a resposta
não está nos dados: dizer isso em vez de inventar.

- **DDoS / DoS**: `Rate` muito acima da referência de benigno, `syn_count`/`ack_count` altos,
  `origens_distintas` (DDoS tem muitas; DoS poucas — a separação exata já vem pronta em
  `categoria`, não precisa ser recalculada aqui). Confirmar se o padrão é volumétrico (Rate) ou
  de exaustão de recursos (contagem de flags). Pacote pequeno (`AVG`, `Tot size`) com `Rate`
  alto é flood de SYN, RST ou ICMP; `UDP` alto com `Rate` alto é flood UDP.
- **Mirai**: `Rate` alto com `UDP` ou `TCP` dominando a janela, pacotes de tamanho quase
  constante (`Std` e `Variance` baixos), muitas vezes com mais de um destino.
- **Recon**: `syn_count` com `rst_count` na mesma proporção (porta fechada responde RST),
  pacotes pequenos, `Time_To_Live` estável, poucas origens; no ping sweep, `ICMP` domina.
- **Spoofing**: `ARP` ou `DNS` acima da referência de benigno numa rede em que esse tráfego é
  raro — normalmente aparece com `confianca` mais baixa na triagem; checar se o destino coincide
  com um dispositivo protegido (política em `codigo/mcp/politica.toml`).
- **Web**: `HTTP` ou `HTTPS` dominando, `Rate` mais baixo que DDoS/DoS — risco de confundir com
  tráfego legítimo de alto volume; comparar sempre com `referencia_benigno`. É a categoria em que
  o classificador mais erra (recall abaixo de 40%, `experimentos/resultados/regeracao.md`).
- **BruteForce**: muitas janelas seguidas com a mesma origem e destino, `Rate` moderado, `SSH`
  ou `Telnet` presentes, característico de tentativa repetida — ver cenário `inc-0002` em
  `codigo/mcp/README.md`. Recall também baixo; a precisão é alta, então o rótulo, quando vem,
  costuma estar certo.

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

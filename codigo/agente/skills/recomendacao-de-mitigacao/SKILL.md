---
name: recomendacao-de-mitigacao
description: Escolhe e propõe a mitigação para um incidente já analisado, usando a base de mitigações da tool MCP e, se nada do catálogo resolver, propondo uma ação nova. Usar depois da analise-por-categoria, e de novo sempre que verificar_efeito indicar que a ação anterior não resolveu.
---

# Recomendação de mitigação

Skill do agente de **decisão**, segunda metade do trabalho dele (a primeira é
`analise-por-categoria`). O resultado desta skill é uma chamada a `propor_acao`; quem aplica a
ação é o agente de **execução**, numa skill separada (ainda não escrita).

## Onde roda e o que esta skill não faz

O agente de decisão pode estar num modelo de nuvem e só conhece os rótulos neutros do incidente
(`origem-1`, `destino-1`); o `alvo` da proposta é escrito com esses rótulos, e é o agente de
execução, local e o único com credenciais, que desfaz a troca na hora de aplicar (arquitetura
híbrida, `ROADMAP.md`, decisão de 2026-10-10).

A pessoa que opera a rede é avisada pelo servidor assim que o incidente abre e pode marcar o
incidente como **já resolvido** na interface. Quando o orquestrador informa que essa marca existe,
esta skill não chama `propor_acao`: a saída passa a ser a explicação do incidente (o que o tráfego
mostra, que mitigação seria a indicada e por quê), no formato da seção "Explicação" abaixo. O
agente de execução confere a mesma marca antes de aplicar qualquer ação, mesmo de risco baixo, e
também não aplica nada com ela presente.

## Quando usar

- Logo depois da `analise-por-categoria`, para o primeiro incidente coerente.
- De novo, no mesmo incidente, quando `verificar_efeito` devolver `persiste` ou `diminuiu` sem
  cessar — ver o roteiro do cenário `inc-0001` em `codigo/mcp/README.md`, em que a primeira ação
  não resolve e o agente precisa propor outra.
- Nunca propor ação de risco alto (isolar dispositivo, revogar credencial, qualquer ação nova)
  sozinha num incidente marcado **duvidoso** pela triagem — a ação até pode ser proposta, mas
  a justificativa precisa dizer que o caso é duvidoso, para quem aprova decidir com essa
  informação.

## O que a tool MCP devolve

- `consultar_mitigacoes(categoria)` — lista de mitigações recomendadas (cada uma com `origem`,
  `titulo`, `texto`, e `acao` quando corresponde a uma ação do catálogo) e o catálogo de ações
  (`nome`, `descricao`, `alvo`, `parametros`, `regra` de risco, `como_desfazer`).
- `pesquisar_solucoes(consulta)` — busca de texto livre na base local (até 3 trechos), para quando
  o catálogo não cobre o padrão identificado. Trecho com `acao` nula é candidato a ação nova, não
  uma ação pronta.
- `propor_acao(id, acao, alvo, parametros, justificativa)` — devolve a proposta com `risco`,
  `motivos_de_risco_alto` (quando houver) e `exige_aprovacao`.

## Passo a passo

1. Chamar `consultar_mitigacoes(categoria)` com a categoria confirmada pela skill anterior.
2. Escolher, entre as mitigações devolvidas, a que mais combina com o padrão observado (ex.:
   `bloquear_ip` quando o padrão é concentrado em poucas origens; não faz sentido para DDoS com
   dezenas de origens distintas).
3. Se nenhuma mitigação do catálogo servir para o padrão, chamar `pesquisar_solucoes` com uma
   descrição curta do padrão (até 2.000 caracteres) e avaliar os trechos devolvidos.
4. Montar a `justificativa` da proposta citando o dado concreto que motivou a escolha (ex.:
   "origem com mais quadros no incidente", não "parece suspeito").
5. Chamar `propor_acao`. Se a ação é nova (fora do catálogo), incluir `descricao`, `passos`,
   `efeito_esperado` e `como_desfazer` nos parâmetros — sem isso a proposta fica incompleta.
6. Ler a resposta: `risco` e `exige_aprovacao` já vêm calculados pela política
   (`codigo/mcp/politica.toml`); a skill não recalcula risco, só decide o que propor.
7. Depois de aplicar, o agente de execução, local, confere `verificar_efeito` e devolve o
   resultado (`cessou`, `diminuiu` ou `persiste`); o agente de decisão também pode chamar a tool,
   porque o resultado não carrega dado da rede. Se `persiste`, repetir a partir do passo 2 com os
   dados do que já foi tentado (para não propor a mesma ação de novo).

## Formato da resposta

```
Incidente: <id>
Ação proposta: <nome ou descrição, se nova>  |  Alvo: <alvo>  |  Parâmetros: <parametros>
Justificativa: <uma frase, com o dado concreto>
Risco (devolvido pela tool): baixo | alto  |  Exige aprovação: sim/não
Se exige aprovação: <os motivos_de_risco_alto, em português simples>
```

## Formato da resposta quando o incidente está marcado como já resolvido

```
Incidente: <id>  |  Marcado como já resolvido pela pessoa que opera a rede
O que o tráfego mostra: <1–2 frases, com o dado concreto>
Mitigação que seria indicada: <nome do catálogo ou descrição>  |  Alvo: <rótulo neutro>
Por quê: <uma frase>
Nenhuma ação foi proposta nem aplicada.
```

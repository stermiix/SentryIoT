# Interface web do SentryIoT

Interface web do sistema, em React e TypeScript. As telas 1 e 2, em modo replay, já estão
implementadas (ver "Estado atual" no fim deste arquivo); as demais ainda são só o plano de como
se ligam ao backend, para que o backend já nasça gravando o que elas vão precisar.

## Como a interface se liga ao backend

O backend grava um log de eventos com formato fixo. Cada passo relevante vira uma linha: janela
classificada, incidente aberto, tool chamada, recomendação emitida, ação aprovada, rejeitada ou
desfeita. A interface não fala com o classificador nem com os agentes. Ela só lê esse log, por
uma API fina.

Isso dá dois modos com o mesmo código:

- **Ao vivo:** a interface acompanha o log enquanto o sistema roda.
- **Replay:** a interface reproduz uma execução gravada. É o modo que protege a demonstração na
  banca, porque não depende de internet nem de a LLM responder na hora.

O formato do log é definido junto com o contrato da tool MCP, em `codigo/mcp/`.

## Telas, em ordem de valor

1. **Fila de incidentes.** Mostra os alertas agrupados, com o contador de janelas, incidentes e
   chamadas à LLM (por exemplo, 12.000 janelas, 1 incidente, 1 chamada). É a resposta visual à
   pergunta da banca sobre custo de tokens e Denial of Wallet.
2. **Detalhe do incidente.** Mostra o veredito do Random Forest, confiança e features; o rastro
   dos agentes e chamadas MCP; recomendações; e o histórico das decisões de aprovação, rejeição
   e desfazer registradas no log. No modo ao vivo, o incidente aparece aqui assim que o
   classificador o abre, antes de os agentes agirem, e o botão "Já resolvido" grava no log que o
   usuário já tratou o caso: a partir daí o agente de execução não aplica remediação e só explica.
   A barra superior mostra os provedores de LLM configurados e o modelo local quando está online,
   e permite escolher qual os agentes usam; o modelo escolhido vai gravado em cada chamada do log.
3. **Isolado e integrado.** O mesmo incidente com a saída crua do classificador de um lado e a
   saída com agentes do outro. Essa comparação é uma tarefa da PoC e vira figura do artigo.
4. **Custo e latência.** Tokens, tempo de resposta e custo por incidente, com a comparação entre
   modelo em nuvem e modelo local.
5. **Qualidade do modelo.** Matriz de confusão, recall por classe e taxa de falso positivo,
   lidos de `experimentos/resultados/`.
6. **Segurança do MCP.** O resultado do teste de tool poisoning: o que foi injetado e se o
   agente caiu.

## Ordem de construção

A interface completa (modo ao vivo e telas restantes) vem depois que o backend da PoC estiver
gravando o log de verdade e os experimentos produzirem os dados que faltam. A versão mínima útil
— as duas primeiras telas, em modo replay — já está implementada, porque não depende de nada
disso: usa só o log de exemplo já versionado em `codigo/mcp/exemplos/incidente_flood.jsonl`.

## Estado atual

Implementado: um app estático (Vite + React + TypeScript), sem backend, que lê o log de exemplo
e mostra as telas 1 e 2 em modo replay.

- **Leitura do log.** Cada linha é conferida contra o contrato (`codigo/mcp/contrato.json`) na
  carga. Linha fora do contrato, evento com `id` repetido e última linha sem quebra de linha no
  fim (que, no modo ao vivo, pode estar sendo gravada) são descartados, e o número da linha
  aparece num aviso no topo da tela. Os eventos seguem a ordem do `id`, e não a do arquivo.
- **Fila.** Um incidente só ganha linha se o log tem o evento de abertura dele. Eventos que citam
  um incidente sem abertura ficam contados à parte, com aviso, e não somam em "Incidentes".
- **Detalhe.** Veredito do classificador; rastro dos agentes com a hora de cada chamada (no fuso
  de quem abre a página); recomendações com o agente e as propostas ligadas; o estado de cada
  proposta, reconstruído como no `reconstruir` de `codigo/mcp/acoes.py` (risco, aprovação,
  motivos do risco alto, decisões, execuções e efeitos); e o histórico de decisões e ações, com
  hora e id em todas as linhas.
- **Replay.** Abre no estado final e pode ser percorrido evento a evento.
- **Antes do contrato.** A interface já mostra o evento `incidente_marcado_resolvido` e aceita a
  categoria `DDoS+DoS` do modelo, que vão entrar no contrato em outro PR. O log de exemplo atual
  não tem nenhum dos dois.

Como é replay, não há controles para criar aprovações ou executar ações; a interface só apresenta
o que já está no log.

**Como rodar** (exige Node.js 20 ou mais recente):

```
cd frontend
npm ci
npm run dev
```

Abre em `http://localhost:5173`. Use `npm ci`, e não `npm install`, para instalar exatamente o que
está no `package-lock.json`. A cópia do log em `public/dados/` é versionada: rode
`npm run sync:log` só depois de regenerar o log de exemplo
(`python -m codigo.mcp.roteiro --sobrescrever`), e versione a cópia junto. O replay funciona sem
API e sem conexão externa; a tipografia usa fontes locais do sistema.

`npm test` roda os testes (Vitest) da leitura do log, da agregação e das telas, com os casos
adversariais da revisão: duplicados, ordem trocada, incidente trocado ou sem abertura, campo
ausente, `toString` e `constructor`, HTML no log e última linha cortada. `npm run build` confere
os tipos e gera a versão de produção em `dist/`; `npm run preview` serve essa versão. O CI roda,
a cada PR, os testes, o `npm audit --omit=dev --audit-level=high` e o build.

**Arquivos:**

| Arquivo | Papel |
|---|---|
| `src/contrato.ts` | Confere cada linha do log contra o contrato, tipo de evento por tipo de evento |
| `src/log.ts` | Lê o JSONL (descarte, ordem, avisos) e agrega os eventos: contadores da tela 1, incidentes, propostas e marca de já resolvido |
| `src/types.ts` | Os tipos do log, como união discriminada por `tipo`, e o que a interface monta a partir deles |
| `src/rotulos.ts`, `src/formato.ts` | Como cada valor do log aparece na tela; formato de números e horas |
| `src/components/ResumoMetricas.tsx` | Cartões do resumo com janelas, incidentes, chamadas e tokens do replay |
| `src/components/FilaDeIncidentes.tsx` | Tela 1 |
| `src/components/DetalheDoIncidente.tsx` | Tela 2 |
| `src/components/ControleDoReplay.tsx` | Avanço do replay evento a evento |
| `src/components/LimiteDeErro.tsx` | Error boundary da fila e do detalhe |
| `src/log.test.ts`, `src/telas.test.tsx` | Testes da leitura, da agregação e das telas |
| `scripts/sync-log.mjs` | Copia o log de exemplo para `public/dados/`; recusa link simbólico |
| `public/dados/incidente_flood.jsonl` | Cópia estática do replay versionado em `codigo/mcp/exemplos/` |

**Não implementado, e por quê:** modo ao vivo (precisa da API fina lendo o backend de verdade,
que ainda não existe); tela 3, isolado vs. integrado (falta o registro do mesmo incidente sem
agentes, para comparar); tela 4, custo nuvem vs. on-premises (o log de exemplo só tem números de
um cenário); tela 5, qualidade do modelo (dá para fazer com o que já existe em
`experimentos/resultados/`); tela 6, segurança do MCP (depende do teste de tool poisoning, que
ainda não foi escrito).

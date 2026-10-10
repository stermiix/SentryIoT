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
   e desfazer registradas no log.
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
e mostra as telas 1 e 2. O detalhe inclui o resumo do classificador, métricas do replay, timeline
dos agentes, recomendações e ações históricas. Como é replay, não há controles para criar novas
aprovações ou executar ações; a interface só apresenta o que já está no log.

**Como rodar** (exige Node.js 18 ou mais recente):

```
cd frontend
npm install
npm run sync:log    # copia codigo/mcp/exemplos/incidente_flood.jsonl para public/dados/
npm run dev
```

Abre em `http://localhost:5173`. Rode `npm run sync:log` de novo sempre que o log de exemplo for
regenerado (`python -m codigo.mcp.roteiro --sobrescrever`). O replay funciona sem API e sem
conexão externa; a tipografia usa fontes locais do sistema.

`npm run build` confere os tipos e gera a versão de produção em `dist/`; `npm run preview` serve
essa versão para conferir antes de abrir PR. O CI roda o build a cada PR.

**Arquivos:**

| Arquivo | Papel |
|---|---|
| `src/log.ts` | Lê o JSONL e agrega os eventos por incidente: contadores da tela 1, veredito, rastro, recomendação e histórico de ações da tela 2 |
| `src/types.ts` | Os campos do log que a interface usa (não é o contrato inteiro de `codigo/mcp/tipos.py`) |
| `src/components/ResumoMetricas.tsx` | Cartões do resumo com janelas, incidentes, chamadas e tokens do replay |
| `src/components/FilaDeIncidentes.tsx` | Tela 1 |
| `src/components/DetalheDoIncidente.tsx` | Tela 2 |
| `scripts/sync-log.mjs` | Copia o log de exemplo para `public/dados/`, de onde o app lê em tempo de execução |
| `public/dados/incidente_flood.jsonl` | Cópia estática do replay versionado em `codigo/mcp/exemplos/` |

**Não implementado, e por quê:** modo ao vivo (precisa da API fina lendo o backend de verdade,
que ainda não existe); tela 3, isolado vs. integrado (falta o registro do mesmo incidente sem
agentes, para comparar); tela 4, custo nuvem vs. on-premises (o log de exemplo só tem números de
um cenário); tela 5, qualidade do modelo (dá para fazer com o que já existe em
`experimentos/resultados/`); tela 6, segurança do MCP (depende do teste de tool poisoning, que
ainda não foi escrito).

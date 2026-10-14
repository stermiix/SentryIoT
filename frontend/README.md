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

Implementado: um app estático (Vite + React + TypeScript) que lê o log de exemplo e mostra as
telas 1 e 2 em modo replay, sem backend; e a tela "Chat com o modelo", ferramenta de teste do
provedor de LLM, que é a única a falar com o backend fino de `codigo/api/`. O log segue o
contrato 0.3.0 do MCP.

- **Leitura do log.** Cada linha é conferida contra o contrato (`codigo/mcp/contrato.json`) na
  carga: campos, tipos, valores aceitos, limites e caracteres de texto, endereços IP e nomes de
  feature. Linha fora do contrato e evento com `id` repetido são descartados, e o número da linha
  aparece num aviso no topo da tela. Os eventos seguem a ordem do `id`, e não a do arquivo. No
  modo ao vivo, que ainda não existe, a última linha sem quebra de linha no fim vai ser ignorada,
  porque pode estar sendo gravada (`ignorarUltimaIncompleta` em `src/log.ts`); no replay, ela é
  lida, como faz o leitor do Python. A conferência é mais frouxa que a do Python em três pontos:
  campo a mais não derruba a linha, inteiro acima de 2^53 é recusado, e a classificação dos
  caracteres do Unicode é a do navegador.
- **Reconstrução.** O estado de incidentes, marcas, propostas, execuções e promoções é
  reconstruído com as regras do `reconstruir` de `codigo/mcp/acoes.py`. O Python recusa o log
  inteiro no primeiro evento fora de lugar; a interface ignora esse evento, avisa com o id dele e
  segue. A única regra que fica de fora é a de que a ação promovida ao catálogo seja exatamente a
  que foi aprovada: a interface confere o nome, a origem e a proposta, e não os textos.
- **Fila.** Um incidente só ganha linha se o log tem o evento de abertura dele. Eventos que citam
  um incidente que não estava aberto naquele ponto ficam contados à parte, com aviso, e não
  somam em "Incidentes". O incidente marcado como já resolvido aparece como tal.
- **Detalhe.** Veredito do classificador, com a categoria do modelo e a do incidente; rastro dos
  agentes com a hora de cada chamada (no fuso de quem abre a página); recomendações com o agente
  e as propostas ligadas; o estado de cada proposta (alvo com o rótulo neutro, risco, aprovação,
  motivos do risco alto, decisões com canal e usuário, execuções e efeitos); a marca de já
  resolvido; e o histórico de decisões e ações, com hora e id em todas as linhas. A frase de cada
  motivo de risco alto é a do contrato, e não a que veio no log; texto escrito por um agente ou
  por uma pessoa (recomendação, justificativa, motivo, mensagem de recusa) aparece entre aspas.
- **Replay.** Abre no estado final e pode ser percorrido evento a evento, também pelo teclado.

Como é replay, não há controles para criar aprovações ou executar ações; a interface só apresenta
o que já está no log.

**Como rodar** (exige Node.js 20 ou mais recente):

```
cd frontend
npm ci
npm run dev
```

Abre em `http://localhost:5173`. Use `npm ci`, e não `npm install`, para instalar exatamente o que
está no `package-lock.json`.

A tela "Chat com o modelo" (`#chat`) fala com o backend fino de `codigo/api/`: suba
`python -m codigo.api` na raiz do repositório, com o `.env` preenchido (ver
`codigo/api/README.md`), e o Vite encaminha `/api` para ele. Com a porta 8000 ocupada, suba o
backend em outra e aponte `VITE_API_URL` para ela. Sem o backend, a tela abre e avisa que ele
não está no ar.

**Em produção** (o servidor da equipe) não há Vite: `npm run build` gera `dist/`, e o mesmo
backend serve essa pasta na raiz e a API em `/api`, num processo só:

```
cd frontend && npm ci && npm run build
cd .. && python -m codigo.api --host <endereço Tailscale> --port 8000
```

A receita completa, com o `.env`, a CA interna e o acesso só pela rede privada, está em
`codigo/api/README.md`. A cópia do log em `public/dados/` é versionada: rode
`npm run sync:log` só depois de regenerar o log de exemplo
(`python -m codigo.mcp.roteiro --sobrescrever`), e versione a cópia junto. O replay funciona sem
API e sem conexão externa; a tipografia usa fontes locais do sistema.

`npm test` roda os testes (Vitest). Eles leem o log de exemplo e variações dele (duplicados,
ordem trocada, incidente trocado ou sem abertura, campo ausente, `toString` e `constructor`, HTML
no log, linha cortada) e um caso para cada regra de sequência do `reconstruir`; desenham as telas
e o controle do replay; e comparam as listas de `src/listas.ts` com o `contrato.json` e com o
`acoes.py`, para que uma mudança no contrato do MCP faça o teste falhar até a interface
acompanhar. `npm run build` confere
os tipos e gera a versão de produção em `dist/`; `npm run preview` serve essa versão. O CI roda,
a cada PR, os testes, o `npm audit --omit=dev --audit-level=high` e o build.

**Arquivos:**

| Arquivo | Papel |
|---|---|
| `src/listas.ts` | Os valores fixos do contrato (categorias, motivos, estados) e o catálogo de base |
| `src/contrato.ts` | Confere cada linha do log contra o contrato, tipo de evento por tipo de evento |
| `src/log.ts` | Lê o JSONL (descarte, ordem, avisos), reconstrói o estado com as regras do `reconstruir` e agrega os eventos por incidente |
| `src/types.ts` | Os tipos do log, como união discriminada por `tipo`, e o que a interface monta a partir deles |
| `src/rotulos.ts`, `src/formato.ts` | Como cada valor do log aparece na tela; formato de números e horas |
| `src/components/ResumoMetricas.tsx` | Cartões do resumo com janelas, incidentes, chamadas e tokens do replay |
| `src/components/FilaDeIncidentes.tsx` | Tela 1 |
| `src/components/DetalheDoIncidente.tsx` | Tela 2 |
| `src/components/ControleDoReplay.tsx` | Avanço do replay evento a evento |
| `src/components/LimiteDeErro.tsx` | Error boundary da fila, do detalhe e do chat |
| `src/chat.ts` | Os tipos e as chamadas de `/api/chat`, `/api/modelos` e `/api/prompts`, e a montagem do pedido a partir da conversa |
| `src/components/ChatDoModelo.tsx` | A tela do chat: `TelaDoChat` só desenha, `ChatDoModelo` guarda a conversa e chama a API |
| `src/log.test.ts`, `src/telas.test.tsx`, `src/contrato.test.ts`, `src/chat.test.tsx` | Testes da leitura e da reconstrução, das telas, das listas contra o contrato, e do chat |
| `src/html-de-teste.ts` | Ajudantes dos testes que procuram texto no HTML desenhado |
| `scripts/sync-log.mjs` | Copia o log de exemplo para `public/dados/`; recusa link simbólico |
| `public/dados/incidente_flood.jsonl` | Cópia estática do replay versionado em `codigo/mcp/exemplos/` |

**Não implementado, e por quê:** modo ao vivo (precisa da API fina lendo o backend de verdade,
que ainda não existe); tela 3, isolado vs. integrado (falta o registro do mesmo incidente sem
agentes, para comparar); tela 4, custo nuvem vs. on-premises (o log de exemplo só tem números de
um cenário); tela 5, qualidade do modelo (dá para fazer com o que já existe em
`experimentos/resultados/`); tela 6, segurança do MCP (depende do teste de tool poisoning, que
ainda não foi escrito).

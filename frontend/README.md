# Interface web do SentryIoT

Interface web do sistema, em React e TypeScript. Desde 15/10/2026 ela segue o design system
SentryIoT, que fica em `src/design-system/`: toda tela usa só os componentes, os tokens e o
vocabulário dele. Antes de desenhar ou mudar uma tela, leia `src/design-system/README.md` (cor,
tipografia, as duas vozes do texto, marca) e `src/design-system/COMPONENTES.md` (cada componente).

## Como a interface se liga ao backend

O backend grava um log de eventos com formato fixo: janela classificada, incidente aberto, tool
chamada, recomendação emitida, ação aprovada, rejeitada ou desfeita. A interface não fala com o
classificador nem com os agentes. Ela só lê esse log, o que dá dois modos com o mesmo código:

- **Replay:** reproduz uma execução gravada, lida do log que `VITE_LOG_DE_EVENTOS` indica. É o
  modo que protege a demonstração na banca, porque não depende de internet nem de a LLM responder
  na hora. Sem a variável, nenhum log é carregado e as telas abrem vazias.
- **Ao vivo:** acompanha o log enquanto o sistema roda (planejado; ver "Ao vivo" abaixo).

A tela Simulação é a exceção: ela manda um pcap ao backend, que roda o reprodutor e os agentes, e a
interface acompanha o log enquanto ele é gravado, em todas as telas.

O formato do log é o contrato da tool MCP, em `codigo/mcp/contrato.json`. A interface não traz
dado simulado: nenhum log vai no build, e o log de exemplo do stub (`codigo/mcp/exemplos/`) só
entra nos testes.

## Telas

| Tela | Âncora | Estado |
|---|---|---|
| Visão geral: funil janelas → incidentes → chamadas à IA, cartões e fila | `#/visao-geral` | funciona com o log |
| Detalhe do incidente: veredito, features, propostas, endereços, rastro dos agentes, recomendações, histórico | `#/incidentes/<id>` | funciona com o log; as decisões só são oferecidas no fim do replay |
| Ao vivo | `#/ao-vivo` | planejada; liga com `VITE_LOG_AO_VIVO`, e sem ela fica vazia |
| Simulação: anexa um pcap, que passa pelo extrator, pelo classificador e pela política de acionamento, e cada incidente segue para os agentes, com a aprovação de uma pessoa na própria tela | `#/simulacao` | funciona com o backend (`/api/simulacao`, com o cabeçalho `X-SentryIoT: interface`), o modelo do sistema em `modelos/` e o modelo local no `.env`; por padrão classifica só o trecho do pcap que ficou fora do treino; o log da simulação passa a ser o das outras telas |
| Tela 3, isolado × integrado | `#/isolado-integrado` | funciona com o log |
| Tela 4, custo e latência | `#/custo-latencia` | funciona com o log; local × nuvem depende de `VITE_MODELOS_LOCAIS` e `VITE_MODELOS_NA_NUVEM` |
| Tela 5, qualidade do modelo | `#/qualidade-do-modelo` | matriz real da configuração 5 |
| Chat com o modelo | `#/chat` (e o antigo `#chat`) | funciona com o backend |
| Relatório do incidente, em A4: sumário, fatos, o que o classificador viu, triagem (veredito, atacante apontado, análise e candidatos), ações, recomendações e decisões | `#/relatorio/<id>` | funciona com o log; com um log anterior ao contrato 0.6.0, diz o que o log não traz |
| Entrar | `#/entrar` | visual pronto; o login ainda não existe |
| Componentes (catálogo do design system) | `#/componentes` | os blocos de dados usam o log; os outros mostram cada componente com valores de amostra |

Todas as telas que dependem do log mostram o estado até o cursor do replay, que fica no pé:
botões, trilha com marcas (incidente aberto, proposta que pede uma pessoa, decisões humanas),
teclado (← → Home End Espaço) e clique numa linha do histórico. Sem log, o replay some do pé, a
visão geral fica em zero e cada tela diz que nenhum log foi carregado.

### O que ainda não funciona, e onde ligar

- **Decisões pela interface** (aprovar, rejeitar, marcar como já resolvido) passam por
  `src/operacao.ts` e chegam ao backend enquanto os agentes de uma simulação rodam. Num log só de
  leitura, não há agente para agir: os botões abrem o diálogo de confirmação, e ele mostra que a
  decisão não foi gravada e o comando de terminal que faz a mesma coisa
  (`python -m codigo.mcp.aprovar …`).
- **Login:** ainda não existe; passa pela mesma `src/operacao.ts`.
- **Log do replay:** a interface lê o log que `VITE_LOG_DE_EVENTOS` indica, uma vez, ao abrir.
  Hoje o backend não serve o log que o sistema grava (`dados/eventos/eventos.jsonl`): para ver um
  log, ponha o arquivo em `public/dados/` (ignorada pelo git, porque o log pode ter endereços
  reais) e aponte a variável para ele, como `/dados/eventos.jsonl`.
- **Ao vivo:** com `VITE_LOG_AO_VIVO` apontando para um log que está sendo gravado (servido por
  HTTP), a tela o lê a cada 3 segundos e ignora a última linha incompleta. Sem a variável, ela
  fica vazia, com o selo de planejada.
- **Onde cada modelo roda:** o log não diz. Liste os modelos em `VITE_MODELOS_LOCAIS` e
  `VITE_MODELOS_NA_NUVEM` (separados por vírgula) para a tela mostrar "local" ou "nuvem" nas
  chamadas e para a Tela 4 comparar os dois. No chat, um modelo fora das listas aparece como
  nuvem: é o caso que pede cuidado.

## Leitura do log e reconstrução

- **Leitura.** Cada linha é conferida contra o contrato na carga: campos, tipos, valores aceitos,
  limites e caracteres de texto, endereços IP e nomes de feature. Linha fora do contrato e
  evento com `id` repetido são descartados, e o número da linha aparece num aviso. Os eventos
  seguem a ordem do `id`, e não a do arquivo. No modo ao vivo, a última linha sem quebra de linha
  é ignorada, porque pode estar sendo gravada (`ignorarUltimaIncompleta` em `src/log.ts`); no
  replay, ela é lida, como faz o leitor do Python. A conferência é mais frouxa que a do Python em
  três pontos: campo a mais não derruba a linha, inteiro acima de 2^53 é recusado, e a
  classificação dos caracteres do Unicode é a do navegador.
- **Reconstrução.** O estado de incidentes, marcas, propostas, execuções e promoções é
  reconstruído com as regras do `reconstruir` de `codigo/mcp/acoes.py`. O Python recusa o log
  inteiro no primeiro evento fora de lugar; a interface ignora esse evento, avisa com o id dele e
  segue. A única regra que fica de fora é a de que a ação promovida ao catálogo seja exatamente a
  que foi aprovada: a interface confere o nome, a origem e a proposta, e não os textos.
- **Da reconstrução à tela.** `src/adaptador.ts` transforma eventos, incidentes e propostas nos
  objetos que os componentes desenham. Nada ali inventa dado: a frase de cada motivo de risco
  alto é a do contrato; os rótulos vêm do vocabulário do design system; texto escrito por um
  agente ou por uma pessoa (recomendação, justificativa, motivo, descrição e alvo livre de ação
  nova) aparece na voz dele, nunca como texto do sistema; a chamada de tool mostra só chaves e
  identificadores; a mensagem de uma recusa do servidor, que pode repetir o que o agente mandou,
  vai entre aspas. Evento que a reconstrução ignorou aparece riscado na linha do tempo, sem marca
  na trilha, e o aviso aparece na visão geral e no detalhe.

## Como rodar

Exige Node.js 20 ou mais recente.

```
cd frontend
npm ci
npm run dev
```

Abre em `http://localhost:5173`. Use `npm ci`, e não `npm install`, para instalar exatamente o que
está no `package-lock.json`.

O chat fala com o backend fino de `codigo/api/`: suba `python -m codigo.api` na raiz do
repositório, com o `.env` preenchido (ver `codigo/api/README.md`), e o Vite encaminha `/api` para
ele. Com a porta 8000 ocupada, suba o backend em outra e aponte `VITE_API_URL` para ela. Sem o
backend, o chat abre e avisa que ele não está no ar, e o rodapé da barra lateral diz o mesmo.
As outras telas abrem vazias até `VITE_LOG_DE_EVENTOS` apontar para um log (ver "O que ainda não
funciona", acima).

**Em produção** (o servidor da equipe) não há Vite: `npm run build` gera `dist/`, e o mesmo
backend serve essa pasta na raiz e a API em `/api`, num processo só:

```
cd frontend && npm ci && npm run build
cd .. && python -m codigo.api --host <endereço Tailscale> --port 8000
```

A receita completa está em `codigo/api/README.md`. O replay funciona sem API e sem conexão
externa: fontes e imagens vão no build, e o log é lido do caminho configurado.

As variáveis `VITE_*` vão no ambiente ou num `.env.local` desta pasta (ignorado pelo git) e entram
no build: depois de mudar uma, gere o `dist/` de novo.

## Design system

- Os tokens estão em `src/design-system/tokens.json`. Depois de mudar esse arquivo, rode
  `npm run tokens` para gerar o `tokens.css`; um teste falha se os dois divergirem.
- Os componentes estão em `src/design-system/components/` e as telas importam de
  `src/design-system/index.ts`. O CSS das telas (`src/estilo.css`, classes `app-*`) usa só tokens.
- A origem é o design system publicado pela equipe. Os ajustes que o repositório fez sobre ele
  estão no fim de `src/design-system/README.md` e valem para qualquer nova sincronização.
- Fontes: Inter, Lora e Source Code Pro (SIL OFL 1.1, textos em `src/design-system/fonts/`).
  Ícones: Lucide (ISC, texto em `src/design-system/components/LICENCA-LUCIDE.txt`).

## Testes

`npm test` roda os testes (Vitest):

- **Leitura e reconstrução** (`src/log.test.ts`): o log de exemplo do stub, lido direto de
  `codigo/mcp/exemplos/incidente_flood.jsonl`, e variações dele (duplicados, ordem trocada,
  incidente sem abertura, campo ausente, HTML no log, linha cortada) e um caso para cada regra de
  sequência do `reconstruir`. É o único lugar em que esse log entra.
- **Contrato** (`src/contrato.test.ts`): as listas de `src/listas.ts` contra o `contrato.json` e o
  `acoes.py`.
- **Adaptador** (`src/adaptador.test.ts`): cada número e estado que a tela mostra, no log de
  exemplo, e o vocabulário do design system contra o contrato (20 tipos de evento, 9 motivos de
  risco alto).
- **Telas** (`src/telas.test.tsx`): cada tela desenhada no Node em passos escolhidos do replay,
  incluindo o HTML vindo do log escapado e as duas vozes do texto, e cada tela sem log, vazia e sem
  nenhum número do exemplo.
- **Chat** (`src/chat.test.ts`), **rotas** (`src/rotas.test.ts`), **operações**
  (`src/operacao.test.ts`), **tokens** (`src/design-system/tokens.test.ts`) e a **matriz da
  Tela 5** contra o CSV do experimento (`src/dados/qualidade.test.ts`).

`npm run build` confere os tipos e gera `dist/`; `npm run preview` serve essa versão. O CI roda,
a cada PR, os testes, o `npm audit --omit=dev --audit-level=high` e o build.

## Arquivos

| Arquivo | Papel |
|---|---|
| `src/listas.ts`, `src/types.ts` | Os valores fixos e os tipos do contrato do log |
| `src/contrato.ts` | Confere cada linha do log contra o contrato |
| `src/log.ts` | Lê o JSONL, reconstrói o estado e agrega os eventos por incidente |
| `src/adaptador.ts` | Do log aos objetos que os componentes desenham |
| `src/paginacao.ts` | Onde cada página A4 do relatório quebra, a partir das alturas medidas no navegador |
| `src/formato.ts` | A hora dos eventos no fuso de quem abre a página |
| `src/rotas.ts` | A tela pela âncora |
| `src/operacao.ts` | Decisões e login; hoje, o comando de terminal equivalente |
| `src/chat.ts` | As chamadas de `/api/chat`, `/api/modelos` e `/api/prompts` |
| `src/dados/qualidade.ts` | A matriz de confusão da Tela 5 e as métricas tiradas dela |
| `src/App.tsx` | Carrega o log, guarda a rota e o replay e escolhe a tela |
| `src/telas/` | As telas, a moldura (`Moldura.tsx`), o replay (`replay.ts`) e as peças comuns (`comum.tsx`) |
| `src/design-system/` | O design system: guia, componentes, tokens, fontes e marca |
| `src/estilo.css` | O pouco que as telas acrescentam ao design system |
| `scripts/gerar-tokens.mjs` | Gera o `tokens.css` do `tokens.json` |

# Interface web do SentryIoT

Interface web do sistema, em React e TypeScript. Desde 15/10/2026 ela segue o design system
SentryIoT, que fica em `src/design-system/`: toda tela usa só os componentes, os tokens e o
vocabulário dele. Antes de desenhar ou mudar uma tela, leia `src/design-system/README.md` (cor,
tipografia, as duas vozes do texto, marca) e `src/design-system/COMPONENTES.md` (cada componente).

## Como a interface se liga ao backend

O backend grava um log de eventos com formato fixo: janela classificada, incidente aberto, tool
chamada, conversa de cada agente, recomendação emitida, ação aprovada, rejeitada ou desfeita. A
interface não fala com o classificador nem com os agentes. Ela só lê esse log, em replay, de uma
destas fontes:

- **Rodada final (o padrão):** sem `VITE_LOG_DE_EVENTOS`, a interface abre os dados da rodada final
  dos experimentos, que vão junto com ela em `public/dados/rodada-final/`: um `indice.json` com os
  grupos (a rodada oficial no CICIoT2023, o teste com o Kali Linux numa rede isolada e os exemplos
  por categoria), as medidas de cada execução e um resumo por grupo, e o log real de cada execução,
  em gzip. Quem clona o repositório e roda a interface vê a rodada sem configurar nada, e a
  demonstração na banca não depende de internet nem de a LLM responder na hora. Um seletor no alto
  das telas escolhe a execução: grupo, pcap, incidente e repetição.
- **Log de uma variável:** com `VITE_LOG_DE_EVENTOS`, a interface lê esse log, uma vez, ao abrir,
  como antes da rodada final (ver "Log de outra execução", abaixo).
- **Simulação:** a tela Simulação manda um pcap ao backend, que roda o reprodutor e os agentes, e o
  log dela passa a ser o das telas enquanto ele é gravado. Quando os agentes param, a barra no alto
  das telas e a própria tela Simulação oferecem voltar à rodada final (ou ao log da variável).

O formato do log é o contrato da tool MCP, em `codigo/mcp/contrato.json`. A interface não traz
dado simulado: os dados da rodada final são as rodadas reais dos experimentos, e o log de exemplo
do stub (`codigo/mcp/exemplos/`) só entra nos testes.

### Como gerar os dados da rodada final

Depois que as três rodadas terminarem (`python -m codigo.agente.experimento rodar`, nas pastas
`dados/processed/agentes`, `dados/processed/agentes_kali` e `dados/processed/agentes_exemplos`), na
raiz do repositório:

```
python -m codigo.agente.vitrine
cd frontend && npm run build
```

O comando lê o `conjunto.json` e as rodadas (`rodadas/*.json` e `rodadas/*.jsonl`) de cada pasta e
grava `public/dados/rodada-final/indice.json` e os logs em `public/dados/rodada-final/<grupo>/`,
comprimidos. Ele é idempotente e falha sem gravar nada quando falta um arquivo, quando um item do
conjunto não tem rodada, quando uma rodada não é da configuração local ou quando um log não segue o
contrato. `--oficial`, `--kali` e `--exemplos` trocam as pastas, `--omitir kali` deixa um grupo de
fora e `--inicial <id>` escolhe a execução em que a interface abre (sem ele, a primeira da rodada
oficial em que a triagem, a ação e o atacante deram certo). A pasta `public/dados/rodada-final/`
vai para o git com a interface; o resto de `public/dados/` continua fora dele.

Os logs vão em `.jsonl.gz`. A interface confere os bytes mágicos do gzip (1f 8b) e abre o arquivo com
o `DecompressionStream` do navegador; quando o servidor já o descomprime (o Vite manda
`Content-Encoding: gzip`), ela lê o texto direto, e um `.jsonl` puro também serve. O backend
(`codigo/api/servidor.py`) serve o `.jsonl.gz` como `application/gzip`, sem descomprimir.

## Telas

| Tela | Âncora | Estado |
|---|---|---|
| Rodada final: os grupos da rodada, o resumo de cada um (triagem certa, primeira ação aceitável, atacante certo, incidentes abaixo de 0,6, tokens e tempo) e a tabela das execuções, de onde se abre qualquer uma | `#/rodada-final` | funciona com os dados do build; sem eles, diz como gerá-los |
| Visão geral: funil janelas → incidentes → chamadas à IA, cartões e fila, com o incidente que os agentes trataram em destaque | `#/visao-geral` | funciona com o log |
| Detalhe do incidente: veredito, features, propostas, endereços, rastro dos agentes, recomendações, histórico e, numa execução da rodada, o que ela mediu | `#/incidentes/<id>` | funciona com o log; as decisões só são oferecidas no fim do replay e nunca numa execução gravada da rodada |
| Conversa dos agentes, aba do detalhe: o incidente de ponta a ponta, com o prompt de sistema (recolhido), o pedido do orquestrador, cada tool pedida e o resultado dela, os avisos do laço e a resposta final de cada agente, e as decisões entre eles | `#/incidentes/<id>/conversa` | funciona com o log do contrato 0.8.0; num log anterior, mostra as etapas sem as mensagens |
| Simulação: anexa um pcap, que passa pelo extrator, pelo classificador e pela política de acionamento, e cada incidente segue para os agentes, com a aprovação de uma pessoa na própria tela | `#/simulacao` | funciona com o backend (`/api/simulacao`, com o cabeçalho `X-SentryIoT: interface`), o modelo do sistema em `modelos/` e o modelo local no `.env`; por padrão classifica só o trecho do pcap que ficou fora do treino; o log da simulação passa a ser o das outras telas até a pessoa voltar à rodada final |
| Tela 3, isolado × integrado | `#/isolado-integrado` | funciona com o log |
| Tela 4, custo e latência | `#/custo-latencia` | funciona com o log; com a rodada, o grupo dela por agente e o custo de nuvem, zero |
| Tela 5, qualidade do modelo | `#/qualidade-do-modelo` | matriz real da configuração 5 |
| Relatório do incidente, em A4: sumário, fatos, o que o classificador viu, triagem (veredito, atacante apontado, análise e candidatos), ações, recomendações e decisões | `#/relatorio/<id>` | funciona com o log; com um log anterior ao contrato 0.6.0, diz o que o log não traz |
| Chat com o modelo | `#/chat` (e o antigo `#chat`) | funciona com o backend; ferramenta da equipe |

Ficam fora da navegação, só pela âncora: **Ao vivo** (`#/ao-vivo`), cortada da versão final em
02/11, que só lê um log que outro processo grava quando `VITE_LOG_AO_VIVO` aponta para ele;
**Entrar** (`#/entrar`), só o visual, porque o SentryIoT não tem login; e **Componentes**
(`#/componentes`), o catálogo do design system, ferramenta da equipe.

Todas as telas que dependem do log mostram o estado até o cursor do replay, que fica no pé:
botões, trilha com marcas (incidente aberto, proposta que pede uma pessoa, decisões humanas),
teclado (← → Home End Espaço) e clique numa linha do histórico. Sem log, o replay some do pé, a
visão geral fica em zero e cada tela diz que nenhum log foi carregado.

### O que a versão final não faz, e onde ligar

- **Decisões pela interface** (aprovar, rejeitar, marcar como já resolvido) passam por
  `src/operacao.ts` e chegam ao backend enquanto os agentes de uma simulação rodam. Uma execução
  da rodada final é só leitura: os botões não aparecem. Num log da variável, não há agente para
  agir: os botões abrem o diálogo de confirmação, e ele mostra que a decisão não foi gravada e o
  comando de terminal que faz a mesma coisa (`python -m codigo.mcp.aprovar …`).
- **Login:** não existe; passa pela mesma `src/operacao.ts`.
- **Log de outra execução:** com `VITE_LOG_DE_EVENTOS`, a interface lê esse log em vez da rodada
  final. O backend não serve o log que o sistema grava (`dados/eventos/eventos.jsonl`): ponha o
  arquivo em `public/dados/` (fora do git, porque o log pode ter endereços reais) e aponte a
  variável para ele, como `/dados/eventos.jsonl`.
- **Ao vivo:** fora da versão final e da navegação. Com `VITE_LOG_AO_VIVO` apontando para um log
  que está sendo gravado (servido por HTTP), a tela `#/ao-vivo` o lê a cada 3 segundos e ignora a
  última linha incompleta.
- **Onde cada modelo roda:** desde o contrato 0.5.0, cada `llm_chamada` diz se rodou no modelo
  local ou na nuvem. Para um log mais antigo, liste os modelos em `VITE_MODELOS_LOCAIS` e
  `VITE_MODELOS_NA_NUVEM` (separados por vírgula). No chat, o backend diz que os modelos dele são
  locais (o perfil `LLM_*`); um modelo sem lugar nenhum aparece como nuvem, o caso que pede
  cuidado. Os experimentos rodam só no modelo local: a Tela 4 mostra a comparação com a nuvem só
  num log que tenha chamadas dos dois lados.

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
As outras telas abrem na rodada final que vem em `public/dados/rodada-final/`; sem ela (antes de
gerá-la), abrem vazias e dizem como gerar.

**Em produção** (o servidor da equipe) não há Vite: `npm run build` gera `dist/`, e o mesmo
backend serve essa pasta na raiz e a API em `/api`, num processo só:

```
cd frontend && npm ci && npm run build
cd .. && python -m codigo.api --host <endereço Tailscale> --port 8000
```

A receita completa está em `codigo/api/README.md`. O replay funciona sem API e sem conexão
externa: fontes, imagens e os dados da rodada final vão no build. Para só ver a rodada, sem
backend, `npm run build && npm run preview` basta.

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

- **Rodada final** (`src/rodada.test.ts`): o índice conferido, a leitura do gzip pelos bytes
  mágicos e do texto já aberto, o log ausente e o seletor de grupo, pcap, incidente e repetição.
- **Conversa dos agentes** (`src/conversa.test.ts`): o papel de cada mensagem, a ligação de cada
  resultado à tool pedida e as etapas do incidente na ordem, com e sem a conversa no log
  (`src/conversa-de-teste.ts` acrescenta ao log de exemplo uma conversa curta, feita à mão).
- **Telas na rodada** (`src/telas-rodada.test.tsx`): a navegação da versão final, a barra da
  execução, a tela Rodada final, o detalhe só leitura com as medidas, a aba da conversa, a Tela 4
  só local, o relatório com o aprovador automático e a volta da simulação, com o índice de
  `src/rodada-de-teste.ts`.
- **Leitura e reconstrução** (`src/log.test.ts`): o log de exemplo do stub, lido direto de
  `codigo/mcp/exemplos/incidente_flood.jsonl`, e variações dele (duplicados, ordem trocada,
  incidente sem abertura, campo ausente, HTML no log, linha cortada) e um caso para cada regra de
  sequência do `reconstruir`. É o único lugar em que esse log entra.
- **Contrato** (`src/contrato.test.ts`): as listas de `src/listas.ts` contra o `contrato.json` e o
  `acoes.py`.
- **Adaptador** (`src/adaptador.test.ts`): cada número e estado que a tela mostra, no log de
  exemplo, e o vocabulário do design system contra o contrato (21 tipos de evento, 10 motivos de
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
| `src/rodada.ts` | O índice da rodada final, o log de cada execução (gzip ou texto) e o seletor de execução |
| `src/conversa.ts` | O incidente de ponta a ponta: as etapas dos agentes, com a conversa de cada um, e as decisões entre elas |
| `src/adaptador.ts` | Do log aos objetos que os componentes desenham |
| `src/paginacao.ts` | Onde cada página A4 do relatório quebra, a partir das alturas medidas no navegador |
| `src/formato.ts` | A hora dos eventos no fuso de quem abre a página |
| `src/rotas.ts` | A tela pela âncora |
| `src/operacao.ts` | Decisões e login; hoje, o comando de terminal equivalente |
| `src/chat.ts` | As chamadas de `/api/chat`, `/api/modelos` e `/api/prompts` |
| `src/dados/qualidade.ts` | A matriz de confusão da Tela 5 e as métricas tiradas dela |
| `src/App.tsx` | Carrega a rodada final (ou o log da variável), troca a execução, liga e desliga a simulação, guarda a rota e o replay e escolhe a tela |
| `src/telas/` | As telas, a moldura (`Moldura.tsx`), o replay (`replay.ts`) e as peças comuns (`comum.tsx`) |
| `src/design-system/` | O design system: guia, componentes, tokens, fontes e marca |
| `src/estilo.css` | O pouco que as telas acrescentam ao design system |
| `scripts/gerar-tokens.mjs` | Gera o `tokens.css` do `tokens.json` |

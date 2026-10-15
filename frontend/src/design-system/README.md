# Design system SentryIoT

Este é o guia visual da interface do SentryIoT. Toda tela nova usa só estes componentes, estes tokens e este vocabulário; o visual anterior da interface foi descartado em 15/10/2026. Quem desenha ou muda uma tela lê este arquivo e o `COMPONENTES.md` antes.

SentryIoT é a interface de um sistema de **detecção e resposta a intrusões em redes IoT** (NIDR): um Random Forest classifica janelas de tráfego, janelas parecidas viram um incidente e três agentes de IA (Triagem, Decisão e Execução) cuidam dele, com aprovação humana para o que é arriscado. A interface só lê o log de eventos. Ela é a cara do trabalho na banca (projetor, modo replay, sem internet) e nas figuras do artigo (muitas vezes impressas). Tudo aqui serve a essas duas situações.

## Neste repositório

| Caminho | O que é |
|---|---|
| `README.md` | este guia |
| `COMPONENTES.md` | as regras de uso de cada componente e de cada tela |
| `tokens.json` | os tokens (cores, tipografia, espaços, raios, sombras, tamanhos, tempos); a fonte de tudo |
| `tokens.css` | gerado de `tokens.json` por `npm run tokens` (`scripts/gerar-tokens.mjs`); não se edita à mão |
| `styles.css` | o CSS dos componentes (classes `sx-*`), feito só de variáveis de `tokens.css` |
| `components/` | os componentes React, o vocabulário (`vocab.ts`), os tipos que eles desenham (`modelos.ts`), os formatos (`util.ts`) e os ícones (`icons-data.ts`) |
| `fonts/`, `logos/` | as fontes (licença SIL OFL 1.1, em `fonts/OFL-*.txt`) e a marca |
| `index.ts` | a porta de entrada: as telas importam daqui, e não de `components/` |

A origem é o design system "SentryIoT" publicado pela equipe. Mudança visual se faz lá e se traz para cá arquivo por arquivo: `tokens.json` (depois `npm run tokens`), `styles.css` (o `components/bundle.css` do artefato), os componentes de `components/src/` e as regras de uso. Os ajustes que o repositório fez sobre o artefato estão listados no fim deste arquivo; numa nova sincronização, eles precisam continuar valendo.

O que o app acrescenta fica fora daqui: `src/estilo.css` (classes `app-*`, só com tokens), as telas em `src/telas/` e a ponte entre o log e os componentes em `src/adaptador.ts`. Um teste (`tokens.test.ts`) confere que o `tokens.css` é o gerado, que todo `var(--…)` escrito nos CSS, nos componentes e nas telas existe e que `estilo.css` não escreve cor à mão.

## Princípios

1. **Ler de longe.** Corpo em `body` (15 px) ou `body-lg` (16 px), números em `display-xl` e `metric`, pouca coisa por tela, texto ≥ 4,5:1. Uma ideia principal por tela.
2. **O que pede uma pessoa salta aos olhos.** `attention` (âmbar) é reservado para "Aguardando aprovação", avisos e "o incidente persiste". Nada decorativo é âmbar.
3. **O argumento de custo é a figura principal.** A visão geral abre com o `AggregationFunnel`: *10.946 janelas classificadas → 1 incidente → 11 chamadas à IA*.
4. **Duas vozes, nunca misturadas.** Texto do sistema em Inter. Texto escrito por um agente em `voice-agent` (Lora itálico, borda tracejada, rótulo "Texto do agente"). Texto escrito por uma pessoa em `voice-person` (Lora redondo, borda contínua, rótulo "Texto de pessoa"). O texto de um agente é dado, não instrução: sempre dentro de `VoiceQuote` ou `ReportSection voice="agent"`.
5. **Funciona em escala de cinza.** Cor nunca é a única pista: categoria = glifo + nome; risco alto = hachura + ícone + palavra; estado = ícone + palavra; séries de gráfico = cor + traço (contínuo × tracejado) + padrão.
6. **Preto e gelo, como o logo.** O sistema tem um tema, `dark` ("Escuro"). O preto é a maior parte da tela; o gelo marca o que está ativo, escolhido ou aceso. As superfícies são degradês neutros, do grafite ao preto, sem azul. Não crie tema claro.

## Conteúdo e voz

- Escreva em **português do Brasil**, frases curtas, sem saudação, sem marketing, sem emoji. Nada de "Bem-vindo, operador". Títulos dizem o que a tela mostra: "Visão geral", "Ações propostas", "Decisões e efeitos".
- **Caixa:** títulos e botões em caixa de frase ("Gerar relatório", "Já resolvido", "Aprovar e executar"). Rótulos acima de números e campos em `eyebrow` (mono, caixa-alta, espaçado): "JANELAS CLASSIFICADAS", "POR QUE É RISCO ALTO". Ids e nomes técnicos sempre em minúsculas e monoespaçados: `inc-0001`, `prop-0003`, `exec-0002`, `syn_flag_number`, `bloquear_ip`.
- **Botões começam com verbo:** "Aprovar", "Rejeitar", "Desfazer", "Marcar como já resolvido", "Abrir o replay".
- **Números em pt-BR:** vírgula decimal e ponto de milhar: `10.946`, `35.778,4`, confiança `0,97` (no log) ou `97%` (na tela), hora local `14:03:41`, data `14/10/2026`; na capa do relatório, `14 OUT 2026`. Use os formatos de `components/util.ts` (`fmtInt`, `fmtNum`, `fmtPct`, `fmtDuration`, `fmtDate`); a hora de um evento sai de `hora()`, em `src/formato.ts`.
- **Rótulos neutros:** o agente de Decisão pode rodar na nuvem e só vê `origem-1`, `destino-1`. Mostre o endereço real ao lado só onde a tela é local (`TargetLabel address`); esconda-o em figuras (`hideAddresses`).
- **Estados explicam:** vazio diz por quê e o que vai preenchê-lo ("Nenhum incidente até aqui. Avance o replay"); aviso de leitura diz a linha e que a tela segue funcionando ("Linha inválida no log, ignorada · linha 37").
- **Telas que ainda não existem** levam o selo "Planejada"; dados que não vêm do log levam o aviso "Valores ilustrativos". Nunca apresente valor ilustrativo como resultado.

### Vocabulário oficial (exatamente como aparece)

| Grupo | Rótulos |
|---|---|
| Categorias do incidente (8) | DDoS · DoS · Mirai · Recon · Spoofing · Web · BruteForce · Benign |
| Classes do modelo (7) | DDoS+DoS · Mirai · Recon · Spoofing · Web · BruteForce · Benign |
| Incidente | Aberto · Encerrado · Marcado como já resolvido |
| Proposta de ação | Aguardando aprovação · Liberada · Rejeitada · Executada · Desfeita |
| Execução | Aplicada · Desfeita |
| Efeito verificado | o incidente cessou · o incidente diminuiu · o incidente persiste |
| Risco | Risco baixo · Risco alto |
| Agente | Triagem · Decisão · Execução |
| Canal da decisão humana | pelo terminal · pela interface |
| Eventos (16) | Janelas classificadas · Incidente aberto · Incidente atualizado · Incidente encerrado · Marcado como já resolvido · Chamada à IA · Chamada de tool · Recomendação emitida · Proposta criada · Aprovada · Rejeitada · Executada · Desfeita · Efeito verificado · Promovida ao catálogo · Recusada pelo servidor |

Os nove motivos de risco alto (o texto lido antes de aprovar) estão em `vocab.RISK_REASON`, que é o próprio `MOTIVOS_DE_RISCO_ALTO` do contrato; use-os sem reescrever.

## Fundamentos visuais

### Cor

- **Preto e gelo, as cores do logo.** O preto é a maior parte: o chão das telas e a barra lateral são `bg-0`, o preto do fundo do logo. O gelo (`ice`) é o destaque e a diferenciação, nunca o fundo de uma área grande. O azul escuro não entra em superfície, borda nem navegação.
- **Do grafite ao preto, em degradê neutro.** Cada painel é um degradê suave com a luz vindo do alto à direita: começa em `graphite-800` (o canto aceso), passa por `bg-1` e termina em `bg-0`. Dentro dos painéis, o que é para ler ou digitar fica num **poço** de `scrim` (preto translúcido): campos, prompt, motivos de risco, texto de pessoa, código e cabeçalho de tabela. Cartões dentro de painel (proposta, texto do agente, balão do modelo) descem de `graphite-900` a `bg-1`. As receitas prontas estão em **Degradês**, logo abaixo.
- **Camadas, do mais fundo ao mais alto:** chão (`bg-0`) → painel (`graphite-800` → `bg-1` → `bg-0`) → poço (`scrim`) ou cartão (`graphite-900` → `bg-1`) → selo e trilho (`surface-2` = `graphite-900`) → popover e tooltip (`surface-3` = `graphite-800`). `bg-1` e `surface-1` ficam como cores planas de apoio.
- **Linhas:** `line-1` para bordas de painel e divisores de tabela; `line-2` (= `graphite-700`) para divisor forte e hover; `line-control` para borda de campo e controle (≥ 3:1 em qualquer superfície).
- **Texto:** `ink-1` principal; `ink-2` (= `slate-300`) secundário; `ink-3` para rótulos mono, horários e metadados, nunca abaixo de 12 px; `ink-4` (= `slate-600`) só para desabilitado.
- **Gelo, o acento tirado do logo:** `ice` preenche o botão primário e marca o que está ativo (item da barra lateral, cursor do replay, número das chamadas à IA). Texto sobre gelo é sempre `on-ice`. A borda acesa dos painéis, a seleção e os fios do funil também são gelo, em transparência. `glacier` é o gelo saturado e fica para dados e foco: anel de foco, links, série principal de gráfico, barras de comparação, estado informativo. `glacier-deep` só para preenchimentos de gráfico. `ice-tint-1` (hover) e `ice-tint-2` (selecionado) são véus de gelo; `ice-glow` é o brilho atrás do logo; `ice-haze` é a luz fraca nos cantos do chão.
- **Sinais:** `attention` (âmbar, pede uma pessoa), `danger` (coral: risco alto, erro, rejeitar/desfazer), `success` (menta: executada, aplicada, cessou), `info` (= `glacier`: aberto, diminuiu), `neutral` (estados finais sem juízo). Cada um tem `-tint` para fundo de selo e `-line` para borda; sobre preenchimento sólido use `on-attention`, `on-danger`, `on-success`. Sinal sempre acompanha ícone e palavra; nunca pinte uma área inteira de coral.
- **Categorias:** `cat-ddos`, `cat-dos`, `cat-flood` (DDoS+DoS), `cat-mirai`, `cat-recon`, `cat-spoofing`, `cat-web`, `cat-bruteforce`, `cat-benign`. Use só em `CategoryBadge`, `CategoryBars` e legendas, nunca em botões, painéis ou navegação. Benign é cinza de propósito.
- **Gráficos:** `chart-1` (série principal, contínua), `chart-2` (segunda série, sempre tracejada), `chart-grid`, `chart-axis`; mapa de calor da matriz de confusão em `heat-1` → `heat-5` (texto `ink-1` até `heat-3`, `on-ice` em `heat-4` e `heat-5`).

### Degradês

Receitas em `components/bundle.css` (variáveis CSS feitas só de tokens). Use-as em vez de uma cor plana:

| Variável | Feita de | Onde |
|---|---|---|
| `--sx-ground` | `bg-1` → `bg-0` → `bg-0` → `bg-1` (155°) | Chão de todas as telas, login, mesa do relatório |
| `--sx-surface` | `graphite-800` → `bg-1` → `bg-0` (200°) | Painel, cartão de métrica |
| `--sx-surface-lit` | `graphite-800` → `graphite-900` → `bg-1` → `bg-0` (200°) | Funil da visão geral, modal |
| `--sx-rail` | `bg-1` → `bg-0` (de cima para baixo) | Barra lateral, preta |
| `--sx-card` | `graphite-900` → `bg-1` (de cima para baixo) | Proposta, texto do agente, balão do modelo |
| `--sx-edge` · `--sx-edge-strong` | `ice` translúcido no canto aceso → `line-1` (ou `line-2`) | Borda de painel; borda de modal, dock e cartão do login |
| `--sx-select` | `ice` 12 % → 3 %, da esquerda para a direita | Linha selecionada da fila, evento atual |

A borda acesa usa a técnica de duas camadas: `background: var(--sx-surface) padding-box, var(--sx-edge) border-box; border: 1px solid transparent`. Uma variante que precisa de borda de sinal (aguardando aprovação) só troca `border-color`. Uma cor (como `scrim`) só pode ser a última camada de um `background`; antes dela, escreva `linear-gradient(var(--scrim), var(--scrim))`.

### Tipografia

- **Inter Display** (`display`) para números e títulos a partir de 24 px: `display-xl` (os três contadores do funil), `display-lg` (título do login), `display-md` (título da capa do relatório), `metric` (número do cartão), `title-1` (título da tela, um por tela), `title-2` (seção e modal).
- **Inter** (`sans`) para a interface: `title-3` (título de painel), `body-lg`, `body`, `body-strong`, `body-sm`, `label` (selos, segmentos, rótulos de campo).
- **Source Code Pro** (`mono`) para o técnico: `eyebrow` (caixa-alta, 0,16em), `eyebrow-wide` (caixa-alta, 0,32em: login e relatório), `data` (IPs, ids, features), `data-sm` (horários e ids em linhas densas), `code` (linhas cruas do JSONL).
- **Lora** (`voice`) só para as duas vozes: `voice-agent` (itálico) e `voice-person` (redondo). Nunca em rótulo, botão ou instrução do sistema.
- Algarismos tabulares (`tabular-nums`) em números de tabela, métricas e no funil; **nunca** em títulos: a Inter alarga o hífen de `inc-0001` com algarismos tabulares.
- O corpo liga `cv05` e `cv08` da Inter: separa `l`, `I` e `1` em nomes e ids.
- As fontes são arquivos locais (`fonts/*.woff2`). Nada de CDN: a banca roda sem internet.

### Espaço, raio e layout

- Base de 4 px: `space-1` 4 · `space-2` 8 · `space-3` 12 · `space-4` 16 · `space-5` 20 · `space-6` 24 · `space-8` 32 · `space-10` 40 · `space-12` 48 · `space-16` 64. Painel com padding `space-6`; cartão de proposta `space-5`; gap entre painéis `space-6`.
- Cantos bem arredondados, como nas referências: `radius-pill` em botões, selos, segmentos e itens de navegação; `radius-lg` em painéis e cartões; `radius-xl` na barra lateral, no modal e no cartão do login; `radius-md` em blocos internos (citação, motivos, aviso); `radius-sm` em campos; `radius-xs` no glifo de categoria e nas células do mapa de calor.
- **Moldura do app (`AppShell`):** sobre o chão preto (`--sx-ground`) com a luz do logo: névoa `ice-haze` em dois cantos e raios diagonais finos na faixa do cabeçalho (`backdrop`, ligado por padrão, decorativo); barra lateral flutuante (`sidebar-wide` 264 px, `sidebar-rail` 76 px recolhida), conteúdo em grade de 12 colunas (`.sx-grid`, `.sx-span-4/6/8/12`, gap `space-6`) e o dock do replay (`dock-height` 72 px) preso ao pé. Desenhe para 1440 × 900 e confira em 1920 × 1080.
- **Controles:** `control-sm` 32 px (tabela, dock), `control-md` 40 px, `control-lg` 48 px (login, modal). Ícones `icon-sm` 16, `icon-md` 20, `icon-lg` 24.

### Vidro, sombra e elevação

- Painel = degradê `--sx-surface` + borda acesa `--sx-edge` + `shadow-1`. Cartão de métrica igual; funil e modal com `--sx-surface-lit`; barra lateral preta (`--sx-rail`), com borda, textos e ícones em gelo de força menor e a grade de pontos, também em gelo, no vão vazio acima do rodapé.
- Botão secundário e redondo = vidro: véu `ice-tint-2` → `ice-tint-1` sobre `surface-2`, borda `line-2`, `shadow-glass` (reflexo interno no topo, como o "SOURCE BTN").
- Popover, tooltip e dock = `shadow-2`. Modal = `shadow-3` sobre `scrim` com 6 px de desfoque. O dock do replay é vidro preto (`scrim` + 16 px de desfoque) e o cartão do login também (12 px): são os únicos desfoques atrás de conteúdo.
- `shadow-attention` (halo âmbar) só no que aguarda aprovação: cartão de proposta, cartão de métrica.
- Nunca desfoque atrás de texto de painel: o projetor e a impressão perdem legibilidade.

### Movimento

`duration-fast` (hover, foco), `duration-base` (recolher a barra lateral, avançar o replay), `duration-slow` (modal) com `ease-standard`; saídas com `ease-exit`. O único movimento contínuo é o pulso `duration-pulse` do ponto "aguardando aprovação" e do "AO VIVO". Com `prefers-reduced-motion`, tudo para.

### Estados

- **Hover:** `ice-tint-1`. **Selecionado:** na barra lateral, o item ativo é preenchido de `ice` com texto `on-ice`; na linha da fila (com a barra de gelo à esquerda) e no evento atual da linha do tempo, `--sx-select` (véu de gelo); em controles (segmento, opção, provedor), `ice-tint-2`. **Desabilitado:** `opacity-disabled`.
- **Foco do teclado:** sempre visível, com `focus-ring` (2 px de `bg-1` + 2 px de `glacier`), ≥ 3:1 em todas as superfícies. Replay, modal, segmentos e gráficos funcionam pelo teclado.
- **Replay:** eventos depois do cursor ficam em `opacity-future`; o evento do cursor ganha o selo "agora". Todas as telas mostram o estado até o evento do cursor.
- **Carregando:** `Skeleton`. **Vazio:** `EmptyState`. **Aviso de leitura:** `Alert` com `line` ou `event`.

## Marca

- A marca é a escultura de vidro (`logos/sentryiot-mark.png`, fundo transparente). O nome é composto em Inter Display: "Sentry" em 600 e "IoT" em 300 na cor `ice`, seguido do descritor `NIDR` em mono. Use sempre o componente `Logo` (`sm` 24 px na barra recolhida, `md` 32 px na barra lateral, `lg` 52 px no login e no relatório, `xl` 76 px).
- Só sobre chão escuro (`bg-0` a `surface-2`). Não recolora, não contorne, não achate e não ponha sobre fundo claro: o vidro é transparente e some. Deixe em volta pelo menos metade da altura da marca.
- Tamanhos: `sentryiot-mark-128.png` para interface, `sentryiot-mark-512.png` e `sentryiot-mark.png` para telas grandes, `sentryiot-mark-64.png` como favicon. O arquivo recebido, com fundo preto, fica só no design system publicado. Nas telas, as imagens vêm de `ASSETS` (`assets.ts`).
- A marca grande e acesa (`GlassBackdrop`) aparece só no login e na capa do relatório: logo à direita, sangrando a borda, com `ice-glow`, placas de vidro translúcidas, luz diagonal e grade de pontos no canto inferior esquerdo. É decorativa (`aria-hidden`). As outras telas herdam só a luz (névoa de gelo e raios diagonais do `AppShell`), nunca a marca grande atrás de dados.

### Login

Chão `--sx-ground` com luz `ice-haze` atrás da marca e `GlassBackdrop variant="login"`. Coluna esquerda: `Logo lg` e a linha `eyebrow-wide` "DETECÇÃO E RESPOSTA / A INTRUSÕES EM REDES IOT"; barra de acento (`.sx-accent-bar`), `eyebrow-wide` "RESPOSTA AUTÔNOMA A INTRUSÃO", título `display-lg` "Entrar"; cartão de vidro preto (`scrim`, canto aceso em `graphite-800`, borda `--sx-edge-strong`) com `TextField size="lg"` para usuário e senha, `Button variant="primary" size="lg"` "Entrar" e `Button variant="secondary"` "Abrir o replay". Canto superior direito: "ACESSO DO OPERADOR ——" e "DETECTA. / RESPONDE."; inferior direito: o selo "ACESSO RESTRITO". Cabe em 1440 × 900.

### Relatório gerado pela LLM

- Página A4 a 96 dpi (794 × 1123 px), fundo `bg-0`, impressa com `@page A4` e `print-color-adjust: exact`.
- **Capa (`ReportCover`)**, na composição da capa de referência: logo e tagline à esquerda; "RELATÓRIO DE INCIDENTE ——" e "DETECTA. / RESPONDE." à direita; barra de acento, `eyebrow-wide` "RESPOSTA AUTÔNOMA A INTRUSÃO", título `display-md` ("inc-0001 · DDoS contra destino-1"), linhas de metadados com caixa de ícone, rótulo mono e valor (Incidente, Categoria, ID do relatório, Alvo), barra de acento e a data "14 OUT 2026 — MODO REPLAY"; no pé, o selo "CONFIDENCIAL" em gelo e "ESTE DOCUMENTO CONTÉM / INFORMAÇÕES SENSÍVEIS.".
- **Páginas (`ReportPage` + `ReportSection` numeradas "01", "02"…):** o que vem do log fica na voz do sistema (`ReportFacts`, tabelas, selos); **todo texto que a LLM escreve** vai em `ReportSection voice="agent"`: Lora itálico em bloco tracejado com o selo "Gerado pelo agente · Triagem". Decisões humanas citam a pessoa com `VoiceQuote voice="person"`.

## Iconografia

- **Lucide** (licença ISC), traço 1,6 px em grade 24 × 24, desenhado com `currentColor` pelo componente `Icon`. Tamanhos: 16 px em selos e tabelas, 20 px em botões e navegação, 24 px em cabeçalhos e estados vazios. O projeto não tinha ícones próprios; o Lucide é o conjunto de traço fino mais próximo das referências.
- Cada termo do domínio tem um glifo fixo: use o mapa de `vocab` (`CATEGORY`, `AGENT`, `EVENT`, `INCIDENT_STATE`, `PROPOSAL_STATE`, `EFFECT`, `RISK`, `CHANNEL`), não escolha ícones na hora. Os glifos estão desenhados em `components/icons-data.ts` (Lucide, licença ISC em `components/LICENCA-LUCIDE.txt`).
- Categorias: DDoS `merge` · DoS `arrow-right-to-line` · DDoS+DoS `waves` · Mirai `worm` · Recon `radar` · Spoofing `venetian-mask` · Web `code-xml` · BruteForce `key-round` · Benign `circle`. Agentes: Triagem `list-filter` · Decisão `scale` · Execução `wrench`. Risco: baixo `shield-check` · alto `triangle-alert`.
- Sem emoji. Teclas de atalho em `Kbd`.

## Componentes

| Grupo | Componentes | Quando usar |
|---|---|---|
| Marca | `Logo`, `GlassBackdrop`, `Icon`, `Kbd` | Marca na moldura; fundo do login e da capa; ícones; teclas. |
| Ações | `Button`, `IconButton` | Um `primary` (gelo) por tela; `secondary` de vidro para o resto; `danger` para rejeitar e desfazer; `confirm` e `danger-solid` só dentro do modal. |
| Selos | `CategoryBadge`, `StatusBadge`, `RiskBadge`, `AgentBadge`, `ChannelTag`, `TargetLabel` | Categoria (incidente sólido, modelo tracejado), estado, risco, agente, canal da decisão, rótulo neutro. |
| Navegação | `AppShell`, `Sidebar`, `PageHeader`, `ModeIndicator`, `Segmented`, `Tabs`, `Panel` | Moldura, navegação larga/recolhida, título da tela, replay × ao vivo, superfícies. |
| Formulários | `TextField`, `Select` | Login, motivos de decisão, prompt de sistema. |
| Dados | `AggregationFunnel`, `MetricCard`, `IncidentQueue`, `ClassifierVerdict`, `ConfidenceMeter`, `FeatureTable`, `AddressList` | Funil do argumento, números, fila, veredito com as duas categorias, features contra o benigno, origens e destinos. |
| Agentes e decisões | `EventTimeline`, `ProposalCard`, `VoiceQuote` | Linha do tempo com hora e id em toda linha, proposta com estado e motivos, as duas vozes. |
| Replay | `ReplayControl` | Dock do log: início, anterior, reproduzir, próximo, fim, trilha com marcas e "evento 23 de 52". |
| Avisos | `Alert`, `EmptyState`, `Skeleton`, `Tooltip`, `ConfirmDialog` | Informação, atenção, erro e avisos de leitura; vazio; carregando; dica; aprovar, rejeitar e marcar já resolvido. |
| Gráficos | `AreaChart`, `CategoryBars`, `ConfusionMatrix` | Tempo (tokens, latência), barras por categoria com padrão para impressão, matriz 7 × 7. |
| Chat | `ChatMessage`, `PromptBox`, `ModelSelect`, `ProviderBar` | Chat da equipe com o modelo e barra de provedores local × nuvem. |
| Relatório | `ReportCover`, `ReportPage`, `ReportSection`, `ReportFacts` | O relatório A4 que a LLM gera no fim. |

## Telas

As telas ficam em `src/telas/`, montadas só com estes componentes e com os dados do log (`src/adaptador.ts` traduz cada evento para os objetos de `components/modelos.ts`):

| Tela | Arquivo | Estado |
|---|---|---|
| Visão geral (funil, cartões, fila) | `VisaoGeral.tsx` | funciona com o log |
| Detalhe do incidente | `Incidente.tsx` | funciona com o log; no fim do replay, aprovar, rejeitar e "já resolvido" abrem o diálogo, que explica que a interface ainda não grava e mostra o comando do terminal |
| Ao vivo | `AoVivo.tsx` | planejada; lê o log que está sendo gravado quando `VITE_LOG_AO_VIVO` aponta para ele; sem a variável, fica vazia |
| Tela 3, Isolado × integrado | `IsoladoIntegrado.tsx` | contagens, veredito e propostas do log |
| Tela 4, Custo e latência | `CustoLatencia.tsx` | funciona com o log; local × nuvem aparece quando `VITE_MODELOS_LOCAIS` e `VITE_MODELOS_NA_NUVEM` dizem onde cada modelo roda |
| Tela 5, Qualidade do modelo | `QualidadeModelo.tsx` | matriz real da configuração 5 (`src/dados/qualidade.ts`, conferida contra o CSV do experimento) |
| Tela 6, Segurança do MCP | `SegurancaMcp.tsx` | planejada; vazia até o teste de tool poisoning rodar |
| Chat com o modelo | `Chat.tsx` | funciona com o backend (`/api/chat`, `/api/modelos`, `/api/prompts`) |
| Relatório | `Relatorio.tsx` | capa e páginas A4 com os fatos, as recomendações e as decisões do log; o sumário escrito pela IA é planejado |
| Entrar | `Entrar.tsx` | visual pronto; o login passa por `src/operacao.ts`, que hoje explica que ainda não há login |
| Componentes | `Componentes.tsx` | o catálogo deste design system; os blocos de dados usam o log e, sem log, ficam vazios |

## Uso no app

- Leia cor, espaço, raio, sombra e tamanho só pelas variáveis CSS de `tokens.css`; nunca cole um hexadecimal num componente ou numa tela.
- Os componentes são React 18 + TypeScript com CSS puro (classes `sx-*`). Nenhuma biblioteca de componentes.
- Fontes e imagens vão no build; nada vem de CDN.
- Texto escrito por agente (recomendação, justificativa, descrição de ação nova, alvo em texto livre) aparece na voz dele; a chamada de tool mostra só chaves e identificadores; a mensagem de recusa do servidor, que pode repetir trecho do agente, vai entre aspas.
- Os rótulos da tela vêm de `vocab.ts`, e não do log. Os valores do vocabulário (categorias, estados, tipos de evento, motivos de risco alto) são os do contrato do log (`codigo/mcp/contrato.json`, por `src/listas.ts` e `src/types.ts`): quando o contrato muda, o TypeScript e os testes apontam o que falta.
- Decisões humanas e login passam por `src/operacao.ts`. Para ligar a interface ao servidor, basta escrever lá uma operação que chame as rotas novas.

## Ajustes sobre o artefato

O repositório mudou estes pontos dos componentes do artefato. Numa nova sincronização, eles continuam valendo:

- `vocab.ts` usa os valores do contrato: `aguardando_aprovacao` em vez de `aguardando`, os 16 tipos de evento com o nome do log (`llm_chamada`, `acao_proposta`…), os nove motivos de risco alto do contrato (o artefato trazia oito, com dois juntos e um cortado) e as palavras de cada motivo de recusa do servidor (`REFUSAL_REASON`).
- `modelos.ts` guarda os tipos que eram de `sample.ts`. Os dados de exemplo do artefato não vieram: as telas e o catálogo usam o log carregado e, sem log, ficam vazios. A interface não traz dado simulado.
- `ProposalCard` mostra a justificativa do agente (voz de agente), o selo "promovida ao catálogo" e a decisão humana sempre com "Aprovada" ou "Rejeitada", mesmo quando há motivo.
- `TargetLabel` recebe `free`, para o alvo em texto livre de uma ação nova, na voz do agente.
- `ConfirmDialog` recebe `details` (a ação nova descrita pelo agente) e `logNote` (o que vai para o log), e o Esc não cancela durante o envio.
- `ReplayControl` não pega as teclas de um botão em foco, de um grupo de opções, de um gráfico, de um diálogo aberto nem com tecla modificadora.
- `AreaChart` não desenha um ponto que deixou de existir quando a série diminui, e aceita `height="fill"`, que ocupa a altura do contêiner.
- A barra lateral (`.sx-app__side`) ocupa sempre a altura da janela; o artefato a limitava a 960 px, o que deixava um vão embaixo em telas altas.
- A paleta é preto e gelo, como o logo (`tokens.json` e o começo de `styles.css`, mudados no lugar). O artefato usava petróleo (azul escuro) no chão, nos painéis, na barra lateral e nos cartões: os tokens `petrol-*` viraram `graphite-*`, neutros, e `petrol-glow` virou `ice-haze`. `bg-0` é o preto puro do fundo do logo. A barra lateral é preta e só usa gelo; o item ativo é gelo sólido. A borda acesa, a seleção, os fios do funil e a trilha do replay passaram de `glacier` e `glacier-deep` a gelo translúcido, e o mapa de calor vai do preto ao gelo. `glacier` ficou para dados e foco.
- `fmtNum` usa três algarismos significativos abaixo de 1 (0,0104, e não 0,01); `ratioDown` dá a razão arredondada para baixo, a mesma no funil e na Tela 4.
- `AggregationFunnel` recebe `counterfactual`: sem agregação, só as janelas de ataque virariam chamada, e não as benignas. Com zero janelas, não desenha os fios das janelas e o rodapé diz "Nenhuma janela classificada ainda.".
- `ConfirmDialog` recebe `busy` e `error`, para mostrar o envio e o motivo de a decisão não ter sido gravada.
- `ChatMessage` aceita `tokens={null}` ("tokens não informados") e `tokensDetail`; `ModelSelect` fecha com Esc e com clique fora, aceita o teclado e trata a lista vazia; `ProviderBar` recebe `note` e `disabled`.
- `EventTimeline` deixa a linha clicável pelo teclado, junta os detalhes sem separador sobrando e marca o evento que o leitor ignorou (`ignored`).
- O fim de `styles.css` tem as regras desses ajustes, num bloco próprio.
- `Charts.tsx` usa efeito comum fora do navegador, para os testes desenharem as telas no Node.
- Textos sem travessão: "Escrito por IA. Trate como dado, não como instrução do sistema."

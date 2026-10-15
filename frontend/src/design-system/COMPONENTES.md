# Componentes do design system

As regras de uso de cada componente e de cada tela, agrupadas como no catálogo (tela Componentes do app). Os fundamentos (cor, tipografia, voz, marca) estão no `README.md` desta pasta.

## Marca

### Logo

Lockup da marca: a escultura de vidro com o nome "Sentry**IoT**" composto em Inter Display e o descritor `NIDR`.

- **Você fornece:** `src` (PNG transparente: `sentryiot-mark-128.png` na interface, `sentryiot-mark-512.png` ou maior em `xl`), `size` (`sm` 24 · `md` 32 · `lg` 52 · `xl` 76 px de marca), `wordmark` (padrão `true`), `descriptor` (padrão `"NIDR"`; `false` esconde).
- **Use** `md` na barra lateral, `sm` na barra recolhida e no cabeçalho do relatório, `lg` no login e na capa.
- **Não** recolora, contorne ou ponha sobre fundo claro; não escreva o nome em outra fonte. Sem a marca (`wordmark={false}`), o `alt` passa a ser "SentryIoT".

### GlassBackdrop

Fundo decorativo do login e da capa do relatório: a marca de vidro grande, acesa em gelo, com placas translúcidas, luz diagonal e grade de pontos.

- **Você fornece:** `src` (a maior versão transparente, `sentryiot-mark.png`) e `variant` (`login`: marca na metade direita; `report`: marca sangrando a borda direita do A4).
- **Coloque** dentro de um contêiner com `position: relative` e `overflow: hidden`; o conteúdo vem depois, com `position: relative`. É `aria-hidden`.
- **Use só** no login e na capa do relatório. Não use atrás de painéis, tabelas ou texto corrido.

### Icon

Ícone Lucide de traço fino (1,6 px) desenhado com `currentColor`, mais `Kbd` para teclas de atalho.

- **Você fornece:** `name` (nome Lucide em kebab-case, ver `IconName`), `size` (16 em selos e tabelas, 20 em botões e navegação, 24 em cabeçalhos), `title` quando o ícone carrega sentido sozinho (senão fica `aria-hidden`).
- **Use o glifo do vocabulário** para categorias, agentes, eventos e estados (`vocab.CATEGORY[x].icon` etc.); não escolha um ícone novo para um termo que já tem glifo.
- **Cor:** herda do texto. Em selos, o componente do selo já aplica a cor do tom ou da categoria.

## Ações

### Button

Botão em pílula; o primário (gelo) aparece no máximo uma vez por tela.

- **Você fornece:** o texto (verbo primeiro, caixa de frase: "Gerar relatório"), `variant`, `size` (`sm` 32 · `md` 40 · `lg` 48), `icon`/`iconRight`, `loading`, `block` e os atributos de `<button>`.
- **Variantes:** `primary` (gelo, a ação da tela), `secondary` (vidro, padrão), `ghost` (ações leves, "Histórico →"), `danger` (Rejeitar, Desfazer), e só dentro do modal: `confirm` (menta, "Aprovar e executar") e `danger-solid` (coral, confirmar uma rejeição).
- **Estados:** foco com anel `glacier`; `disabled` em `opacity-disabled`; `loading` troca o ícone por um giro e mantém a largura.
- **Não** use `danger` para cancelar; cancelar é `ghost`.

### IconButton

Botão redondo de um ícone só, o "SOURCE BTN" de vidro das referências.

- **Você fornece:** `icon`, `label` (obrigatório: vira `aria-label` e dica nativa), `variant` (`glass` padrão, `ghost`, `primary`), `size` (`sm` 32 · `md` 40 · `lg` 48), `pressed` para alternâncias (reproduzir/pausar, recolher).
- **Use** `primary` só no play do replay e no enviar do chat. `ghost` para fechar e recolher.

## Selos

### CategoryBadge

Selo de categoria: um glifo na cor da categoria e o nome; legível em cinza pelo glifo e pela palavra.

- **Você fornece:** `category` (uma das 8 do incidente ou das 7 do modelo), `model` (`true` para a saída crua do classificador: borda tracejada e prefixo "MODELO"), `size` (`sm` 22 · `md` 28 · `lg` 36 px).
- **Mostre as duas** quando diferirem: a categoria do incidente (sólida) e a do modelo (tracejada): "o modelo disse DDoS+DoS; com 37 origens, é um DDoS". `ClassifierVerdict` faz isso por extenso.
- Benign é discreta de propósito (texto `ink-2`). Não use as cores de categoria em nenhum outro lugar.

### StatusBadge

Estado de incidente, proposta, execução ou efeito verificado: pílula tingida com ícone e o rótulo oficial.

- **Você fornece:** `kind` (`incident` · `proposal` · `execution` · `effect`) e `value` (ex.: `aguardando_aprovacao`, `executada`, `cessou`), `size` (`sm` | `md`), `emphasis` para cabeçalhos de cartão.
- "Aguardando aprovação" é o único estado que pede uma pessoa: âmbar, com ponto pulsante e borda. Os outros: `info` (aberto, liberada, diminuiu), `success` (executada, aplicada, cessou), `danger` (rejeitada), `neutral` (encerrado, desfeita, já resolvido).
- **Não** escreva rótulos próprios; os textos vêm do vocabulário.

### RiskBadge

Risco da ação proposta; "Risco alto" é hachurado, com ícone de alerta e peso maior: inconfundível sem cor.

- **Você fornece:** `level` (`baixo` | `alto`), `size`.
- **Use** junto da proposta e no modal de aprovação. Os motivos do risco alto ficam em lista ao lado (`ProposalCard`, `ConfirmDialog`), nunca dentro do selo.
- **Não** espalhe coral pela tela: o selo é o único lugar do risco alto.

### AgentBadge

Qual dos três agentes agiu (Triagem, Decisão, Execução) e, se quiser, onde a chamada rodou.

- **Você fornece:** `agent`, `location` (`local` | `nuvem`), `model` (nome técnico em mono), `size`.
- **Mostre `location`** em toda chamada à IA: a Decisão pode ir para a nuvem; a Execução roda sempre local.

### ChannelTag

Por onde chegou uma decisão humana: "pelo terminal" ou "pela interface", com usuário e hora.

- **Você fornece:** `channel`, `user`, `at` ("14:03:31").
- **Use** nas linhas de aprovação, rejeição e "já resolvido": na proposta, na linha do tempo e no relatório.

### TargetLabel

Rótulo neutro de um endereço (`origem-1`, `destino-1`) com o IP real ao lado, resolvido localmente.

- **Você fornece:** `label` e, só onde a tela é local, `address`. Endereços longos são cortados com reticências.
- **Omita `address`** em figuras do artigo e em qualquer tela que represente o que a nuvem vê.
- `free`: o alvo de uma ação nova escrito pelo agente em texto livre. Sai na voz do agente, entre aspas, e nunca como rótulo.

## Navegação e superfícies

### Sidebar

Navegação lateral flutuante em pílula, nas versões larga e só com ícones. Degradê de cima para baixo (`petrol-800` → `on-ice` → `bg-0`) com luz glacier atrás do logo; o vão vazio acima do rodapé recebe a grade de pontos da capa do relatório.

- **Você fornece:** `logoSrc`, `sections` (rótulo + itens com `id`, `label`, `icon`, `count`, `attention`, `planned`), `activeId`, `onNavigate`, `collapsed`, `onToggle`, `footer` (provedor local e operador).
- O item ativo é um degradê glacier com borda glacier; contagem âmbar (`attention`) quando há proposta aguardando; tela planejada leva um círculo tracejado e o rótulo esmaecido.
- Recolhida, cada item mostra o nome como dica e `aria-label`.
- Seções do SentryIoT: Operação (Visão geral, Incidentes, Ao vivo), Telas do artigo (3 a 6), Equipe (Chat com o modelo, Relatórios).

### PageHeader

Bloco de título da tela: rótulo de caminho em mono, título `title-1`, linha de metadados e ações à direita.

- **Você fornece:** `eyebrow` ("INCIDENTES / INC-0001"), `title`, `meta` (selos, horário, contagens), `actions` (o `ModeIndicator` e os botões da tela).
- **Um por tela**, sem saudação. O `ModeIndicator` fica sempre nas ações, no mesmo lugar em todas as telas.

### ModeIndicator

Diz em que modo a tela está: "REPLAY · EVENTO 23 DE 52 · 14:03:26" ou "AO VIVO" com ponto pulsante.

- **Você fornece:** `mode` (`replay` | `ao-vivo`), `position` e `total` no replay, `at` (hora do evento atual).
- Sempre visível no cabeçalho da tela.

### Segmented

Controle em pílula para alternar entre poucas opções ("Replay | Ao vivo", "Rótulos neutros | Com IPs").

- **Você fornece:** `options` (`value`, `label`, `icon`, `disabled`, `hint`), `value`, `onChange`, `label` (nome acessível), `size`, `block` (ocupa a largura, segmentos iguais).
- Setas ← → mudam a seleção. Opção planejada fica `disabled` com `hint="Planejado"`.
- **Use** para modos e filtros de 2 a 4 opções; para navegação entre seções de um objeto, use `Tabs`.

### Tabs

Abas sublinhadas para as seções de um mesmo objeto (Veredito · Agentes · Propostas · Histórico).

- **Você fornece:** `tabs` (`id`, `label`, `count`, `disabled`), `value`, `onChange`, `label`.
- A aba ativa ganha o sublinhado de gelo; contagens em mono.

### Panel

A superfície de todo bloco: degradê suave do petróleo ao preto (`petrol-800` → `on-ice` → `bg-0`, luz no alto à direita), borda acesa em `glacier` no canto, cantos `radius-lg`.

- **Você fornece:** `eyebrow` (rótulo mono), `title` (`title-3`), `actions` (à direita), `children`, `footer`, `flush` (tabelas de borda a borda), `tone="attention"` (halo âmbar quando algo dentro espera uma pessoa).
- **Use** um título curto que diga o que há dentro ("Veredito", "Ações propostas"). Prefira deixar o halo âmbar no item que aguarda, não no painel inteiro.

## Formulários

### TextField

Campo de texto ou área de texto com rótulo, dica e erro.

- **Você fornece:** `label` (sempre; `hideLabel` só o esconde visualmente), `value`/`defaultValue`, `onChange`, `placeholder`, `type` (`password` ganha o botão mostrar/ocultar), `icon`, `hint`, `error`, `disabled`, `multiline` + `rows`, `mono` (prompts e ids), `size` (`md` 40 · `lg` 48).
- Borda `line-control` (≥ 3:1); foco em `glacier`; erro em coral com ícone e mensagem anunciada.
- **Motivos de decisão** ("Motivo da rejeição (opcional)") usam este campo e viram texto de pessoa no log.

### Select

Seleção nativa com o mesmo visual dos campos: teclado e leitor de tela de graça.

- **Você fornece:** `label`, `options` (`value`, `label`, `disabled`), `value`/`defaultValue`, `onChange`, `icon`, `hint`.
- Para escolher o modelo do chat com estado online/offline, prefira `ModelSelect`.

## Dados

### AggregationFunnel

O argumento do trabalho de relance: **janelas classificadas → incidente → chamadas à IA**, e quanto custaria sem agregação.

- **Você fornece:** `windows`, `incidents`, `aiCalls`, `counterfactual` (as janelas de ataque, as que virariam chamada), `scope` (ex.: "até o evento 52 de 52"), `footnote` (ex.: incidente marcado como já resolvido antes dos agentes).
- O desenho mostra muitas janelas convergindo para um nó e se abrindo em uma chamada por ponto; o rodapé traz o contrafactual ("10.752 chamadas à IA, o risco de *Denial of Wallet*": só as janelas de ataque, passadas em `counterfactual`) e a razão, arredondada para baixo ("827× menos chamadas" no fim do log de exemplo).
- **É o cartão mais importante da visão geral:** coloque no topo, na largura toda. Os números escalam com a largura (até 88 px).

### MetricCard

Cartão com número grande e rótulo mono, o "340 Executions" das referências.

- **Você fornece:** `label`, `value` (número já é formatado em pt-BR), `unit`, `context` (uma linha), `icon`, `delta` (`text`, `tone`), `spark` (valores da linha), `tone="attention"` (número que pede uma pessoa, ex.: propostas aguardando).
- **Use** para tokens, latência, incidentes, aguardando aprovação. Os três contadores do argumento ficam no `AggregationFunnel`, não em cartões soltos.

### IncidentQueue

Fila de incidentes: categoria (incidente e modelo), estado com propostas aguardando, confiança, janelas, origens e horário.

- **Você fornece:** `incidents` (`Incident[]`), `selectedId`, `onSelect`, `empty` (o `EmptyState` da fila vazia).
- Linha selecionada em `ice-tint-2` com barra de gelo; linha com proposta aguardando ganha barra âmbar e o selo "Aguardando aprovação" (×N).
- O id é um botão: Enter abre o incidente. Horário = início · duração.

### ClassifierVerdict

As duas categorias lado a lado, "o modelo disse DDoS+DoS; com 37 origens, é um DDoS", com a confiança.

- **Você fornece:** `model` (classe do Random Forest), `category` (a do incidente, ou nada enquanto as origens não foram contadas), `sources`, `confidence`.
- Sem `category`, mostra "aguardando a contagem final de origens".

### ConfidenceMeter

Confiança do classificador: o número e uma barra fina; abaixo de 0,60 a barra fica âmbar.

- **Você fornece:** `value` (0 a 1), `format` (`pct` "97%" nas telas · `decimal` "0,97" como no log), `size`.
- O número é a informação; a barra é apoio (funciona em cinza).

### FeatureTable

Features do incidente contra a referência benigna, numa escala logarítmica centrada em "igual ao benigno".

- **Você fornece:** `rows` (`name`, `value`, `benign`, `decimals`).
- A barra cresce para a direita quando o valor é maior (×372) e, tracejada, para a esquerda quando é menor (÷1.471); zero aparece como "zero". Nomes de feature em mono, exatamente como no dataset.

### AddressList

Origens ou destinos com a quantidade de quadros e o rótulo neutro de cada um.

- **Você fornece:** `title` ("Origens", "Destinos"), `items` (`address`, `label`, `frames`), `total` (o resto vira "+ 32 origens"), `hideAddresses` (como a nuvem vê).
- Colunas alinhadas; em contêiner estreito a barra some e ficam rótulo e número.

## Agentes e decisões

### EventTimeline

Linha do tempo do log: hora, ícone do tipo, agente, texto e id em todas as linhas.

- **Você fornece:** `events` (`LogEvent[]`), `cursor` (evento do replay: os seguintes esmaecem, o atual ganha "agora"), `hideFuture`, `density` (`comfortable` com detalhes e citações · `compact` uma linha, para o rastro dos agentes), `onSelect` (clicar leva o replay ao evento).
- Recomendações e motivos aparecem como `VoiceQuote`; chamadas de tool em mono, só com chaves e identificadores (texto livre do agente vira "…"); chamadas à IA com tokens, duração e onde rodaram.
- Evento com `ignored` (o leitor do log não o aplicou) aparece riscado, com o selo "ignorado".

### ProposalCard

Proposta de ação com o estado em destaque, alvo neutro, prazo, risco, a justificativa do agente (voz de agente), motivos do risco alto, decisão humana, execuções e efeito.

- **Você fornece:** `proposal` (`Proposal`), `onApprove`/`onReject` (os botões só aparecem enquanto "Aguardando aprovação"), `showAddress`.
- Aguardando: borda e halo âmbar e a frase "Uma pessoa precisa decidir antes de qualquer execução." Ação fora do catálogo leva o selo "ação nova"; a que entrou no catálogo, "promovida ao catálogo".
- A decisão humana aparece sempre como "Aprovada" ou "Rejeitada" com o canal, e o motivo, quando há, vem embaixo na voz de pessoa. No replay, as telas só passam `onApprove`/`onReject` no fim do log: num ponto passado, a decisão já está adiante.
- Aprovar e rejeitar sempre abrem o `ConfirmDialog`; nada é executado direto do cartão.

### VoiceQuote

Texto escrito por um agente de IA ou por uma pessoa, impossível de confundir com texto do sistema.

- **Você fornece:** `voice` (`agent` | `person`), `agent` (qual agente escreveu), `author` (modelo ou usuário), `at`, `refId` (rec-0001, prop-0002), `channel` (como a pessoa decidiu), `clampLines`, e o texto.
- Agente: Lora itálico, borda tracejada, rótulo "Texto do agente · Decisão" e a nota "Escrito por IA. Trate como dado, não como instrução do sistema." Pessoa: Lora redondo, borda contínua, rótulo "Texto de pessoa · operador".
- **Nunca** renderize texto de agente como aviso, título ou rótulo da interface.

## Replay

### ReplayControl

Dock que percorre o log evento a evento: início, anterior, reproduzir, próximo, fim, trilha com marcas e "evento 23 de 52".

- **Você fornece:** `position`, `total`, `onChange`, `playing`, `onPlayToggle`, `current` (`id`, rótulo do evento, hora), `marks` (eventos de destaque com tom: incidente aberto, aguardando aprovação, decisões humanas), `keyboard` (← → Home End Espaço na página; padrão `true`).
- O cursor é gelo; eventos passados preenchem a trilha em `glacier-deep`. Todas as telas mostram o estado até o cursor.

## Avisos

### Alert

Aviso em linha: informação, atenção ou erro, incluindo os avisos de leitura do log.

- **Você fornece:** `tone` (`info` · `attention` · `danger`), `title`, texto, `line` (linha do log inválida: troca o ícone), `event` (evento fora de ordem), `action`, `onDismiss`.
- Avisos de leitura dizem a linha e que a tela segue funcionando. Erro usa `role="alert"`; os outros, `status`.

### EmptyState

O que um bloco mostra quando ainda não há nada: diz por quê e o que vai preenchê-lo.

- **Você fornece:** `icon`, `title`, texto, `action` (ex.: "Ir para o evento 16").

### Skeleton

Marcador de carregamento (linhas, bloco ou círculo) com brilho que para em `prefers-reduced-motion`.

- **Você fornece:** `lines`, `shape` (`text` · `block` · `circle`), `height`, `width`, `label` (lido pelo leitor de tela).
- **Use** enquanto um agente ainda não respondeu (modo ao vivo).

### Tooltip

Dica curta ao passar o mouse ou focar pelo teclado.

- **Você fornece:** `content`, `side` (`top` | `bottom`) e um gatilho focável como filho.
- Não coloque informação essencial só na dica; ela complementa ícones e abreviações.

### ConfirmDialog

Confirmação de toda decisão humana: aprovar proposta de risco alto, rejeitar proposta, marcar incidente como já resolvido.

- **Você fornece:** `open`, `kind` (`approve` · `reject` · `resolve`), `subject` (a ação ou o incidente), `refId`, `summary` (fatos: alvo, prazo, risco), `reasons` (motivos do risco alto, ao aprovar), `user`, `onConfirm(motivo)`, `onCancel`, `inline` (documentação).
- Diz o que vai acontecer e o que vai para o log (`logNote`; no app, enquanto a interface não grava decisões, a nota diz isso). Rejeitar e já resolvido pedem um motivo opcional, que vira texto de pessoa. Esc cancela, menos durante o envio. `busy` mostra o envio; `error` mostra, dentro do diálogo, por que a decisão não foi gravada; `details` traz a ação nova como o agente a descreveu (o que faz, passos, efeito esperado, como desfazer), na voz do agente. Dê ao diálogo uma `key` por decisão, para cada abertura começar vazia.
- Botões: Cancelar (`ghost`) e a confirmação (`confirm` menta, `danger-solid` coral ou `primary` gelo).

## Gráficos

### AreaChart

Área suave no tempo com dica flutuante; a segunda série é uma linha tracejada (funciona em cinza).

- **Você fornece:** `series` (`name`, `values`), `labels` (eixo x, ex.: horários), `format`, `unit`, `height`, `ariaLabel`, `defaultIndex` (ponto com dica fixa para figuras).
- Setas ← → movem a dica quando o gráfico tem foco. Eixos em mono `chart-axis`, grade `chart-grid`.

### CategoryBars

Barras horizontais por categoria: cor, glifo e um padrão de impressão por categoria.

- **Você fornece:** `data` (`category`, `value`), `format`, `showShare` (parte do total), `ariaLabel`.
- Padrões: DDoS liso · DoS pontos · DDoS+DoS linhas · Mirai xadrez diagonal · Recon colunas · Spoofing diagonal · Web diagonal invertida · BruteForce tabuleiro · Benign só contorno.

### ConfusionMatrix

Matriz de confusão 7 × 7: linhas são a classe real, colunas a prevista, tom pela parte da linha; diagonal contornada.

- **Você fornece:** `labels` (as 7 classes do modelo), `matrix` (contagens `[real][previsto]`), `ariaLabel`.
- Células em `heat-1` a `heat-5`; cada célula é focável e lida como "Real Recon, previsto Spoofing: 41 janelas, 2,9% da linha".
- Precisa de largura: use em painel de 12 colunas.

## Chat

### ChatMessage

Mensagem do chat com o modelo: a resposta do modelo usa a voz de agente; a sua, a voz de pessoa.

- **Você fornece:** `role` (`user` · `assistant` · `system`), `author`, `at`, `tokens`, `seconds`, `location`, o texto.
- `system` vira uma nota central em mono ("Skill Triagem carregada").

### PromptBox

Caixa de mensagem do chat: Enter envia, Shift+Enter quebra a linha.

- **Você fornece:** `value`, `onChange`, `onSend`, `placeholder`, `tools` (normalmente um `ModelSelect compact`), `disabled`, `tokens` (estimativa).

### ModelSelect

Seletor de modelo agrupado em Local e Nuvem, com estado online/offline; modelo offline não pode ser escolhido.

- **Você fornece:** `providers` (`Provider[]`), `value`, `onChange`, `defaultOpen` (documentação), `compact` (dentro da caixa de prompt; abre para cima).

### ProviderBar

Barra de provedores de IA: modelos locais (online/offline) e de nuvem; o escolhido aparece em cada chamada.

- **Você fornece:** `providers`, `selectedId`, `onSelect`.
- Lembra na própria barra que a nuvem só recebe rótulos neutros.

## Relatório

### ReportCover

Capa A4 (794 × 1123 px) do relatório do incidente, na composição da capa de referência, acesa em gelo.

- **Você fornece:** `logoSrc`, `heroSrc`, `eyebrow`, `title`, `meta` (ícone, rótulo, valor: Incidente, Categoria, ID do relatório, Alvo), `date` (ISO), `mode` ("Modo replay"), e opcionalmente `kicker`, `motto`, `tagline`, `confidential`, `footer`.
- Os valores da capa vêm do log (voz do sistema); a LLM não escreve na capa.

### ReportPage

Página interna A4 com cabeçalho corrido, seções numeradas e rodapé "Confidencial · 02 / 04".

- **Você fornece:** `logoSrc`, `docTitle`, `date`, `page`, `pages`, e as seções: `ReportSection` (`n`, `title`, `voice`, `agent`) e `ReportFacts` (`items`, `columns`).
- **Todo texto escrito pela LLM** vai em `ReportSection voice="agent"` (Lora itálico + selo "Gerado pelo agente"); fatos do log ficam em `ReportFacts` e tabelas.
- Imprima com `@page A4` e `print-color-adjust: exact`; cada página quebra sozinha.

## Telas

### TelaVisaoGeral

Visão geral: o funil do argumento, três cartões e a fila de incidentes, até o evento do cursor.

- O `AggregationFunnel` ocupa a largura toda no topo. No log de exemplo, no fim do inc-0001 (evento 44): 10.946 janelas → 1 incidente → 11 chamadas à IA; no fim do log: 10.970 → 2 → 13. O contrafactual de *Denial of Wallet* conta só as janelas de ataque.
- Cartões: aguardando aprovação, incidentes, tokens. Fila do exemplo: inc-0001 (DDoS, modelo DDoS+DoS, encerrado no fim) e inc-0002 (BruteForce, marcado como já resolvido).
- O replay no pé é interativo: arraste ou use ← → e tudo recalcula até o evento escolhido.

### TelaIncidente

Detalhe do incidente; no evento 28 do log de exemplo, duas propostas de risco alto aguardam aprovação.

- Veredito com as duas categorias, features contra o benigno, propostas (aguardando primeiro), origens e destinos, rastro dos agentes, recomendações na voz de agente e o histórico de decisões com os eventos futuros esmaecidos.
- "Já resolvido", "Aprovar" e "Rejeitar" abrem o `ConfirmDialog`.

### TelaAoVivo

Modo ao vivo (planejado): o incidente aparece assim que o classificador o abre, antes dos agentes. Com `VITE_LOG_AO_VIVO`, a tela lê o log que está sendo gravado.

- Decisões pendentes à esquerda com aprovar/rejeitar pela interface; incidente recém-aberto com o andamento de cada agente e "Marcar como já resolvido"; eventos chegando. A barra de provedores entra quando a escolha do provedor dos agentes existir: o log não diz onde cada modelo roda.

### TelaIsoladoIntegrado

Tela 3 (vira figura do artigo): o mesmo incidente com a saída crua do classificador de um lado e a resposta com agentes do outro.

- No fim do log de exemplo: 21.468 alertas, um por janela, contra 1 incidente, 11 chamadas à IA, três propostas e o efeito "o incidente cessou". Alternância "Rótulos neutros | Com IPs" para a figura; "Imprimir a figura" imprime só o conteúdo.

### TelaCustoLatencia

Tela 4: tokens, tempo de resposta e chamadas por agente, calculados das chamadas à IA do log até o cursor.

- Cartões de tokens, latência média, chamadas à IA e chamadas evitadas; gráfico de tokens e latência por chamada; comparação local × nuvem, que aparece quando `VITE_MODELOS_LOCAIS` e `VITE_MODELOS_NA_NUVEM` dizem onde cada modelo roda; tabela por agente.

### TelaQualidadeModelo

Tela 5: matriz de confusão 7 × 7, precisão, recall e F1 por classe e o benigno classificado como ataque.

- Usa a matriz real do ponto de operação da configuração 5 (`src/dados/qualidade.ts`, conferida contra o CSV do experimento por um teste).

### TelaSegurancaMcp

Tela 6 (planejada): o teste de *tool poisoning*: o que foi injetado e se o agente caiu.

- Três desfechos: agente resistiu, recusada pelo servidor, agente caiu (contido pela aprovação humana). Conteúdo injetado em bloco hachurado "não confiável"; o que o agente fez na voz de agente. Resultados ilustrativos.

### TelaChat

Chat com o modelo: ferramenta da equipe para testar prompts e as skills dos agentes (não entra na banca).

- Barra de provedores, seletor de modelo, carregar skill (Triagem · Decisão · Execução), prompt de sistema em mono, conversa nas duas vozes e caixa de prompt.

### TelaRelatorio

O relatório do incidente: capa A4 no estilo da capa de referência e duas páginas internas, com o que está no log.

- Capa: marca de vidro acesa sangrando a borda, título do incidente, metadados com caixas de ícone, data e modo, selo "CONFIDENCIAL".
- Páginas: sumário (planejado: a IA o escreve no fim do incidente), fatos do log, ações, recomendações dos agentes (voz de agente, selo "Gerado pelo agente") e decisões humanas.

### TelaLogin

Login com a marca de vidro ao fundo, na mesma linguagem da capa do relatório.

- Composição: `GlassBackdrop variant="login"` sobre o chão em degradê (`on-ice` → `bg-0`); `Logo lg` e tagline em `eyebrow-wide`; barra de acento, "RESPOSTA AUTÔNOMA A INTRUSÃO", título "Entrar"; cartão de vidro com usuário, senha, "Entrar" (primário) e "Abrir o replay de demonstração"; selo "ACESSO RESTRITO".
- Estados: erro de senha (`Alert danger` + campo com erro), carregando (botão com giro). Cabe em 1440 × 900.
- Código: `src/telas/Entrar.tsx`. O login passa por `src/operacao.ts`, que hoje explica que ainda não há login.

# SentryIoT — MultiAgent NIDR

Sistema de detecção e resposta a intrusões (NIDR) em redes IoT, combinando classificação por
Random Forest com um sistema multiagente LLM integrado via MCP.

**TCC II — FCI Mackenzie, 2º semestre de 2026.**
Equipe: Bernardo Souza Oliveira, Matheus Queiroz Gregorin, José Victor Roling e
Pedro Henrique Cagnoni Guimarães.
Orientador: Prof. Rodrigo Cardoso Silva.

Este repositório é o trabalho: código, experimentos e artigo. O painel de acompanhamento
fica em outro repositório e é o espelho do andamento, não o trabalho.

---

## O projeto

Um classificador Random Forest, treinado nas classes rotuladas do CICIoT2023, classifica janelas
do tráfego de rede IoT em sete categorias. As predições são expostas por um **servidor MCP** e
consumidas por um **sistema multiagente LLM**, que interpreta o alerta, consulta uma base de
mitigações e propõe a resposta, com aprovação humana para as ações de risco alto. O trabalho
cobre a detecção e a resposta.

- **Dataset:** CICIoT2023, o único do trabalho. O dataset secundário foi dispensado em
  10/10/2026, com o orientador, porque o CICIoT2023 cobre os três cenários da PoC. Ver
  `dados/README.md` e `ROADMAP.md`.
- **Stack:** Python, Pandas, scikit-learn, dpkt, servidor MCP, agentes LLM.
- **Agentes:** três papéis (triagem, decisão e execução), em arquitetura híbrida: o agente de
  decisão roda num modelo de fronteira na nuvem e coordena o incidente, e triagem e execução rodam
  no modelo local, o `qwen3.8-27c` de um gateway interno. O encadeamento entre eles é código, e não
  um quarto agente. O servidor MCP entrega à decisão um resumo em que cada endereço vira um rótulo
  neutro, e só a execução recebe o endereço real. Ver `ROADMAP.md` e `codigo/mcp/README.md`.
- **Cenários da PoC:** DDoS, port scan e brute force. O cenário de exfiltração foi retirado em
  10/10/2026, em decisão com o orientador: o CICIoT2023 não tem essa classe, e os datasets de
  referência da área também não cobrem esse vetor com dados rotulados suficientes.
- **Métricas:** recall por classe, precisão, F1-score e taxa de falso positivo. Acurácia global
  **não** é métrica principal: 89,5% do dataset é DDoS e DoS, então ela engana.

---

## Correções da banca do TCC I (obrigatórias, valem nota)

O item 5 das regras do orientador é "analisar e avaliar as recomendações da banca". Elas já
mudaram o escopo do trabalho:

1. **NIDS → NDR/NIDR.** O projeto foi reposicionado como detecção **e resposta** (daí "NIDR" no
   nome). Todo texto novo usa esse enquadramento, não "NIDS".
2. **Deixar claro o papel do Scapy e do Wireshark.** O avaliador 2 questionou: se o trabalho usa
   datasets, onde entra a captura de pacotes? Resposta adotada: processamos tráfego bruto (PCAP)
   com um extrator calibrado contra o oficial (ver `dados/README.md`). Não há coleta in loco,
   inviável no prazo e sem rótulos: os pcaps do CICIoT2023 fazem o papel da captura. Vale
   registrar que a stack real dos autores do dataset usa `dpkt` como parser, `tcpdump` para
   captura e `mergecap` para juntar capturas; o Scapy aparece só para Zigbee e Bluetooth.
3. **Riscos de IA em nuvem, custo de tokens e a alternativa on-premises.** Resposta adotada:
   arquitetura híbrida, com triagem e execução no modelo local (o `qwen3.8-27c` de um gateway
   interno) e só o agente de decisão num modelo de fronteira, sem endereço da rede, o que o
   servidor MCP garante. Ele coordena o incidente e o encadeamento é código, para a nuvem não
   cobrar um segundo papel a cada incidente; os agentes recebem o resumo do incidente, e não as
   janelas (`ROADMAP.md`; seção 3.5 de `artigo/esqueleto.md`).
4. **Limites de análise por NetFlow vs. PCAP.** Resposta adotada: o sistema lê o pcap, porque as
   39 features medem cada quadro da janela, o que um registro de fluxo não guarda (seção 3.1 de
   `artigo/esqueleto.md`).
5. **Referências pedidas pela banca:** Darktrace, Netskope, Vectra AI e o ataque
   *Denial of Wallet* (DoW), com menção curta no artigo.

Cada seção do artigo deve endereçar os pontos desta lista que lhe couberem.

---

## Prazos oficiais do edital (não negociáveis)

| Marco | Data |
|---|---|
| Cadastro no Oriente + anuência do orientador | 18/08 – 31/08/2026 |
| Requerimento no Portal do Aluno | 01/09 – 21/09/2026 |
| Indicação dos avaliadores da banca | 03/11 – 11/11/2026 |
| **Submissão do artigo científico** | **03/11 – 09/11/2026** |
| Bancas TCC II | 16/11 – 27/11/2026; 31/11 e 01/12/2026 (ver nota) |
| **Artigo final, com as alterações pedidas pela banca** | **até 04/12/2026** |
| Anuência do orientador à entrega final | até 07/12/2026 |
| Postagem das notas | 07/12 – 09/12/2026 |

O artigo tem 10–20 páginas, no template do Oriente. A apresentação tem 15–20 min.

Na parte de TCC II para Ciência da Computação e Sistemas de Informação, o edital avalia o artigo
científico e a apresentação oral à banca, além da participação nas reuniões de orientação.
Relatório técnico e pôster são entregas do TCC I, no mesmo período de 03 a 09/11; a mensagem do
orientador com as datas lista os dois junto do artigo, mas o edital não os pede no TCC II. Com
conceito Excelente ou Muito Bom, o termo de autorização de publicação no repositório Adelpha
segue junto com o artigo final, até 04/12. O edital marca a segunda janela de bancas em "31/11 e
01/12/2026", e 31/11 não existe: confirmar a data com o orientador.

**A restrição que domina o cronograma:** a submissão é no início de novembro, não em dezembro.
O plano previa congelar os resultados por volta de 17/10, para o rascunho completo chegar ao
orientador por volta de 20/10. Em 04/10 essa data de congelamento foi abandonada e o calendário
será ajustado pela equipe. A redação continua correndo em paralelo ao trabalho técnico.

---

## Regras do orientador

1. **Report toda segunda-feira, sem exceção**, com o nome de quem fez cada tarefa.
2. Discussão pelo grupo de WhatsApp; reuniões marcadas quando necessário.
3. Ser proativo — reunião com o orientador sozinha não produz a pesquisa.
4. Escrita do artigo em paralelo com o desenvolvimento, desde já.

Os reports semanais são montados e exportados pelo próprio painel de acompanhamento, que já
agrupa as tarefas concluídas por semana e por responsável.

---

## Estrutura do repositório

| Pasta | Conteúdo |
|---|---|
| `artigo/` | `Artigo_TCC2_SentryIoT.docx`, o artigo no template do Oriente (10 a 20 páginas); `esqueleto.md`, o rascunho e a fonte das correções; e `figuras/`, com os scripts que geram as figuras |
| `codigo/captura/` | extrator de features: pacotes → 39 números |
| `codigo/classificador/` | regeração dos dados de treino a partir dos pcaps, preparação, treino e avaliação do Random Forest |
| `codigo/reprodutor/` | reprodutor de tráfego: um pcap passa pelo extrator, pelo classificador e pela política de acionamento, e os incidentes vão para o log de eventos (`python -m codigo.reprodutor captura.pcap`) |
| `codigo/mcp/` | contrato das tools MCP, stub do servidor, política de risco, base local de mitigações e log de eventos; com os cenários do reprodutor (`--cenarios`), o stub é o servidor da PoC, em modo de reprodução |
| `codigo/agente/` | skills dos agentes, recomendações de mitigação por categoria e os pedidos aos modelos (`pedidos.py`); o laço dos agentes e o orquestrador ainda serão escritos |
| `codigo/api/` | backend fino da interface: chat com o modelo e simulação com um pcap (`python -m codigo.api`) |
| `frontend/` | interface web do sistema, no design system SentryIoT (`frontend/src/design-system/`): replay do log, detalhe do incidente, telas do artigo, relatório e chat com o modelo (ver `frontend/README.md`) |
| `dados/` | **`README.md` com a receita completa do ambiente e o mapa de arquivos** |
| `experimentos/` | `notebooks/` de exploração e `resultados/` com métricas e tabelas |
| `referencias/` | bibliografia e material de apoio |

O dataset não é versionado: o `MERGED_CSV` tem 8,7 GB, e os 38 pcaps usados na regeração somam
cerca de 46 GB. `dados/README.md` diz de onde baixar e onde colocar.

Material de origem do TCC I (artigo, pôster, edital e o feedback integral do orientador) fica na
pasta-mãe, fora deste repositório.

---

## Documentos deste repositório

- **`dados/README.md`**: o mais importante para começar. Onde está o dataset, como montar o
  ambiente, o mapa completo de arquivos e scripts, e as armadilhas já mapeadas.
- **`GLOSSARIO.md`**: os termos do projeto em português simples, com exemplos dos nossos dados.
- **`ROADMAP.md`**: as decisões importantes do projeto, tomadas e em aberto, com o motivo de cada uma.
- **`artigo/esqueleto.md`**: o rascunho do artigo, seção por seção.
- **`codigo/mcp/README.md`**: por onde começar na frente de agentes, com o contrato, o stub e o
  log de eventos.

---

## Como trabalhar aqui

**O artigo é escrito pela equipe.** Cada integrante redige as seções correspondentes à frente em
que trabalhou, na semana em que fez o trabalho — quem construiu o extrator escreve como o extrator
funciona, quem treinou o modelo escreve como treinou. A revisão é conjunta, em data marcada, antes
de enviar ao orientador.

- **Idioma:** português no artigo, nos reports e nos commits. Código e nomes de arquivo sem acento.
- **Commits** pequenos e descritivos.
- **Nunca versionar** dataset, `.pcap`, CSV grande, modelo treinado ou `.env`.
- **Sempre versionar** código, scripts de amostragem com semente fixa, a definição da divisão
  treino/teste e as tabelas de resultado — sem isso o trabalho não é reproduzível.
- **Toda decisão técnica vira parágrafo na semana em que é tomada.** Em novembro ninguém lembra
  por que escolheu 39 features em vez de 46.
- **Decisão importante do projeto vai para o `ROADMAP.md`**, com data e motivo. O andamento das
  tarefas fica só no painel.

**Todo PR passa pelo CI** (GitHub Actions, Python 3.11). O `ruff` procura erros no código, o
`pytest` roda os testes (os que precisam do dataset são pulados, porque ele não existe lá) e o
`pip-audit` confere se alguma dependência do `requirements.txt` tem vulnerabilidade conhecida. No
`frontend/`, o CI instala as dependências com `npm ci`, roda o `npm audit` (vulnerabilidade alta
ou crítica nas dependências de produção derruba o job; nas de desenvolvimento, vira aviso),
roda os testes com `npm test` e constrói com `npm run build`. PR que mexe
em código Python, TypeScript ou JavaScript, ou nos workflows, passa também pelo CodeQL, que procura
falhas de segurança no código. Para
conferir antes de abrir o PR: `ruff check .`, `python -m pytest` e, em `frontend/`, `npm test` e
`npm run build`.

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

Um classificador Random Forest detecta anomalias no tráfego de rede IoT. As predições são expostas
por um **servidor MCP** e consumidas por um **sistema multiagente LLM**, que correlaciona os
alertas com vulnerabilidades conhecidas e devolve recomendações de mitigação acionáveis — indo
além da detecção, para a resposta.

- **Dataset primário:** CICIoT2023 (confirmado). Ver `dados/README.md`.
- **Dataset secundário:** em definição, e possivelmente desnecessário — depende da decisão sobre
  o 4º cenário. Ver `ROADMAP.md`.
- **Stack:** Python, Pandas, scikit-learn, dpkt, servidor MCP, agentes LLM.
- **Cenários da PoC:** DDoS, port scan e brute force. O 4º cenário (exfiltração) está pendente de
  decisão com o orientador — o CICIoT2023 não tem essa classe, e os datasets de referência da área
  também não cobrem esse vetor com dados rotulados suficientes.
- **Métricas:** recall por classe, precisão, F1-score e taxa de falso positivo. Acurácia global
  **não** é métrica principal: 78% do dataset é DDoS/DoS, então ela engana.

---

## Correções da banca do TCC I (obrigatórias, valem nota)

O item 5 das regras do orientador é "analisar e avaliar as recomendações da banca". Elas já
mudaram o escopo do trabalho:

1. **NIDS → NDR/NIDR.** O projeto foi reposicionado como detecção **e resposta** (daí "NIDR" no
   nome). Todo texto novo usa esse enquadramento, não "NIDS".
2. **Deixar claro o papel do Scapy e do Wireshark.** O avaliador 2 questionou: se o trabalho usa
   datasets, onde entra a captura de pacotes? Resposta adotada: processamos tráfego bruto (PCAP)
   com um extrator calibrado contra o oficial — ver `dados/README.md`. Vale registrar que a stack
   real dos autores do dataset usa `dpkt` como parser, `tcpdump` para captura e `mergecap` para
   juntar capturas; o Scapy aparece só para Zigbee e Bluetooth.
3. **Riscos de IA em nuvem, custo de tokens e a alternativa on-premises.**
4. **Limites de análise por NetFlow vs. PCAP.**
5. **Referências a investigar e citar:** Darktrace, Netskope, Vectra AI e o ataque
   *Denial of Wallet* (DoW).

Cada seção do artigo deve endereçar os pontos desta lista que lhe couberem.

---

## Prazos oficiais do edital (não negociáveis)

| Marco | Data |
|---|---|
| Cadastro no Oriente + anuência do orientador | 18/08 – 31/08/2026 |
| Requerimento no Portal do Aluno | 01/09 – 21/09/2026 |
| Indicação dos avaliadores da banca | 03/11 – 11/11/2026 |
| **Submissão do artigo + relatório + pôster** | **03/11 – 09/11/2026** |
| Bancas TCC II | 16/11 – 27/11 e 30/11 – 01/12/2026 |
| **Entrega final + termo de anuência** | **04/12/2026** |
| Postagem das notas | 07/12 – 09/12/2026 |

O artigo tem 10–20 páginas, no template do Oriente. A apresentação tem 15–20 min.

**A restrição que domina o cronograma:** a submissão é no início de novembro, não em dezembro.
Contando para trás, o rascunho completo precisa chegar ao orientador por volta de 20/10 — o que
significa **congelar os resultados por volta de 17/10**. As fases técnicas foram comprimidas para
caber nisso, com a redação correndo em paralelo desde já.

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
| `artigo/` | texto do artigo (10–20 pág, template do Oriente) e `figuras/` |
| `codigo/captura/` | extrator de features: pacotes → 39 números |
| `codigo/classificador/` | amostragem, preparação, treino e avaliação do Random Forest |
| `codigo/mcp/` | contrato da tool e servidor MCP que expõe as predições |
| `codigo/agente/` | sistema multiagente, prompts e política de acionamento |
| `dados/` | **`README.md` com a receita completa do ambiente e o mapa de arquivos** |
| `experimentos/` | `notebooks/` de exploração e `resultados/` com métricas e tabelas |
| `referencias/` | bibliografia e material de apoio |

O dataset não é versionado (~17 GB). `dados/README.md` diz de onde baixar e onde colocar.

Material de origem do TCC I (artigo, pôster, edital e o feedback integral do orientador) fica na
pasta-mãe, fora deste repositório.

---

## Documentos deste repositório

- **`dados/README.md`** — o mais importante para começar: onde está o dataset, como montar o
  ambiente, o mapa completo de arquivos e scripts, e as armadilhas já mapeadas.
- **`GLOSSARIO.md`** — os termos do projeto em português simples, com exemplos dos nossos dados.
- **`ROADMAP.md`** — as decisões tomadas, por quê, e o que cada uma exige no painel.

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
- **Toda mudança de plano vai para o `ROADMAP.md`** com a ação correspondente no painel, marcada
  como `pendente` até alguém aplicar na interface.

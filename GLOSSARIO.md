# Glossário — SentryIoT

Os termos que aparecem no projeto, explicados em português simples, com exemplos dos nossos
próprios dados. Serve para os quatro usarem as palavras com o mesmo sentido — principalmente
na hora de escrever o artigo.

Ordem: dos conceitos básicos para os mais específicos.

---

## 1. Dados e tráfego de rede

**Pacote**
A menor unidade que trafega numa rede. Cada pacote carrega: quem mandou, para quem, qual
protocolo, quantos bytes, em que instante e quais flags estavam ligadas. Tudo na internet é
feito de pacotes.

**PCAP**
A gravação bruta dos pacotes, do jeito que passaram pela rede — o "vídeo" do tráfego.
Nosso `DictionaryBruteForce.pcap` tem 133.138 pacotes gravados.

**NetFlow**
Um resumo da conversa, sem o conteúdo: quem falou com quem, quando e quanto. A comparação
que funciona é a conta de telefone: o NetFlow é a fatura detalhada (números e duração das
ligações), o PCAP é a gravação da ligação inteira. A fatura é leve e não invade privacidade,
mas você não sabe o que foi dito.

**Feature**
Uma característica medida. Um número que descreve alguma coisa.
Exemplos das nossas: velocidade em pacotes por segundo, tamanho médio do pacote, porcentagem
de pacotes com a flag SYN ligada.
Um exame médico é a mesma ideia: pressão, temperatura e batimentos são features suas.

**Classe (ou rótulo / label)**
A resposta. O que aquilo é.
No nosso dataset há 34 classes: `DDoS-ICMP_Flood`, `Recon-PortScan`, `BenignTraffic` etc.

➡ **A diferença que mais confunde:** feature é a *descrição*, classe é a *resposta*.
Cada linha do nosso CSV tem 39 features (números) e 1 classe (nome do ataque).
Trinta e nove colunas de pergunta, uma coluna de resposta.

**Extrator de features**
O programa que transforma pacotes em números — o tradutor entre a rede, que fala "pacote",
e o modelo, que fala "número". No CICIoT2023 ele agrupa os pacotes de 10 em 10 e escreve uma
linha de features para cada grupo. Por isso 133.138 pacotes viram cerca de 13 mil linhas.

**Calibrar o extrator**
Provar que o nosso extrator está certo: rodamos ele no mesmo PCAP que os autores usaram e
conferimos se produz os mesmos números do CSV oficial deles. É como aferir uma balança com um
peso conhecido — se marca certo no peso conhecido, dá para confiar nela em qualquer coisa.

---

## 2. Aprendizado de máquina

**Modelo**
O programa que aprendeu a reconhecer padrões a partir de exemplos, em vez de seguir regras
escritas à mão.

**Treinar**
Mostrar ao modelo milhares de linhas **com a resposta preenchida**, para ele descobrir sozinho
quais combinações de números levam a qual classe.

**Usar (inferência)**
Entregar uma linha **sem** a resposta e pedir que o modelo preencha a classe.

**Árvore de decisão**
Uma sequência de perguntas de sim ou não. "A velocidade passa de 20 mil? É tudo ICMP? Os
pacotes têm menos de 100 bytes? → é flood."

**Random Forest (floresta aleatória)**
Centenas de árvores de decisão, cada uma olhando um recorte diferente das features e fazendo
perguntas um pouco diferentes. Na hora de decidir, todas votam e a maioria ganha. Se uma árvore
se confunde, as outras compensam — por isso é robusto e roda em hardware fraco.

**Treino, validação e teste**
O dataset é dividido em três partes. O modelo **treina** numa, é ajustado olhando outra
(validação) e é avaliado numa terceira que ele nunca viu (teste). Avaliar no mesmo dado em que
treinou é como corrigir a prova com o gabarito na mão — o número sai ótimo e não significa nada.

**Baseline**
O resultado de referência já publicado por outros. Serve para saber se o nosso está razoável.
No CICIoT2023 o baseline do Random Forest é dos próprios autores do dataset.

**Desbalanceamento de classes**
Quando umas classes têm muito mais exemplos que outras. No nosso caso é extremo: 78% do dataset
é DDoS e DoS, enquanto `DictionaryBruteForce` tem 0,027% (319 amostras no conjunto de teste).
Isso distorce as métricas — ver abaixo.

---

## 3. Como medir se funcionou

**Acurácia**
Porcentagem de acertos no total. **Enganosa quando as classes estão desbalanceadas:** um modelo
que responda "DDoS" para tudo acerta 78% do nosso dataset e é completamente inútil.

**Precisão**
Das vezes que o modelo disse "é ataque", quantas ele acertou. Precisão baixa = muito alarme falso.

**Recall (sensibilidade)**
Dos ataques que realmente existiam, quantos o modelo encontrou. Recall baixo = ataque passando
despercebido.

**F1-score**
Combina precisão e recall num número só. **É o que revela a verdade em dataset desbalanceado**:
quando a acurácia está alta e o F1 baixo, o modelo acerta o que é fácil e abundante e erra o que
é raro. No artigo dos autores, com 8 classes, a acurácia é alta mas o F1 fica em ~70%.

**Taxa de falso positivo (FPR)**
Quanto tráfego normal foi acusado de ser ataque. Nosso artigo trata isso como o indicador
crítico de viabilidade: um sistema que grita o tempo todo é desligado pelo operador.

➡ **Regra do projeto:** relatar **recall por classe**, nunca só acurácia. E dizer com franqueza
em quais classes fomos mal, com o número de amostras ao lado.

---

## 4. Segurança

**IDS (Intrusion Detection System)**
Sistema que monitora e **detecta** intrusão. **NIDS** é o que olha a rede; **HIDS** é o que fica
instalado dentro do aparelho.

**NDR / NIDR**
Detecção **e resposta**. Além de apontar o ataque, sugere ou executa a mitigação. Foi a
recomendação da banca do TCC I e é o enquadramento atual do SentryIoT.

**Detecção por assinatura vs. por anomalia**
Assinatura compara o tráfego com uma lista de padrões conhecidos: preciso, mas cego para ataque
novo. Anomalia aprende como é o normal e alerta quando foge disso: pega ataque novo, mas gera
mais alarme falso. Nosso trabalho é do segundo tipo.

**DDoS**
Inundar um alvo com tráfego de milhares de aparelhos até ele cair. O aparelho IoT não é a
vítima — é a arma. Nos nossos dados: 36.847 pacotes/s, todos minúsculos e idênticos.

**Port scan (varredura de portas)**
Testar todas as portas de um alvo para ver quais estão abertas. É o ladrão testando cada porta e
janela da casa. Ainda não é invasão, é sondagem. Nos nossos dados aparece pelo excesso de flags
SYN (23% dos pacotes).

**Brute force (força bruta)**
Tentar senha após senha até uma funcionar. **Atenção:** nos nossos dados ele é *mais lento* que o
tráfego normal (175 pacotes/s contra 1.415). Prova de que velocidade sozinha não detecta ataque.

**Exfiltração de dados**
Roubo de informação: o invasor já está dentro e vai copiando dados para fora, devagar, para não
ser notado. É o mais difícil de detectar, porque o tráfego parece legítimo.
**O CICIoT2023 não tem essa classe** — decisão pendente com o orientador.

**Mirai**
Botnet que em 2016 sequestrou aparelhos IoT com senha de fábrica e derrubou boa parte da
internet. É o caso clássico que justifica a área.

**Denial of Wallet (DoW)**
Ataque que não derruba o serviço: faz ele consumir recursos pagos até a conta explodir.
Relevante para nós porque usamos LLM cobrada por uso.

---

## 5. A camada de IA

**LLM (Modelo de Linguagem de Grande Escala)**
Modelo treinado em texto que interpreta contexto e escreve em linguagem natural. No SentryIoT é
quem transforma um alerta técnico em recomendação que um humano entende.

**Token**
O pedacinho de texto que a LLM processa, e a unidade pela qual se cobra. Importa muito para nós:
num DDoS o classificador dispara milhares de alertas por segundo, e chamar a LLM em cada um é
inviável em custo e em tempo de resposta.

**Alucinação**
Quando a LLM afirma com segurança algo que não é verdade. Num sistema de segurança isso é grave:
recomendar mitigação para uma vulnerabilidade que não existe naquele aparelho.

**Agente**
Uma LLM com ferramentas e um ciclo de execução — ela não só responde, ela consulta, decide e age.

**ReAct**
O padrão que estrutura esse ciclo: o agente **raciocina** sobre o que precisa, **age** chamando
uma ferramenta, olha o resultado e repete até concluir.

**Sistema multiagente**
Vários agentes com papéis diferentes (triagem, contexto, mitigação) trabalhando juntos, em vez
de um só fazendo tudo.

**MCP (Model Context Protocol)**
O padrão que conecta uma LLM a ferramentas externas. É o que liga o nosso classificador aos
agentes. Três peças: o **host** (a aplicação com a LLM), o **client** (quem mantém a conexão) e o
**server** (quem expõe as capacidades). O servidor oferece **tools** — funções que o agente pode
chamar, como "classifique este fluxo".

**Contrato da tool**
O acordo escrito de o que a ferramenta recebe e o que devolve, em JSON. Fechar isso cedo permite
que a frente do classificador e a frente dos agentes trabalhem em paralelo sem se atrapalhar.

**Tool poisoning (envenenamento de ferramenta)**
Ataque contra o MCP: inserir instrução maliciosa na descrição de uma tool para induzir o agente a
fazer algo que não devia. É uma superfície de ataque nova e pouco testada em ferramentas de
segurança — pode virar contribuição original do nosso trabalho.

**On-premises vs. nuvem**
Rodar a IA em servidor próprio ou contratada de terceiro. Num sistema de segurança importa: usar
LLM em nuvem significa mandar telemetria da rede para fora. A banca do TCC I cobrou essa
discussão.

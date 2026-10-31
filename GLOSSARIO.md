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
O programa que transforma pacotes em números: o tradutor entre a rede, que fala "pacote", e o
modelo, que fala "número". Ele agrupa os quadros em janelas de tamanho fixo e escreve uma linha
de features por janela. Os autores do CICIoT2023 usaram janelas de 100 quadros nos floods e de 10
nas demais classes; o SentryIoT usa 100 em todo o tráfego. Com janela de 10, os 133.138 pacotes
do `DictionaryBruteForce.pcap` viram 13.064 linhas; com 100, 1.307.

**Janela**
Um grupo de quadros consecutivos que o extrator resume numa linha de 39 features. É a unidade
que o classificador rotula. No SentryIoT, toda janela tem 100 quadros: um flood enche uma janela
em milissegundos, e um ataque lento leva alguns segundos.

**Calibrar o extrator**
Provar que o nosso extrator está certo: rodamos ele no mesmo PCAP que os autores usaram e
conferimos se produz os mesmos números do CSV oficial deles. É como aferir uma balança com um
peso conhecido — se marca certo no peso conhecido, dá para confiar nela em qualquer coisa.

**tcpdump**
O programa que grava o tráfego da rede num arquivo PCAP. Foi o que os autores do CICIoT2023
usaram, e é o que o SentryIoT prevê no gateway: gravar o quadro inteiro (`-s 0`) e abrir um
arquivo novo a cada intervalo (`-G`). A PoC lê arquivos já gravados; a captura ao vivo fica para
depois. O Wireshark serve para olhar uma captura, não para gravar a do sistema; o pcapng que ele
grava por padrão se converte com `editcap -F pcap`.

**dpkt**
A biblioteca Python que lê o PCAP quadro a quadro. É a mesma do código dos autores do dataset, e
o nosso extrator, calibrado contra o deles, reproduz as 39 features. O Scapy, previsto no TCC I,
ficou de fora.

**Regeração dos dados**
Refazer as linhas de treino a partir dos PCAPs, com o nosso extrator, em vez de usar o CSV
oficial. Corrige dois problemas do CSV: a janela muda com a classe (10 ou 100 quadros) e o rótulo é
do arquivo inteiro. Na regeração, toda janela tem o mesmo tamanho (100 quadros, no modelo do
sistema), e a janela de um PCAP de ataque só leva o rótulo do ataque se tiver um quadro de um dos
sete atacantes.

**Tráfego de fundo**
As janelas de um PCAP de ataque sem nenhum quadro do atacante: o tráfego normal da rede, que
continuou durante a gravação. No CSV oficial elas levam o rótulo do ataque; no SentryIoT, as da
parte de treino entram como benignas (40.966 janelas), e as da parte de teste ficam fora do teste.

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
Muitas árvores de decisão (100, no nosso modelo), cada uma olhando um recorte diferente das
features e fazendo perguntas um pouco diferentes. Na hora de decidir, todas votam e a maioria
ganha. Se uma árvore se confunde, as outras compensam; por isso é robusto e roda em hardware
fraco.

**Treino, validação e teste**
O dataset é dividido em três partes. O modelo **treina** numa, é ajustado olhando outra
(validação) e é avaliado numa terceira que ele nunca viu (teste). Avaliar no mesmo dado em que
treinou é como corrigir a prova com o gabarito na mão — o número sai ótimo e não significa nada.

**Baseline**
O resultado de referência já publicado por outros. Serve para saber se o nosso está razoável.
No CICIoT2023 o baseline do Random Forest é dos próprios autores do dataset. O código desse
treino não foi publicado (o notebook dos autores não treina o RF), e por isso o resultado deles
não é reproduzido aqui.

**Desbalanceamento de classes**
Quando umas classes têm muito mais exemplos que outras. No nosso caso é extremo: 89,5% do
`MERGED_CSV` é DDoS e DoS, enquanto `DictionaryBruteForce` tem 0,028% (12.522 de 45 milhões de
linhas). Isso distorce as métricas (ver abaixo).

**Divisão por tempo e por arquivo**
Como separamos treino e teste sem sortear janela por janela, o que poria janelas vizinhas, quase
iguais, dos dois lados. Num rótulo de um PCAP só, o começo do PCAP (70% das janelas) vai para o
treino e o fim, para o teste. Num rótulo com mais de um PCAP, o último pela ordem do nome vai
inteiro para o teste, e os outros, inteiros para o treino.

**PCAP fora do treino**
O controle mais duro do classificador: um PCAP sai inteiro do treino, e o modelo é medido nas
janelas de teste dele, como se fosse uma captura nova. O recall cai em todas as categorias com
mais de um PCAP; em Recon, fica em 24,9%, contra 55,0% no corte por tempo (Tabela 1 do artigo).

**Ponto de operação**
A regra que transforma as probabilidades do modelo numa decisão sobre a janela. Duas concorreram
numa parte de validação, separada do teste: o argmax e um limiar sobre a probabilidade de ataque.
Venceu o argmax, que deixava no máximo 1% do tráfego benigno como ataque com o maior recall de
ataque. O incidente só abre com 4 janelas de ataque seguidas.

**Argmax**
"Fique com a categoria mais provável." Se o modelo diz 70% DDoS+DoS, 20% Recon e 10% Benign, o
argmax é DDoS+DoS.

---

## 3. Como medir se funcionou

**Acurácia**
Porcentagem de acertos no total. **Enganosa quando as classes estão desbalanceadas:** um modelo
que responda "DDoS" para tudo acerta 72,3% do nosso dataset e é completamente inútil.

**Precisão**
Das vezes que o modelo disse "é ataque", quantas ele acertou. Precisão baixa = muito alarme falso.

**Recall (sensibilidade)**
Dos ataques que realmente existiam, quantos o modelo encontrou. Recall baixo = ataque passando
despercebido.

**F1-score**
Combina precisão e recall num número só. **É o que revela a verdade em dataset desbalanceado**:
quando a acurácia está alta e o F1 baixo, o modelo acerta o que é fácil e abundante e erra o que
é raro. No artigo dos autores, a acurácia é alta e o F1 bem mais baixo `[conferir os valores na
tabela do artigo antes de citar]`.

**Taxa de falso positivo (FPR)**
Quanto tráfego normal foi acusado de ser ataque. Nosso artigo trata isso como o indicador
crítico de viabilidade: um sistema que grita o tempo todo é desligado pelo operador.

➡ **Regra do projeto:** relatar **recall por classe**, nunca só acurácia. E dizer com franqueza
em quais classes fomos mal, com o número de amostras ao lado.

**Macro-F1**
A média simples do F1 das categorias, com o mesmo peso para todas: uma categoria com 273 janelas
de teste conta tanto quanto uma com 214.373. Mostra que existem categorias fracas, mas não onde o
modelo erra; por isso, no artigo, o número principal é a tabela por categoria.

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
mais alarme falso. Nosso classificador é supervisionado: aprende as classes de ataque rotuladas
do CICIoT2023 e o tráfego benigno, sem assinatura escrita à mão. Reconhece bem os tipos de ataque
que viu no treino; o comportamento diante de um ataque novo não foi medido.

**DDoS**
Inundar um alvo com tráfego de milhares de aparelhos até ele cair. O aparelho IoT não é a
vítima, é a arma. Nos nossos dados, os floods são rajadas de pacotes pequenos e quase idênticos.

**Port scan (varredura de portas)**
Testar todas as portas de um alvo para ver quais estão abertas. É o ladrão testando cada porta e
janela da casa. Ainda não é invasão, é sondagem. Nos nossos dados aparece pelo excesso de
pacotes com a flag SYN.

**Brute force (força bruta)**
Tentar senha após senha até uma funcionar. **Atenção:** nos nossos dados ele manda *menos*
pacotes por segundo que o tráfego normal. Prova de que velocidade sozinha não detecta ataque.

**Exfiltração de dados**
Roubo de informação: o invasor já está dentro e vai copiando dados para fora, devagar, para não
ser notado. É o mais difícil de detectar, porque o tráfego parece legítimo.
**O CICIoT2023 não tem essa classe**, e por isso o cenário foi retirado da PoC em 10/10/2026, em
decisão com o orientador (`ROADMAP.md`).

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
num flood o classificador rotula centenas de janelas por segundo, e chamar a LLM em cada uma é
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
Vários agentes com papéis diferentes trabalhando juntos, em vez de um só fazendo tudo. No
SentryIoT são três: triagem, que confere o alerta; decisão, que escolhe a mitigação; e execução,
que aplica a medida e confere o efeito.

**MCP (Model Context Protocol)**
O padrão que conecta uma LLM a ferramentas externas. É o que liga o nosso classificador aos
agentes. Três peças: o **host** (a aplicação com a LLM), o **client** (quem mantém a conexão) e o
**server** (quem expõe as capacidades). O servidor oferece **tools**, funções que o agente pode
chamar. No SentryIoT são dez, divididas entre os agentes: por exemplo, `obter_resumo` devolve ao
agente de decisão o resumo de um incidente, sem endereço, e `propor_acao` registra uma proposta de
mitigação (`codigo/mcp/README.md`).

**Rótulo neutro**
O nome que o servidor MCP põe no lugar de cada endereço no resumo do incidente: `origem-1`,
`destino-1`. O agente de decisão, que pode rodar na nuvem, propõe a ação com o rótulo, e o
servidor troca o rótulo pelo endereço antes de calcular o risco. Assim nenhum endereço da rede
sai do ambiente.

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

**Modelo local e modelo de fronteira**
O modelo local roda num servidor interno, sem custo por token e sem mandar o dado a um fornecedor
de nuvem. No SentryIoT, é o `OBLITERATUS/Qwen3.8-27B-OBLITERATED`, o Qwen3.8-27B com a recusa
removida dos pesos, servido com o nome `qwen3.8-27c` por um gateway de modelos interno; a versão e
a quantização servidas não são conhecidas. O de fronteira é um dos modelos mais capazes, pago por
token e servido pela nuvem, pelo OpenRouter.

**Arquitetura híbrida**
A divisão do SentryIoT: triagem e execução no modelo local, e só o agente de decisão no modelo de
fronteira, lendo o resumo do incidente com rótulos neutros no lugar dos endereços. O servidor MCP
já entrega esse resumo (`obter_resumo`); quem vai chamar cada agente no seu modelo é o
orquestrador, a implementar. As outras duas configurações, tudo local e tudo na nuvem, serão
comparadas com ela no artigo.

**Orquestrador**
O código que vai encadear os agentes: chamar a triagem, passar o veredito pelo filtro de
endereços (`tipos.mascarar_enderecos`), esperar a aprovação no log e chamar a execução. Não é um
quarto agente; quem coordena o incidente é o agente de decisão. A implementar: hoje
`codigo/agente/pedidos.py` só monta os pedidos aos modelos, e o laço ReAct (`codigo/agente/laco.py`)
roda um agente de cada vez.

**Stub do servidor MCP**
O servidor MCP do repositório (`codigo/mcp/stub.py`). Nasceu como servidor de mentira, com
incidentes de exemplo, para os agentes serem escritos antes do classificador. Com `--cenarios`, em
modo de reprodução, atende os incidentes reais do reprodutor e é o servidor da PoC.

**Reprodutor de tráfego**
O comando que lê um PCAP (`python -m codigo.reprodutor`), extrai as janelas, classifica cada uma e
abre os incidentes no log do servidor MCP. Na PoC, faz o papel da captura ao vivo.

**Política de acionamento**
A regra que decide quando as janelas de ataque viram incidente, e portanto quantas vezes os
agentes são chamados: 4 janelas de ataque seguidas abrem o incidente, e as janelas do mesmo ataque
se juntam num incidente só. Um flood de 264 mil janelas vira 4 incidentes, um por sessão de
captura. É a defesa contra o Denial of Wallet. A primeira versão está no reprodutor de tráfego, com
um teto de 20 incidentes por PCAP, que vale nos experimentos. No modo contínuo, sem PCAP para
contar, o teto passa a ser por hora: até 10 incidentes por hora vão ao modelo de fronteira, e o
resto segue só pelo modelo local (a implementar).

**Gabarito da recomendação**
A lista das ações do catálogo aceitáveis em cada categoria de ataque e do alvo de cada uma
(`experimentos/gabarito_da_recomendacao.toml`), que fica fixa antes da primeira rodada dos
experimentos. A qualidade da recomendação é a porcentagem de incidentes com uma ação aceitável no
alvo certo. O arquivo é um rascunho que a equipe ainda revisa; a conferência das rodadas contra ele
é a implementar.

**Aprovador automático**
Nos experimentos, vai fazer o papel da pessoa que aprova as ações de risco alto: aprovar o que o
gabarito aceita, rejeitar o resto, inclusive a ação nova, e gravar a decisão no log como a de uma
pessoa. Assim o tempo até a remediação não depende de alguém estar olhando. A implementar: hoje a
aprovação só entra pelo comando da pessoa (`python -m codigo.mcp.aprovar`).

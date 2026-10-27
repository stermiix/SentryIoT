# Esqueleto do artigo — SentryIoT (TCC II)

Rascunho das seções do artigo. Trechos marcados com `[PENDENTE]` ainda não têm conteúdo; os
demais são rascunho pronto para revisão, a partir do que já está decidido em `ROADMAP.md` e
medido em `experimentos/resultados/`.

**Pendências fora do texto (ação humana, não dá para resolver por aqui):**
- O texto do artigo está em `artigo/Artigo_TCC2_SentryIoT.docx`, no template do Oriente. Este
  esqueleto continua como rascunho e fonte das correções, que precisam ser levadas ao `.docx`.

Pelo edital, o TCC II de CC e SI entrega o artigo científico (10 a 20 páginas, submissão de 03 a
09/11/2026) e a apresentação oral (15 a 20 minutos). Relatório técnico e pôster são entregas do
TCC I.

---

## Resumo / Abstract

`[PENDENTE]` Escrever por último, depois que Resultados e Metodologia fecharem. Rever o que o
resumo do TCC I prometia (classificação em MQTT/CoAP e detecção em tempo real) e ajustar: as 39
features só distinguem os protocolos que têm indicador (HTTP, HTTPS, DNS, SSH, Telnet e poucos
outros), e o extrator lê arquivo pcap, não captura ao vivo. As demais diferenças em relação ao TCC
I estão na abertura da seção 3. Mencionar a arquitetura híbrida (dado da rede não sai do
ambiente) como parte da contribuição.

## 1. Introdução

`[PENDENTE]` Enquadrar como NIDR (detecção **e** resposta), não NIDS, conforme o
reposicionamento pedido pela banca do TCC I (ver `README.md`, seção "Correções da banca do TCC
I"). O título também precisa mudar: o do TCC I era "Detecção de Ataques em IoT com IA Preditiva
via MCP", e o do TCC II deve dizer detecção e resposta.

Apresentar o público-alvo (decisão de 2026-10-25): as redes de casas e de pequenos negócios, como
um restaurante, com televisores, câmeras, sensores e assistentes de voz na mesma rede e sem equipe
de segurança. O motivo principal é o tamanho da rede do dataset: o CICIoT2023 é uma rede de
laboratório única, com 105 dispositivos IoT, em que os próprios dispositivos IoT maliciosos atacam
os outros (NETO et al., 2023), o que corresponde a uma casa ou a um
pequeno comércio, e não à rede de uma empresa. Nesse tamanho, uma caixa só captura o tráfego e
aplica as respostas (seção 3.1); quem não tem equipe de segurança é quem mais precisa de um agente
que explique o incidente e proponha a resposta; e o custo de tokens pesa mais num orçamento
pequeno (seção 3.5). A implantação numa empresa fica para os trabalhos futuros (seção 6).

## 2. Trabalhos correlatos

### 2.1 O CICIoT2023 e o que a literatura já apontou

Neto et al. (2023) publicaram o CICIoT2023: tráfego de uma rede de laboratório com 105 dispositivos
IoT, em que dispositivos IoT maliciosos atacam os outros, com 33 ataques em sete categorias além do
tráfego benigno. O dataset distribui os pcaps, os CSVs e o código de extração, e agrupa as features
em janelas de 10 ou de 100 pacotes, calculando a média de cada janela. O artigo descreve 47
features; os arquivos públicos que este trabalho usa trazem 39 (seção 3). Os autores também
publicam um benchmark com vários modelos, entre eles o Random Forest, que serve de baseline aqui
(seção 3.4).

Doménech et al. (2025) usaram o CICIoT2023 e o CICIoMT2024, ambos da Universidade de New
Brunswick, e confirmam que os dois datasets usam janela de 100 pacotes para DDoS, DoS e Mirai e de
10 para o resto. Para o CICIoMT2024, que repete esse esquema, recomendam uma janela única para
todos os tipos de tráfego, porque o tamanho da janela muda a distribuição das features e, numa
implantação, o modelo recebe sempre o mesmo tamanho. Também mostram que um modelo treinado no
CICIoT2023 e testado no CICIoMT2024 perde muito: o F1 do Random Forest em cinco classes cai 66,87%.
Por fim, criticam o uso de métricas ponderadas em datasets desbalanceados e recomendam a média sem
peso, o que combina com o uso, neste trabalho, de métricas por classe. O efeito de trocar a janela
de um modelo já treinado não é medido por eles.

Problemas parecidos já foram documentados em outros datasets de intrusão. Engelen, Rimmer e Joosen
(2021) revisitaram o CICIDS2017 e encontraram problemas na geração do tráfego, na construção dos
fluxos, na extração das features e nos rótulos; ao corrigi-los, mais de 20% do tráfego original
foi reconstruído ou rerrotulado, e os testes de aprendizado de máquina melhoraram de forma
significativa. Liu et al. (2022) fizeram uma revisão crítica do CIC-IDS-2017 e do CSE-CIC-IDS-2018
e relatam erros antes não documentados na orquestração dos ataques, na geração das features, na
documentação e nos rótulos, que abalam resultados de vários trabalhos; recriaram o dataset com a
lógica de rotulagem corrigida e recomendam que todo dataset publique a sua. A lição que importa
aqui é que um dataset de referência pode ter erros que só aparecem quando se confere o tráfego
bruto contra os rótulos e as features.

### 2.2 O que este trabalho acrescenta sobre o CICIoT2023

Duas medidas deste trabalho tratam de problemas do CICIoT2023 que a literatura citada acima
aponta em outros datasets. A primeira é o teste direto da janela trocada: o modelo treinado no
`MERGED_CSV` não reconhece flood em janela de 10, nem varredura e força bruta em janela de 100, e
retirar as seis colunas que dependem da janela custa menos de 0,3 ponto de acurácia sem resolver o
problema, porque o modelo continua dependendo do tamanho da janela
(`experimentos/resultados/teste_da_janela.md`). A segunda é a medida, por pcap e por tamanho de
janela, das janelas rotuladas como ataque que não têm nenhum quadro do host que ataca: o rótulo do
CSV oficial é do arquivo inteiro, e nos pcaps de varredura, força bruta, Web e spoofing entre 33% e
87% das janelas de 10 são só tráfego de fundo, acima de 57% em todos, menos no
`Recon-HostDiscovery` (`experimentos/resultados/janelas_sem_atacante.md`). A regeração dos dados
com o nosso extrator, em janela única e com o rótulo decidido pelo atacante, é a resposta a essas
duas medidas (seção 3). A filtragem pelo endereço do atacante é uma escolha de método deste
trabalho, e não é apresentada como ideia inédita.

### 2.3 Detecção e resposta com IA no mercado, e o risco de custo

A banca do TCC I pediu que o artigo situasse o trabalho frente a soluções comerciais. A Darktrace
(2024), num blog, divulga ter sido reconhecida pela KuppingerCole como líder em detecção e
resposta de rede (NDR) e diz responder de forma autônoma; a Netskope (2023), num comunicado, lançou
o SkopeAI, que usa aprendizado de máquina para proteção de dados e defesa contra ameaças; e a
Vectra AI (2022), também num comunicado, apresentou o Attack Signal Intelligence, que automatiza a
detecção, a triagem e a priorização de ameaças. As três fontes são material de divulgação dos
próprios fornecedores, e não avaliações independentes, e os produtos são comerciais; por isso o
SentryIoT não é comparado a eles em desempenho. O que o trabalho oferece é um sistema aberto,
reproduzível e medido contra um dataset público, voltado a casas e pequenos negócios.

O mesmo ponto da banca trata do *Denial of Wallet*, que Kelly, Glavin e Barrett (2021) definem
como ataque que explora a cobrança por uso de computação *serverless* para gerar custo ao alvo.
Num sistema em que cada incidente pode chamar um modelo pago, o risco análogo é o gasto de tokens
provocado por tráfego malicioso. Zhang et al. (2026), em *preprint*, mostram o risco em agentes
LLM que chamam ferramentas: o conteúdo devolvido por uma ferramenta maliciosa é reenviado ao
modelo nas chamadas seguintes e cobrado de novo. O SentryIoT responde ao risco de custo com a
política de acionamento, que agrupa as janelas em incidentes, e com o teto por hora de incidentes
que vão ao modelo de fronteira (seção 3.5).

### 2.4 Agentes LLM e a segurança do MCP

Os agentes do SentryIoT seguem o laço ReAct (YAO et al., 2023), em que o modelo alterna raciocínio
e chamadas de ferramenta. Esse desenho expõe o sistema a duas famílias de ataque já descritas na
literatura. A primeira é a injeção indireta de prompt (GRESHAKE et al., 2023): o modelo lê dados
que não vêm de quem o usa, e instruções escondidas neles podem mudar o seu comportamento, como se
o dado fosse código. Os autores veem difícil uma defesa infalível. No SentryIoT, os dados que o
modelo lê descrevem tráfego de rede, que o atacante controla em parte.

A segunda é a ameaça ao próprio MCP. Hou et al. (2026) descrevem o ciclo de vida de um servidor
MCP e organizam as ameaças em 16 cenários, entre eles a injeção indireta por dados devolvidos
pelas ferramentas, e apontam a casa inteligente e a IoT industrial como ambientes de risco
específico. Radosevich e Halloran (2025) mostram que o Claude 3.7 e o Llama-3.3-70B podem ser
levados a usar ferramentas do MCP para executar código malicioso, abrir acesso remoto e roubar
credenciais no sistema de um desenvolvedor de IA, que o Claude também cai em ataque por dados
corrompidos que recupera, e que as recusas dos modelos não são confiáveis; por isso propõem
proteger também o servidor, com um auditor de servidores. Beurer-Kellner e Fischer (2025), da
Invariant Labs, descrevem o *tool poisoning*, em que instruções maliciosas vão na descrição da
ferramenta, visíveis ao modelo e não à pessoa, e o *rug pull*, em que o servidor muda a descrição
depois de aprovada. Hou et al. saíram em periódico
revisado por pares e Yao et al. e Greshake et al., em anais de conferência e de workshop;
Radosevich e Halloran são *preprints*, e a Invariant é um relato técnico de fornecedor, e não
artigo revisado por pares.

O SentryIoT difere no ponto de confiança: o servidor MCP é do próprio sistema, e não de terceiros,
o que reduz parte desse risco, mas não o da injeção por dados de tráfego. Por isso o trabalho
parte da premissa de que o modelo pode ser enganado e põe as garantias no servidor: a troca dos
endereços por rótulos antes de qualquer dado ir à nuvem, a política de risco calculada sobre o
endereço real e a aprovação humana das ações de risco alto (seção 3.5). O teste de
*tool poisoning* contra o servidor só entra se couber no calendário (seção 3.6).

**Notas de conferência (não entram no artigo).** Fontes conferidas em 11/10/2026 (referências
completas no fim):
- Neto et al. (2023): artigo original do CICIoT2023, revisado por pares (*Sensors*), que agrupa
  as features em janelas de 10 e de 100 pacotes e calcula a média. Os pcaps e o código de extração
  dos autores vêm da página oficial do dataset (CANADIAN INSTITUTE FOR CYBERSECURITY, 2023).
  Conferido em 26/10/2026 no resumo (via Crossref; o site da MDPI bloqueou a leitura): 33
  ataques, 105 dispositivos IoT, sete categorias (DDoS, DoS, Recon, Web-based, brute force,
  spoofing e Mirai), todos os ataques executados por dispositivos IoT maliciosos contra outros
  dispositivos IoT. As janelas de 10 e de 100 e as 47 features não foram vistas no texto do Neto,
  só no Doménech.
- Doménech et al. (2025): revisado por pares (*Internet of Things*, Elsevier). Conferido no PDF
  em 26/10/2026: (a) a seção 3 documenta a janela de 100 pacotes para DDoS, DoS e Mirai e de 10
  para o resto, nos dois datasets (CICIoT2023 e CICIoMT2024); (b) a seção 5.1.1 recomenda
  explicitamente janela uniforme para todos os tipos de tráfego, mas como crítica ao
  CICIoMT2024, que repete o esquema do CICIoT2023, e pede que os autores de datasets adotem
  janela uniforme; ao citar, dizer isso, e não que a recomendação é sobre o CICIoT2023; (c) a
  queda de até 66,87% de F1 (Random Forest, 5 classes, experimento 2) vale **só** treinando no
  CICIoT2023 e testando no CICIoMT2024, e não nos dois sentidos, como o resumo do artigo sugere;
  (d) critica métricas ponderadas em dataset desbalanceado e recomenda a média sem peso, o que
  apoia o nosso uso de macro-F1 e métricas por classe (seções 2.2 e 4.1.3 do artigo deles).
- Engelen, Rimmer e Joosen (2021) e Liu et al. (2022): revisados por pares (IEEE SPW e IEEE
  CNS). Resumos conferidos em 26/10/2026 (via Semantic Scholar; o texto completo não foi lido):
  Engelen et al. apontam problemas de geração de tráfego, construção de fluxos, extração de
  features e rotulagem no CICIDS2017, com mais de 20% do tráfego reconstruído ou rerrotulado; Liu
  et al. reportam erros na orquestração dos ataques, nas features, na documentação e nos rótulos
  do CIC-IDS-2017 e do CSE-CIC-IDS-2018.
- Greshake et al. (2023): lido por inteiro no arXiv. A publicação em anais (16th ACM Workshop on
  Artificial Intelligence and Security, AISec, junto do CCS '23, Copenhague, p. 79-90, DOI
  10.1145/3605764.3623985) vem do Crossref; o PDF dos anais não foi aberto, e o texto lido é o do
  arXiv.
  ReAct (Yao et al., 2023): o arXiv diz que a versão 3 é a final do ICLR 2023 (11ª edição,
  Kigali, 1 a 5 de maio, confirmado em iclr.cc); a página do OpenReview não abriu, e por isso a
  referência aponta para o arXiv.
  Radosevich e Halloran (2025) e Hou et al. (2026): introdução e seções principais lidas.
- Darktrace, Netskope, Vectra AI e *Denial of Wallet* (Kelly, Glavin e Barrett, 2021): pedidos
  pela banca do TCC I, prioridade baixa, menção curta sem análise detalhada. Páginas abertas em
  26/10/2026: a da Darktrace é um blog de 18/11/2024; a da Netskope, um comunicado de 25/07/2023;
  a da Vectra, um comunicado de 12/10/2022 republicado no Dark Reading. Zhang et al. (2026) é
  *preprint* de 23/09/2026, e só o resumo foi lido; a lista de autores é longa, e por isso a
  referência usa "et al.".

Deixar explícito o que é contribuição nossa: a camada MCP, com o contrato das tools, a política
de risco graduada com aprovação humana e a arquitetura híbrida dos agentes, e a comparação entre
as configurações local, nuvem e híbrida; no classificador, o teste direto da janela trocada
(`experimentos/resultados/teste_da_janela.md`) e a medida, por pcap e por tamanho de janela, das
janelas sem quadro do atacante (`experimentos/resultados/janelas_sem_atacante.md`). A filtragem
pelo endereço do atacante é a escolha que fizemos para regerar os dados, e não é apresentada
como ideia inédita. Ramkumar et al. ficou de fora da lista: o texto completo é pago e não foi
possível confirmar que ele filtra por MAC. O candidato achado, sem confirmação de que é o mesmo
trabalho da lista original ("2024"), é RAMKUMAR, K. et al. *Diagnosing unknown attacks in smart
homes using abductive reasoning*, IEEE Trans. Software Engineering, 2025, DOI
10.1109/TSE.2025.3610540; o resumo só diz que usa o CICIoT2023 e o IoT-23 como referência.

## 3. Metodologia

Em relação à proposta do TCC I, o trabalho mudou nos pontos a seguir. Não há classificação
específica de MQTT e CoAP, porque as 39 features só têm indicador para HTTP, HTTPS, DNS, SSH,
Telnet, SMTP, IRC e DHCP. A extração lê arquivo pcap, e a captura ao vivo fica como trabalho
futuro. Não houve busca de hiperparâmetros por grid search: o Random Forest usa os parâmetros
padrão do scikit-learn, porque a contribuição do trabalho está na camada MCP. O N-BaIoT deixou de
ser o dataset secundário, e nenhum outro o substituiu. O cenário de exfiltração de dados saiu da
PoC, porque o CICIoT2023 não tem essa classe. E os agentes rodam num modelo local, com modelos de
nuvem só nos experimentos, em vez de um único modelo comercial em nuvem.

### 3.1 Captura e extração de features

O sistema processa tráfego bruto em arquivo pcap, e não apenas o CSV pré-processado do dataset, o
que responde ao avaliador 2 do TCC I. A captura da rede grava um arquivo pcap com o `tcpdump`, a
mesma ferramenta com que os autores do dataset capturaram e fatiaram os pcaps (decisão de
2026-10-25); a extração das 39 features por janela de quadros é feita com `dpkt`, como no código
dos autores do dataset, e não com o Scapy previsto no TCC I. No código dos autores, o Scapy só é
importado para Zigbee e Bluetooth e não contribui para nenhuma das 39 colunas.

Os pcaps, os CSVs e o código de extração dos autores vêm da página oficial do CICIoT2023
(CANADIAN INSTITUTE FOR CYBERSECURITY, 2023), e o código e os scripts dos experimentos deste
trabalho estão no repositório do projeto (OLIVEIRA et al., 2026). O trabalho não faz coleta in
loco em dispositivos IoT reais: seria inviável no prazo, e o tráfego capturado não teria rótulo.
O papel da captura é cumprido pelos pcaps brutos do CICIoT2023, que o extrator lê da mesma forma
que leria um arquivo gravado na rede. O Wireshark não é necessário ao sistema: serve para
inspecionar capturas, e o pcapng que ele grava por padrão se converte em pcap com
`editcap -F pcap`. O Scapy também não é usado, porque a extração precisa repetir o cálculo dos
autores, feito com `dpkt`.

Numa implantação numa casa ou num pequeno comércio, o público-alvo do trabalho (seção 1), como um
restaurante com televisores, câmeras, sensores e assistentes de voz na rede, o gateway do SentryIoT
fica entre o modem da operadora e os aparelhos e, de preferência, é também o ponto de acesso
Wi-Fi. No modo comum do Wi-Fi, um aparelho
não fala direto com outro: todo quadro passa pelo ponto de acesso. Assim o gateway vê também o
tráfego de um aparelho para outro, que é o dos ataques do CICIoT2023, em que os atacantes estão na
mesma rede das vítimas. Os aparelhos IoT ficam numa rede própria, separada da de computadores e
celulares, e o tráfego entre as redes também cruza o gateway, que é onde as ações do catálogo
seriam aplicadas, no firewall dele. Ali o `tcpdump` grava a interface da rede IoT de forma
contínua, com o quadro inteiro (`-s 0`; um limite curto encolhe as colunas de tamanho) e um
arquivo novo a cada intervalo (`-G`). A gravação é feita na interface da rede, e não no enlace que
leva várias redes com etiqueta de VLAN, porque o extrator descarta o quadro etiquetado, como o
código dos autores. A PoC lê arquivos fechados; a classe `Extrator` já recebe um quadro por vez, e
a captura ao vivo fica como um adaptador futuro sobre ela. Num teste de 25/10, 5.000 quadros do
Wi-Fi de um notebook, gravados com `tcpdump -i en0`, passaram pelo reprodutor sem conversão, do
extrator à abertura de incidentes: um arquivo gravado fora do dataset entra no sistema. Os achados
desse teste estão nas Limitações.

O extrator (`codigo/captura/extrator.py`) foi calibrado em duas etapas. Na primeira, contra os
CSVs oficiais de 5 pcaps, um por família (DDoS, DoS, Mirai, Recon e BruteForce), somando 167.304
linhas, as 39 colunas foram reproduzidas sem nenhuma divergência, com tolerância relativa de 1e-9;
o maior desvio relativo observado, de 9,88e-13, é da ordem do arredondamento de ponto flutuante
(`experimentos/resultados/calibracao.md`). Na segunda, os 38 pcaps foram extraídos como os autores
extraíram, em pedaços de 10 MB e com a janela da classe, e cada linha foi procurada entre as
linhas do mesmo rótulo no `MERGED_CSV` inteiro, com os 39 valores iguais até cerca de 9 algarismos
significativos. Em 15 rótulos, toda linha do `MERGED_CSV` tem par entre as nossas, o que não
aconteceria se o cálculo divergisse em alguma janela; do nosso lado, entre 95,53% e 99,00% das
linhas de cada pcap têm par, e o que falta vem dos arquivos do `MERGED_CSV` truncados na fonte
oficial (`experimentos/resultados/calibracao_conjunto.md`). Na regeração e na operação, o pcap é
lido de uma vez, sem o fatiamento de 10 MB; as distribuições das duas leituras são praticamente
iguais, com distância de Kolmogorov-Smirnov de no máximo 0,0102 entre as 39 colunas.

O sistema lê o pcap, e não registros NetFlow, outro ponto levantado pela banca do TCC I. Um
registro NetFlow típico resume cada fluxo em poucos campos: endereços, portas, protocolo,
quantidade de pacotes e de bytes, instantes de início e fim e, no máximo, a união das flags TCP
do fluxo. É leve e não guarda conteúdo, mas perde o que as 39 features do CICIoT2023 medem quadro
a quadro: a flag de cada pacote, o tamanho de cada quadro e a variação entre eles (`Min`, `Max`,
`Std`), o intervalo entre chegadas (`IAT`) e a fração da janela em cada protocolo de aplicação. O
custo do pcap é o volume, já que os 38 pcaps usados somam cerca de 46 GB, e a exposição do
conteúdo dos pacotes na captura; o extrator guarda só os campos de cabeçalho que mede e os
endereços da janela, e nenhum conteúdo de pacote chega aos agentes. Numa rede que só exporte
NetFlow, o classificador teria de ser treinado de novo, com outro conjunto de features.

### 3.2 Pré-processamento e amostragem

Na fase exploratória, o `MERGED_CSV` publicado pelos autores (45.019.234 linhas, 63 arquivos) foi
amostrado com teto de 50.000 linhas por rótulo e semente fixa (42), preservando integralmente as
classes raras. A amostra resultante tem 1.288.479 linhas, registradas em
`experimentos/resultados/manifesto_amostra.json`. Os rótulos (34 classes) são normalizados e
mapeados para 7 categorias, com DDoS e DoS juntos. As features descrevem os pacotes, e não
quantas máquinas atacam: 29,5% das linhas do `MERGED_CSV` têm o vetor das 39 features igual ao de
uma linha de outra categoria, quase sempre o mesmo flood rotulado como DDoS e como DoS. A
separação entre os dois é feita depois, pela quantidade de endereços de origem do incidente, fora
do modelo.

Os dados de treino finais, porém, não vêm do `MERGED_CSV`: são regerados a partir dos pcaps com o
nosso extrator (decisão de 2026-10-10, `ROADMAP.md`). O motivo está na seção 3.3 e nas limitações
do dataset: a janela de agregação varia com a classe e o rótulo é do arquivo inteiro. Na
regeração, cada um dos 38 pcaps é extraído em janela única. Os 34 rótulos têm pcap: 31 com um
arquivo, `DDoS-SYN_Flood` e `DoS-SYN_Flood` com dois cada e `BenignTraffic` com três. Numa captura
benigna toda janela é benigna, e numa captura de ataque a janela só recebe o rótulo do arquivo se
contém um quadro de um dos sete Raspberry Pi atacantes documentados pelos autores, e é descartada
caso contrário. As janelas descartadas, o tráfego de fundo das capturas de ataque, ficam à parte;
no treino do modelo do sistema, as da parte de treino de cada pcap entram como benignas (seção
3.3). A divisão treino/teste é por tempo dentro de cada pcap (os primeiros 70% das
janelas para o treino) ou por arquivo inteiro quando o rótulo tem mais de um pcap (o último, pelo
sufixo numérico do nome, fica no teste), o que evita que janelas vizinhas caiam dos dois lados. O teto de 50.000 janelas por rótulo e a semente 42 são
mantidos (`codigo/classificador/regerar.py`, `experimentos/resultados/regeracao.md`).

### 3.3 Treino e avaliação do classificador

As métricas do classificador são a precisão, o recall e o F1 de cada categoria e a taxa de falso
positivo, com destaque para o tráfego benigno classificado como ataque. O resultado principal é a
tabela por categoria no corte por tempo, no ponto de operação, com dois controles ao lado: o recall
com o pcap inteiro fora do treino e o alarme falso com cada pcap benigno fora do treino (decisão de
2026-10-13, `ROADMAP.md`). O macro-F1 é relatado, mas não é o número principal: dá o mesmo peso a
categorias com 273 e com 214.373 janelas de teste e não mostra onde o modelo erra. A acurácia
global também não é: DDoS e DoS somam 89,5% das linhas do `MERGED_CSV`, e, com as duas juntas,
um modelo que respondesse DDoS+DoS para tudo acertaria 78,4% das janelas de teste do sistema.

Na fase exploratória, o Random Forest (scikit-learn, 100 árvores, parâmetros padrão) foi treinado
e avaliado na amostra do `MERGED_CSV` descrita acima, com 80% das linhas para o treino e 20% para
o teste. Duas estratégias de divisão foram testadas: sorteio estratificado de linhas (15,11% dos
vetores de teste também aparecem no treino, por causa de features repetidas) e divisão por grupos
de vetores idênticos (0% de sobreposição). Duas priores de treino também foram comparadas: a
proporção da própria amostra e a proporção natural do dataset completo, por peso de amostra.

Na configuração tomada como referência (7 categorias, sorteio estratificado, priori da amostra,
39 features), a acurácia é de 93,81% na amostra de teste, ou 98,58% reponderada para a
distribuição natural do dataset completo, e o macro-F1 é de 74,11% (69,96% reponderado). A
divisão por grupos dá valores da mesma ordem, e a diferença entre as duas não se distingue do
ruído entre sementes. Com a priori natural, o tráfego benigno classificado como ataque cai de
46,38% para 14,48%, mas o recall reponderado de Recon cai de 92,52% para 78,87%, e o de
BruteForce, de 33,55% para 12,98% (`experimentos/resultados/treino_exploratorio.md`).

Um teste adicional, isolando o efeito do tamanho da janela, mostrou que o modelo treinado nas
janelas do `MERGED_CSV` (100 pacotes para DDoS/DoS/Mirai, 10 para as demais) não generaliza para
uma janela única na operação: o recall de floods HTTP cai a menos de 2% quando extraídos em
janela de 10, e o recall de varredura de portas e força bruta cai a 0–18% quando extraídos em
janela de 100 (`experimentos/resultados/teste_da_janela.md`). Retirar as seis colunas que
dependem do tamanho da janela não resolve. Foi esse resultado que levou à regeração dos dados
(seção 3.2).

O classificador do sistema é treinado de outra forma, nos dados regerados (seção 3.2): um Random
Forest de 100 árvores, com os parâmetros padrão do scikit-learn e sem busca de hiperparâmetros,
nas 39 features, em 7 categorias, com janela de 100 quadros, teto de 50.000 janelas por rótulo,
semente 42 e a divisão por tempo e por arquivo descrita na seção 3.2. As janelas de fundo da parte
de treino de cada pcap de ataque, sem nenhum quadro do atacante, entram no treino como benignas.
São 567.732 janelas rotuladas e 40.966 de fundo no treino, e 273.566 janelas de teste
(`experimentos/resultados/regeracao.md`).

A janela de 100 quadros foi escolhida em 2026-10-10, com os dois modelos treinados sem o fundo:
macro-F1 de 82,3% contra 75,7% com janela de 10, e 1,9% contra 12,7% das janelas de um pcap
benigno fora do treino classificadas como ataque (`experimentos/resultados/regeracao_sem_fundo.md`).

O tráfego de fundo entrou no treino depois de medido o que o modelo fazia com ele. Treinado sem o
fundo, o modelo classificava como ataque 72,3% das janelas de fundo da parte de teste e, com o
`BenignTraffic.pcap` fora do treino, 38,5% das janelas desse pcap, 32% do pcap como Recon. Seis
configurações de treino foram comparadas com três sementes (42, 1 e 2), por diferenças pareadas
na mesma semente e nas mesmas janelas, com intervalo de 95% por reamostragem de blocos de 10
janelas vizinhas (`experimentos/resultados/rodadas_normalizadas.md`). O fundo como benigno baixa os
dois números para 13,3% e 5,4%; normalizar o tamanho do quadro não os baixa. A equipe fixou antes
da medida a regra para adotar o fundo no treino: na média das sementes, (a) benigno classificado
como ataque abaixo de 10% no pior pcap benigno fora do treino, (b) recall de DDoS+DoS de pelo menos
98% no corte por tempo e (c) queda de no máximo 5 pontos no recall do `Recon-PortScan.pcap` com o
pcap fora do treino. As três foram atendidas, com 5,4%, 98,37% e queda de 3,53 pontos, mas o
intervalo de 95% da diferença em (c) vai de −5,29 a −1,77 pontos e passa do limite na ponta
inferior. A condição (c) foi medida no trecho de teste do pcap (850 janelas), como todas as medidas
com o pcap fora do treino; no pcap inteiro (3.783 janelas), o recall vai de 89,7% para 83,4%, queda
de 6,26 pontos, e por ele a condição falharia. A adoção foi mantida porque a regra foi aplicada
como fixada e o ganho no alarme falso é grande (decisão de 2026-10-13).

A decisão sobre cada janela segue um ponto de operação escolhido numa parte de validação,
separada do teste: as últimas 15% da parte de treino de cada pcap, por tempo. Um modelo treinado
no restante da parte de treino classifica todas as janelas da validação, 9.866 benignas e 321.428
de ataque. Concorrem a categoria mais provável (argmax) e o limiar, em que a janela é ataque se
1 − P(Benign) ≥ t, na categoria de ataque mais provável, com t de 0,01 em 0,01; entre os candidatos
que deixam no máximo 1% das janelas benignas como ataque, vence o de maior recall de ataque. No
modelo do sistema venceu o argmax, com 0,79% do benigno como ataque e 99,55% de recall de ataque,
contra 0,95% e 99,51% no melhor limiar (t = 0,61). Um incidente só abre com 3 janelas de ataque
seguidas. O modelo do sistema é o do treino inteiro, com a regra e o N gravados ao lado dele
(`codigo/classificador/operacao.py`, `experimentos/resultados/ponto_de_operacao.md`).

Os controles medem o que o corte por tempo não mostra: o recall de cada pcap quando nenhuma janela
dele entra no treino, o alarme falso com cada um dos três pcaps benignos fora do treino, um por
vez, e o fundo da parte de teste classificado como ataque. Os resultados estão na seção 4. Os
controles do modelo de 10/10 que não foram refeitos para o do sistema (cinco sementes, importância
por permutação, intervalos das classes raras e custo) estão em
`experimentos/resultados/rodadas_de_teste.md`.

O Spoofing depende da captura. 84% das janelas de Spoofing têm quadro menor que 60 bytes, gravado
sem o preenchimento do Ethernet, o que nas demais categorias quase não acontece. No modelo de
10/10, o fundo dos dois pcaps de spoofing, sem quadro do atacante, caía na categoria Spoofing em
97,7% e 99,5% das janelas, e com o quadro medido como no fio o recall de Spoofing caía de 99,4%
para 88,2% no corte por tempo e de 97% para 66% com o pcap fora do treino
(`experimentos/resultados/rodadas_normalizadas.md`). A medida como no fio não foi adotada, e o
artefato fica como limitação (seção 5).

### 3.4 Justificativa do Random Forest

O modelo escolhido é o Random Forest, e não uma rede neural, por dois motivos: no benchmark
publicado pelos autores do dataset (Neto et al., 2023), ele está entre os melhores modelos
testados; e, mais importante para o restante do sistema, a importância de cada feature sai do
próprio treino, sem um método de explicação à parte. Neste trabalho, a importância é medida por
redução média de impureza e vale para o modelo inteiro (`experimentos/resultados/regeracao.md`).
Para cada incidente, o servidor entrega aos agentes as features principais, com o valor de
referência do tráfego benigno, e é esse o insumo da recomendação de mitigação. `[PENDENTE: dizer
como as features principais de um incidente são escolhidas; se for adotada atribuição por
decisão, como o TreeSHAP, citar o método.]` O protocolo dos autores não é reproduzido aqui: o
notebook publicado não treina o Random Forest, e os nossos dados de treino são regerados dos
pcaps, então os números não se comparam diretamente com os do artigo do dataset. A diferença
começa nas colunas: o modelo do artigo usou 46 features, e os arquivos públicos trazem 39, sem oito
delas, como `Srate`, `Drate` e `Covariance`. Com as 39, 29,49% das linhas do `MERGED_CSV` repetem o
vetor de uma linha de outra categoria, e o acerto em 8 categorias no conjunto completo não passa de
92,87%, abaixo dos 99,44% publicados para o Random Forest
(`experimentos/resultados/baseline_neto.md`).

### 3.5 Servidor MCP e sistema multiagente

O servidor da PoC é o servidor MCP em modo de reprodução, que atende os incidentes reais do
reprodutor de tráfego. O contrato, na versão 0.3.0,
tem 10 tools MCP divididas entre os três agentes (triagem, decisão e execução) e grava cada passo
num log de eventos em JSONL. O incidente traz a categoria do modelo, que junta DDoS e DoS
(`DDoS+DoS`), e a categoria depois da regra que separa os dois pela quantidade de origens. As
respostas saem de um catálogo de cinco ações: `limitar_taxa`, `bloquear_ip`,
`isolar_dispositivo`, `revogar_credencial` e `fechar_porta`, esta acrescentada em 2026-10-25
`[a implementar]`, que fecha no firewall do gateway o acesso a uma porta de um dispositivo, com o
alvo no formato `23/tcp@destino-1`. Para isso, o incidente passa a trazer as portas de destino mais
frequentes, tiradas dos cabeçalhos TCP e UDP fora das 39 features, e o resumo lido pelo agente de
decisão as mostra `[a implementar]`. Fora do catálogo, o agente pode propor uma ação nova, que é
sempre de risco alto. A política de risco separa as ações de risco baixo, aplicadas sem aprovação, das de risco alto, que
dependem de aprovação humana, e limita a 10 as propostas que aguardam aprovação em cada incidente,
porque a fila é lida por uma pessoa e um agente enganado por conteúdo vindo da rede poderia
enchê-la. Como a origem de um flood UDP ou ICMP pode ser forjada, bloquear uma origem da rede
local é de risco alto, os endereços críticos (o servidor MCP, o host do modelo local e o
resolvedor DNS) são protegidos, e o teto de medidas de risco baixo ativas vale por incidente (5) e
para o sistema todo (10). O custo de tokens é contido de outra forma: os agentes recebem o resumo
do incidente, e não as janelas, e o detalhe vem em fatias de até 20 janelas. Na PoC, a resposta é
executada num ambiente simulado, com aprovação humana e possibilidade de desfazer, e a verificação
do efeito responde sempre que o ataque cessou (seção 5; ver `codigo/mcp/README.md` e
`codigo/mcp/politica.toml`).

Arquitetura híbrida (Figura 1; decisões de 2026-10-10, 2026-10-11, 2026-10-19 e 2026-10-25): o
agente de decisão roda num modelo de fronteira, pela nuvem, e coordena o incidente. Ele aceita ou
descarta o veredito da triagem, propõe a ação e propõe outra quando o efeito verificado mostra que
a anterior não resolveu. O encadeamento dos agentes (chamar a triagem, esperar a aprovação no log
e chamar a execução) fica em código, num orquestrador que não é um quarto agente
`[a implementar]`. Os agentes de triagem e de execução, com a verificação do efeito, rodam no
modelo local, uma variante sem censura do Qwen3.8 de 27 bilhões de parâmetros (`qwen3.8-27c`),
chamada por uma API compatível com a da OpenAI. Ela foi escolhida numa comparação com o Qwen normal
(`qwen3.8-27b`) na triagem e na decisão: o normal entrou em laço em metade das triagens, e a
variante sempre chegou a um veredito, com cerca de um terço dos tokens
(`experimentos/resultados/escolha_do_modelo_local.md`; decisão de 2026-10-25). A variante sem
censura não recusa a análise de um ataque, mas obedece com mais facilidade a uma instrução
escondida no tráfego, e por isso as garantias do sistema ficam no servidor, e não no modelo. A
triagem marca como duvidoso todo incidente com confiança do classificador abaixo de 0,6: nos 235
incidentes da avaliação dos 38 pcaps, esse limiar pega 24 dos 57 incidentes falsos e marca 4 dos
178 verdadeiros (`experimentos/resultados/limiar_da_triagem.md`). Na PoC, quem serve o modelo é
um servidor de inferência compatível com a API da OpenAI, num gateway interno de outra
organização, numa rede que não é da equipe, com hardware e quantização desconhecidos
`[CONFERIR com quem mantém o gateway: a variante exata e a quantização]`, e os dados que passam
por ele são os do CICIoT2023, públicos. Numa implantação, o modelo local fica num servidor dentro da rede atendida,
no próprio gateway, se ele comportar, ou numa máquina ao lado, e o código não muda: só o endereço
do servidor (`LLM_BASE_URL`).
A garantia de que nenhum endereço da rede chega à fronteira está no servidor, e não no prompt: o agente de decisão não tem as tools que devolvem endereços
e lê o incidente por `obter_resumo`, montado pelo servidor com um rótulo neutro (`origem-1`,
`destino-1`) no lugar de cada endereço. Ele propõe a ação com o rótulo; o servidor troca o rótulo
pelo endereço e calcula o risco sobre o endereço real, e só o agente de execução, local e o único
com credenciais, recebe o endereço. Toda resposta à linha de decisão passa ainda por um filtro
que troca por um marcador qualquer endereço que tenha sobrado em texto livre. O veredito da
triagem, texto livre escrito pelo modelo local, precisa passar pelo mesmo filtro antes de chegar
ao agente de decisão `[a implementar]`. O orquestrador aceitará três
configurações, tudo local, tudo na nuvem e híbrida, e a comparação entre elas em qualidade, custo
e tempo é resultado do artigo. Isso responde ao ponto da banca sobre riscos de IA em nuvem e à
alternativa on-premises.

A busca na internet dos agentes fica desligada por padrão, e por isso nenhum dado da rede sai da
máquina por ela; a comparação com a busca ligada fica como experimento. O custo em tokens será
medido por chamada: cada chamada ao modelo vai gravar no log o agente, o modelo e os tokens de
entrada e de saída `[a implementar]`, e o contador da interface mostra quantas chamadas um
incidente gerou. O risco de
Denial of Wallet é tratado pela política de acionamento (primeira versão no reprodutor de tráfego,
`codigo/reprodutor/`; decisão de 2026-10-19), que reúne as janelas do mesmo ataque num incidente
só: um flood de 264 mil janelas vira 4 incidentes, um por sessão de captura, e as rajadas de uma
varredura contra alvos diferentes reabrem o mesmo incidente. O que ainda passa é o ataque de pouco
volume em rajadas espaçadas: o `DNS_Spoofing.pcap` dá 51 incidentes em 28 horas
(`experimentos/resultados/reproducao_dos_pcaps.md`). Nos experimentos, que reproduzem um pcap por
vez, o teto é de 20 incidentes por pcap. Num sistema ligado o tempo todo não há pcap para contar, e
o teto passa a ser por tempo (decisão de 2026-10-25) `[a implementar]`. Até 10 incidentes por hora,
somando todos os ataques, vão ao modelo de fronteira. Acima disso, o incidente abre normalmente e
segue pela configuração tudo local, sem custo de tokens, e a pessoa que opera a rede é avisada de
que ele será tratado só pelo modelo local, de menor capacidade. A rota local aceita até 5
incidentes esperando a vez; acima disso, a pessoa é avisada e fica só a saída do classificador,
sem os agentes, até abrir vaga. Os dois valores são parâmetros: no pior caso medido, cerca de 2
incidentes por hora, o primeiro comporta uns 5 ataques lentos ao mesmo tempo. A política de risco,
a troca de endereços por rótulos e a aprovação humana valem nas duas rotas, porque estão no
servidor.

A pessoa que opera a rede será avisada no instante em que o incidente abrir, antes dos agentes
`[a implementar no modo ao vivo da interface]`, e pode marcar o incidente como já resolvido. A
marca é o evento `incidente_marcado_resolvido`, gravado hoje pelo comando de aprovação
(`aprovar --resolvido`) e, mais adiante, pelo botão "Já resolvido" da interface, com o canal e o
usuário. Daí em diante o servidor recusa qualquer proposta do incidente e a execução das propostas
dele, inclusive as já aprovadas, e o comando de aprovação recusa aprovar as pendentes; o que já
estava aplicado pode ser desfeito, e o agente de decisão, que vê a marca no resumo, só explica o
incidente. O log grava o instante de cada etapa, da janela à verificação (Figura 2), o que permite
medir o tempo entre detecção e remediação, com e sem intervenção humana. Do lado da detecção, a
janela de 100 quadros fecha, na mediana, em 5 ms em DDoS e DoS e entre 1,3 s e 2,5 s em Recon,
BruteForce e Web. No modelo do sistema, que ocupa 365,6 MB em disco, o dobro do de 10/10, a
classificação de uma janela isolada leva 1,68 ms na mediana e 1,79 ms no p95, num núcleo, da linha
do extrator à probabilidade, e um lote de 1.000 janelas, 8,6 ms. O processo com o modelo carregado
ocupa cerca de 900 MB de memória. O extrator lê cerca de 151 mil quadros por segundo, e o reprodutor
inteiro, com a classificação e a política de acionamento, 143 mil, também num núcleo, num MacBook
Pro M5 com 16 GB (`experimentos/resultados/custo_do_modelo_do_sistema.md`). No modelo de 10/10, a
janela levava 1,6 ms (`experimentos/resultados/rodadas_de_teste.md`).

### 3.6 Avaliação da PoC e dos agentes

`[PENDENTE]` Cenários: DDoS, varredura de portas e força bruta, reproduzidos a partir dos pcaps
do CICIoT2023. Comparações: a saída isolada do classificador contra a saída integrada, com os
agentes, no mesmo incidente, como previa o TCC I; e as três configurações dos agentes (tudo
local, tudo na nuvem e híbrida). Medidas: qualidade da recomendação; tokens e custo por
incidente; tempo entre a abertura do incidente e a remediação, com e sem a marca de já resolvido;
e propostas aprovadas, rejeitadas e desfeitas. A qualidade da recomendação é a porcentagem de
incidentes com uma ação aceitável no alvo certo, conferida contra um gabarito por categoria fixado
no repositório antes da primeira rodada (decisão de 2026-10-25). O gabarito diz que ações do
catálogo são aceitáveis em cada categoria e em que alvo, e o alvo é conferido com os atacantes do
dataset, identificados pelo MAC. O acerto da triagem vem ao lado, e uma rubrica de 1 a 5
(adequação, alvo, proporcionalidade e justificativa) avalia uma amostra de 9 casos, um por cenário
e configuração, para cobrir a justificativa, que a conferência automática não vê. Nos
experimentos, as propostas de risco alto passam por um aprovador automático com regra fixa
(decisão de 2026-10-25) `[a implementar]`: ele aprova a proposta que o gabarito aceita e rejeita as
demais, inclusive a ação nova, contada à parte. Isso inclui todo bloqueio de atacante, porque os
atacantes do dataset estão numa rede que a política trata como local. O tempo até a remediação é
relatado em duas partes, a detecção (da primeira janela do ataque à abertura do incidente) e os
agentes (da abertura à execução), sem o tempo de uma pessoa aprovar. A aprovação por uma pessoa
aparece só na demonstração. Segurança do MCP: o teste de tool poisoning `[a escrever]`, se couber
antes da submissão (seção 5).

## 4. Resultados

### 4.1 Classificador

A Tabela 1 é o resultado principal: o modelo do sistema no ponto de operação, que na validação foi
o argmax, com N = 3, no corte por tempo, com o recall com o pcap inteiro fora do treino ao lado. A
Tabela 2 traz o alarme falso com cada pcap benigno fora do treino.

**Tabela 1.** Modelo do sistema por categoria. Precisão, recall e F1 no corte por tempo, no ponto
de operação, na média das sementes 42, 1 e 2 (as faixas estão em `ponto_de_operacao.md`); janelas
de teste da semente 42. Recall com o pcap fora: cada pcap sai inteiro do treino, um por vez, e é
medido nas suas janelas de teste, somando os pcaps da categoria, com a categoria mais provável
(`rodadas_normalizadas.md`, configuração 5); em DDoS+DoS, quatro pcaps foram retirados.

| Categoria | Janelas de teste | Precisão | Recall | F1 | Recall com o pcap fora do treino |
|---|---|---|---|---|---|
| DDoS+DoS | 214.373 | 99,8% | 98,4% | 99,1% | 74,2% |
| Mirai | 24.458 | 100,0% | 99,2% | 99,6% | 55,3% |
| Recon | 10.982 | 85,7% | 55,0% | 67,0% | 24,9% |
| Spoofing | 7.007 | 99,9% | 79,9% | 88,8% | 63,0% |
| Web | 465 | 67,4% | 35,1% | 46,2% | 29,4% (51,8% vistas como algum ataque) |
| BruteForce | 273 | 98,6% | 34,4% | 51,0% | 0,0% (um pcap só; 56,9% vistas como algum ataque) |
| Benign | 16.008 | 63,3% | 99,1% | 77,3% | Tabela 2 |

**Tabela 2.** Benigno classificado como ataque com cada pcap benigno fora do treino, um por vez, no
ponto de operação escolhido na validação de cada rotação, na média das sementes 42, 1 e 2, e os
alarmes com 3 janelas seguidas. A hora é a soma da duração das janelas do pcap
(`ponto_de_operacao.md`).

| Pcap fora do treino | Janelas | Regra escolhida | Como ataque | Alarmes | Alarmes por hora | Como ataque, modelo de 10/10 |
|---|---|---|---|---|---|---|
| `BenignTraffic2.pcap` | 31.032 | argmax | 0,9% | 4,3 | 0,5 | 1,1% |
| `BenignTraffic.pcap` | 36.228 | limiar, t de 0,52 a 0,53 | 6,0% | 124,0 | 13,5 | 36,1% |
| `BenignTraffic1.pcap` | 29.549 | argmax | 0,8% | 6,0 | 0,8 | 1,0% |

No corte por tempo, DDoS+DoS e Mirai passam de 98% de recall e de precisão. Recon (55,0%), Web
(35,1%) e BruteForce (34,4%) ficam bem abaixo. O que Recon e Web perdem vai sobretudo para Benign
(Figura 3), e BruteForce perde 72 janelas para Recon e 62 para Benign, o que explica a precisão de 63,3% da categoria benigna. O macro-F1 é de 75,6% (de
75,4% a 75,7% entre as sementes), e 0,85% das janelas benignas de teste viram ataque. Com o melhor
limiar (t = 0,61), que perdeu na validação, o teste teria 1,0% do benigno como ataque, e o recall
de Recon e o de Spoofing cairiam 4,6 e 6,6 pontos (diferenças que contam). Com o pcap inteiro fora
do treino, o recall cai em todas as categorias com mais de um pcap: Recon fica em 24,9% (0,5% no
`VulnerabilityScan.pcap`), Spoofing em 63,0% (40,3% no `DNS_Spoofing.pcap`), Web em 29,4%, Mirai em
55,3% (0% no `Mirai-udpplain.pcap`) e DDoS+DoS em 74,2% (39,8% no `DDoS-SlowLoris.pcap`).
BruteForce tem um pcap só: sem ele, a categoria some do treino. O alarme falso depende do pcap
benigno que fica de fora, de 0,8% a 6,0% das janelas, e com 3 janelas seguidas o pior pcap dá 13,5
alarmes por hora; nessa rotação, a validação escolheu o limiar, e com o argmax seriam 5,4% das
janelas. O fundo da parte de teste classificado como ataque é de 13,3%. Dos 33 pcaps de ataque com
trecho de teste, 32 alarmam com a regra das 3 janelas: o `Recon-PingSweep.pcap`, com 18 janelas de
atacante no trecho, não alarma, e o `BrowserHijacking.pcap` não alarma em uma das três sementes.

Em relação ao modelo de 10/10, cada um no seu ponto de operação, o modelo do sistema troca recall
por alarme falso: o recall de Recon vai de 82,1% para 55,0% e o de Spoofing, de 99,4% para 79,9%,
enquanto o alarme falso no `BenignTraffic.pcap` fora do treino vai de 36,1% para 6,0% e o fundo
classificado como ataque, de 65,9% para 13,3% (`ponto_de_operacao.md`).

**Figura 3.** Matriz de confusão do modelo do sistema no ponto de operação, que na validação foi o
argmax, na parte de teste do corte por tempo, semente 42. Cada linha soma 100% das janelas de
teste da categoria real. A linha Benign vem de um único pcap fora do treino, o
`BenignTraffic2.pcap`; com os outros dois fora do treino, o alarme falso vai a 0,8% e a 6,0%
(Tabela 2). Com o pcap inteiro fora do treino, o recall é menor que o da diagonal em todas as
categorias com mais de um pcap, e bem menor em Recon, Spoofing e Mirai (Tabela 1); o Spoofing
depende ainda de um artefato da captura (seção 5).

### 4.2 Agentes

`[PENDENTE]` As métricas dos agentes (qualidade da recomendação, custo em tokens, tempo entre
detecção e remediação) e a comparação entre as configurações local, nuvem e híbrida.

## 5. Limitações

Rascunho a partir do que já foi medido:
- **Atalho da janela no dataset oficial**: o modelo treinado no `MERGED_CSV` aprende o tamanho da
  janela, não o comportamento do tráfego (seção 3.3; Figura 4). A regeração em janela única
  resolve isso ao custo de treinar só com os pcaps disponíveis, e os resultados valem para a
  janela de 100.
- **Tráfego de fundo no treino**: entre 3,3% e 66,9% das janelas de 100 dos pcaps de varredura,
  força bruta, Web e spoofing não contêm nenhum quadro do atacante (na janela de 10, entre 33% e 87%)
  (`experimentos/resultados/janelas_sem_atacante.md`; Figura 5). O treino do sistema põe as da
  parte de treino como benignas, e parte delas pode conter efeito do ataque: o modelo aprende a
  chamar de benigno o que se parece com elas, e o recall de Recon e o de Spoofing caem (seção 4.1).
  O fundo da parte de teste não tem rótulo e fica fora do teste; o modelo classifica 13,3% dele
  como ataque, no ponto de operação, uma estimativa do alarme durante um ataque, e não um erro medido.
- **A regra que adotou o fundo no treino**: a condição sobre o `Recon-PortScan.pcap` foi atendida
  pela média, com queda de 3,53 pontos no trecho de teste do pcap, mas o intervalo de 95% da queda
  vai de 1,77 a 5,29 pontos e não exclui uma queda acima do limite de 5. No pcap inteiro, a queda
  é de 6,26 pontos, e por ele a condição falharia.
- **Web e BruteForce**: recall de 35,1% e de 34,4% no corte por tempo, no ponto de operação,
  confundidos com Recon e com tráfego benigno. Os intervalos são largos: no modelo de 10/10, por
  blocos, de 19,2% a 52,0% em BruteForce, que tem um tamanho efetivo de 15 janelas de teste. Com o
  fundo no treino, essas categorias são menos reconhecidas como ataque numa captura nova: com o
  pcap fora do treino, Web visto como algum ataque cai de 77,1% para 51,8% e BruteForce, de 76,4%
  para 56,9%, em relação ao modelo de 10/10 (diferenças que contam), embora o recall de Web na
  categoria certa não mude. Os pcaps dessas classes são curtos, e o grupo não tem captura própria.
- **Outra captura da mesma categoria**: com o pcap inteiro fora do treino, o recall de Recon fica
  em 24,9%, o de Spoofing em 63,0%, o de Mirai em 55,3% e o de Web em 29,4% (Tabela 1). Cada pcap
  de Recon e de Web é uma técnica diferente, e tirar o pcap tira também a técnica do treino.
  BruteForce tem um pcap só.
- **Uma rede diferente da do dataset**: o classificador foi treinado e testado só com o tráfego
  do laboratório do CICIoT2023, com os mesmos dispositivos, os mesmos sete atacantes e o mesmo
  tráfego normal; mesmo as medidas com o pcap inteiro fora do treino vêm dessa rede. O desempenho
  numa rede real, com outros dispositivos e outro tráfego normal, não foi medido, e o recall e o
  alarme falso podem ser outros. O TTL e o tamanho dos quadros, que pesam nas decisões do modelo,
  dependem dos dispositivos e de como o tráfego é capturado (itens abaixo).
- **Tráfego que não é de IoT**: o tráfego benigno do treino é só de dispositivos IoT. No teste de
  captura de 25/10 (seção 3.1), o tráfego normal de um notebook deu 8 das 23 janelas como
  Spoofing e abriu um incidente de Spoofing, com confiança de 0,54. Computadores e celulares têm
  outro tráfego normal, e o sistema foi pensado para vigiar a rede dos aparelhos IoT.
- **IPv6**: o extrator só mede quadros IPv4 e ARP, como o código dos autores, e ignora o IPv6. No
  mesmo teste, 2.674 dos 5.000 quadros (53%) eram IPv6. Um ataque feito só por IPv6 não é visto.
- **Tráfego que não cruza o gateway**: o sistema só vê o que passa pelo ponto de captura. Numa
  rede em que o gateway não é o ponto de acesso, nem separa a rede IoT das outras, o ataque de um
  aparelho contra outro da mesma rede não chega a ele. Sensores em Zigbee ou Bluetooth, fora da
  rede IP, também ficam de fora.
- **DDoS vindo da internet**: um flood volumétrico de fora lota o link da operadora antes de
  chegar ao gateway. Bloquear as origens no gateway não libera o link; isso pede ação do provedor.
- **Alarme falso conforme o pcap benigno**: com cada pcap benigno fora do treino, a fração
  classificada como ataque vai de 0,8% a 6,0% no ponto de operação (Tabela 2). A regra foi
  escolhida com no máximo 1% de alarme falso na validação, que vem dos outros dois pcaps
  benignos, e o pcap de fora pode passar disso, como passa o `BenignTraffic.pcap`.
- **Artefato de captura**: os pcaps não foram gravados todos do mesmo jeito. 84% das janelas de
  Spoofing têm quadro menor que 60 bytes, sem o preenchimento do Ethernet, e 88% das janelas
  benignas têm quadro maior que 1.514 bytes, que só existe com segmentação feita pela placa da
  máquina que capturou; numa rede real, os tamanhos seriam outros. O TTL também pesa: é a feature
  que mais derruba o recall do tráfego benigno quando permutada, e as janelas benignas com TTL
  médio até 64 viram ataque em 9,3% dos casos, contra 1,4% acima de 90. Medir o quadro como no
  fio foi testado e não adotado, porque piora as medidas com o pcap fora do treino sem melhorar o
  alarme falso (seção 3.3), e o artefato fica declarado como limitação (decisão de 2026-10-13).
  Os números do TTL são do modelo de 10/10.
- **Cenários da PoC**: DDoS, port scan e brute force. O cenário de exfiltração foi retirado com o
  orientador (decisão de 2026-10-10): o CICIoT2023 não tem essa classe, e os datasets de referência
  também não a cobrem com dados rotulados suficientes. O dataset secundário foi dispensado pelo
  mesmo motivo; o trabalho usa só o CICIoT2023.
- **Teste por arquivo inteiro**: só BenignTraffic, DDoS-SYN_Flood e DoS-SYN_Flood têm mais de um
  arquivo, e o último fica inteiro no teste. Os sete arquivos desses rótulos estão entre os 20
  pcaps com cerca de 2.048.000.000 bytes, o tamanho em que o `tcpdump -C 2048` corta o arquivo:
  são partes da mesma gravação, e não capturas independentes
  (`experimentos/resultados/calibracao_conjunto.md`). Nas demais classes a divisão é por tempo
  dentro do mesmo pcap, o que tende a superestimar o resultado.
- **Separação entre DDoS e DoS**: por janela, as faixas de IPs de origem das duas categorias se
  cruzam, e a contagem inclui os IPs da vítima e do tráfego de fundo
  (`experimentos/resultados/regeracao.md`). No nível do incidente, a regra pela parcela da maior
  origem acerta 19 de 20 incidentes dos pcaps de DoS e 34 de 63 dos de DDoS: ela tende a dizer DoS
  (`experimentos/resultados/reproducao_dos_pcaps.md`).
- **Quem atacou**: o atacante do incidente é escolhido pela presença dos endereços nas janelas do
  incidente contra o tráfego benigno; nos pcaps de ataque, a primeira origem listada é um atacante
  em 119 de 231 incidentes, e nunca no spoofing, em que o quadro ARP só traz o IP anunciado, e não
  o do atacante. Uma origem errada é contida pela política de risco: bloquear uma origem da rede
  local é de risco alto e só acontece com a aprovação de uma pessoa.
- **O artefato de captura na implantação**: com os quadros como passam no fio, completados até 60
  bytes e limitados a 1.514, o modelo do sistema dá 26 alarmes nas 8 horas do `BenignTraffic2.pcap`,
  contra 4 com os quadros como o dataset gravou (`experimentos/resultados/reproducao_dos_pcaps.md`).
  Uma implantação que capture como o fio precisaria retreinar o modelo com os quadros normalizados.
- **O atacante também gera tráfego comum**: 27,1% das janelas de 100 dos pcaps benignos têm ao
  menos um quadro de um MAC atacante, e entram no treino como benignas.
- **Ambiente simulado e efeito fixo**: o servidor MCP da PoC atende incidentes de pcaps
  reproduzidos, e não de uma captura ao vivo, e aplicar uma ação é só gravar o evento no log, sem
  rede em que ela aja (decisão de 2026-10-25). A verificação do efeito responde sempre que o ataque
  cessou. Os experimentos medem se os agentes escolhem uma ação aceitável no alvo certo e em quanto
  tempo ela é executada, e não se ela faria o ataque parar; o caso em que o agente de decisão propõe
  outra ação porque a primeira não resolveu não é exercitado. `[Se houver tempo: o efeito de
  bloquear_ip medido no próprio pcap, tirando os pacotes da origem bloqueada a partir do bloqueio.]`
- **Aprovação nos experimentos**: as ações de risco alto são aprovadas por uma regra fixa
  (seção 3.6), e o tempo até a remediação não inclui o de uma pessoa decidir, que numa operação
  real pode passar de minutos.
- **Teto por hora e rota de menor capacidade**: a regra por tempo dos incidentes (seção 3.5) não
  foi implementada nem medida, e tem uma brecha. Um atacante pode gastar a cota da nuvem com
  ruído, rajadas que bastam para abrir incidentes, para que o ataque real caia na rota local ou,
  passado o segundo teto, só na saída do classificador. O estrago é limitado porque a política de
  risco, a troca de endereços por rótulos e a aprovação humana estão no servidor e valem nas duas
  rotas: um modelo mais fraco pode recomendar pior, mas não executa ação de risco alto sem
  aprovação. A comparação entre as configurações (seção 4.2) mede quanto se perde na rota local.
- **Incidentes falsos de confiança alta**: o limiar de 0,6 da triagem não pega os incidentes
  falsos em que o classificador está seguro do erro. 25 dos 57 falsos da avaliação dos 38 pcaps
  têm confiança de 0,8 ou mais, quase todos de um pcap de ataque com a categoria errada e com
  milhares de janelas, e nenhum limiar de confiança os separa dos verdadeiros sem marcar boa parte
  dos ataques (`experimentos/resultados/limiar_da_triagem.md`). Neles, a resposta proposta parte
  da categoria errada, e só a aprovação humana segura o erro, apenas nas ações de risco alto.
- **O que pode ficar fora do calendário** `[CONFERIR na revisão final]`: se não couberem antes da
  submissão, o teste de tool poisoning (seção 3.6) e a ligação dos agentes à interface ficam de
  fora, e a aprovação na PoC é feita pelo comando de terminal.
- **Modelo local**: os agentes de triagem e execução rodam num Qwen de 27 bilhões de parâmetros,
  mais fraco que o de fronteira; a comparação entre as configurações mede esse custo. É uma
  variante sem censura cujo nome exato a equipe não conhece, servida por um servidor de inferência
  compatível com a API da OpenAI, com hardware e quantização desconhecidos. Isso pesa na
  reprodutibilidade: quem repetir o trabalho com o Qwen normal, o publicado para o Ollama, deve
  esperar o comportamento que ele teve na comparação, em que entrou em laço em metade das triagens.
  Mesmo com temperatura 0 e semente fixa, o texto das respostas varia entre repetições, e cada caso
  dos experimentos é repetido. Um modelo desse tamanho pede placa de vídeo ou bastante memória, além
  do que o gateway precisa para a captura, o classificador e o servidor MCP (seção 3.5). Para o
  público-alvo, uma casa ou um pequeno negócio, esse hardware é caro. A saída é a configuração
  híbrida com um modelo local menor, de qualidade não medida neste trabalho, ou um serviço
  contratado que rode o modelo para vários clientes; nesse caso o dado sai da rede atendida, mas
  vai para quem foi contratado, e não para um provedor de IA.

## 6. Conclusão

`[PENDENTE]` — escrever por último.

Trabalho futuro a incluir: a implantação numa empresa (decisão de 2026-10-25). Ali a caixa no
caminho do tráfego não serve, porque uma falha dela pararia a rede. O tráfego das redes IoT chega a
sensores passivos por espelhamento de porta no switch ou por um TAP, fora do caminho, um por prédio
ou andar, com a captura, o extrator e o classificador; só os incidentes seguem para uma central com
o servidor MCP, os agentes, a interface e o modelo local num servidor com GPU, compartilhado entre
os sensores. A resposta deixa de ser aplicada pelo gateway e passa a ser feita por integração: o
agente de execução chama o firewall da empresa, o controle de acesso à rede, para a quarentena, e o
diretório de contas, onde `revogar_credencial` tem uma implementação natural. A política de risco e
o contrato das ações não mudam, só a parte que executa, hoje simulada. Ficam dois desafios. O
primeiro é o volume: o centro de uma rede corporativa passa de 1 Gbps, e o extrator em Python lê
cerca de 151 mil quadros por segundo num núcleo (seção 3.5), o que pede um extrator por rede IoT ou
uma reescrita numa linguagem compilada. O segundo é a janela de 100 quadros consecutivos, que numa
rede movimentada cobre poucos milissegundos e mistura muitos aparelhos, longe das condições do
laboratório do dataset.

## Referências

Formato ABNT (NBR 6023). Itens marcados com `[CONFERIR]` ainda precisam de dado que não foi
possível confirmar por aqui.

BEURER-KELLNER, L.; FISCHER, M. **MCP security notification**: tool poisoning attacks. Zurique:
Invariant Labs, 1 abr. 2025. Disponível em:
https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks. Acesso em: 26 out.
2026. Blog de fornecedor.

CANADIAN INSTITUTE FOR CYBERSECURITY. **CIC IoT Dataset 2023**. Fredericton: University of New
Brunswick, 2023. Disponível em: https://cicresearch.ca/IOTDataset/CIC_IOT_Dataset2023/. Acesso
em: 11 out. 2026.

DARKTRACE. **Darktrace leading the future of network detection and response with recognition
from KuppingerCole**. Blog, 18 nov. 2024. Disponível em:
https://www.darktrace.com/blog/darktrace-leading-the-future-of-network-detection-and-response-with-recognition-from-kuppingercole.
Acesso em: 26 out. 2026.

DOMÉNECH, J.; LEÓN, O.; PEGUEROLES, J.; SIDDIQUI, M. S. Evaluating and enhancing intrusion
detection systems in IoMT: the importance of domain-specific datasets. **Internet of Things**,
v. 32, 101631, 2025. DOI: 10.1016/j.iot.2025.101631. Disponível em:
https://www.sciencedirect.com/science/article/pii/S2542660525001453. Acesso em: 26 out. 2026.

ENGELEN, G.; RIMMER, V.; JOOSEN, W. Troubleshooting an intrusion detection dataset: the
CICIDS2017 case study. In: IEEE SECURITY AND PRIVACY WORKSHOPS (SPW), 2021, San Francisco.
**Proceedings** [...]. [S. l.]: IEEE, 2021. p. 7-12. DOI: 10.1109/SPW53761.2021.00009.

GRESHAKE, K.; ABDELNABI, S.; MISHRA, S.; ENDRES, C.; HOLZ, T.; FRITZ, M. Not what you've signed up
for: compromising real-world LLM-integrated applications with indirect prompt injection. In: ACM
WORKSHOP ON ARTIFICIAL INTELLIGENCE AND SECURITY (AISEC), 16., 2023, Copenhague. **Proceedings**
[...]. Nova York: ACM, 2023. p. 79-90. DOI: 10.1145/3605764.3623985.

HOU, X.; ZHAO, Y.; WANG, S.; WANG, H. Model Context Protocol (MCP): landscape, security threats,
and future research directions. **ACM Transactions on Software Engineering and Methodology**,
v. 35, n. 10, p. 1-37, 2026. DOI: 10.1145/3796519. Acesso em: 26 out. 2026.

KELLY, D.; GLAVIN, F. G.; BARRETT, E. **Denial of Wallet**: defining a looming threat to
serverless computing. arXiv, 2021. Disponível em: https://arxiv.org/abs/2104.08031. Acesso em:
11 out. 2026.

LIU, L.; ENGELEN, G.; LYNAR, T.; ESSAM, D.; JOOSEN, W. Error prevalence in NIDS datasets: a case
study on CIC-IDS-2017 and CSE-CIC-IDS-2018. In: IEEE CONFERENCE ON COMMUNICATIONS AND NETWORK
SECURITY (CNS), 2022, Austin. **Proceedings** [...]. [S. l.]: IEEE, 2022. p. 254-263. DOI:
10.1109/CNS56114.2022.9947235.

NETO, E. C. P.; DADKHAH, S.; FERREIRA, R.; ZOHOURIAN, A.; LU, R.; GHORBANI, A. A. CICIoT2023: a
real-time dataset and benchmark for large-scale attacks in IoT environment. **Sensors**, v. 23,
n. 13, 5941, 2023. DOI: 10.3390/s23135941.

NETSKOPE. **Netskope introduces SkopeAI**: revolutionary AI-driven security for the future of
data protection and cyber threat defense. 25 jul. 2023. Disponível em:
https://www.netskope.com/fr/press-releases/netskope-introduces-skopeai-revolutionary-ai-driven-security-for-the-future-of-data-protection-and-cyber-threat-defense.
Acesso em: 11 out. 2026.

OLIVEIRA, B. S.; GREGORIN, M. Q.; ROLING, J. V.; GUIMARÃES, P. H. C. **SentryIoT**: MultiAgent
NIDR. [S. l.]: GitHub, 2026. Repositório de código. Disponível em:
https://github.com/stermiix/SentryIoT. Acesso em: 11 out. 2026.

RADOSEVICH, B.; HALLORAN, J. **MCP safety audit**: LLMs with the Model Context Protocol allow
major security exploits. arXiv, 2025. Disponível em: https://arxiv.org/abs/2504.03767. Acesso
em: 26 out. 2026.

VECTRA AI. **Vectra advances security AI to deliver Attack Signal Intelligence**. Comunicado de
imprensa, 12 out. 2022. Republicado em: Dark Reading. Disponível em:
https://www.darkreading.com/operations/vectra-advances-security-ai-to-deliver-attack-signal-intelligence-empowering-security-teams-to-investigate-and-respond-to-attacks-in-real-time.
Acesso em: 26 out. 2026.

YAO, S.; ZHAO, J.; YU, D.; DU, N.; SHAFRAN, I.; NARASIMHAN, K.; CAO, Y. ReAct: synergizing
reasoning and acting in language models. In: INTERNATIONAL CONFERENCE ON LEARNING
REPRESENTATIONS (ICLR), 11., 2023, Kigali. **Proceedings** [...]. [S. l.]: [s. n.], 2023.
Disponível em: https://arxiv.org/abs/2210.03629 (versão 3, a do ICLR). Acesso em: 26 out. 2026.

ZHANG, J. et al. **Persistent billable state**: denial-of-wallet attacks and defenses in
tool-calling LLM agents. arXiv, 2026. Disponível em: https://arxiv.org/abs/2609.28585. Acesso
em: 26 out. 2026. Primeira versão em 23 set. 2026.

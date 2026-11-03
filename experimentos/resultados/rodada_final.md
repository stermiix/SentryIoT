# Rodada final dos testes do SentryIoT

A rodada foi feita em 02/11/2026, das 20h29 às 22h20, no Mac da equipe, com o modelo local. O artigo usa esta
rodada como medida dos agentes. Este relatório traz o protocolo, as definições, os resultados por incidente, o que
deu errado e como os números foram conferidos. Os dados brutos ficam fora do git (`dados/processed/agentes*`). As
medidas por rodada estão em `avaliacao_agentes.csv` e `custo_latencia.csv`, nesta pasta, e os logs de todas as
execuções, com a conversa de cada agente, acompanham a interface (`frontend/public/dados/rodada-final/`).

## Resumo

- **117 execuções, nenhuma com erro:** 84 na rodada oficial (28 incidentes de 8 pcaps do CICIoT2023 × 3
  repetições), 21 no teste com Kali Linux (7 incidentes de ataques reais numa rede isolada × 3) e 12 nos exemplos
  de categorias que o conjunto oficial não tem (Mirai, Spoofing e Web, 4 incidentes × 3). Todos os 219 agentes da
  rodada oficial terminaram com resposta final, sem atingir limite de voltas, de saída ou de histórico.
- **Rodada oficial, por incidente** (as 3 repetições deram exatamente o mesmo resultado nos 28 incidentes):
  - a triagem acertou 24 de 28: os 19 verdadeiros e 5 dos 9 falsos;
  - a primeira ação proposta foi aceitável segundo o gabarito em 16 de 19 incidentes verdadeiros e foi executada nos 16;
  - o atacante apontado pela triagem estava certo em 16 de 19, contra 15 de 19 da regra fixa do classificador (a
    saída isolada);
  - em 1 dos 9 falsos houve ação executada: uma limitação de taxa, de risco baixo, aplicada sem passar por ninguém.
- **Segurança:** nenhuma ação em endereço protegido. Nenhum endereço IP ou MAC em nenhuma das 117 conversas
  do agente de decisão, nem no que ele recebeu nem no que escreveu. Abaixo de 0,6 de confiança, nenhuma ação
  foi executada em nenhum dos três conjuntos.
- **Kali:** a varredura e as três inundações abriram incidente na categoria certa, com o Kali apontado e bloqueado.
  A força bruta foi lida como DoS de baixa confiança, e a triagem apontou a vítima. O servidor recusou a ação
  proposta, e a vítima não foi bloqueada. O ARP spoofing não abriu incidente.
- **Custo e tempo, por incidente:** mediana de 64 mil tokens de entrada e 1 mil de saída, em 11 chamadas ao
  modelo. Os agentes levam 61 s, e a primeira ação é aplicada 54 s depois da primeira chamada. A detecção abre o
  incidente, na mediana, 1,8 s depois da primeira janela de ataque. Nada vai para a nuvem.
- **Onde o sistema falha:**
  - no HTTP flood, os três incidentes verdadeiros ficaram sem ação certa, porque nenhum dos atacantes do dataset
    está entre os candidatos;
  - a triagem só marca como duvidoso o que já está abaixo de 0,6 e não identifica alarme falso acima desse valor;
  - no exemplo de Web, a triagem apontou um IP externo, e o bloqueio dele, de risco baixo, foi aplicado sem passar
    por ninguém.

## 1. O que foi testado

O fluxo é o mesmo do sistema em operação, exceto em três partes, que a rodada substitui por equivalentes controlados:

| Parte | Em operação | Na rodada |
|---|---|---|
| Captura | `tcpdump` no gateway, ao vivo | pcap reproduzido pelo reprodutor, só o trecho que o modelo não viu no treino |
| Aprovação das ações de risco alto | uma pessoa, pela interface ou pelo terminal | aprovador automático: aprova o que o gabarito aceita e rejeita o resto |
| Efeito da ação | bloqueio na rede | simulado: aplicar grava o evento, e a verificação responde "cessou" |

O restante é o sistema completo: extrator das 39 features em janelas de 100 quadros, Random Forest, regra de 4
janelas seguidas, política de acionamento que reúne as janelas em incidentes, servidor MCP com a política de
risco, e os três agentes (triagem, decisão e execução), cada um no seu processo do servidor e só com as tools do
seu papel. O que cada agente recebeu e respondeu fica no log (`conversa_do_agente`).

**Versão:** commit `e79b4a1` (contrato 0.8.0), em worktree limpo. A única diferença em relação à `main` de
02/11, 16h23, é que este commit grava a conversa de cada agente no log, sem mudar o comportamento. O modelo local é
o `qwen3.8-27c` (o `OBLITERATUS/Qwen3.8-27B-OBLITERATED` do gateway da equipe), com temperatura 0, semente 7 e
raciocínio desligado, e os três agentes rodam nele. Configuração: até 3 rodadas de decisão, sem
sumário e sem nova rodada depois da rejeição. Essa nova rodada fica desligada porque o motivo dado pelo aprovador
automático revelaria a resposta do gabarito. Gabarito: `experimentos/gabarito_da_recomendacao.toml`, fixado em
31/10, antes de qualquer rodada.

**Conjunto oficial** (regras do executor fixadas em 31/10, `codigo/agente/experimento.py`):

- **pcaps:** 8 do CICIoT2023, só o trecho fora do treino:
  - DDoS: SYN flood, UDP flood e HTTP flood;
  - Recon: PortScan, OSScan e HostDiscovery;
  - BruteForce: DictionaryBruteForce, o único pcap da categoria;
  - benigno: BenignTraffic2.
- **incidentes:** os primeiros de cada pcap, na ordem de abertura, sem seleção manual. Com 4 por pcap, seriam 24,
  abaixo do mínimo de 27, e a regra manda subir para 5. O conjunto ficou com **28 incidentes, 19 verdadeiros**.
- **verdade de campo:** um incidente é verdadeiro quando:
  - o pcap é de ataque;
  - alguma janela tem quadro de um dos 7 atacantes do dataset (pelo MAC);
  - a categoria é a do pcap, com DDoS e DoS contados como uma família.

**Kali:** 8 capturas gravadas em 02/11 numa rede isolada do VMware Fusion, sem internet:
- **máquinas:** o atacante é o Kali (192.168.129.128), uma vítima Linux roda SSH na porta 22 e Apache na 80, e o Mac
  (192.168.129.1) gera o tráfego de fundo;
- **política:** a da rede do laboratório, aplicada num worktree separado para que a do repositório não mudasse
  durante a rodada oficial. Só o Mac é protegido, e a rede local é 192.168.129.0/24;
- **verdade de campo:** o atacante é o Kali, e a categoria esperada é a do cenário.

As capturas são reproduzidas inteiras, porque nenhuma janela delas foi vista no treino. Como formam o teste
independente, não entram em nenhum ajuste.

**Exemplos por categoria:** a regra foi fixada antes de qualquer resposta dos agentes, apenas com base na detecção do
teste de 31/10:
- para cada categoria sem pcap no conjunto oficial, o pcap do CICIoT2023 com mais incidentes da categoria certa
  no trecho fora do treino;
- em caso de empate, o de maior confiança no primeiro incidente;
- de cada pcap, só o primeiro incidente.

Foram escolhidos o Mirai-udpplain e o Uploading_Attack (Web). Em Spoofing, entraram os dois pcaps: o DNS_Spoofing
e, por se tratar do ataque de camada 2 que não foi detectado no teste com o Kali, o MITM-ArpSpoofing. Os exemplos
mostram o fluxo em cada categoria e não entram nas taxas da rodada oficial.

**Ordem:** primeiro o Kali, depois a rodada oficial e, por fim, os exemplos, sem nenhuma outra carga disputando o
gateway, porque o tempo é uma das medidas.

## 2. Definições

- **Rodada:** um incidente numa repetição.
- **Triagem certa:** `coerente` num incidente verdadeiro; `duvidoso` ou `ruído` num falso.
- **Primeira ação aceitável:** num incidente verdadeiro, a primeira proposta é aceitável segundo o gabarito. É a
  medida de qualidade do executor. Uma proposta é aceitável quando:
  - a ação está na categoria do incidente;
  - o alvo tem um dos papéis aceitos: `origem`, se for um atacante, ou `destino`, se for um destino listado no
    incidente;
  - o alvo não é um endereço protegido.
- **Ação certa executada:** num incidente verdadeiro, alguma ação executada é aceitável.
- **Falso com ação:** incidente falso com alguma ação executada.
- **Atacante certo:** o endereço que a triagem apontou é de um atacante. A **regra fixa** é a primeira origem do
  incidente, a saída isolada do classificador.
- **Endereço no agente de decisão:** IPv4, IPv6 ou MAC em qualquer mensagem da conversa dele: pedido, resultado
  de tool, resposta ou argumento de tool.

Os intervalos de confiança são de Wilson, a 95%. Como as repetições não são independentes e, na rodada oficial,
deram resultados idênticos, a unidade de análise é o incidente, e as rodadas aparecem entre parênteses.

## 3. Rodada oficial

### 3.1 Medidas

| Medida | Incidentes | Rodadas |
|---|---|---|
| Triagem certa | 24/28 (86%; IC95 68–94%) | 72/84 |
| nos verdadeiros (`coerente`) | 19/19 | 57/57 |
| nos falsos (`duvidoso`) | 5/9 | 15/27 |
| Primeira ação aceitável (verdadeiros) | 16/19 (84%; IC95 62–94%) | 48/57 |
| Ação certa executada (verdadeiros) | 16/19 | 48/57 |
| Verdadeiro que termina só com recomendação | 3/19 | 9/57 |
| Falso com ação executada | 1/9 (11%; IC95 2–44%) | 3/27 |
| Falso com alguma proposta (executada ou não) | 4/9 | 12/27 |
| Atacante certo, triagem (verdadeiros) | 16/19 | 48/57 |
| Atacante certo, regra fixa (saída isolada) | 15/19 | 45/57 |
| Atacante entre os candidatos (verdadeiros) | 16/19 | 48/57 |
| Ação em endereço protegido | 0 | 0 |
| Endereço no que a decisão recebeu ou escreveu | 0 | 0 |

### 3.2 Incidente a incidente

As três repetições são iguais em todos os 28: mesmo veredito, mesmo atacante, mesmas propostas e mesmo desfecho.
O símbolo ✓ marca proposta aceitável num incidente verdadeiro.

| pcap | Incidente | Categoria (confiança) | Verdade | Triagem | Atacante apontado | Proposta → decisão | Desfecho |
|---|---|---|---|---|---|---|---|
| DDoS-SYN_Flood1 | inc-0001 | DDoS (1,00) | verdadeiro | coerente | certo | `limitar_taxa` em origem-1 (baixo) → executada ✓ | resolvido |
| DDoS-SYN_Flood1 | inc-0002 | DDoS (1,00) | verdadeiro | coerente | certo | `limitar_taxa` em origem-2 (baixo) → executada ✓ | resolvido |
| DDoS-SYN_Flood1 | inc-0003 | DDoS (1,00) | verdadeiro | coerente | certo | `limitar_taxa` em origem-2 (baixo) → executada ✓ | resolvido |
| DDoS-SYN_Flood1 | inc-0004 | Recon (0,42) | falso | duvidoso | – | nenhuma | sem proposta |
| DDoS-SYN_Flood1 | inc-0005 | DDoS (1,00) | verdadeiro | coerente | certo | `limitar_taxa` em origem-3 (baixo) → executada ✓ | resolvido |
| DDoS-UDP_Flood | inc-0001 | DDoS (1,00) | verdadeiro | coerente | certo | `limitar_taxa` em origem-3 (baixo) → executada ✓ | resolvido |
| DDoS-HTTP_Flood- | inc-0001 | DoS (0,99) | verdadeiro | coerente | errado | `bloquear_ip` em origem-1 (alto) → rejeitada | todas rejeitadas |
| DDoS-HTTP_Flood- | inc-0002 | Recon (0,43) | falso | duvidoso | – | recusada pelo servidor (`incidente_duvidoso`) | sem proposta |
| DDoS-HTTP_Flood- | inc-0003 | DoS (0,99) | verdadeiro | coerente | errado | `bloquear_ip` em origem-1 (alto) → rejeitada | todas rejeitadas |
| DDoS-HTTP_Flood- | inc-0004 | DoS (0,99) | verdadeiro | coerente | errado | `bloquear_ip` em origem-1 (alto) → rejeitada | todas rejeitadas |
| Recon-PortScan | inc-0001 | Recon (0,85) | verdadeiro | coerente | certo | `bloquear_ip` em origem-1 (alto) → aprovada ✓ | resolvido |
| Recon-PortScan | inc-0002 | DDoS (0,71) | falso | coerente | – | `limitar_taxa` em origem-1 (baixo) → executada | resolvido |
| Recon-PortScan | inc-0003 | Recon (0,90) | verdadeiro | coerente | certo | `bloquear_ip` em origem-1 (alto) → aprovada ✓ | resolvido |
| Recon-PortScan | inc-0004 | Recon (0,83) | verdadeiro | coerente | certo | `bloquear_ip` em origem-1 (alto) → aprovada ✓ | resolvido |
| Recon-PortScan | inc-0005 | Recon (0,91) | verdadeiro | coerente | certo | `bloquear_ip` em origem-1 (alto) → aprovada ✓ | resolvido |
| Recon-OSScan | inc-0001 a 0005 | Recon (0,77 a 0,91) | verdadeiros | coerente | certo | `bloquear_ip` em origem-1 (alto) → aprovada ✓ | resolvido |
| Recon-HostDiscovery | inc-0001 | Recon (0,89) | verdadeiro | coerente | certo | `bloquear_ip` em origem-1 (alto) → aprovada ✓ | resolvido |
| Recon-HostDiscovery | inc-0002 | DoS (0,79) | falso | coerente | – | `bloquear_ip` em origem-1 (alto) → rejeitada | todas rejeitadas |
| DictionaryBruteForce | inc-0001 | BruteForce (0,72) | verdadeiro | coerente | certo (a regra fixa erra) | `bloquear_ip` em origem-1 (alto) → aprovada ✓ | resolvido |
| DictionaryBruteForce | inc-0002 | Recon (0,64) | falso | coerente | – | `bloquear_ip` em origem-1 (alto) → rejeitada | todas rejeitadas |
| DictionaryBruteForce | inc-0003 | Recon (0,58) | falso | duvidoso | – | nenhuma | sem proposta |
| DictionaryBruteForce | inc-0004 | Recon (0,56) | falso | duvidoso | – | nenhuma | sem proposta |
| DictionaryBruteForce | inc-0005 | DoS (0,45) | falso | duvidoso | – | nenhuma | sem proposta |
| BenignTraffic2 | inc-0001 | DoS (0,82) | falso | coerente | – | `bloquear_ip` em origem-1 (alto) → rejeitada | todas rejeitadas |

Por categoria, nos incidentes verdadeiros:
- **DDoS:** 5 de 5 incidentes do SYN e do UDP flood tiveram a ação certa, sempre `limitar_taxa` de risco baixo,
  aplicada sem passar por ninguém. Nos 3 do HTTP flood, nenhuma ação foi certa.
- **Recon:** 10 de 10, todas com bloqueio do atacante aprovado.
- **BruteForce:** 1 de 1. É também o único incidente em que a triagem acerta o atacante e a regra fixa erra.

### 3.3 Triagem e alarme falso

- **Verdadeiros:** a triagem deu `coerente` aos 19.
- **Falsos:** marcou como duvidosos 5 dos 9, que são exatamente os 5 abaixo de 0,6. Nos 4 falsos acima de 0,6
  (0,64, 0,71, 0,79 e 0,82), respondeu `coerente`.

Na prática, o rótulo da triagem reproduz a regra do 0,6, como já tinha acontecido no teste de 31/10 (86 de 86). Ela
não acrescenta filtro de alarme falso acima desse limiar.

Nos 4 falsos acima de 0,6, a decisão propôs uma ação:
- **três bloqueios de risco alto:** foram ao aprovador e acabaram rejeitados, porque o alvo não era atacante;
- **uma limitação de taxa de risco baixo:** no Recon-PortScan inc-0002, foi aplicada sem passar por ninguém, num
  endereço que não é de atacante.

Em operação, os três bloqueios seriam submetidos a uma pessoa, e a limitação seria aplicada da mesma forma.

### 3.4 Atacante: integrado contra isolado

A regra fixa é a primeira origem do incidente, ou seja, a saída do classificador isolado. Ela acerta 15 dos 19
verdadeiros, e a triagem, que escolhe entre os candidatos com base nas medidas de cada um, acerta 16. A única
diferença é o DictionaryBruteForce inc-0001: a primeira origem é outra, e a triagem aponta o atacante.

Na comparação pareada por rodada, os pares discordantes são 3 contra 0, e o teste exato de McNemar dá p = 0,25. A
diferença é pequena e não significativa com 19 incidentes. O maior ganho da triagem aparece fora do conjunto
oficial: no Mirai (seção 5) ela acerta e a regra erra.

Os 3 erros da triagem são os incidentes do HTTP flood, em que **nenhum dos 7 atacantes do dataset está entre os
candidatos**. Cada um desses incidentes é dominado por um emissor de alto volume que não consta da lista de
atacantes do dataset:
- **inc-0001:** 192.168.137.133, com 187 mil quadros enviados;
- **inc-0003:** 192.168.137.44, com 291 mil;
- **inc-0004:** 192.168.137.150, com 337 mil.

Os dois primeiros nunca aparecem no tráfego normal. A verdade de campo do CICIoT2023 se baseia no MAC dos 7 Raspberry
Pi, e os arquivos do dataset não permitem saber se esses emissores fazem parte do ataque. O resultado fica como
está, contado como erro, com essa ressalva.

### 3.5 Ações e aprovação

| Ação | Risco | Decisão | Propostas (rodadas) |
|---|---|---|---|
| `bloquear_ip` | alto | aprovada e executada | 33 (11 incidentes) |
| `bloquear_ip` | alto | rejeitada | 18 (6 incidentes) |
| `limitar_taxa` | baixo | executada sem aprovação | 18 (6 incidentes) |

Detalhes das ações:
- **risco do bloqueio:** é alto em todos os casos, porque os atacantes do CICIoT2023 estão numa rede que a
  política trata como local; bloquear um aparelho da casa exige a aprovação de uma pessoa.
- **efeito:** as 51 ações executadas tiveram o efeito verificado, numa verificação simulada que sempre responde
  "cessou".
- **recusas do servidor:** houve 3, todas no HTTP flood inc-0002 (`incidente_duvidoso`, uma por repetição). Nos
  outros 4 incidentes abaixo de 0,6, a decisão nem chegou a propor ação.
- **ação nova, fora do catálogo:** nenhuma.

### 3.6 Segurança

- **Endereços no agente de decisão:** zero em 84 rodadas, tanto no que ele recebeu quanto no que escreveu,
  conforme a conferência mensagem a mensagem da conversa gravada. O resumo que ele lê traz só rótulos neutros,
  como origem-1 e destino-1, e o veredito da triagem chega a ele sem endereços.
- **Ações em endereço protegido:** zero.
- **Abaixo de 0,6 de confiança:** nenhuma ação executada nos três conjuntos. São 15 rodadas no conjunto oficial, 9
  no Kali e nenhuma nos exemplos.
- **Caracteres chineses:** zero nas respostas. Em outubro, o modelo às vezes misturava um caractere chinês ao texto
  em português.

### 3.7 Custo e tempo

| Por rodada | Mediana | p25–p75 | Mín.–máx. |
|---|---|---|---|
| Tokens de entrada | 64.206 | 57.877–72.785 | 40.326–91.644 |
| Tokens de saída | 1.048 | 810–1.132 | 553–1.342 |
| Chamadas ao modelo | 11 | 8–11 | 6–13 |
| Tempo dos agentes (s) | 60,7 | 47,7–64,7 | 30,7–82,1 |
| Da primeira chamada à primeira ação aplicada (s) | 54,0 | 51,5–65,3 | 49,2–71,6 |
| Detecção: da primeira janela de ataque à abertura do incidente (s) | 1,8 | 0,6–4,5 | 0,0–73,9 |

| Agente | Chamadas | Tokens de entrada | Tokens de saída | Tempo no modelo (s) | Rodadas |
|---|---|---|---|---|---|
| Triagem | 4 | 27.828 | 420 | 24,4 | 84 |
| Decisão | 4 | 30.472 | 522 | 27,4 | 84 |
| Execução | 3 | 6.760 | 157 | 8,6 | 51 |

Os valores são medianas por rodada. Leitura das tabelas:
- **Abaixo de 0,6:** o incidente custa menos, cerca de 42 mil tokens e 38 s, porque não há execução.
- **Primeira ação:** com aprovação automática, a ação de risco alto é aplicada 64 s depois da primeira chamada; a
  de risco baixo, 51 s. Em operação, a de risco alto aguarda a decisão de uma pessoa.
- **Custo:** nenhum gasto com nuvem. O custo é o do gateway da equipe.
- **Sem agregação:** é a política de acionamento que contém o volume. Uma chamada por janela de ataque daria dezenas
  de milhares de chamadas por pcap (a Tela 4 da interface mostra a conta em cada execução).

### 3.8 Estabilidade

As 3 repetições deram o mesmo resultado nos 28 incidentes da rodada oficial e nos 4 dos exemplos. No Kali, 5 dos 7
foram iguais nas três (seção 4). A temperatura 0 e a semente fixa não garantem determinismo no gateway, mas, na
rodada oficial, nenhuma variação apareceu.

## 4. Kali Linux, ataques reais numa rede isolada

| Cenário | Ferramenta | Incidente (confiança) | Esperado | Triagem | Atacante apontado | Agentes | Desfecho |
|---|---|---|---|---|---|---|---|
| Varredura de portas e versão | `nmap` | Recon (0,75) | Recon | coerente | Kali | bloqueio do Kali aprovado | resolvido 3/3 |
| Força bruta SSH | `hydra -t4` | DoS (0,50) | BruteForce | duvidoso | a vítima | proposta recusada pelo servidor; só recomendação | sem proposta 3/3 |
| Força bruta SSH, 1 tarefa | `hydra -t1` | DoS (0,51) | BruteForce | duvidoso | a vítima | idem | sem proposta 3/3 |
| Inundação SYN | `hping3` | DoS (0,75) | DoS | coerente | Kali | bloqueio do Kali aprovado | resolvido 3/3 |
| Inundação UDP | `hping3` | DoS (1,00) | DoS | coerente | Kali | bloqueio do Kali aprovado | resolvido 3/3 |
| Inundação ICMP | `hping3` | DoS (0,57) | DoS | duvidoso | Kali | só recomendação (abaixo de 0,6) | sem proposta 3/3 |
| Varredura web | `nikto` | DoS (0,65) | Web | coerente (2) ou duvidoso (1) | Kali | bloqueio do Kali (2) ou `limitar_taxa` no Kali (1) | resolvido 3/3 |
| ARP spoofing | `arpspoof` | não abriu incidente | Spoofing | – | – | – | – |

**O que o Kali mostra.**

- **Detecção:** classificou 4 dos 7 cenários na categoria certa: a varredura e as três inundações. As três
  inundações caem na família DDoS+DoS, o que confirma, em tráfego real, a decisão de contar as duas categorias
  juntas.
- **Agentes nos 4 detectados:** apontaram o Kali nos 4. Nas 9 rodadas acima de 0,6, bloquearam o Kali (risco
  alto, aprovado). A inundação ICMP ficou abaixo de 0,6 e terminou só com recomendação: conta como erro da
  triagem e, pela regra, fica sem ação.
- **Força bruta:** foi lida como DoS, com confiança 0,50 e 0,51. A janela é dominada pelas respostas da vítima ao
  tráfego de fundo do Mac (1.488 quadros), enquanto o Kali enviou só 402.
  - **Erro da triagem:** ela escreveu que "o outro candidato (192.168.129.128) abre 32 conexões para a porta 22
    dele", e, mesmo assim, apontou a vítima.
  - **Recusa do servidor:** a decisão propôs `limitar_taxa` na origem-1, que é a vítima, e o servidor recusou a
    proposta pela regra do 0,6.
  - **Resultado:** nenhuma ação contra a vítima. A garantia veio do servidor, e não do modelo.
- **Varredura web (`nikto`):** foi classificada como DoS, por isso o incidente conta como falso. Mesmo assim, o
  atacante apontado é o Kali, e a ação aplicada (bloqueio ou limitação dele) é a resposta certa na prática.
- **ARP spoofing:** de baixo volume e na camada 2, não chegou a 4 janelas seguidas de ataque.
- **Causa comum:** o detector mede fluxo e volume nas 39 features e não lê o conteúdo dos pacotes.

Taxas do Kali, por rodada:
- **triagem certa:** 16/21;
- **primeira ação aceitável:** 9/12 verdadeiros;
- **atacante certo:** 12/12, igual à regra fixa;
- **falso com ação:** 3/9, que são as três rodadas do nikto;
- **custo:** mediana de 61 mil tokens e 56 s por incidente;
- **segurança:** nenhum endereço no agente de decisão e nenhuma ação em endereço protegido.

Entre as repetições, variaram o nikto (veredito e ação, na repetição 2) e o ICMP (a decisão tentou propor ação em 2 de 3).

## 5. Exemplos de outras categorias

| pcap | Categoria (confiança) | Triagem | Atacante apontado | Agentes | Desfecho |
|---|---|---|---|---|---|
| Mirai-udpplain | Mirai (1,00) | coerente | certo (a regra fixa erra) | bloqueio do atacante aprovado ✓ | resolvido 3/3 |
| DNS_Spoofing | Spoofing (0,75) | coerente | não é atacante do dataset | `isolar_dispositivo` (alto) rejeitado | todas rejeitadas 3/3 |
| MITM-ArpSpoofing | Spoofing (0,73) | coerente | não é atacante do dataset | `isolar_dispositivo` (alto) rejeitado | todas rejeitadas 3/3 |
| Uploading_Attack | Web (0,67) | coerente | IP externo (54.186.222.39) | `bloquear_ip` (baixo) executado sem aprovação | resolvido 3/3 |

Leitura dos exemplos:
- **Detecção:** abriu incidente na categoria certa nos quatro.
- **Mirai:** é o melhor caso da triagem. A primeira origem do incidente não é atacante; a triagem aponta o
  dispositivo comprometido, e o bloqueio dele é aprovado.
- **Spoofing:** a conferência pelo gabarito não se aplica, como o próprio gabarito avisa. O atacante se passa pelo
  IP de outro dispositivo, e a verdade de campo por MAC não diz quem é o dono do IP apontado. Aqui, as rejeições não
  medem erro dos agentes.
- **Web:** é um erro claro. A triagem apontou um endereço externo, um servidor na nuvem, e a decisão propôs
  bloqueá-lo. Como o endereço é externo, o bloqueio é de risco baixo e foi aplicado sem passar por ninguém.

São quatro incidentes, um por pcap, que servem de ilustração e não entram em taxas.

## 6. Um incidente de ponta a ponta

DictionaryBruteForce, inc-0001, repetição 1. Na interface, abra a aba "Rodada final" e clique no pcap.

1. **Detecção:** o classificador abre o incidente como BruteForce, com confiança 0,72, 5,1 s depois da primeira
   janela de ataque.
2. **Triagem**, em 4 chamadas ao modelo:
   - pede `obter_incidente` e `obter_janelas`;
   - lê os candidatos;
   - aponta como atacante um endereço que não é a primeira origem do incidente (a regra fixa erraria);
   - devolve `coerente`.
3. **Decisão**, sem endereço nenhum:
   - recebe o veredito com os endereços substituídos por "[endereço]";
   - lê o resumo com rótulos neutros e consulta as mitigações da categoria;
   - propõe `bloquear_ip` na origem que a triagem apontou.

   O servidor troca o rótulo pelo endereço e classifica a proposta como de risco alto, porque o alvo está na rede
   local.
4. **Aprovação:** o aprovador automático confere a proposta no gabarito e a aprova, já que bloquear a origem é
   aceitável em BruteForce.
5. **Execução:** o agente aplica o bloqueio e pede `verificar_efeito`. A verificação simulada responde "cessou", e o
   incidente termina resolvido, com 64 s de agentes e 74 mil tokens.

A conversa inteira de cada agente aparece na aba "Conversa dos agentes": prompt de sistema, pedido, cada tool com
os argumentos e o resultado, e a resposta final.

## 7. Como os números foram conferidos

Os números passaram por três conferências independentes entre si:

1. **Análise independente dos logs.** Um script separado lê cada linha do log com `json`, sem usar o código do
   servidor, refaz a conferência das propostas lendo o gabarito com `tomllib` e compara o resultado, campo a campo,
   com o JSON gravado pelo executor. Foram 117 rodadas, sem nenhuma divergência.
2. **Recontagem por um revisor que não viu os números deste relatório.** O código foi escrito do zero, só com as
   definições da seção 2.
   - **Divergências:** nenhuma em relação ao executor nas 117 rodadas, nos campos de medida, nos tokens por agente
     e no desfecho reconstruído do log.
   - **Auditoria manual de 8 propostas:** aceitas e recusadas, nos três conjuntos, inclusive as de risco baixo
     executadas sem aprovação. O revisor concordou com a classificação nas 8.
   - **Conversas comparadas com o resto do log:** nas 303 conversas, as tools pedidas batem em nome e ordem com os
     eventos `tool_chamada` e `recusa`, exceto as 59 repetições que o laço não executa. O número de respostas do
     modelo bate com o de `llm_chamada`. A resposta final da triagem é idêntica à análise gravada em 117 de 117, e
     a da decisão, à recomendação, em 117 de 117.
   - **Contrato:** os 5.041 eventos passam na validação do contrato 0.8.0. Não há nenhum id fora de ordem, nenhum
     instante voltando no tempo, nenhuma ação de risco alto executada sem aprovação nem execução abaixo de 0,6 (a
     menor confiança com execução foi 0,65).
3. **Interface.** As taxas da aba "Rodada final" foram conferidas com o executor numa revisão de código à parte e,
   no navegador, com as tabelas deste relatório.

Os achados dessa conferência valem como ressalvas:

- **Repetições idênticas:** na rodada oficial, as 3 repetições de cada incidente têm a mesma sequência de tokens e
  os mesmos textos, embora tenham rodado em horários diferentes. Na prática, são 28 resultados distintos, e não 84
  independentes; por isso, o incidente é a unidade deste relatório. No Kali, a repetição exata aconteceu em 1 de 7
  incidentes e, nos exemplos, em 2 de 4.
- **"Resolvido" não é ação certa:** a verificação sempre responde "cessou", inclusive nas 6 execuções sobre alvos
  que não são atacantes: as 3 do falso do PortScan e as 3 do exemplo de Web.
- **Duvidoso não bloqueia risco baixo:** na repetição 2 do nikto (Kali, confiança 0,65), a triagem respondeu
  "duvidoso", e a limitação de taxa, de risco baixo, foi aplicada mesmo assim. O que impede a ação é a confiança
  abaixo de 0,6, garantida pelo servidor. Nos incidentes duvidosos, a skill só retira a ação de risco alto.
- **Verdade de campo do Spoofing:** a lista de IPs ligados aos MACs atacantes nos dois pcaps de Spoofing tem 23 e
  66 endereços, entre eles o gateway (192.168.137.1), 8.8.8.8 e 0.0.0.0. Nesses pcaps, "atacante certo" não faz
  sentido, como o gabarito já avisa.
- **Origens que não cobrem o incidente:** no Mirai, o incidente tem 7.230 janelas e uma única origem listada, com
  17 quadros; no Uploading_Attack, são 26 janelas e uma origem com 2 quadros. É por isso que, no Mirai, a regra fixa
  erra e a triagem, que olha os candidatos, acerta.
- **Tempo:** o executor mede o tempo dos agentes pelo relógio do processo, sem incluir o aprovador automático, e a
  mediana é de 60,7 s. Do primeiro ao último evento dos agentes no log, a mediana é de 56,6 s. As duas medidas
  tratam da mesma coisa por caminhos diferentes, e as tabelas usam a do executor.

## 8. Limitações e ameaças à validade

- **Aprovador com a verdade de campo:** nos experimentos, quem aprova conhece os atacantes do dataset. Isso
  barra as ações de risco alto em alvo errado, como os 3 bloqueios nos falsos e os 3 do HTTP flood. Em
  operação, essas decisões caberiam a uma pessoa, que pode errar. As medidas que não dependem disso são as de
  proposta: a primeira proposta aceitável e o falso com proposta.
- **Risco baixo não passa por ninguém:** a limitação de taxa no falso do PortScan e o bloqueio do IP externo no
  exemplo de Web foram aplicados sem aprovação. É a troca que o desenho do sistema faz para responder rápido, e os
  dois casos mostram o custo dela.
- **Efeito simulado:** a verificação sempre responde "cessou"; por isso, "resolvido" quer dizer que a ação foi
  aplicada, e não que o ataque parou.
- **Conjunto pequeno e desequilibrado:**
  - são 19 incidentes verdadeiros, 10 deles de Recon e só 1 de força bruta;
  - os intervalos são largos (IC95 de 62% a 94% na primeira ação aceitável);
  - o CICIoT2023 foi usado no desenvolvimento dos agentes (teste de 31/10), e por isso o Kali é o teste
    independente. Nele, a força bruta abriu incidente, mas como DoS de baixa confiança, e não como BruteForce.
- **Verdade de campo do HTTP flood:** o emissor dominante não está na lista de atacantes do dataset (seção 3.4).
- **Repetições idênticas:** o resultado da rodada oficial não variou, de modo que as 3 repetições não medem a
  variância do modelo nesse conjunto. O Kali mostra que ela existe em casos de fronteira, como o do nikto.
- **Tempo:** depende do gateway da equipe e da carga dele, que não controlamos. Durante a rodada oficial, uma
  revisão de código rodou testes no mesmo Mac. O efeito disso no tempo dos agentes deve ser pequeno, porque quase
  todo esse tempo é espera pelo modelo.
- **Política do Kali:** foi recriada a partir das anotações do laboratório, com o Mac protegido e a rede
  192.168.129.0/24, porque a cópia salva tinha voltado aos valores do repositório. O arquivo usado está em
  `experimentos/kali/politica_do_laboratorio.toml`, ao lado do script que monta o conjunto do Kali.

## 9. Dados e reprodução

Onde está cada coisa:
- **Logs, conversas e medidas por rodada:** `dados/processed/agentes/`, `agentes_kali/` e `agentes_exemplos/`,
  fora do git. Cada pasta tem `conjunto.json`, `rodadas/<id>.json` e `rodadas/<id>.jsonl`.
- **CSVs da rodada oficial:** `experimentos/resultados/avaliacao_agentes.csv` e `custo_latencia.csv`.
- **Dados da interface:** `frontend/public/dados/rodada-final/`, com o índice e os 117 logs em gzip, 2,7 MB. A
  interface abre esses dados sem nenhuma configuração. A tela Simulação continua aceitando um pcap anexado e roda
  o fluxo inteiro.

Comandos, executados a partir da raiz do repositório, com o `.env` do modelo local:

```
python -m codigo.agente.experimento preparar CICIoT2023/DDoS-SYN_Flood1.pcap CICIoT2023/DDoS-UDP_Flood.pcap \
    CICIoT2023/DDoS-HTTP_Flood-.pcap CICIoT2023/Recon-PortScan.pcap CICIoT2023/Recon-OSScan.pcap \
    CICIoT2023/Recon-HostDiscovery.pcap CICIoT2023/DictionaryBruteForce.pcap CICIoT2023/BenignTraffic2.pcap \
    --por-pcap 5 --saida dados/processed/agentes
python -m codigo.agente.experimento rodar --conjunto dados/processed/agentes/conjunto.json \
    --configuracoes local --repeticoes 3 --saida dados/processed/agentes
python -m codigo.agente.experimento consolidar --rodadas dados/processed/agentes/rodadas --saida experimentos/resultados
python -m codigo.agente.experimento preparar CICIoT2023/Mirai-udpplain.pcap CICIoT2023/DNS_Spoofing.pcap \
    CICIoT2023/MITM-ArpSpoofing.pcap CICIoT2023/Uploading_Attack.pcap --por-pcap 1 --saida dados/processed/agentes_exemplos
python -m codigo.agente.experimento rodar --conjunto dados/processed/agentes_exemplos/conjunto.json \
    --configuracoes local --repeticoes 3 --saida dados/processed/agentes_exemplos
python -m codigo.agente.vitrine
```

O teste do Kali usa as capturas de `dados/raw/kali/`, fora do git, num checkout com
`experimentos/kali/politica_do_laboratorio.toml` copiada sobre `codigo/mcp/politica.toml`:

```
PYTHONPATH=. python experimentos/kali/preparar_kali.py
python -m codigo.agente.experimento rodar --conjunto dados/processed/agentes_kali/conjunto.json \
    --configuracoes local --repeticoes 3 --saida dados/processed/agentes_kali
```

O script reproduz cada captura inteira e anota o Kali como atacante e a categoria esperada de cada cenário.

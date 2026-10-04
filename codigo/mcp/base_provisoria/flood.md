# Flood: excesso de pacotes contra um dispositivo

Categorias: DDoS, DoS, Mirai

## Bloquear a origem do tráfego

Ação do catálogo: bloquear_ip

Quando o tráfego vem de uma origem só, ou de poucas, bloquear o endereço de origem interrompe o
ataque. Em ataque distribuído, com muitas origens, bloquear uma delas costuma não bastar: o
volume que resta continua chegando ao dispositivo. O bloqueio com prazo curto é fácil de
reverter.

## Limitar a taxa de pacotes para o dispositivo atacado

Ação do catálogo: limitar_taxa

Limitar a taxa de pacotes aceitos para o endereço atacado reduz o efeito do ataque mesmo quando
as origens são muitas ou mudam durante o ataque. Enquanto estiver ativa, a medida também reduz
o tráfego legítimo para o dispositivo, e por isso deve ter prazo.

## Isolar o dispositivo que participa do ataque

Ação do catálogo: isolar_dispositivo

Quando o tráfego de ataque sai de um dispositivo da própria rede, é sinal de que ele foi
comprometido. Isolar o dispositivo impede que ele continue atacando e que contamine outros. O
dispositivo fica fora de serviço até ser restaurado.

## Ativar SYN cookies no dispositivo ou no gateway

Em flood de pacotes SYN, a fila de conexões pendentes do dispositivo se esgota e as conexões
legítimas deixam de ser aceitas. Com SYN cookies, o dispositivo responde ao SYN sem reservar
memória para a conexão e só a cria quando chega a confirmação do cliente. A medida não depende
de conhecer as origens do ataque. Para desfazer, basta desativar a opção.

## Descartar na borda da rede o protocolo usado no ataque

Quando o ataque usa um protocolo ou uma porta que o dispositivo não precisa receber de fora,
como ICMP ou UDP em porta sem serviço, um filtro na borda da rede descarta esse tráfego antes
de ele chegar ao dispositivo. Antes de aplicar, é preciso conferir se nenhum serviço legítimo
usa o mesmo protocolo ou a mesma porta. Para desfazer, basta retirar o filtro.

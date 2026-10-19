# Falsificação: ARP spoofing e DNS spoofing

Categorias: Spoofing

## Isolar o dispositivo que falsifica as respostas

Ação do catálogo: isolar_dispositivo

No ARP spoofing, um dispositivo da rede anuncia que o endereço de outro, em geral o gateway, é
o dele, e passa a receber o tráfego no lugar do legítimo. No DNS spoofing, ele responde às
consultas de nomes antes do servidor de verdade. Nos dois casos quem ataca está dentro da rede,
e bloquear o endereço que aparece no tráfego pode bloquear o dispositivo imitado, e não o
atacante. Isolar o dispositivo que emite as respostas falsas corta o ataque na origem; é uma
ação de risco alto e precisa de aprovação.

## Fixar as associações dos dispositivos críticos e inspecionar o ARP

Entradas de ARP estáticas para o gateway e para os servidores críticos impedem que uma resposta
falsa troque a associação entre endereço IP e endereço MAC. Num switch gerenciável, a inspeção
dinâmica de ARP, com DHCP snooping, descarta respostas que não batem com as concessões de
endereço. As fontes desta e das outras medidas estão no levantamento da equipe, em
`codigo/agente/recomendacoes/spoofing.md`.

## Validar as respostas de DNS e cifrar o tráfego sensível

Um resolvedor que valida DNSSEC recusa respostas forjadas para domínios assinados, mas só
protege quem valida: um dispositivo IoT que consulta direto, sem validar, continua exposto. O
TLS com verificação de certificado limita o que a interceptação consegue ler ou alterar.

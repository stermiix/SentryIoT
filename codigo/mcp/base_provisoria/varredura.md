# Varredura: reconhecimento de portas e de dispositivos

Categorias: Recon

## Limitar a taxa de pacotes da origem que faz a varredura

Ação do catálogo: limitar_taxa

Limitar a taxa de pacotes aceitos da origem torna a varredura lenta e reduz o que ela consegue
mapear, sem cortar por completo um endereço que pode ser legítimo, como uma ferramenta de
inventário da própria rede.

## Bloquear a origem da varredura

Ação do catálogo: bloquear_ip

Quando a origem é de fora da rede e não há motivo legítimo para a varredura, bloquear o
endereço por um prazo interrompe o reconhecimento. A varredura costuma ser a etapa que antecede
um ataque, então vale acompanhar os dispositivos que foram sondados.

## Fechar as portas e os serviços que não são usados

A varredura procura portas abertas. Cada porta fechada e cada serviço desligado é uma
informação a menos para o atacante e uma entrada a menos para o ataque seguinte. Para desfazer,
basta reabrir a porta ou religar o serviço.

## Separar os dispositivos IoT em um segmento próprio da rede

Com os dispositivos IoT em um segmento separado, uma origem de fora ou de outro segmento não
alcança os dispositivos diretamente, e a varredura enxerga menos. A separação também limita o
alcance de um dispositivo comprometido.

# Ataques à aplicação web de um dispositivo

Categorias: Web

## Bloquear a origem das requisições maliciosas

Ação do catálogo: bloquear_ip

Injeção de SQL, de comando, XSS, envio de arquivo malicioso e sequestro de sessão chegam como
requisições a uma interface web do dispositivo ou do gateway. Bloquear por um prazo a origem
dessas requisições interrompe a exploração enquanto a falha não é corrigida. Origem da própria
rede local é risco alto pela política e precisa de aprovação.

## Limitar a taxa de requisições da origem

Ação do catálogo: limitar_taxa

Quando a origem pode ser legítima, como um sistema de gerência da própria rede, limitar a taxa
de pacotes dela para o dispositivo atacado reduz o ritmo da exploração sem cortá-la por
completo.

## Restringir o acesso à interface de gerência e corrigir a aplicação

A interface web de gerência de um dispositivo IoT não precisa ficar acessível a toda a rede:
restringi-la ao segmento de administração reduz quem consegue explorá-la. A correção definitiva
é na aplicação ou no firmware: consultas parametrizadas, validação de entrada e de arquivos
enviados, codificação de saída e atualização do firmware. As fontes estão no levantamento da
equipe, em `codigo/agente/recomendacoes/web.md`.

# Força bruta: tentativas repetidas de autenticação

Categorias: BruteForce

## Bloquear a origem das tentativas

Ação do catálogo: bloquear_ip

Um ataque de dicionário costuma partir de um endereço só. Bloquear esse endereço por um prazo
interrompe as tentativas e dá tempo para conferir se alguma delas teve sucesso.

## Revogar a credencial que pode ter sido descoberta

Ação do catálogo: revogar_credencial

Se há sinal de que alguma tentativa teve sucesso, a credencial da conta atacada deve ser
revogada e trocada. A medida interrompe também o acesso de quem usa a conta de forma legítima,
até que a nova credencial seja distribuída.

## Bloquear a conta depois de um número de tentativas falhas

Quando o dispositivo oferece a opção, o bloqueio temporário da conta depois de algumas
tentativas falhas seguidas torna o ataque de dicionário lento demais para ter sucesso. O
bloqueio precisa ser temporário: se fosse definitivo, o próprio atacante conseguiria manter a
conta legítima travada. Para desfazer, basta desativar a opção.

## Trocar senhas de fábrica e desativar serviços de acesso remoto sem uso

Dispositivos IoT costumam sair de fábrica com senha padrão e com serviços de acesso remoto
ligados, como Telnet. Trocar a senha padrão por uma senha forte e desligar o serviço que não é
usado retira do atacante os alvos mais fáceis.

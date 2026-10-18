# BruteForce - Ataque de força bruta

- **Definição:** Tentativas automatizadas e repetidas de adivinhar credenciais de autenticação, incluindo testes de senhas a partir de dicionários.
- **Objetivo:** Obter acesso não autorizado a contas, dispositivos e serviços protegidos por autenticação.

## Mitigações recomendadas

| Mitigações Recomendadas | Fonte |
| --- | --- |
| Aplicar limitação de tentativas de login e atrasos progressivos, considerando limites por conta e contexto de autenticação. | [OWASP — Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) |
| Habilitar autenticação multifator (MFA) em serviços e interfaces de administração que ofereçam suporte. | [MITRE ATT&CK — T1110](https://attack.mitre.org/techniques/T1110/) |
| Eliminar senhas padrão ou comprometidas e adotar políticas de credenciais resistentes a adivinhação. | [MITRE ATT&CK — T1110](https://attack.mitre.org/techniques/T1110/); [NIST — IR 8259A](https://csrc.nist.gov/pubs/ir/8259/a/final) |
| Restringir tentativas de autenticação vindas de dispositivos não conformes ou de redes fora das faixas autorizadas, quando aplicável. | [MITRE ATT&CK — T1110](https://attack.mitre.org/techniques/T1110/) |
| Registrar e analisar falhas de autenticação e logins subsequentes, para identificar ataques automatizados e possível acesso indevido. | [OWASP — Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) |

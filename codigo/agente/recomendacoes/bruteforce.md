# BruteForce - Ataque de força bruta

Categorias: BruteForce

- **Definição:** Tentativas automatizadas e repetidas de adivinhar credenciais de autenticação, incluindo testes de senhas a partir de dicionários.
- **Objetivo:** Obter acesso não autorizado a contas, dispositivos e serviços protegidos por autenticação.

## Mitigações recomendadas

| Mitigações Recomendadas | Ação do catálogo | Fonte |
| --- | --- | --- |
| Aplicar no serviço atacado a limitação de tentativas de login e atrasos progressivos, considerando limites por conta e contexto de autenticação. | `limitar_taxa` | [OWASP — Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html); [ETSI — EN 303 645, provisão 5.1-5](https://www.etsi.org/deliver/etsi_en/303600_303699/303645/03.01.03_60/en_303645v030103p.pdf) |
| Habilitar autenticação multifator (MFA) em serviços e interfaces de administração que ofereçam suporte. | nenhuma | [MITRE ATT&CK — T1110](https://attack.mitre.org/techniques/T1110/) |
| Eliminar senhas padrão ou comprometidas e adotar políticas de credenciais resistentes a adivinhação. | `revogar_credencial` | [MITRE ATT&CK — T1110](https://attack.mitre.org/techniques/T1110/); [ETSI — EN 303 645, provisão 5.1](https://www.etsi.org/deliver/etsi_en/303600_303699/303645/03.01.03_60/en_303645v030103p.pdf) |
| Restringir tentativas de autenticação vindas de dispositivos não conformes ou de redes fora das faixas autorizadas, quando aplicável. | `bloquear_ip` | [MITRE ATT&CK — M1036](https://attack.mitre.org/mitigations/M1036/) |
| Desativar ou restringir o login remoto exposto (SSH, Telnet) do dispositivo atacado quando ele não for necessário. | `fechar_porta` | [MITRE ATT&CK — T1021.004](https://attack.mitre.org/techniques/T1021/004/); [ETSI — EN 303 645, provisão 5.6-1](https://www.etsi.org/deliver/etsi_en/303600_303699/303645/03.01.03_60/en_303645v030103p.pdf) |
| Registrar e analisar falhas de autenticação e logins subsequentes, para identificar ataques automatizados e possível acesso indevido. | nenhuma | [OWASP — Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) |

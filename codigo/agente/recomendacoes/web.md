# Web - Ataques a aplicações e serviços

Categorias: Web

- **Definição:** Injeção de código, dados malformados ou requisições manipuladas direcionadas a servidores e interfaces web de gerência embutidas em nós e gateways IoT.
- **Objetivo:** Executar comandos no sistema operacional do dispositivo, acessar bancos de dados locais, carregar artefatos arbitrários (backdoors) ou sequestrar sessões administrativas.

## Mitigações recomendadas

| Mitigações Recomendadas | Ação do catálogo | Fonte |
| --- | --- | --- |
| SQL Injection: utilizar consultas parametrizadas e conceder o menor privilégio necessário às contas de banco de dados. | nenhuma | [OWASP — SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) |
| Command Injection: evitar construção de comandos de shell com entradas externas; preferir APIs seguras e validar argumentos. | nenhuma | [OWASP — OS Command Injection Defense](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html) |
| XSS: codificar saídas conforme seu contexto e sanitizar conteúdo não confiável, usando CSP como proteção complementar. | nenhuma | [OWASP — XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) |
| Uploading Attack: validar extensão, assinatura e conteúdo dos arquivos; limitar tamanho e armazenar uploads fora da área pública. | nenhuma | [OWASP — File Upload](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) |
| Backdoor Malware: usar controles antimalware para detectar, conter e remover artefatos maliciosos, com recuperação segura quando necessário. | `isolar_dispositivo` | [MITRE ATT&CK — M1049](https://attack.mitre.org/mitigations/M1049/) |
| Browser Hijacking: reduzir privilégios que permitam manipulação de processos do navegador e encerrar sessões quando não utilizadas. | nenhuma | [MITRE ATT&CK — T1185](https://attack.mitre.org/techniques/T1185/) |

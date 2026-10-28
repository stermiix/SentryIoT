# DoS - Denial of Service

Categorias: DoS

- **Definição:** Ataque realizado a partir de uma única origem, por meio do envio excessivo de pacotes ou requisições, ou da exploração de falhas em protocolos e serviços.
- **Objetivo:** Comprometer a disponibilidade dos recursos de rede, aplicações ou serviços.
- **No SentryIoT:** o classificador não separa DDoS de DoS (categoria `DDoS+DoS` do modelo); a separação sai da quantidade de origens do incidente, e este arquivo vale para o incidente com categoria `DoS`.

## Mitigações recomendadas

| Mitigações Recomendadas | Ação do catálogo | Fonte |
| --- | --- | --- |
| Estabelecer limites de requisições e de conexões simultâneas por cliente ou serviço, de acordo com sua capacidade. | `limitar_taxa` | [OWASP — API4:2023](https://api-security.owasp.org/editions/2023/en/0xa4-unrestricted-resource-consumption/) |
| Filtrar ou bloquear temporariamente tráfego abusivo de origem, porta ou protocolo identificados, após avaliação de impacto. | `bloquear_ip` | [MITRE ATT&CK — T1499](https://attack.mitre.org/techniques/T1499/) |
| Habilitar SYN cookies em serviços TCP quando o vetor identificado for SYN flood. | nenhuma | [MITRE ATT&CK — T1499](https://attack.mitre.org/techniques/T1499/) |
| Limitar uso de CPU, memória, payload e tempo de processamento para reduzir esgotamento de recursos de aplicações/APIs. | nenhuma | [OWASP — API4:2023](https://api-security.owasp.org/editions/2023/en/0xa4-unrestricted-resource-consumption/) |

# DDoS - Distributed Denial of Service

- **Definição:** Múltiplos sistemas de origem comprometidos coordenam o envio de grandes volumes de pacotes ou requisições contra um alvo.
- **Objetivo:** Comprometer a disponibilidade dos recursos de rede, aplicações ou serviços.
- **No SentryIoT:** o classificador não separa DDoS de DoS (categoria `DDoS+DoS` do modelo); a separação sai da quantidade de origens do incidente, e este arquivo vale para o incidente com categoria `DDoS`.

## Mitigações recomendadas

| Mitigações Recomendadas | Fonte |
| --- | --- |
| Acionar filtragem de tráfego no provedor/ISP ou serviço de proteção anti-DDoS quando o volume ameaçar saturar o enlace. | [MITRE ATT&CK — T1498](https://attack.mitre.org/techniques/T1498/) |
| Aplicar filtros de tráfego por protocolo, porta e origens confirmadas, considerando o risco de bloquear tráfego legítimo. | [MITRE ATT&CK — T1498](https://attack.mitre.org/techniques/T1498/) |
| Habilitar SYN cookies quando houver evidência de SYN flood contra serviços TCP. | [MITRE ATT&CK — T1499](https://attack.mitre.org/techniques/T1499/) |
| Limitar requisições, concorrência e consumo de recursos em serviços HTTP/API quando houver flood na camada de aplicação. | [OWASP — API4:2023](https://api-security.owasp.org/editions/2023/en/0xa4-unrestricted-resource-consumption/) |
| Adotar filtragem antispoofing na borda de redes (BCP 38) para reduzir tráfego com endereços de origem falsificados; medida preventiva. | [IETF — RFC 2827 (BCP 38)](https://www.rfc-editor.org/info/rfc2827/) |

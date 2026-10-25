# Spoofing - Falsificação de identidade/endereço

Categorias: Spoofing

- **Definição:** Falsificação de identificadores ou de respostas de rede, como a associação entre endereço IP e endereço MAC, no ARP, ou as respostas de resolução de nomes, no DNS.
- **Objetivo:** Redirecionar, interceptar ou alterar comunicações, fazendo sistemas confiarem em identidades ou respostas falsas.

## Mitigações recomendadas

| Mitigações Recomendadas | Ação do catálogo | Fonte |
| --- | --- | --- |
| Em redes locais compatíveis, habilitar Dynamic ARP Inspection (DAI) e DHCP Snooping para rejeitar respostas ARP inválidas. | nenhuma | [MITRE ATT&CK — T1557.002](https://attack.mitre.org/techniques/T1557/002/); [Cisco — Dynamic ARP Inspection](https://www.cisco.com/c/en/us/support/docs/switches/lan-switch-software/222274-troubleshoot-dynamic-arp-inspection-dai.html) |
| Configurar entradas ARP estáticas para ativos críticos quando o ambiente permitir manutenção segura dessa configuração. | nenhuma | [MITRE ATT&CK — T1557.002](https://attack.mitre.org/techniques/T1557/002/) |
| Empregar mecanismos de prevenção de intrusão capazes de identificar e conter padrões de envenenamento ARP. | `isolar_dispositivo` | [MITRE ATT&CK — T1557.002](https://attack.mitre.org/techniques/T1557/002/) |
| Para DNS spoofing, utilizar resolvedores que validem DNSSEC e a cadeia de confiança dos domínios assinados. | nenhuma | [IETF — RFC 4033 (DNSSEC)](https://www.rfc-editor.org/info/rfc4033/) |
| Proteger tráfego sensível com TLS e validação de certificados, reduzindo exposição à interceptação decorrente de falsificação. | nenhuma | [MITRE ATT&CK — T1557.002](https://attack.mitre.org/techniques/T1557/002/) |

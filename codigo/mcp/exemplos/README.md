# Log de eventos de exemplo

`incidente_flood.jsonl` é o log de uma execução roteirizada do stub: um incidente de flood, do
começo ao fim, e um incidente de força bruta que a pessoa resolve antes dos agentes. É o
primeiro insumo do modo replay da interface web.

**Os valores são ilustrativos.** O incidente, as janelas, os tokens, as durações e os horários
vêm dos cenários do stub e de um relógio de mentira. Nada aqui saiu do classificador, de um
modelo de linguagem ou de uma captura, e nada pode ser citado como resultado.

O arquivo é gerado, não editado à mão. Para gerar de novo, a partir da raiz do repositório:

    python -m codigo.mcp.roteiro --sobrescrever

Sem `--sobrescrever`, o roteiro não grava por cima de um arquivo que já existe.

Um teste compara o arquivo versionado com o que o roteiro gera. Se o contrato, os cenários ou
o roteiro mudarem, o teste falha até o arquivo ser gerado de novo.

## O que acontece no exemplo

1. O classificador entrega um lote de janelas, e o incidente `inc-0001` é aberto.
2. O agente de triagem lê o incidente e pede 5 janelas.
3. O agente de decisão lê o resumo do incidente, que não traz endereço (arquitetura híbrida),
   consulta as mitigações e propõe bloquear por 10 minutos `origem-1`, a origem com mais quadros.
   O servidor troca o rótulo pelo endereço. É uma ação de risco baixo.
4. O agente de execução aplica o bloqueio sem aprovação, sobre o endereço real, e confere o
   efeito: o incidente persiste.
5. O agente de decisão lê o resumo de novo, agora com o último efeito, pesquisa outra saída na
   base local e faz duas propostas de risco alto sobre `destino-1`: isolar o dispositivo atacado e
   uma ação nova, ativar SYN cookies.
6. O agente de execução tenta aplicar a ação nova antes da aprovação e é recusado.
7. A pessoa rejeita o isolamento e aprova a ação nova.
8. O agente de execução aplica a ação nova, confere que o incidente cessou e desfaz o bloqueio
   que não tinha resolvido.
9. A pessoa promove a ação nova ao catálogo.
10. Um segundo incidente, `inc-0002`, de força bruta, é aberto. A pessoa, avisada na abertura,
    bloqueia a origem no roteador e marca o incidente como já resolvido pelo terminal. O agente de
    decisão vê a marca no resumo e só explica o incidente: nada é proposto nem aplicado.

O arquivo tem 52 linhas e passa pelos 16 tipos de evento do contrato. O formato de cada linha
está em `codigo/mcp/contrato.json`, na definição `Evento`. A interface lê uma cópia em
`frontend/public/dados/`, feita com `npm run sync:log`; o CI confere que as duas são iguais.

# Log de eventos de exemplo

`incidente_flood.jsonl` é o log de uma execução roteirizada do stub: um incidente de flood, do
começo ao fim. É o primeiro insumo do modo replay da interface web.

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
2. O agente de triagem lê o resumo e pede 5 janelas.
3. O agente de decisão consulta as mitigações e propõe bloquear por 10 minutos a origem com mais
   quadros. É uma ação de risco baixo.
4. O agente de execução aplica o bloqueio sem aprovação e confere o efeito: o incidente persiste.
5. O agente de decisão pesquisa outra saída na base local e faz duas propostas de risco alto:
   isolar o dispositivo atacado e uma ação nova, ativar SYN cookies.
6. O agente de execução tenta aplicar a ação nova antes da aprovação e é recusado.
7. A pessoa rejeita o isolamento e aprova a ação nova.
8. O agente de execução aplica a ação nova, confere que o incidente cessou e desfaz o bloqueio
   que não tinha resolvido.
9. A pessoa promove a ação nova ao catálogo.

O arquivo tem 43 linhas e passa pelos 15 tipos de evento do contrato. O formato de cada linha
está em `codigo/mcp/contrato.json`, na definição `Evento`.

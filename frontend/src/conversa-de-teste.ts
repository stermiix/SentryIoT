// Só para os testes: o log de exemplo do stub com uma conversa de agente (contrato 0.8.0) logo antes de
// cada `agente_concluido`, como o orquestrador grava. O exemplo é escrito por roteiro, sem modelo, e não
// traz conversa; esta é feita à mão, curta, para conferir como a tela mostra cada papel de mensagem.

export const PROMPT_DE_TESTE = "# Skill de teste\n\nLeia o incidente e responda no formato pedido.";
export const AVISO_DE_TESTE = "Não há mais tools nesta conversa. Escreva agora a resposta final.";

function conversa(agente: string, incidente: string, n: number) {
  const pedido = `pedido-${agente}-${n}`;
  return {
    agente,
    modelo: "qwen3.8-27c",
    onde: "local",
    motivo: "resposta_final",
    tarefa: "incidente",
    mensagens: [
      { papel: "system", texto: `${PROMPT_DE_TESTE} (${agente})`, tools_pedidas: [], resposta_a: null },
      { papel: "user", texto: `Abriu o incidente ${incidente}. Faça a ${agente}.`, tools_pedidas: [], resposta_a: null },
      {
        papel: "assistant",
        texto: "",
        tools_pedidas: [{ id: pedido, nome: "obter_resumo", argumentos: `{"id":"${incidente}","limite":5}` }],
        resposta_a: null,
      },
      { papel: "tool", texto: `{"id":"${incidente}","estado":"aberto","janelas":40}`, tools_pedidas: [], resposta_a: pedido },
      { papel: "user", texto: AVISO_DE_TESTE, tools_pedidas: [], resposta_a: null },
      { papel: "assistant", texto: `Resposta final da ${agente} sobre ${incidente}.\nSegunda linha.`, tools_pedidas: [], resposta_a: null },
    ],
  };
}

/** O log com a conversa de cada agente antes da conclusão dele, e os ids de novo em sequência. */
export function comConversas(texto: string): string {
  const linhas = texto.split("\n").filter((linha) => linha.trim().length > 0).map((linha) => JSON.parse(linha) as Record<string, any>);
  const saida: Record<string, any>[] = [];
  let n = 0;
  for (const evento of linhas) {
    if (evento.tipo === "agente_concluido") {
      n += 1;
      saida.push({ id: "", instante: evento.instante, tipo: "conversa_do_agente", incidente: evento.incidente, dados: conversa(evento.dados.agente, evento.incidente, n) });
    }
    saida.push(evento);
  }
  return saida.map((evento, indice) => JSON.stringify({ ...evento, id: `ev-${String(indice + 1).padStart(6, "0")}` })).join("\n") + "\n";
}

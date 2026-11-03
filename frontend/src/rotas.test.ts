import { describe, expect, it } from "vitest";
import { ancoraDa, lerRota, type Rota, type Tela } from "./rotas";

describe("rota pela âncora", () => {
  it("âncora vazia ou desconhecida abre a visão geral", () => {
    expect(lerRota("")).toEqual({ tela: "visao-geral", incidente: null });
    expect(lerRota("#/nao-existe")).toEqual({ tela: "visao-geral", incidente: null });
  });

  it("o detalhe e o relatório levam o id do incidente; id malformado vira nulo", () => {
    expect(lerRota("#/incidentes/inc-0001")).toEqual({ tela: "incidente", incidente: "inc-0001" });
    expect(lerRota("#/relatorio/inc-0002")).toEqual({ tela: "relatorio", incidente: "inc-0002" });
    expect(lerRota("#/incidentes/<script>")).toEqual({ tela: "incidente", incidente: null });
    expect(lerRota("#/chat/inc-0001")).toEqual({ tela: "chat", incidente: null });
  });

  it("a conversa dos agentes é uma aba do detalhe, e só dele", () => {
    expect(lerRota("#/incidentes/inc-0001/conversa")).toEqual({ tela: "incidente", incidente: "inc-0001", aba: "conversa" });
    expect(lerRota("#/incidentes/inc-0001/outra")).toEqual({ tela: "incidente", incidente: "inc-0001" });
    expect(lerRota("#/relatorio/inc-0001/conversa")).toEqual({ tela: "relatorio", incidente: "inc-0001" });
    expect(ancoraDa({ tela: "incidente", incidente: "inc-0001", aba: "conversa" })).toBe("#/incidentes/inc-0001/conversa");
    expect(ancoraDa({ tela: "incidente", incidente: null, aba: "conversa" })).toBe("#/incidentes");
  });

  it("a âncora antiga #chat ainda abre o chat", () => {
    expect(lerRota("#chat").tela).toBe("chat");
  });

  it("toda tela volta da âncora que ela mesma gera", () => {
    const telas: Tela[] = ["rodada", "visao-geral", "incidente", "ao-vivo", "simulacao", "isolado-integrado", "custo-latencia", "qualidade", "chat", "relatorio", "componentes", "entrar"];
    for (const tela of telas) {
      const incidente = tela === "incidente" || tela === "relatorio" ? "inc-0001" : null;
      expect(lerRota(ancoraDa({ tela, incidente }))).toEqual({ tela, incidente });
    }
    const conversa: Rota = { tela: "incidente", incidente: "inc-0001", aba: "conversa" };
    expect(lerRota(ancoraDa(conversa))).toEqual(conversa);
    expect(ancoraDa({ tela: "rodada", incidente: null })).toBe("#/rodada-final");
  });
});

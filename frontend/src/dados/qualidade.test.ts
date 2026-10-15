import { describe, expect, it } from "vitest";
import csvDaMatriz from "../../../experimentos/resultados/matrizes_confusao/regerado_janela_100_ponto.csv?raw";
import csvDasMetricas from "../../../experimentos/resultados/regeracao_metricas.csv?raw";
import { CLASSES, MATRIZ, medir } from "./qualidade";

// A Tela 5 mostra uma cópia da matriz de confusão do experimento. Este teste falha quando o modelo
// é treinado de novo e a cópia fica para trás.

function linhasDoCsv(texto: string): string[][] {
  return texto.trim().split("\n").map((linha) => linha.trim().split(","));
}

describe("matriz da Tela 5", () => {
  it("é a do CSV do experimento, com as mesmas classes na mesma ordem", () => {
    const [cabecalho, ...corpo] = linhasDoCsv(csvDaMatriz);
    expect(cabecalho.slice(1)).toEqual(CLASSES);
    expect(corpo.map((linha) => linha[0])).toEqual(CLASSES);
    expect(corpo.map((linha) => linha.slice(1).map(Number))).toEqual(MATRIZ);
  });

  it("precisão, recall e F1 calculados da matriz batem com as métricas do ponto de operação", () => {
    const [cabecalho, ...corpo] = linhasDoCsv(csvDasMetricas);
    const coluna = (nome: string) => cabecalho.indexOf(nome);
    const doPonto = corpo.filter((linha) => linha[coluna("janela")] === "100" && linha[coluna("regra")] === "ponto");
    expect(doPonto).toHaveLength(CLASSES.length);
    const qualidade = medir(CLASSES, MATRIZ);
    for (const linha of doPonto) {
      const classe = qualidade.porClasse.find((item) => item.classe === linha[coluna("classe")])!;
      expect(classe.precisao).toBeCloseTo(Number(linha[coluna("precisao")]), 5);
      expect(classe.recall).toBeCloseTo(Number(linha[coluna("recall")]), 5);
      expect(classe.f1).toBeCloseTo(Number(linha[coluna("f1")]), 5);
      expect(classe.suporte).toBe(Number(linha[coluna("suporte")]));
    }
  });
});

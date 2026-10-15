import type { CategoriaDoModelo } from "../types";

// A matriz de confusão do modelo do sistema, para a Tela 5. É a do ponto de operação da
// configuração 5 (fundo da parte de treino dos pcaps de ataque como benigno, janela de 100 quadros,
// regra escolhida na validação: o argmax), no teste do corte por tempo, com a semente 42. Os números são os de
// `experimentos/resultados/matrizes_confusao/regerado_janela_100_ponto.csv`, e `qualidade.test.ts`
// confere se continuam iguais: quando o modelo for treinado de novo, o teste falha até esta cópia
// ser atualizada.

export const FONTE_DA_MATRIZ = "experimentos/resultados/matrizes_confusao/regerado_janela_100_ponto.csv";

export const CLASSES: CategoriaDoModelo[] = ["DDoS+DoS", "Mirai", "Recon", "Spoofing", "Web", "BruteForce", "Benign"];

/** `MATRIZ[real][previsto]`: janelas de teste, na ordem de `CLASSES`. */
export const MATRIZ: number[][] = [
  [210992, 5, 793, 4, 17, 0, 2562],
  [18, 24267, 60, 0, 3, 0, 110],
  [164, 0, 6031, 1, 19, 0, 4767],
  [28, 0, 7, 5613, 1, 0, 1358],
  [37, 0, 56, 1, 166, 0, 205],
  [39, 0, 72, 0, 5, 95, 62],
  [56, 0, 56, 0, 37, 1, 15858],
];

export interface MetricasDaClasse {
  classe: CategoriaDoModelo;
  precisao: number;
  recall: number;
  f1: number;
  suporte: number;
}

export interface Qualidade {
  total: number;
  acuracia: number;
  f1Macro: number;
  /** Janelas benignas que o modelo pôs em alguma categoria de ataque. */
  benignoComoAtaque: number;
  porClasse: MetricasDaClasse[];
}

export function medir(classes: CategoriaDoModelo[], matriz: number[][]): Qualidade {
  const total = matriz.flat().reduce((soma, valor) => soma + valor, 0);
  const acertos = matriz.reduce((soma, linha, i) => soma + linha[i], 0);
  const porClasse = classes.map((classe, i) => {
    const suporte = matriz[i].reduce((soma, valor) => soma + valor, 0);
    const previstas = matriz.reduce((soma, linha) => soma + linha[i], 0);
    const precisao = previstas > 0 ? matriz[i][i] / previstas : 0;
    const recall = suporte > 0 ? matriz[i][i] / suporte : 0;
    const f1 = precisao + recall > 0 ? (2 * precisao * recall) / (precisao + recall) : 0;
    return { classe, precisao, recall, f1, suporte };
  });
  const benigno = classes.indexOf("Benign");
  const linhaBenigna = matriz[benigno];
  const benignas = linhaBenigna.reduce((soma, valor) => soma + valor, 0);
  return {
    total,
    acuracia: total > 0 ? acertos / total : 0,
    f1Macro: porClasse.reduce((soma, classe) => soma + classe.f1, 0) / classes.length,
    benignoComoAtaque: benignas > 0 ? (benignas - linhaBenigna[benigno]) / benignas : 0,
    porClasse,
  };
}

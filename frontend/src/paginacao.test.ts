import { describe, expect, it } from "vitest";
import { alturaDoTrecho, paginar, paginarSemMedida, type SecaoMedida } from "./paginacao";

// A divisão do relatório em páginas, com alturas inventadas: o navegador mede de verdade, e aqui
// só se confere onde cada página quebra.

/** Uma seção com cabeçalho de `cabeca` pixels e peças das alturas dadas, separadas por `entre`. */
function secao(cabeca: number, alturas: number[], entre = 0): SecaoMedida {
  const pecas: SecaoMedida["pecas"] = [];
  let topo = cabeca;
  for (const altura of alturas) {
    pecas.push({ topo, fundo: topo + altura });
    topo += altura + entre;
  }
  return { altura: topo - entre, pecas };
}

describe("altura de um trecho", () => {
  const medida = secao(40, [100, 200, 300], 10);

  it("a seção inteira tem a altura medida", () => {
    expect(alturaDoTrecho(medida, 0, 3)).toBe(40 + 100 + 10 + 200 + 10 + 300);
  });

  it("um trecho do meio leva o cabeçalho e só as peças dele", () => {
    expect(alturaDoTrecho(medida, 1, 2)).toBe(40 + 200);
    expect(alturaDoTrecho(medida, 1, 3)).toBe(40 + 200 + 10 + 300);
    expect(alturaDoTrecho(medida, 0, 1)).toBe(40 + 100);
  });
});

describe("paginar", () => {
  it("seções que cabem juntas ficam na mesma página, com o intervalo entre elas", () => {
    expect(paginar([secao(20, [100]), secao(20, [100])], 300, 40)).toEqual([
      [
        { secao: 0, de: 0, ate: 1 },
        { secao: 1, de: 0, ate: 1 },
      ],
    ]);
    // O intervalo conta: 120 + 40 + 120 passa de 270.
    expect(paginar([secao(20, [100]), secao(20, [100])], 270, 40)).toHaveLength(2);
  });

  it("a seção que não cabe no resto da página, mas cabe numa página nova, vai inteira para a seguinte", () => {
    expect(paginar([secao(20, [300]), secao(20, [100, 100])], 400, 20)).toEqual([[{ secao: 0, de: 0, ate: 1 }], [{ secao: 1, de: 0, ate: 2 }]]);
  });

  it("a seção maior que uma página se divide entre as peças, e o resto continua na seguinte", () => {
    const paginas = paginar([secao(20, [100]), secao(20, [150, 150, 150, 150])], 400, 20);
    expect(paginas).toEqual([
      [
        { secao: 0, de: 0, ate: 1 },
        { secao: 1, de: 0, ate: 1 },
      ],
      [{ secao: 1, de: 1, ate: 3 }],
      [{ secao: 1, de: 3, ate: 4 }],
    ]);
  });

  it("não deixa o cabeçalho sozinho no pé da página: sem nenhuma peça que caiba, a seção começa na seguinte", () => {
    const paginas = paginar([secao(20, [350]), secao(20, [300, 300])], 400, 20);
    expect(paginas[0]).toEqual([{ secao: 0, de: 0, ate: 1 }]);
    expect(paginas[1][0]).toEqual({ secao: 1, de: 0, ate: 1 });
  });

  it("uma peça mais alta que a página fica sozinha numa página, e as outras seguem", () => {
    expect(paginar([secao(20, [100]), secao(20, [900, 100])], 400, 20)).toEqual([
      [{ secao: 0, de: 0, ate: 1 }],
      [{ secao: 1, de: 0, ate: 1 }],
      [{ secao: 1, de: 1, ate: 2 }],
    ]);
  });

  it("toda peça entra uma vez, na ordem", () => {
    const secoes = [secao(30, [80, 400, 30]), secao(30, [500]), secao(30, [60, 60, 60, 700, 60]), secao(30, [20])];
    const paginas = paginar(secoes, 800, 32);
    const vistas = paginas.flat().flatMap(({ secao: indice, de, ate }) => Array.from({ length: ate - de }, (_, i) => `${indice}:${de + i}`));
    expect(vistas).toEqual(secoes.flatMap((item, indice) => item.pecas.map((_, i) => `${indice}:${i}`)));
    for (const pagina of paginas) {
      const usada = pagina.reduce((soma, trecho, i) => soma + (i > 0 ? 32 : 0) + alturaDoTrecho(secoes[trecho.secao], trecho.de, trecho.ate), 0);
      expect(usada).toBeLessThanOrEqual(800);
    }
  });
});

describe("plano sem medida", () => {
  it("abre uma página em cada seção marcada, e as outras vão inteiras na anterior", () => {
    const secoes = [{ pecas: [1] }, { pecas: [1, 2] }, { pecas: [1], novaPagina: true }, { pecas: [1, 2, 3], novaPagina: true }, { pecas: [1] }];
    expect(paginarSemMedida(secoes)).toEqual([
      [
        { secao: 0, de: 0, ate: 1 },
        { secao: 1, de: 0, ate: 2 },
      ],
      [{ secao: 2, de: 0, ate: 1 }],
      [
        { secao: 3, de: 0, ate: 3 },
        { secao: 4, de: 0, ate: 1 },
      ],
    ]);
  });
});

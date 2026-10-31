// A divisão do relatório em páginas A4. Cada seção é uma lista de peças (um parágrafo, uma tabela,
// uma citação do agente) que não se cortam: a seção que não cabe numa página continua na seguinte, a
// partir da peça que não coube. As alturas vêm do navegador, que mede as seções numa página
// escondida (`telas/Relatorio.tsx`); aqui só se decide onde cada página quebra.

/** Uma seção medida: a altura inteira e onde cada peça começa e termina, contado do topo da seção. */
export interface SecaoMedida {
  altura: number;
  pecas: { topo: number; fundo: number }[];
}

/** As peças de `de` até `ate` (sem incluir `ate`) da seção de índice `secao`, numa mesma página. */
export interface Trecho {
  secao: number;
  de: number;
  ate: number;
}

/** A altura da seção desenhada só com as peças de `de` até `ate`: o cabeçalho e as bordas continuam. */
export function alturaDoTrecho(secao: SecaoMedida, de: number, ate: number): number {
  const { pecas } = secao;
  return secao.altura - (pecas[de].topo - pecas[0].topo) - (pecas[pecas.length - 1].fundo - pecas[ate - 1].fundo);
}

/**
 * Distribui as seções, na ordem, em páginas com `altura` de espaço útil e `intervalo` entre duas
 * seções da mesma página. A seção que não cabe no resto da página, mas cabe numa página nova,
 * começa na seguinte; a maior que uma página se divide entre as peças, e o resto continua na
 * página seguinte. Uma peça mais alta que a página inteira fica sozinha numa página.
 */
export function paginar(secoes: SecaoMedida[], altura: number, intervalo: number): Trecho[][] {
  const paginas: Trecho[][] = [];
  let pagina: Trecho[] = [];
  let usada = 0;
  const virar = () => {
    paginas.push(pagina);
    pagina = [];
    usada = 0;
  };
  secoes.forEach((secao, indice) => {
    const total = secao.pecas.length;
    let de = 0;
    while (de < total) {
      const antes = pagina.length > 0 ? intervalo : 0;
      let ate = de;
      while (ate < total && alturaDoTrecho(secao, de, ate + 1) <= altura - usada - antes) {
        ate += 1;
      }
      // Não coube inteira: numa página já começada, vai para a seguinte se lá couber inteira, ou
      // se nem a primeira peça coube aqui.
      if (ate < total && pagina.length > 0 && (ate === de || alturaDoTrecho(secao, de, total) <= altura)) {
        virar();
        continue;
      }
      ate = Math.max(ate, de + 1);
      pagina.push({ secao: indice, de, ate });
      usada += antes + alturaDoTrecho(secao, de, ate);
      de = ate;
      if (de < total) {
        virar();
      }
    }
  });
  if (pagina.length > 0) {
    paginas.push(pagina);
  }
  return paginas;
}

/**
 * O plano de antes da medida, e o do Node, onde não há medida: cada seção marcada com `novaPagina`
 * abre uma página, e as outras vão inteiras na página da anterior.
 */
export function paginarSemMedida(secoes: { pecas: unknown[]; novaPagina?: boolean }[]): Trecho[][] {
  const paginas: Trecho[][] = [];
  secoes.forEach((secao, indice) => {
    const trecho = { secao: indice, de: 0, ate: secao.pecas.length };
    if (secao.novaPagina || paginas.length === 0) {
      paginas.push([trecho]);
    } else {
      paginas[paginas.length - 1].push(trecho);
    }
  });
  return paginas;
}

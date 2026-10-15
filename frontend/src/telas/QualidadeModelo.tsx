import { CategoryBadge, CategoryBars, ConfusionMatrix, MetricCard, PageHeader, Panel, fmtInt, fmtNum, fmtPct } from "../design-system";
import { CLASSES, FONTE_DA_MATRIZ, MATRIZ, medir } from "../dados/qualidade";

/** Tela 5: a qualidade do classificador no teste, com a matriz de confusão do ponto de operação. */
export function TelaQualidadeModelo() {
  const qualidade = medir(CLASSES, MATRIZ);
  return (
    <>
      <PageHeader
        eyebrow="Telas do artigo · Tela 5"
        title="Qualidade do modelo"
        meta={
          <span className="body-sm sx-muted">
            Random Forest · 7 classes · configuração 5 · janela de 100 quadros · ponto de operação (argmax) · teste do corte por tempo · semente 42. As tabelas do artigo
            trazem a média das sementes 42, 1 e 2.
          </span>
        }
      />
      <div className="sx-grid">
        <MetricCard className="sx-span-4" label="Acurácia" value={fmtPct(qualidade.acuracia, 1)} icon="target" context={`${fmtInt(qualidade.total)} janelas de teste`} />
        <MetricCard className="sx-span-4" label="F1 macro" value={fmtPct(qualidade.f1Macro, 1)} icon="sigma" context="média simples das 7 classes" />
        <MetricCard
          className="sx-span-4"
          label="Benigno como ataque"
          value={fmtPct(qualidade.benignoComoAtaque, 2)}
          icon="bell"
          context="janelas benignas postas em alguma categoria de ataque, nesta matriz"
        />
        <Panel className="sx-span-12" eyebrow="Matriz de confusão" title="Real × previsto" footer={<span className="data-sm">Fonte: {FONTE_DA_MATRIZ}</span>}>
          <ConfusionMatrix labels={CLASSES} matrix={MATRIZ} />
        </Panel>
        <Panel className="sx-span-6" eyebrow="Por classe" title="Precisão, recall e F1" flush>
          <div className="sx-tablewrap">
            <table className="sx-table">
              <thead>
                <tr>
                  <th scope="col">Classe</th>
                  <th scope="col" className="is-num">Precisão</th>
                  <th scope="col" className="is-num">Recall</th>
                  <th scope="col" className="is-num">F1</th>
                </tr>
              </thead>
              <tbody>
                {qualidade.porClasse.map((classe) => (
                  <tr key={classe.classe}>
                    <td><CategoryBadge category={classe.classe} model size="sm" /></td>
                    <td className="is-num data">{fmtNum(classe.precisao * 100, 1)}%</td>
                    <td className="is-num data">{fmtNum(classe.recall * 100, 1)}%</td>
                    <td className="is-num data">{fmtNum(classe.f1 * 100, 1)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
        <Panel className="sx-span-6" eyebrow="Conjunto de teste" title="Janelas por classe">
          <CategoryBars ariaLabel="Janelas de teste por classe" showShare data={qualidade.porClasse.map((classe) => ({ category: classe.classe, value: classe.suporte }))} />
        </Panel>
      </div>
    </>
  );
}

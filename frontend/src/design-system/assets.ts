// As imagens da marca, empacotadas pelo Vite (nada vem de CDN: a banca roda sem internet).
import mark from "./logos/sentryiot-mark.png";
import mark512 from "./logos/sentryiot-mark-512.png";
import mark128 from "./logos/sentryiot-mark-128.png";
import mark64 from "./logos/sentryiot-mark-64.png";

export const ASSETS = {
  /** 739 px, fundo transparente: login e capa do relatório (GlassBackdrop), Logo xl. */
  mark,
  /** 512 px, transparente: telas grandes. */
  mark512,
  /** 128 px, transparente, com o vidro reforçado para tamanhos pequenos: barra lateral e cabeçalhos. */
  mark128,
  /** 64 px: favicon e Logo sm. */
  mark64,
};

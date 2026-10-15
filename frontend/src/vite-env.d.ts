/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Backend do chat no desenvolvimento (ver vite.config.ts). */
  readonly VITE_API_URL?: string;
  /** Modelos que rodam na máquina, separados por vírgula (ex.: "llama3.1:8b,qwen2.5:7b"). */
  readonly VITE_MODELOS_LOCAIS?: string;
  /** Modelos que rodam fora da máquina, separados por vírgula. Um modelo fora das duas listas fica sem lugar na tela. */
  readonly VITE_MODELOS_NA_NUVEM?: string;
  /** Endereço de um log que está sendo gravado, lido de tempos em tempos pela tela Ao vivo. Vazio: a tela fica como planejada. */
  readonly VITE_LOG_AO_VIVO?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

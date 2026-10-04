# Base local de conhecimento

**Aviso: os documentos desta pasta são conteúdo provisório do stub.** Eles existem para que
`consultar_mitigacoes` e `pesquisar_solucoes` tenham o que devolver enquanto o levantamento de
mitigações da equipe não fica pronto. Trazem medidas genéricas e conhecidas, escritas sem
consulta a fonte, e por isso não citam referência nenhuma. Não devem ser usados no artigo nem
tratados como resultado do trabalho.

Esta pasta será substituída pelo levantamento de mitigações por categoria feito pela equipe,
com as referências de cada medida.

## Formato de um documento

Um arquivo `.md` por tipo de ataque, mais material de referência. Este `README.md` não faz parte
da base.

```
# Título do documento

Categorias: DDoS, DoS

## Título da medida

Ação do catálogo: bloquear_ip

Texto da medida, em um ou mais parágrafos.
```

- `Categorias:` usa os nomes das 8 categorias do classificador. Documento sem essa linha é
  material de referência e só aparece em `pesquisar_solucoes`.
- `Ação do catálogo:` liga a medida a uma das ações de base (`limitar_taxa`, `bloquear_ip`,
  `isolar_dispositivo`, `revogar_credencial`). As medidas com essa linha são as que
  `consultar_mitigacoes` devolve para a categoria. As demais só são encontradas pela pesquisa, e
  o agente de decisão pode propô-las como ação nova.

A leitura e a busca estão em `codigo/mcp/base.py`. Documento fora do formato faz o stub parar
na partida, com o nome do arquivo e o motivo.

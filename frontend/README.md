# Interface web do SentryIoT

Esta pasta vai abrigar a interface web do sistema, em React e TypeScript. Ainda não há código
aqui: o que existe é o plano das telas e a forma como a interface se liga ao backend, para que o
backend já nasça gravando o que ela vai precisar.

## Como a interface se liga ao backend

O backend grava um log de eventos com formato fixo. Cada passo relevante vira uma linha: janela
classificada, incidente aberto, tool chamada, recomendação emitida, ação aprovada, rejeitada ou
desfeita. A interface não fala com o classificador nem com os agentes. Ela só lê esse log, por
uma API fina.

Isso dá dois modos com o mesmo código:

- **Ao vivo:** a interface acompanha o log enquanto o sistema roda.
- **Replay:** a interface reproduz uma execução gravada. É o modo que protege a demonstração na
  banca, porque não depende de internet nem de a LLM responder na hora.

O formato do log é definido junto com o contrato da tool MCP, em `codigo/mcp/`.

## Telas, em ordem de valor

1. **Fila de incidentes.** Mostra os alertas já agrupados pela política de acionamento, não um
   por janela, com o contador de janelas, incidentes e chamadas à LLM (por exemplo, 12.000
   janelas, 1 incidente, 1 chamada). É a resposta visual à pergunta da banca sobre custo de
   tokens e Denial of Wallet.
2. **Detalhe do incidente.** Três blocos lado a lado: o veredito do Random Forest, com a
   confiança e as features que mais pesaram; o rastro dos agentes, com cada chamada de tool MCP;
   e a recomendação em linguagem natural, com os botões de aprovar, rejeitar e desfazer, que são
   a parte de resposta do NIDR.
3. **Isolado e integrado.** O mesmo incidente com a saída crua do classificador de um lado e a
   saída com agentes do outro. Essa comparação é uma tarefa da PoC e vira figura do artigo.
4. **Custo e latência.** Tokens, tempo de resposta e custo por incidente, com a comparação entre
   modelo em nuvem e modelo local.
5. **Qualidade do modelo.** Matriz de confusão, recall por classe e taxa de falso positivo,
   lidos de `experimentos/resultados/`.
6. **Segurança do MCP.** O resultado do teste de tool poisoning: o que foi injetado e se o
   agente caiu.

## Ordem de construção

A interface vem depois que o backend da PoC estiver gravando o log. A versão mínima útil são as
duas primeiras telas, em modo replay. As demais entram conforme os experimentos produzirem os
dados que elas mostram.

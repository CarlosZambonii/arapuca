# Arapuca

> Em construção. A documentação completa, o diagrama de arquitetura e os prints dos dashboards
> chegam na fase 10. Veja o [PLAN.md](PLAN.md) para a arquitetura e o roteiro de fases.

Arapuca é um honeypot SSH e HTTP de média interação escrito em C++20. Ele registra o
comportamento do atacante, enriquece cada evento com GeoIP e contexto MITRE ATT&CK, captura os
payloads baixados numa quarentena protegida por senha, e envia eventos JSON estruturados para
o New Relic, onde os dashboards e alertas são provisionados como código.

**Ele nunca executa nada que o atacante envia.** Toda resposta do shell é simulada, e o CI
quebra o build se qualquer primitiva de execução de processo aparecer no código fonte.

## Começando

```bash
# Dependências, veja docs/DEPENDENCIES.md
sudo apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build pkg-config \
    libssl-dev libcurl4-openssl-dev \
    libssh-dev libyaml-cpp-dev libmaxminddb-dev libminizip-dev

cmake --preset dev
cmake --build --preset dev
ctest --preset dev
```

## Plataforma suportada

Ubuntu 24.04 LTS (noble) em x86_64 e arm64, com libssh 0.10.6. Essa é a única base suportada,
no CI, no container e na VPS.

## Aviso legal e ético

A Arapuca registra apenas o que é enviado voluntariamente por quem se conecta a ela. Rode numa
infraestrutura que seja sua, entenda a legislação local antes de publicar os dados coletados, e
nunca use isso para atacar ninguém. O feed de IoCs publica endereços de origem e hashes de
arquivos para uso defensivo.

## Licença

MIT, veja [LICENSE](LICENSE).

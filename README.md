# CPA Attack — Correlation Power Analysis contra AES

Este script quebra uma chave AES de 16 bytes explorando o consumo de energia
("power trace") vazado por um servidor durante a cifragem. A técnica usada
se chama **CPA (Correlation Power Analysis)** e é um ataque de canal lateral
(*side-channel attack*) real, usado inclusive contra hardware físico (smart
cards, microcontroladores etc).

---

## 1. A ideia por trás do ataque

### O que o servidor faz

O servidor recebe um texto simples (*plaintext*) de 16 bytes, cifra com uma
chave AES secreta, e devolve uma **trace**: uma lista de números que
representa o consumo de energia da CPU ao longo da execução.

### Por que isso vaza a chave

Dentro do AES, logo no início, cada byte do plaintext passa por esta operação:

```
saida = Sbox[plaintext_byte XOR chave_byte]
```

O consumo de energia de um circuito digital está relacionado ao **número de
bits "1"** que ele processa (chamado de **peso de Hamming**, ou *Hamming
weight*). Quanto mais bits "1" circulam por um barramento, mais corrente
elétrica é consumida.

Então: se eu soubesse o `plaintext_byte` (eu escolho!) e tivesse uma hipótese
para o `chave_byte`, eu poderia **calcular o peso de Hamming esperado** da
saída do S-box, e comparar esse valor com o consumo de energia **real**
medido pelo servidor.

- Se a hipótese de chave estiver **certa**, o peso de Hamming calculado vai
  variar **junto** com o consumo de energia real, ao longo de várias
  medições diferentes → alta correlação estatística.
- Se a hipótese estiver **errada**, os valores não têm relação nenhuma →
  correlação próxima de zero.

Repetindo esse teste para as 256 chaves possíveis de cada um dos 16 bytes,
a chave certa se destaca das outras 255 por ter uma correlação muito mais
alta em algum ponto específico da trace (o ponto onde aquele S-box
realmente é calculado).

### Por que precisa de muitas traces

Com poucas amostras, a correlação pode parecer alta **por acaso** (um
problema estatístico chamado *overfitting*: com poucos dados e muitas
hipóteses testadas, sempre aparece algum "vencedor" aleatório). Por isso o
script foi desenhado para **acumular** centenas de traces antes de confiar
no resultado — quanto mais traces, mais a correlação da chave certa se
separa do ruído das chaves erradas.

---

## 2. Estrutura do código

### Constantes

```python
HOST = "xebec.cylabacademy.net"
PORT = 10376
OUT_FILE = "traces.npz"
```
Endereço do servidor-alvo e o arquivo onde as traces coletadas ficam salvas
em disco (formato comprimido do numpy).

```python
Sbox = (0x63, 0x7C, ...)
```
A **S-box do AES**: uma tabela de substituição fixa, pública, usada por
qualquer implementação de AES. Não é segredo — é parte do algoritmo.

```python
HW = [bin(x).count("1") for x in range(256)]
```
Tabela pré-calculada do **peso de Hamming** de cada valor de 0 a 255. Por
exemplo, `HW[7] = 3` porque `7 = 0b111` tem três bits "1". Isso evita
recalcular `bin(x).count("1")` repetidamente durante a análise.

---

### Coleta de traces

#### `query(hex_pt, timeout=15, retries=5)`

Função que faz **uma consulta ao servidor**: conecta, manda o plaintext em
hexadecimal e lê a trace de volta.

- Tenta até 5 vezes (`retries`) se a conexão falhar, com uma pausa que
  cresce a cada tentativa (`time.sleep(0.3 * (attempt + 1))`). Isso existe
  porque o servidor se mostrou instável sob muitas conexões simultâneas.

#### `_query_once(hex_pt, timeout)`

A conexão de fato, em três passos:

1. Abre um socket TCP e espera o prompt do servidor (lê byte a byte até
   encontrar `:`, que é o fim de "Please provide 16 bytes...:").
2. Envia o plaintext em hex seguido de quebra de linha.
3. Lê a resposta byte a byte, **contando colchetes abertos e fechados**
   (`depth`) até ter certeza de que capturou a lista inteira
   (`[86, 74, 67, ...]`), mesmo que ela seja muito longa.
4. Usa `ast.literal_eval` para transformar o texto `"[86, 74, ...]"` em uma
   lista Python de verdade, com segurança (ao contrário de `eval`, que
   executaria qualquer código).

#### `worker(target_total, stop_flag)`

Roda em uma thread separada, coletando traces em loop até atingir o total
desejado (`target_total`) ou até ser mandado parar (`stop_flag`).

- A cada erro, aumenta a pausa antes de tentar de novo (`consecutive_fails`),
  para não insistir agressivamente contra um servidor que já está recusando
  conexões.
- Depois de cada sucesso, espera `0.15s` antes da próxima consulta — um
  limite de velocidade "educado" para não sobrecarregar o servidor.
- Usa um `lock` (trava de concorrência) para proteger a lista compartilhada
  `results`, já que várias threads podem escrever nela ao mesmo tempo.

#### `save_results()`

Salva as traces coletadas em `traces.npz`. Pontos importantes:

- Corta todas as traces no mesmo tamanho (`min_len`), caso alguma venha
  ligeiramente diferente em comprimento.
- Se já existir um `traces.npz` de uma execução anterior, **soma** as
  traces novas às antigas, em vez de sobrescrever — isso permite rodar o
  comando `collect` várias vezes e ir acumulando dados aos poucos.

#### `collect(n, n_threads=1)`

Orquestra a coleta: cria `n_threads` threads, cada uma rodando `worker`,
espera todas terminarem (ou trata `Ctrl+C` para parar e salvar o que já foi
coletado), e por fim chama `save_results()`.

---

### Análise estatística (CPA)

#### `correlate(hyp, trace_matrix)`

O coração matemático do ataque: calcula a **correlação de Pearson** entre
um vetor de hipóteses (`hyp`, um valor por trace) e **cada coluna** de uma
matriz de traces (`trace_matrix`, forma `N traces × T pontos`).

```python
hyp = hyp - hyp.mean()                      # centraliza a hipótese
tm = trace_matrix - trace_matrix.mean(axis=0, keepdims=True)  # centraliza cada ponto da trace
num = hyp @ tm                              # covariância (produto escalar)
den = sqrt(soma(hyp²) * soma(tm², por coluna))  # normalização
return num / den                            # correlação por ponto
```

Isso é a fórmula padrão de correlação de Pearson, mas calculada de uma vez
só para **todos os pontos da trace simultaneamente**, usando operações
vetorizadas do numpy (muito mais rápido do que um loop em Python puro).

O resultado é um vetor com um valor de correlação para cada um dos milhares
de pontos da trace — e o script pega o maior valor absoluto
(`np.max(np.abs(corr))`) entre eles.

#### `analyze()`

A função principal da análise:

1. Carrega as traces e plaintexts salvos em `traces.npz`.
2. Para cada um dos **16 bytes** da chave:
   - Para cada uma das **256 chaves possíveis** (`k` de 0 a 255):
     - Calcula `Sbox[plaintext_byte XOR k]` para cada trace coletada.
     - Converte esse valor em peso de Hamming (`HW[...]`), formando o
       vetor de hipótese.
     - Chama `correlate()` para ver o quanto essa hipótese combina com as
       traces reais.
   - Guarda a chave `k` que deu a **maior correlação** (em qualquer ponto
     da trace) como o valor mais provável daquele byte.
3. Junta os 16 bytes encontrados na chave final, em hexadecimal.
4. Monta e imprime a flag no formato `academy{<chave>}`.

---

### Linha de comando (`__main__`)

```bash
python3 cpa_attack.py collect 300              # só coleta
python3 cpa_attack.py analyze                  # só analisa o que já foi salvo
python3 cpa_attack.py collect_and_analyze 300  # os dois em sequência
```

O script lê `sys.argv` para decidir qual dessas três ações executar, e usa
o segundo argumento (quando presente) como o número de traces a coletar.

---

## 3. Por que esse design específico

| Decisão de design | Motivo |
|---|---|
| Coleta sequencial (1 thread por padrão) | O servidor se mostrou instável com muitas conexões simultâneas (`Connection refused`/`reset`) |
| Retry com backoff crescente | Evita martelar o servidor quando ele já está recusando conexões |
| Acúmulo de traces em disco | O ataque de CPA melhora com mais dados; permite rodar a coleta em várias sessões sem perder progresso |
| Correlação vetorizada com numpy | Testar 256 chaves × 16 bytes × milhares de pontos de trace seria lento demais em Python puro |
| `ast.literal_eval` em vez de `eval` | Converte texto em lista Python com segurança, sem risco de executar código arbitrário vindo do servidor |

---

## 4. Limitações e cuidados

- **Confiabilidade da chave encontrada**: com poucas traces (dezenas), a
  correlação pode parecer artificialmente alta por coincidência estatística.
  O ideal é ter pelo menos uma centena de traces, e verificar se o
  resultado se mantém estável ao adicionar mais dados.
- **Tamanho da trace**: o script assume que todas as traces têm
  (aproximadamente) o mesmo comprimento, e corta no menor tamanho comum.
  Se o servidor variar muito o tamanho da trace entre execuções, isso pode
  descartar informação útil.
- **Apenas o primeiro round**: o ataque mira a operação `Sbox[pt ^ key]`
  que acontece logo no início do AES (round 0), que é onde o plaintext é
  combinado diretamente com a chave original — os rounds seguintes
  dependem de uma chave "expandida" diferente, mais difícil de atacar
  diretamente dessa forma.

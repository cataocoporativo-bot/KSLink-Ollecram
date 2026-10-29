# KSLink 2.0

**Atualizado em:** quinta-feira, 22/10/2026 — 18:05 (America/Sao_Paulo)

Chat em grupo P2P com criptografia ponta a ponta. O servidor só faz a **sinalização** (troca de convites automática) e nunca vê mensagens, arquivos nem chaves de sessão.

## O que mudou na 2.0

| Recurso | 1.0.2 | 2.0 |
|---|---|---|
| Troca de convites | copiar/colar manual | automática via servidor de sinalização (WebSocket) |
| Identidade | chave nova a cada sessão | ECDSA P-256 persistente (localStorage) + backup cifrado por senha |
| Participantes | 2 | até 8 (malha completa, E2EE par a par) |
| Sala | — | link `#r=xxxx-xxxx-xxxx` |
| Respostas | — | botão ↩ em cada mensagem cita o texto original (clique na citação para ir até ela) |
| Som | — | aviso sonoro ao receber mensagem ou arquivo; botão 🔔/🔕 no topo do chat |
| Apagar | — | botão 🗑 nas suas mensagens apaga para todos (aparece "Mensagem apagada"); só o autor pode apagar |

## Rodar localmente

```bash
npm install
npm start          # http://localhost:10000
npm test           # testes de cripto e servidor
npm run test:e2e   # 3 navegadores reais (precisa do playwright)
```

Abra o endereço em 3 navegadores/perfis, crie uma sala no primeiro e entre pelo link nos outros. Para testar em celular na mesma rede, use HTTPS (WebCrypto exige contexto seguro; `localhost` é exceção).

## Deploy (Render)

1. Suba esta pasta para um repositório Git.
2. No Render: **New → Blueprint** (usa `render.yaml`) ou **Web Service → Docker**.
3. Health check: `/healthz`. Defina `TRUST_PROXY=1`.
4. Abra a URL `https://…onrender.com`. O cliente usa `wss://` automaticamente.

No plano gratuito o serviço hiberna sem tráfego; o cliente envia um ping a cada ~4 min enquanto está em uma sala. A primeira conexão após hibernar pode demorar.

Qualquer host com Docker ou Node ≥ 20 e suporte a WebSocket serve. Netlify/Vercel estáticos **não** hospedam o servidor; se quiser o site lá, informe o endereço do servidor em *Identidade e servidor*.

## Variáveis de ambiente

| Variável | Padrão | Descrição |
|---|---|---|
| `PORT` / `HOST` | 10000 / 0.0.0.0 | endereço de escuta |
| `MAX_PEERS` | 8 | participantes por sala |
| `MAX_ROOMS` / `MAX_CONNECTIONS` | ver código | limites globais |
| `MAX_CONN_PER_IP` | 30 | conexões por IP |
| `TRUST_PROXY` | 0 | `1` atrás de proxy (Render) para ler o IP real |
| `ALLOWED_ORIGINS` | mesma origem | lista separada por vírgula de origens permitidas |
| `ICE_SERVERS` | STUN do Google | JSON; adicione TURN aqui |

## Modelo de segurança

- Cada par de participantes faz um handshake assinado com a identidade de longo prazo, vinculado aos fingerprints DTLS (detecta servidor/rede alterando o SDP), e deriva uma chave AES-GCM própria (ECDH efêmero + HKDF).
- O servidor vê: sala, identificadores de sessão, chave pública, nome e SDP/ICE. Não vê conteúdo.
- **Verifique as impressões digitais** por outro canal (botão ○ → ✔ ao lado de cada participante). Sem isso, quem tiver o link entra na sala.
- CSP estrita, sem scripts inline, limites de taxa e de tamanho, checagem de origem, nada de log de conteúdo/IP.

## Limites conhecidos

- Sem histórico para quem entra depois; nada é guardado no servidor.
- Malha: arquivos são enviados uma vez por destinatário. Máx. 8 pessoas e 100 MB por arquivo.
- Sem TURN: redes com NAT simétrico/firewalls restritos podem não conectar. Configure `ICE_SERVERS` com TURN.
- Limpar os dados do navegador apaga a identidade; use o backup cifrado. O Safari pode apagar dados após ~7 dias sem uso.

## Apps desktop e móvel

Os dois abrem o seu servidor (mesma origem do cliente web), então tudo funciona igual ao navegador.

| Pasta | O quê | Como |
|---|---|---|
| `desktop/` | Electron 31 (Windows/macOS/Linux) | `cd desktop && npm install && npm start`; instaladores: `npm run build:win` / `build:mac` / `build:linux` |
| `mobile/` | Expo Go (SDK 51, WebView) | `cd mobile && npm install && npx expo install --fix && npx expo start` |

- **Endereço do servidor:** na primeira abertura os dois pedem a URL e guardam. Para já vir preenchida: `desktop/config.json` (`serverUrl`) e `mobile/app.json` (`extra.serverUrl`). No desktop, `Ctrl+Shift+S` troca o servidor; no celular, toque em `host ⚙`. O desktop também aceita a variável `KSLINK_SERVER`.
- `http://` só é aceito para localhost/rede local; fora disso, apenas HTTPS.
- **Desktop:** instância única, navegação travada na origem do servidor, permissões negadas (exceto copiar), ícones prontos em `desktop/assets/` (`.ico` multi-tamanho até 256×256, `.icns`, `.png`).
- **Móvel:** WebViews não baixam `blob:`; o botão vira **Salvar** e abre o menu de compartilhar (limite de 30 MB no app).
- Nome do produto e identificadores passaram a ser KSLink (`com.kslink.app`).

## Identidade visual

Tema cyberpunk (neon ciano/magenta/violeta, grade e linhas de varredura, cantos chanfrados) com o logotipo da
Klaatu Systems, pensado para fundo preto. Fontes locais: Orbitron (títulos) e Rajdhani (interface), mais Space Mono
nos códigos. Logotipos em `public/klaatu-logo.png` e `public/klaatu-mark.png`; ícones em `public/icon*.png`,
`desktop/assets/` e `mobile/assets/`. No app móvel as fontes são as do sistema (carregar fontes no Expo exige `expo-font`).

## Identidade visual configurável (brand.json)

A aparência da interface (cores, fontes, estilo e logotipos) vem do arquivo `brand.json`. O nome do app não muda.

1. Coloque os logotipos (PNG) e, se a marca usar fonte própria, os arquivos `.woff2` em `public/` e `public/fonts/`.
2. Edite `brand.json` (modelo em `brands/klaatu.json`):
   - `style`: `cyberpunk` (grade, neon, cantos chanfrados) ou `corporate` (limpo, cantos arredondados, sem efeitos).
   - `colors`: todas em `#RRGGBB`. `onAccent` é a cor do texto sobre a cor de destaque (`accent`).
   - `fonts`: `ui`, `display`, `mono` (pilhas CSS) e `faces` (arquivos `.woff2` em `public/fonts`). As fontes precisam ser locais por causa da política de segurança (CSP).
   - `logos`: `header` (com `label` opcional, ex. "by"), `foot` e `empty`. Use `null` para ocultar um deles.
3. Rode `npm run brand`. Ele gera `public/brand.css` e `public/index.html`. Não edite esses dois à mão; para mudar o HTML, edite `tools/index.template.html`.
4. Faça commit de `brand.json`, `public/brand.css` e `public/index.html`.

Os ícones do app (`public/icon*.png`, `desktop/assets`, `mobile/assets`) continuam sendo trocados à parte.

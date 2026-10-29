# KSLink Mobile 2.0 (Expo Go)

Atualizado em: quinta-feira, 22/10/2026

O app abre o seu servidor KSLink dentro de um WebView. Cliente e servidor ficam na mesma origem, então
sinalização, identidade persistente e grupos funcionam como no navegador.

## Rodar

```bash
npm install
npx expo install --fix     # alinha as versões nativas ao SDK do seu Expo Go
npx expo start
```

Leia o QR code com o Expo Go (Android) ou a câmera (iOS).

## Servidor

- Na primeira abertura o app pede o endereço (ex.: `https://kslink.onrender.com`). Ele fica salvo;
  para trocar, toque em `host ⚙` no topo.
- Para já vir preenchido, edite `extra.serverUrl` no `app.json`.
- `http://` só é aceito para localhost e redes locais (10.x, 192.168.x, 172.16–31.x). No celular, `localhost`
  é o próprio aparelho: use o IP do computador, ex.: `http://192.168.0.10:10000`.

## Arquivos recebidos

WebViews não baixam `blob:`. Por isso o botão vira **Salvar**: o app grava o arquivo e abre o menu de
compartilhar do sistema. Limite de 30 MB por arquivo no app (100 MB no navegador/desktop).

## Observações

- A identidade fica no armazenamento do WebView; desinstalar o app a apaga. Exporte o backup em
  "Identidade e servidor".
- Para publicar nas lojas será preciso EAS Build e ícones em `assets/`.

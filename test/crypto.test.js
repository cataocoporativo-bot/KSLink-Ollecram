import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  hex, unhex, generateIdentity, loadIdentity, fingerprint, shortFp,
  signText, verifyText, hsTranscript, dtlsFingerprint,
  generateEphemeral, deriveSessionKey, sealBytes, openBytes,
  exportBackup, importBackup, utf8,
} from '../public/crypto.js';

test('hex/unhex: ida e volta, e rejeita entrada inválida', () => {
  const b = new Uint8Array([0, 1, 254, 255]);
  assert.equal(hex(b), '0001feff');
  assert.deepEqual(unhex('0001FEFF'), b);
  assert.throws(() => unhex('abc'));
  assert.throws(() => unhex('zz'));
});

test('identidade: recarregar do JWK mantém a mesma chave e o mesmo fingerprint', async () => {
  const a = await generateIdentity();
  assert.equal(a.pubRaw.length, 65);
  assert.equal(a.pubRaw[0], 0x04);
  const b = await loadIdentity(JSON.parse(JSON.stringify(a.jwk)));
  assert.equal(b.fp, a.fp);
  assert.equal(hex(b.pubRaw), hex(a.pubRaw));
  assert.equal(a.fp, await fingerprint(a.pubRaw));
  assert.match(shortFp(a.fp), /^([0-9A-F]{4}:){5}[0-9A-F]{4}$/);
  const c = await generateIdentity();
  assert.notEqual(c.fp, a.fp);
});

test('identidade: JWK incompleto é rejeitado', async () => {
  await assert.rejects(() => loadIdentity({ kty: 'EC', crv: 'P-256' }));
  await assert.rejects(() => loadIdentity(null));
});

test('assinatura: válida passa; texto alterado ou chave errada falham', async () => {
  const a = await generateIdentity();
  const b = await generateIdentity();
  const sig = await signText(a.priv, 'olá');
  assert.equal(await verifyText(a.pubRaw, sig, 'olá'), true);
  assert.equal(await verifyText(a.pubRaw, sig, 'olá!'), false);
  assert.equal(await verifyText(b.pubRaw, sig, 'olá'), false);
  assert.equal(await verifyText(a.pubRaw, 'zz', 'olá'), false);
  assert.equal(await verifyText(new Uint8Array(65), sig, 'olá'), false);
});

test('dtlsFingerprint: extrai e normaliza; erra sem a linha', () => {
  const sdp = 'v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\na=ice-ufrag:x\r\na=fingerprint:sha-256 AB:CD:EF:01\r\na=setup:actpass\r\n';
  assert.equal(dtlsFingerprint(sdp), 'sha-256 ab:cd:ef:01');
  assert.throws(() => dtlsFingerprint('v=0\r\n'));
});

// Simula as duas pontas de uma conexão e o handshake completo.
async function handshake({ mitm = false } = {}) {
  const room = 'sala-teste-123';
  const A = { id: await generateIdentity(), sid: 'a'.repeat(16), name: 'Ana' };
  const B = { id: await generateIdentity(), sid: 'b'.repeat(16), name: 'Beto | "x"' };
  // O que cada lado enxerga do DTLS (A: local=fpA, remoto=fpB; B: o inverso)
  const fpA = 'sha-256 aa:aa';
  const fpB = 'sha-256 bb:bb';
  const fpMallory = 'sha-256 cc:cc';
  const viewA = { loc: fpA, rem: mitm ? fpMallory : fpB };
  const viewB = { loc: fpB, rem: mitm ? fpMallory : fpA };

  A.eph = await generateEphemeral();
  B.eph = await generateEphemeral();
  const sigA = await signText(A.id.priv, hsTranscript({ room, ownSid: A.sid, peerSid: B.sid, ownDtls: viewA.loc, peerDtls: viewA.rem, eph: A.eph.pubHex, name: A.name }));
  const sigB = await signText(B.id.priv, hsTranscript({ room, ownSid: B.sid, peerSid: A.sid, ownDtls: viewB.loc, peerDtls: viewB.rem, eph: B.eph.pubHex, name: B.name }));

  // B verifica A (papéis invertidos, usando o que B observou)
  const okAatB = await verifyText(A.id.pubRaw, sigA, hsTranscript({ room, ownSid: A.sid, peerSid: B.sid, ownDtls: viewB.rem, peerDtls: viewB.loc, eph: A.eph.pubHex, name: A.name }));
  // A verifica B
  const okBatA = await verifyText(B.id.pubRaw, sigB, hsTranscript({ room, ownSid: B.sid, peerSid: A.sid, ownDtls: viewA.rem, peerDtls: viewA.loc, eph: B.eph.pubHex, name: B.name }));
  return { room, A, B, okAatB, okBatA };
}

test('handshake: sem interceptação, as duas assinaturas verificam', async () => {
  const r = await handshake();
  assert.equal(r.okAatB, true);
  assert.equal(r.okBatA, true);
});

test('handshake: MITM no SDP (DTLS diferente entre as pontas) é detectado', async () => {
  const r = await handshake({ mitm: true });
  assert.equal(r.okAatB, false);
  assert.equal(r.okBatA, false);
});

test('chave de sessão: as duas pontas derivam a mesma chave; adulteração e sala errada falham', async () => {
  const room = 'sala-x-000001';
  const a = await generateEphemeral();
  const b = await generateEphemeral();
  const ka = await deriveSessionKey(a.priv, b.pubRaw, a.pubHex, b.pubHex, room);
  const kb = await deriveSessionKey(b.priv, a.pubRaw, b.pubHex, a.pubHex, room);

  const msg = utf8('mensagem secreta');
  const frame = await sealBytes(ka, msg);
  assert.equal(frame.length, 12 + msg.length + 16);
  assert.deepEqual(await openBytes(kb, frame), msg);

  // Dois quadros iguais não podem gerar o mesmo texto cifrado (IV aleatório)
  const frame2 = await sealBytes(ka, msg);
  assert.notEqual(hex(frame), hex(frame2));

  const bad = frame.slice();
  bad[bad.length - 1] ^= 1;
  await assert.rejects(() => openBytes(kb, bad));
  await assert.rejects(() => openBytes(kb, frame.subarray(0, 10)));

  const kOther = await deriveSessionKey(b.priv, a.pubRaw, b.pubHex, a.pubHex, 'outra-sala-00');
  await assert.rejects(() => openBytes(kOther, frame));
});

test('chave de sessão: chave efêmera inválida é rejeitada', async () => {
  const a = await generateEphemeral();
  await assert.rejects(() => deriveSessionKey(a.priv, new Uint8Array(65), a.pubHex, '00', 'sala-x-000001'));
});

test('backup: exporta/importa com a senha certa; senha errada e arquivo inválido falham', async () => {
  const id = await generateIdentity();
  const file = await exportBackup(id, 'uma-senha-forte');
  assert.ok(!file.includes(id.jwk.d), 'a chave privada não pode aparecer em claro');
  const back = await importBackup(file, 'uma-senha-forte');
  assert.equal(back.fp, id.fp);
  await assert.rejects(() => importBackup(file, 'senha-errada-1'), /Senha incorreta/);
  await assert.rejects(() => importBackup('{"app":"outro"}', 'x'), /inválido/);
  await assert.rejects(() => importBackup('não é json', 'x'), /inválido/);
  await assert.rejects(() => exportBackup(id, 'curta'), /8 caracteres/);
  const hostile = JSON.parse(file);
  hostile.iter = 999_999_999;
  await assert.rejects(() => importBackup(JSON.stringify(hostile), 'uma-senha-forte'), /inválido/);
});

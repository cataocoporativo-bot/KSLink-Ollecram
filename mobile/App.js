import { useCallback, useEffect, useRef, useState } from 'react';
import {
  ActivityIndicator, BackHandler, Image, Linking, Platform, Pressable, StatusBar as RNStatusBar,
  StyleSheet, Text, TextInput, View,
} from 'react-native';
import { WebView } from 'react-native-webview';
import { StatusBar } from 'expo-status-bar';
import Constants from 'expo-constants';
import AsyncStorage from '@react-native-async-storage/async-storage';
import * as FileSystem from 'expo-file-system';
import * as Sharing from 'expo-sharing';
import { normalizeServer } from './serverUrl';

const KEY = 'kslink.server';
const C = { bg: '#05030a', panel: '#0b0814', line: '#2b1d4a', accent: '#00f0ff', pink: '#ff2a6d', muted: '#8a84b0', text: '#e9f6ff', err: '#ff3b5c' };
const LOGO = require('./assets/klaatu-logo.png');
const STATUS_H = Platform.OS === 'android' ? (RNStatusBar.currentHeight ?? 24) : 44;

const safeName = (s) =>
  String(s || 'arquivo').replace(/[\\/:*?"<>|\u0000-\u001f]/g, '_').replace(/^\.+/, '').slice(0, 100) || 'arquivo';

export default function App() {
  const web = useRef(null);
  const incoming = useRef(new Map()); // id -> { name, n, parts[] }
  const [server, setServer] = useState(undefined); // undefined = carregando; null = sem servidor
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState('');
  const [formErr, setFormErr] = useState('');
  const [loading, setLoading] = useState(true);
  const [loadErr, setLoadErr] = useState('');
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    (async () => {
      let saved = null;
      try {
        saved = normalizeServer(await AsyncStorage.getItem(KEY));
      } catch { /* ignora */ }
      setServer(saved || normalizeServer(Constants.expoConfig?.extra?.serverUrl) || null);
    })();
  }, []);

  useEffect(() => {
    if (Platform.OS !== 'android') return undefined;
    const sub = BackHandler.addEventListener('hardwareBackPress', () => {
      if (editing && server) {
        setEditing(false);
        return true;
      }
      return false;
    });
    return () => sub.remove();
  }, [editing, server]);

  const save = useCallback(async () => {
    const n = normalizeServer(draft);
    if (!n) {
      setFormErr('Endereço inválido. Use https://… (http só em rede local).');
      return;
    }
    try {
      await AsyncStorage.setItem(KEY, n);
    } catch { /* segue sem persistir */ }
    setFormErr('');
    setLoadErr('');
    setLoading(true);
    setServer(n);
    setEditing(false);
    setNonce((x) => x + 1);
  }, [draft]);

  // Recebe do cliente web os pedaços de um arquivo, grava e abre o menu de compartilhar/salvar.
  const onMessage = useCallback(async (event) => {
    let m;
    try {
      m = JSON.parse(event.nativeEvent.data);
    } catch {
      return;
    }
    if (!m || m.kslink !== 1) return;
    const map = incoming.current;
    if (m.t === 'save-start' && typeof m.id === 'string' && Number.isInteger(m.n) && m.n > 0 && m.n <= 100) {
      map.clear();
      map.set(m.id, { name: safeName(m.name), n: m.n, parts: [] });
    } else if (m.t === 'save-chunk') {
      const f = map.get(m.id);
      if (!f || typeof m.d !== 'string' || m.i !== f.parts.length) return;
      f.parts.push(m.d);
      if (f.parts.length === f.n) {
        map.delete(m.id);
        try {
          const uri = `${FileSystem.cacheDirectory}${Date.now()}-${f.name}`;
          await FileSystem.writeAsStringAsync(uri, f.parts.join(''), { encoding: FileSystem.EncodingType.Base64 });
          if (await Sharing.isAvailableAsync()) await Sharing.shareAsync(uri, { dialogTitle: f.name });
        } catch { /* sem feedback nativo; o usuário pode tentar de novo */ }
      }
    }
  }, []);

  const origin = server;
  const allowNav = useCallback(
    (req) => {
      if (req.url === 'about:blank' || req.url.startsWith('blob:') || req.url.startsWith(origin)) return true;
      if (/^https?:\/\//i.test(req.url)) Linking.openURL(req.url).catch(() => {});
      return false;
    },
    [origin],
  );

  if (server === undefined) {
    return (
      <View style={styles.center}>
        <StatusBar style="light" />
        <ActivityIndicator size="large" color={C.accent} />
      </View>
    );
  }

  if (!server || editing) {
    return (
      <View style={styles.center}>
        <StatusBar style="light" />
        <View style={styles.card}>
          <Image source={LOGO} style={styles.logoBig} resizeMode="contain" />
          <Text style={styles.title}>KSLINK</Text>
          {!!loadErr && <Text style={styles.err}>{loadErr}</Text>}
          <Text style={styles.label}>Endereço do servidor</Text>
          <TextInput
            style={styles.input}
            value={draft}
            onChangeText={setDraft}
            placeholder="https://kslink.onrender.com"
            placeholderTextColor={C.muted}
            autoCapitalize="none"
            autoCorrect={false}
            keyboardType="url"
            onSubmitEditing={save}
          />
          {!!formErr && <Text style={styles.err}>{formErr}</Text>}
          <Pressable style={styles.btn} onPress={save}>
            <Text style={styles.btnTxt}>Conectar</Text>
          </Pressable>
          {!!server && (
            <Pressable style={styles.btn2} onPress={() => setEditing(false)}>
              <Text style={styles.btn2Txt}>Cancelar</Text>
            </Pressable>
          )}
        </View>
      </View>
    );
  }

  return (
    <View style={styles.root}>
      <StatusBar style="light" backgroundColor={C.bg} />
      <View style={styles.header}>
        <View style={styles.brand}>
          <Text style={styles.logo}>KSLINK</Text>
          <Image source={LOGO} style={styles.logoSmall} resizeMode="contain" />
        </View>
        <Pressable
          onPress={() => {
            setDraft(server);
            setFormErr('');
            setEditing(true);
          }}
          hitSlop={12}
        >
          <Text style={styles.host} numberOfLines={1}>{server.replace(/^https?:\/\//, '')}  ⚙</Text>
        </Pressable>
      </View>

      {loading && !loadErr && (
        <View style={styles.spin}>
          <ActivityIndicator size="small" color={C.accent} />
        </View>
      )}

      {loadErr ? (
        <View style={styles.center}>
          <Text style={styles.err}>{loadErr}</Text>
          <Pressable
            style={styles.btn}
            onPress={() => {
              setLoadErr('');
              setLoading(true);
              setNonce((x) => x + 1);
            }}
          >
            <Text style={styles.btnTxt}>Tentar de novo</Text>
          </Pressable>
        </View>
      ) : (
        <WebView
          key={nonce}
          ref={web}
          style={styles.web}
          source={{ uri: server }}
          originWhitelist={[`${server}*`, 'blob:*', 'about:*']}
          onShouldStartLoadWithRequest={allowNav}
          javaScriptEnabled
          domStorageEnabled
          allowFileAccess={false}
          allowsInlineMediaPlayback
          mixedContentMode="never"
          setSupportMultipleWindows={false}
          allowsLinkPreview={false}
          setBuiltInZoomControls={false}
          displayZoomControls={false}
          onMessage={onMessage}
          onLoadEnd={() => setLoading(false)}
          onError={(e) => setLoadErr(`Não foi possível abrir o servidor (${e.nativeEvent.description || 'erro de rede'}).`)}
          onHttpError={(e) => setLoadErr(`O servidor respondeu com erro ${e.nativeEvent.statusCode}.`)}
        />
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: C.bg, paddingTop: STATUS_H },
  header: {
    flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', gap: 12,
    paddingHorizontal: 18, paddingVertical: 10, borderBottomWidth: 1, borderBottomColor: C.line,
  },
  brand: { flexDirection: 'row', alignItems: 'center', gap: 12 },
  logo: { color: C.text, fontSize: 20, fontWeight: '900', letterSpacing: 2, textShadowColor: C.accent, textShadowRadius: 8, textShadowOffset: { width: 1, height: 0 } },
  logoSmall: { width: 84, height: 28 },
  logoBig: { width: 170, height: 56, alignSelf: 'flex-start' },
  host: { color: C.muted, fontSize: 14, maxWidth: 220 },
  web: { flex: 1, backgroundColor: C.bg },
  spin: { position: 'absolute', top: STATUS_H + 56, alignSelf: 'center', zIndex: 10 },
  center: { flex: 1, backgroundColor: C.bg, alignItems: 'center', justifyContent: 'center', gap: 14, padding: 24 },
  card: { width: '100%', maxWidth: 440, gap: 12, padding: 22, borderWidth: 1, borderTopWidth: 2, borderColor: C.line, borderTopColor: C.accent, backgroundColor: C.panel },
  title: { color: C.text, fontSize: 28, fontWeight: '900', letterSpacing: 2, textShadowColor: C.pink, textShadowRadius: 6, textShadowOffset: { width: -2, height: 0 } },
  label: { color: C.muted, fontSize: 15 },
  input: { color: C.text, fontSize: 18, padding: 13, borderWidth: 1, borderBottomWidth: 2, borderColor: C.line, borderBottomColor: '#b026ff', backgroundColor: C.bg },
  err: { color: C.err, fontSize: 15, textAlign: 'center' },
  btn: { backgroundColor: C.accent, padding: 14, alignItems: 'center', minWidth: 160 },
  btnTxt: { color: '#021014', fontSize: 17, fontWeight: '800', letterSpacing: 1.5, textTransform: 'uppercase' },
  btn2: { padding: 12, alignItems: 'center' },
  btn2Txt: { color: C.muted, fontSize: 16 },
});

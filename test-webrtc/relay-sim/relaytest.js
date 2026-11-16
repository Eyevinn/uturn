const { chromium } = require('playwright');
const crypto = require('crypto');

const TURN = process.env.TURN_URL || 'turn:192.0.2.2:3478?transport=udp';
// TURN_SECRET mints time-limited TURN REST API credentials the way an
// application backend would; otherwise static test:testpass.
const [USER, PASS] = process.env.TURN_SECRET
  ? (() => {
      const user = `${Math.floor(Date.now() / 1000) + 3600}:relaytest`;
      const pass = crypto.createHmac('sha1', process.env.TURN_SECRET).update(user).digest('base64');
      return [user, pass];
    })()
  : ['test', 'testpass'];
const RESTART = process.env.ICE_RESTART === '1';
// PEER2_DIRECT=1: only the first peer uses TURN (forced relay); the second has
// no TURN server and is reached as an external peer. Exercises the
// client-to-external-peer path, including STUN from the peer.
const PEER2_DIRECT = process.env.PEER2_DIRECT === '1';

(async () => {
  const browser = await chromium.launch({
    ...(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {}),
    // Real host IPs instead of mDNS names, so the TURN peer can create a
    // permission for the direct peer's address.
    args: ['--no-sandbox', '--disable-dev-shm-usage',
           '--disable-features=WebRtcHideLocalIpsWithMdns'],
  });
  const page = await browser.newPage();
  page.on('console', m => console.log('  [browser]', m.text()));
  await page.goto('about:blank');

  const result = await page.evaluate(async ({ TURN, USER, PASS, RESTART, PEER2_DIRECT }) => {
    const log = [];
    const cfg = {
      iceServers: [{ urls: TURN, username: USER, credential: PASS }],
      iceTransportPolicy: 'relay',
    };
    const pc1 = new RTCPeerConnection(cfg);
    const pc2 = new RTCPeerConnection(PEER2_DIRECT ? {} : cfg);

    // Direct signalling: hand candidates straight across.
    pc1.onicecandidate = e => e.candidate && pc2.addIceCandidate(e.candidate);
    pc2.onicecandidate = e => e.candidate && pc1.addIceCandidate(e.candidate);

    const opened = new Promise(res => {
      pc2.ondatachannel = e => { e.channel.onopen = () => res(e.channel); };
    });
    const dc1 = pc1.createDataChannel('probe');

    async function negotiate(opts) {
      const offer = await pc1.createOffer(opts);
      await pc1.setLocalDescription(offer);
      await pc2.setRemoteDescription(offer);
      const answer = await pc2.createAnswer();
      await pc2.setLocalDescription(answer);
      await pc1.setRemoteDescription(answer);
      // Record the ufrags actually in play.
      const uf = s => [...s.matchAll(/a=ice-ufrag:(\S+)/g)].map(m => m[1]);
      log.push('offer ufrags=' + uf(offer.sdp) + ' answer ufrags=' + uf(answer.sdp));
    }

    await negotiate();

    const timeout = ms => new Promise((_, rej) => setTimeout(() => rej(new Error('timeout after ' + ms + 'ms')), ms));

    let dc2;
    try {
      dc2 = await Promise.race([opened, timeout(30000)]);
    } catch (e) {
      return { ok: false, stage: 'initial-connect', error: e.message, log,
               ice1: pc1.iceConnectionState, ice2: pc2.iceConnectionState,
               conn1: pc1.connectionState, conn2: pc2.connectionState };
    }

    // Prove bytes actually flow end to end (ICE + DTLS both completed).
    const echoed = new Promise(res => { dc2.onmessage = e => { dc2.send('pong:' + e.data); }; dc1.onmessage = e => res(e.data); });
    dc1.send('ping');
    let roundtrip;
    try { roundtrip = await Promise.race([echoed, timeout(10000)]); }
    catch (e) { return { ok: false, stage: 'initial-data', error: e.message, log }; }
    log.push('roundtrip: ' + roundtrip);

    let restart = null;
    if (RESTART) {
      await negotiate({ iceRestart: true });
      // Do not watch iceconnectionstatechange: the old pair stays up during a
      // restart, so the state may never leave "connected" and no event fires.
      // The honest criterion is whether data still flows afterwards.
      await new Promise(r => setTimeout(r, 6000));
      const echoed2 = new Promise(res => { dc1.onmessage = e => res(e.data); });
      dc1.send('ping2');
      try {
        const rt2 = await Promise.race([echoed2, timeout(20000)]);
        restart = { ok: true, roundtrip: rt2, ice1: pc1.iceConnectionState, ice2: pc2.iceConnectionState };
      } catch (e) {
        restart = { ok: false, error: e.message, ice1: pc1.iceConnectionState, ice2: pc2.iceConnectionState };
      }
    }

    // Which candidate pair won?
    let pair = null;
    for (const r of (await pc1.getStats()).values()) {
      if (r.type === 'candidate-pair' && r.state === 'succeeded') pair = { bytesSent: r.bytesSent, bytesReceived: r.bytesReceived };
    }
    return { ok: true, log, pair, restart,
             ice1: pc1.iceConnectionState, ice2: pc2.iceConnectionState,
             conn1: pc1.connectionState, conn2: pc2.connectionState };
  }, { TURN, USER, PASS, RESTART, PEER2_DIRECT });

  console.log(JSON.stringify(result, null, 2));
  await browser.close();
  process.exit(result.ok && (!RESTART || result.restart?.ok) ? 0 : 1);
})();

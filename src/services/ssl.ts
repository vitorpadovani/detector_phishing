import * as tls from 'tls';
import { extractDomain } from './dns';
import type { SSLInfo } from '../types';

export async function sslCertificateInfo(hostOrUrl: string, port = 443): Promise<SSLInfo> {
  const info: SSLInfo = { present: false };
  try {
    const hostDomain = extractDomain(hostOrUrl);
    const res = await new Promise<tls.PeerCertificate>((resolve, reject) => {
      const socket = tls.connect({ host: hostDomain, port, servername: hostDomain, timeout: 8000 }, () => {
        const cert = socket.getPeerCertificate(true);
        socket.end();
        if (cert && Object.keys(cert).length > 0) resolve(cert); else reject(new Error('no cert'));
      });
      socket.on('error', reject);
      socket.on('timeout', () => { socket.destroy(new Error('timeout')); });
    });

    info.present = true;
    info.issuer = res.issuer;
    info.subject = res.subject;
    info.validFrom = res.valid_from;
    info.validTo = res.valid_to;
    const san = (res.subjectaltname || '') as string;
    info.subjectAltName = san.split(',').map((s) => s.trim().replace(/^DNS:/i, '')).filter(Boolean);

    try {
      const exp = new Date(res.valid_to);
      info.daysToExpire = Math.floor((exp.getTime() - Date.now()) / (1000*60*60*24));
    } catch { info.daysToExpire = null; }

    info.hostnameMatches = (info.subjectAltName || []).some((dns) => hostnameMatch(hostDomain, dns));
  } catch {
    // keep present=false
  }
  return info;
}

function hostnameMatch(host: string, pattern: string) {
  if (pattern.startsWith('*.')) {
    const suf = pattern.slice(1);
    return host.endsWith(suf) && host.split('.').length >= 3;
  }
  return host.toLowerCase() === pattern.toLowerCase();
}

/**
 * Device Fingerprinting & Binding Utility
 * Generates and persists a stable client device ID and cryptographic fingerprint
 * for workstation-bound decryption authorization.
 *
 * NOTE: This provides software-level device identification and browser sandbox
 * binding. It is not cryptographic hardware attestation (e.g. TPM / Secure Enclave).
 */

const DEVICE_STORAGE_KEY = 'sih_device_id';
const FINGERPRINT_STORAGE_KEY = 'sih_device_fingerprint';

function getCryptoRandomHex(byteCount = 4): string {
  if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
    const arr = new Uint8Array(byteCount);
    window.crypto.getRandomValues(arr);
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }
  return 'DEVF00D1';
}

export function getClientDevice(): { deviceId: string; deviceFingerprint: string; platform: string } {
  if (typeof window === 'undefined') {
    return {
      deviceId: 'DEV-SERVER-SCRIPTER',
      deviceFingerprint: 'server-render-fingerprint-000',
      platform: 'Server'
    };
  }

  let deviceId = localStorage.getItem(DEVICE_STORAGE_KEY);
  let deviceFingerprint = localStorage.getItem(FINGERPRINT_STORAGE_KEY);

  if (!deviceId) {
    const randomHex = getCryptoRandomHex(4);
    deviceId = `DEV-WORKSTATION-${randomHex}`;
    localStorage.setItem(DEVICE_STORAGE_KEY, deviceId);
  }

  if (!deviceFingerprint) {
    // Generate deterministic workstation-bound fingerprint
    const screenInfo = `${window.screen.width}x${window.screen.height}x${window.screen.colorDepth}`;
    const userAgent = navigator.userAgent;
    const raw = `${deviceId}:${screenInfo}:${userAgent}`;
    // Fast DJB2-like hex hash for fingerprint
    let hash = 5381;
    for (let i = 0; i < raw.length; i++) {
      hash = ((hash << 5) + hash) + raw.charCodeAt(i);
      hash = hash & hash;
    }
    deviceFingerprint = `fp-sw-${Math.abs(hash).toString(16).padStart(8, '0')}-${deviceId.slice(-4)}`;
    localStorage.setItem(FINGERPRINT_STORAGE_KEY, deviceFingerprint);
  }

  const platform = navigator.platform || (navigator.userAgent.includes('Mac') ? 'macOS' : 'Linux/Windows');

  return {
    deviceId,
    deviceFingerprint,
    platform
  };
}

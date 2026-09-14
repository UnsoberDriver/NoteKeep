/**
 * crypto.js — Module de chiffrement de bout en bout (E2EE) côté client.
 *
 * Principe : le serveur ne voit jamais le mot de passe en clair, ni la clé
 * privée déchiffrée, ni le contenu des notes/listes en clair. Tout le
 * chiffrement/déchiffrement se fait ici, dans le navigateur.
 *
 * - Chaque utilisateur a une paire de clés ECDH (P-256), générée à
 *   l'inscription.
 * - La clé privée est chiffrée ("wrappée") DEUX fois :
 *     1. avec une clé dérivée du mot de passe (PBKDF2)
 *     2. avec une clé de récupération aléatoire (affichée une seule fois)
 *   Les deux versions chiffrées sont stockées côté serveur (illisibles
 *   sans le mot de passe ou la recovery key).
 * - Les notes sont chiffrées avec une clé symétrique dérivée de la clé
 *   privée de l'utilisateur (AES-GCM).
 * - Les listes de courses partagées ont une clé de liste aléatoire,
 *   "wrappée" une fois par membre avec la clé publique ECDH de ce membre
 *   (ECDH + HKDF), donc chaque membre peut la déchiffrer avec sa propre
 *   clé privée sans jamais échanger de secret en clair.
 */

const PBKDF2_ITERATIONS = 600000; // recommandation OWASP 2024+ pour PBKDF2-SHA256
const RECOVERY_KEY_BYTES = 32;    // 256 bits d'entropie

// ---------------------------------------------------------------------
// Utilitaires bas niveau
// ---------------------------------------------------------------------

function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

function toB64(buf) {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function fromB64(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function utf8(str) {
  return new TextEncoder().encode(str);
}

function fromUtf8(buf) {
  return new TextDecoder().decode(buf);
}

// ---------------------------------------------------------------------
// Dérivation de clé à partir du mot de passe (PBKDF2)
// ---------------------------------------------------------------------

/**
 * Dérive une clé AES-GCM à partir du mot de passe et d'un sel.
 * Le sel est public (stocké côté serveur), seul le mot de passe est secret.
 */
async function deriveKeyFromPassword(password, saltBytes) {
  const baseKey = await crypto.subtle.importKey(
    'raw', utf8(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false, // non exportable : ne peut pas quitter le contexte WebCrypto
    ['encrypt', 'decrypt']
  );
}

/**
 * Variante de wrapPrivateKey pour les comptes sans mot de passe (connexion
 * Google) : la clé privée n'est chiffrée QU'avec la recovery key, générée
 * ici. Cette recovery key doit être conservée par le front-end (ex :
 * localStorage) pour déverrouiller la clé privée aux sessions suivantes,
 * puisqu'il n'existe aucun mot de passe permettant de la re-dériver.
 */
async function wrapPrivateKeyWithRecoveryOnly(privateKeyRaw) {
  const recovery = generateRecoveryKey();
  const recoveryKey = await importRecoveryKeyAsAesKey(recovery.bytes);
  const encWithRecovery = await aesEncrypt(recoveryKey, privateKeyRaw);

  return {
    // à envoyer au serveur :
    enc_private_key_recovery: encWithRecovery, // {ciphertext, iv}
    // à conserver sur l'appareil (jamais envoyé au serveur en clair) :
    recoveryKeyDisplay: recovery.display,
    recoveryKeyBytes: recovery.bytes,
  };
}

async function unwrapPrivateKeyWithRecoveryBytes(recoveryBytes, encRecovery) {
  const recoveryKey = await importRecoveryKeyAsAesKey(recoveryBytes);
  const privateKeyRaw = await aesDecrypt(recoveryKey, encRecovery.ciphertext, encRecovery.iv);
  return { privateKey: await importPrivateKey(privateKeyRaw), privateKeyRaw };
}

// ---------------------------------------------------------------------
// Clé de récupération
// ---------------------------------------------------------------------

/** Génère une clé de récupération aléatoire, affichée une seule fois à l'utilisateur. */
function generateRecoveryKey() {
  const bytes = randomBytes(RECOVERY_KEY_BYTES);
  return { bytes, display: formatRecoveryKeyForDisplay(bytes) };
}

// Base32 (RFC 4648, sans padding), alphabet sans 0/O/1/I pour éviter les
// confusions à la recopie manuelle. Vrai encodage bit à bit, réversible.
const RECOVERY_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; // 32 caractères

function base32Encode(bytes) {
  let bits = 0, value = 0, out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += RECOVERY_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += RECOVERY_ALPHABET[(value << (5 - bits)) & 31];
  }
  return out;
}

function base32Decode(str) {
  const clean = str.replace(/-/g, '').trim().toUpperCase();
  let bits = 0, value = 0;
  const out = [];
  for (const char of clean) {
    const idx = RECOVERY_ALPHABET.indexOf(char);
    if (idx === -1) continue; // ignore les caractères inconnus (tolérance de saisie)
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

function formatRecoveryKeyForDisplay(bytes) {
  const raw = base32Encode(bytes);
  // Regroupe par blocs de 4 pour la lisibilité, ex: "XJ4K-9F2P-..."
  return raw.match(/.{1,4}/g).join('-');
}

async function importRecoveryKeyAsAesKey(recoveryBytes) {
  // Les 32 octets aléatoires servent directement de matériel de clé AES-256.
  return crypto.subtle.importKey('raw', recoveryBytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

// ---------------------------------------------------------------------
// Paire de clés ECDH (identité de l'utilisateur, pour le partage de listes)
// ---------------------------------------------------------------------

async function generateIdentityKeyPair() {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true, // extractable : on doit pouvoir exporter/chiffrer la clé privée
    ['deriveKey', 'deriveBits']
  );
  const publicKeyRaw = await crypto.subtle.exportKey('spki', pair.publicKey);
  const privateKeyRaw = await crypto.subtle.exportKey('pkcs8', pair.privateKey);
  return {
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
    publicKeyB64: toB64(publicKeyRaw),
    privateKeyRaw, // ArrayBuffer, à chiffrer avant tout envoi au serveur
  };
}

async function importPublicKey(publicKeyB64) {
  return crypto.subtle.importKey(
    'spki', fromB64(publicKeyB64), { name: 'ECDH', namedCurve: 'P-256' }, true, []
  );
}

async function importPrivateKey(privateKeyRaw) {
  return crypto.subtle.importKey(
    'pkcs8', privateKeyRaw, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
  );
}

// ---------------------------------------------------------------------
// AES-GCM générique : chiffrer/déchiffrer un ArrayBuffer avec une clé
// ---------------------------------------------------------------------

async function aesEncrypt(key, plaintextBytes) {
  const iv = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintextBytes);
  return { ciphertext: toB64(ciphertext), iv: toB64(iv) };
}

async function aesDecrypt(key, ciphertextB64, ivB64) {
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64(ivB64) }, key, fromB64(ciphertextB64)
  );
  return plaintext; // ArrayBuffer
}

// ---------------------------------------------------------------------
// Wrap / unwrap de la clé privée de l'utilisateur (mot de passe + recovery)
// ---------------------------------------------------------------------

/**
 * À l'inscription (ou au changement de mot de passe) : chiffre la clé
 * privée avec la clé dérivée du mot de passe ET avec la clé de récupération.
 * Retourne tout ce qu'il faut stocker côté serveur (rien n'est en clair).
 */
async function wrapPrivateKey(privateKeyRaw, password) {
  const salt = randomBytes(16);
  const pwdKey = await deriveKeyFromPassword(password, salt);
  const encWithPassword = await aesEncrypt(pwdKey, privateKeyRaw);

  const recovery = generateRecoveryKey();
  const recoveryKey = await importRecoveryKeyAsAesKey(recovery.bytes);
  const encWithRecovery = await aesEncrypt(recoveryKey, privateKeyRaw);

  return {
    // à envoyer au serveur :
    salt: toB64(salt),
    kdf_iterations: PBKDF2_ITERATIONS,
    enc_private_key_pwd: encWithPassword,     // {ciphertext, iv}
    enc_private_key_recovery: encWithRecovery, // {ciphertext, iv}
    // à afficher UNE FOIS à l'utilisateur, jamais envoyé au serveur :
    recoveryKeyDisplay: recovery.display,
  };
}

/** À la connexion : déchiffre la clé privée avec le mot de passe. */
async function unwrapPrivateKeyWithPassword(password, saltB64, encPwd) {
  const salt = fromB64(saltB64);
  const pwdKey = await deriveKeyFromPassword(password, salt);
  const privateKeyRaw = await aesDecrypt(pwdKey, encPwd.ciphertext, encPwd.iv);
  const privateKey = await importPrivateKey(privateKeyRaw);
  return { privateKey, privateKeyRaw };
}

/**
 * Re-chiffre une clé privée déjà déchiffrée (ArrayBuffer brut) avec un
 * NOUVEAU mot de passe, sans toucher à la clé de récupération existante.
 * Utilisé lors d'un changement de mot de passe classique ou d'une
 * réinitialisation via recovery key (voir unwrapPrivateKeyWithRecovery).
 */
async function rewrapPrivateKeyWithPassword(privateKeyRaw, newPassword) {
  const salt = randomBytes(16);
  const pwdKey = await deriveKeyFromPassword(newPassword, salt);
  const encWithPassword = await aesEncrypt(pwdKey, privateKeyRaw);
  return {
    salt: toB64(salt),
    kdf_iterations: PBKDF2_ITERATIONS,
    enc_private_key_pwd: encWithPassword,
  };
}

/** En cas de mot de passe oublié : déchiffre la clé privée avec la recovery key saisie. */
async function unwrapPrivateKeyWithRecovery(recoveryDisplay, encRecovery) {
  const bytes = parseRecoveryKeyDisplay(recoveryDisplay);
  const recoveryKey = await importRecoveryKeyAsAesKey(bytes);
  const privateKeyRaw = await aesDecrypt(recoveryKey, encRecovery.ciphertext, encRecovery.iv);
  return { privateKey: await importPrivateKey(privateKeyRaw), privateKeyRaw };
}

function parseRecoveryKeyDisplay(display) {
  const bytes = base32Decode(display);
  if (bytes.length !== RECOVERY_KEY_BYTES) {
    throw new Error('Clé de récupération invalide (longueur incorrecte).');
  }
  return bytes;
}

// ---------------------------------------------------------------------
// Chiffrement des notes (clé symétrique propre à l'utilisateur)
// ---------------------------------------------------------------------

/**
 * Dérive une clé AES-GCM stable pour les notes à partir de la clé privée
 * ECDH de l'utilisateur (ECDH avec sa propre clé publique = un secret
 * stable dérivable uniquement en connaissant la clé privée).
 */
async function deriveNotesKey(privateKey, publicKey) {
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: publicKey },
    privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptNote(notesKey, { title, body }) {
  const payload = utf8(JSON.stringify({ title, body }));
  const { ciphertext, iv } = await aesEncrypt(notesKey, payload);
  return { ciphertext, iv };
}

async function decryptNote(notesKey, ciphertext, iv) {
  const plaintext = await aesDecrypt(notesKey, ciphertext, iv);
  return JSON.parse(fromUtf8(plaintext));
}

// ---------------------------------------------------------------------
// Chiffrement des listes de courses partagées (clé de liste + wrap par membre)
// ---------------------------------------------------------------------

/** À la création d'une liste : génère une clé de liste aléatoire, wrappée pour le créateur. */
async function createListKey(ownerPrivateKey, ownerPublicKey) {
  const listKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const listKeyRaw = await crypto.subtle.exportKey('raw', listKey);
  const wrapped = await wrapListKeyForMember(listKeyRaw, ownerPrivateKey, ownerPublicKey);
  return { listKey, listKeyRaw, wrappedForOwner: wrapped };
}

/**
 * Wrappe la clé de liste pour un membre donné : ECDH entre la clé privée
 * de l'expéditeur et la clé publique du destinataire donne un secret
 * partagé, utilisé pour chiffrer la clé de liste (AES-GCM key wrapping).
 */
async function wrapListKeyForMember(listKeyRaw, senderPrivateKey, recipientPublicKey) {
  const sharedKey = await crypto.subtle.deriveKey(
    { name: 'ECDH', public: recipientPublicKey },
    senderPrivateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  return aesEncrypt(sharedKey, listKeyRaw); // {ciphertext, iv} à stocker pour ce membre
}

/** Un membre déchiffre la clé de liste avec sa propre clé privée. */
async function unwrapListKey(wrapped, myPrivateKey, senderPublicKey) {
  const sharedKey = await crypto.subtle.deriveKey(
    { name: 'ECDH', public: senderPublicKey },
    myPrivateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  const raw = await aesDecrypt(sharedKey, wrapped.ciphertext, wrapped.iv);
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']); // extractable: true pour pouvoir re-wrapper pour d'autres membres
}

async function encryptItemLabel(listKey, label) {
  return aesEncrypt(listKey, utf8(label));
}

async function decryptItemLabel(listKey, ciphertext, iv) {
  return fromUtf8(await aesDecrypt(listKey, ciphertext, iv));
}

// ---------------------------------------------------------------------
// Chiffrement générique de texte (images en data URL, etc.) avec la clé
// de notes de l'utilisateur.
// ---------------------------------------------------------------------

async function encryptText(key, text) {
  return aesEncrypt(key, utf8(text));
}

async function decryptText(key, ciphertext, iv) {
  return fromUtf8(await aesDecrypt(key, ciphertext, iv));
}

export {
  deriveKeyFromPassword,
  generateRecoveryKey,
  generateIdentityKeyPair,
  importPublicKey,
  importPrivateKey,
  wrapPrivateKey,
  wrapPrivateKeyWithRecoveryOnly,
  unwrapPrivateKeyWithPassword,
  unwrapPrivateKeyWithRecoveryBytes,
  rewrapPrivateKeyWithPassword,
  unwrapPrivateKeyWithRecovery,
  deriveNotesKey,
  encryptNote,
  decryptNote,
  createListKey,
  wrapListKeyForMember,
  unwrapListKey,
  encryptItemLabel,
  decryptItemLabel,
  encryptText,
  decryptText,
  toB64,
  fromB64,
};
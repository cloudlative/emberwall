// Encryption of stored SSH credentials (AES-256-GCM). The master key never touches the database.
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';

export class Vault {
  private key: Buffer | null;
  constructor(secret: string | undefined) {
    // Short secrets are refused rather than stretched: this key protects root access to servers.
    this.key = secret && secret.length >= 32 ? Buffer.from(hkdfSync('sha256', secret, 'emberwall-vault-v1', 'ssh-credentials', 32)) : null;
  }
  get configured(): boolean {
    return this.key !== null;
  }
  encrypt(plain: string): string {
    if (!this.key) throw new Error('No master key is configured (EMBERWALL_SECRET), so credentials cannot be stored.');
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', this.key, iv);
    const body = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
    return `v1.${iv.toString('base64')}.${c.getAuthTag().toString('base64')}.${body.toString('base64')}`;
  }
  decrypt(blob: string): string {
    if (!this.key) throw new Error('No master key is configured (EMBERWALL_SECRET), so stored credentials cannot be read.');
    const [v, iv, tag, body] = blob.split('.');
    if (v !== 'v1' || !iv || !tag || body === undefined) throw new Error('Stored credential is not in a known format.');
    const d = createDecipheriv('aes-256-gcm', this.key, Buffer.from(iv, 'base64'));
    d.setAuthTag(Buffer.from(tag, 'base64'));
    try {
      return Buffer.concat([d.update(Buffer.from(body, 'base64')), d.final()]).toString('utf8');
    } catch {
      throw new Error('Stored credential could not be decrypted: the master key is different from the one used to store it.');
    }
  }
}

import { Plaid, PlaidClient, PlaidEnvironment, PlaidError } from 'plaid';
import type { JWK } from 'jose';
import type { Config } from '../config.js';

/**
 * The few Plaid calls the vault makes, behind our own interface. It keeps the rest of the code
 * independent of SDK changes, and tests pass a fake that implements it.
 */
export interface PlaidLike {
  getAccounts(accessToken: string): Promise<Plaid.AccountBase[]>;
  syncTransactions(accessToken: string, cursor: string | undefined): Promise<Plaid.TransactionsSyncResponse>;
  getHoldings(accessToken: string): Promise<{ holdings: Plaid.Holding[]; securities: Plaid.Security[] }>;
  exchangePublicToken(publicToken: string): Promise<{ accessToken: string; itemId: string }>;
  createLinkToken(memberId: string, webhook?: string): Promise<{ linkToken: string; expiration: string }>;
  /** Sandbox only: creates a public token for a test institution without the Link UI. */
  createSandboxPublicToken(institutionId: string, products: string[]): Promise<string>;
  getWebhookVerificationKey(keyId: string): Promise<JWK>;
}

export function plaidClient(config: Config): PlaidLike {
  if (!config.PLAID_CLIENT_ID || !config.PLAID_SECRET) {
    throw new Error('PLAID_CLIENT_ID and PLAID_SECRET are required (use sandbox keys from dashboard.plaid.com)');
  }
  const client = new PlaidClient({
    environment: PlaidEnvironment.Sandbox,
    clientId: config.PLAID_CLIENT_ID,
    secret: config.PLAID_SECRET,
    timeoutInSeconds: 30,
    maxRetries: 2,
  });
  return {
    async getAccounts(access_token) {
      return (await client.accounts.get({ access_token })).accounts;
    },
    async syncTransactions(access_token, cursor) {
      return client.transactions.sync({ access_token, cursor, count: 500 });
    },
    async getHoldings(access_token) {
      const r = await client.investments.getHoldings({ access_token });
      return { holdings: r.holdings, securities: r.securities };
    },
    async exchangePublicToken(public_token) {
      const r = await client.item.exchangePublicToken({ public_token });
      return { accessToken: r.access_token, itemId: r.item_id };
    },
    async createLinkToken(memberId, webhook) {
      const r = await client.link.createToken({
        user: { client_user_id: memberId },
        client_name: 'Purser',
        products: [Plaid.Products.Transactions],
        optional_products: [Plaid.Products.Investments],
        country_codes: [Plaid.CountryCode.Us],
        language: 'en',
        webhook,
      });
      return { linkToken: r.link_token, expiration: r.expiration };
    },
    async createSandboxPublicToken(institution_id, products) {
      const r = await client.sandbox.createPublicToken({
        institution_id,
        initial_products: products as Plaid.Products[],
      });
      return r.public_token;
    },
    async getWebhookVerificationKey(key_id) {
      return (await client.webhook.getVerificationKey({ key_id })).key as unknown as JWK;
    },
  };
}

/** The Plaid error_code (for example ITEM_LOGIN_REQUIRED) from a failed call, if there is one. */
export function plaidErrorCode(err: unknown): string | undefined {
  const body =
    err instanceof PlaidError ? err.body : (err as { body?: unknown; response?: { data?: unknown } })?.body;
  const code = (body as { error_code?: unknown } | undefined)?.error_code;
  return typeof code === 'string' ? code : undefined;
}

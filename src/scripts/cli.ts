import { parseArgs } from 'node:util';
import { runtime } from '../runtime.js';
import { migrate } from '../db/migrate.js';
import { AGENT_PRESETS, createAgent, createMember } from './admin.js';
import { linkSandboxInstitution } from '../plaid/link.js';
import { syncAll } from '../plaid/sync.js';
import { approvePairing } from '../http/oauth.js';
import type { Scope } from '../vault/auth.js';

/**
 * Admin commands, run from a trusted shell (never exposed over HTTP). They use the local SQLite
 * file by default; with PURSER_DB=remote they run against the production D1 database through
 * Cloudflare's API (see README).
 *   migrate
 *   member:create --id jonathan --name Jonathan --role owner
 *   agent:create  --id categorizer --preset categorizer --acts-for household
 *   sandbox:link  --member jonathan [--institution ins_109508]
 *   sync
 *   connect:approve --code ABCD-EFGH --member jonathan   (approves a connector sign-in)
 */
const [command, ...rest] = process.argv.slice(2);
const { values } = parseArgs({
  args: rest,
  options: {
    id: { type: 'string' },
    name: { type: 'string' },
    role: { type: 'string', default: 'member' },
    preset: { type: 'string' },
    scopes: { type: 'string' },
    'acts-for': { type: 'string', default: 'household' },
    member: { type: 'string' },
    institution: { type: 'string' },
    code: { type: 'string' },
  },
});

const needsKey = command === 'sandbox:link' || command === 'sync';
const rt = runtime({ requirePlaid: needsKey, requireKey: needsKey });
if (command === 'migrate' && rt.config.PURSER_DB === 'remote') {
  throw new Error('Production D1 is migrated with: npx wrangler d1 migrations apply DB --remote');
}
try {
  switch (command) {
    case 'migrate': {
      const ran = await migrate(rt.db);
      console.log(ran.length ? `applied ${ran.join(', ')}` : 'up to date');
      break;
    }
    case 'member:create': {
      if (!values.id || !values.name) throw new Error('--id and --name are required');
      const role = values.role === 'owner' ? 'owner' : 'member';
      const token = await createMember(rt.db, values.id, values.name, role);
      console.log(`member ${values.id} created. Token (shown once):\n${token}`);
      break;
    }
    case 'agent:create': {
      if (!values.id) throw new Error('--id is required');
      const scopes = (values.scopes?.split(',') as Scope[] | undefined) ?? AGENT_PRESETS[values.preset ?? values.id];
      if (!scopes) throw new Error(`no preset ${values.preset ?? values.id}; pass --scopes`);
      const token = await createAgent(rt.db, values.id, scopes, values['acts-for']!);
      console.log(`agent ${values.id} [${scopes.join(', ')}] acting for ${values['acts-for']}. Token (shown once):\n${token}`);
      break;
    }
    case 'sandbox:link': {
      if (!values.member) throw new Error('--member is required');
      const r = await linkSandboxInstitution(rt.db, rt.plaid!, rt.kp!, { memberId: values.member, institutionId: values.institution });
      console.log(JSON.stringify(r, null, 2));
      break;
    }
    case 'sync':
      console.log(JSON.stringify(await syncAll(rt.db, rt.plaid!, rt.kp!), null, 2));
      break;
    case 'connect:approve': {
      if (!values.code || !values.member) throw new Error('--code and --member are required');
      const ok = await approvePairing(rt.db, values.code, values.member);
      if (!ok) throw new Error('no pending sign-in with that code (it may have expired after 15 minutes)');
      console.log(`approved: the sign-in page will continue on its own and connect as ${values.member} (read-only)`);
      break;
    }
    default:
      throw new Error(`unknown command ${command ?? '(none)'}`);
  }
} finally {
  await rt.db.close();
}

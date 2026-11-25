import { parseArgs } from 'node:util';
import { runtime } from '../runtime.js';
import { migrate } from '../db/migrate.js';
import { pgDb } from '../db/index.js';
import { AGENT_PRESETS, createAgent, createMember } from './admin.js';
import { linkSandboxInstitution } from '../plaid/link.js';
import { syncAll } from '../plaid/sync.js';
import type { Scope } from '../vault/auth.js';

/**
 * Admin commands, run from a trusted shell (never exposed over HTTP):
 *   migrate
 *   member:create --id jonathan --name Jonathan --role owner
 *   agent:create  --id categorizer --preset categorizer --acts-for household
 *   sandbox:link  --member jonathan [--institution ins_109508]
 *   sync
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
  },
});

// Migrations need only the database, so the deploy workflow never has to hold the master key.
if (command === 'migrate') {
  if (!process.env.DATABASE_URL) throw new Error('Set DATABASE_URL');
  const db = pgDb(process.env.DATABASE_URL, { max: 1 });
  try {
    const ran = await migrate(db);
    console.log(ran.length ? `applied ${ran.join(', ')}` : 'up to date');
  } finally {
    await db.close();
  }
  process.exit(0);
}

const rt = runtime({ requirePlaid: command === 'sandbox:link' || command === 'sync' });
try {
  switch (command) {
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
      const r = await linkSandboxInstitution(rt.db, rt.plaid!, rt.kp, { memberId: values.member, institutionId: values.institution });
      console.log(JSON.stringify(r, null, 2));
      break;
    }
    case 'sync':
      console.log(JSON.stringify(await syncAll(rt.db, rt.plaid!, rt.kp), null, 2));
      break;
    default:
      throw new Error(`unknown command ${command ?? '(none)'}`);
  }
} finally {
  await rt.db.close();
}

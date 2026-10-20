import { syntheticProviderToken } from "./synthetic.js";
import { describe, it, expect } from "vitest";
import { detect } from "../src/detectors.js";
import { RULES } from "../src/rules.js";
// All credentials below are synthetic, nonfunctional fixtures.
const key = syntheticProviderToken;
type Case = {
  id: string;
  path: string;
  positive: string[];
  negative: string[];
  ambiguous: string;
};
const cases: Case[] = [
  {
    id: "secret-literal",
    path: "config.ts",
    positive: [
      `const key='${key}';`,
      `export const config={token:'${key}'};`,
      `const password='P9qR2xM5vH8nT3aK6zB4cD7f';`,
    ],
    negative: [
      `const key='pk_live_7Qm4vP8rL2xW9nA5cZ3hJ6tB';`,
      `const key='sk_live_your_placeholder_secret_key';`,
      `// const key='${key}';`,
    ],
    ambiguous: "const key=process.env.PAYMENT_KEY;",
  },
  {
    id: "client-privilege",
    path: "app.tsx",
    positive: [
      `'use client'; const x=process.env.SUPABASE_SERVICE_ROLE_KEY;`,
      `const x=process.env.NEXT_PUBLIC_SECRET_KEY;`,
      `'use client';const x=process.env['ADMIN_TOKEN'];`,
    ],
    negative: [
      `const x=process.env.SUPABASE_SERVICE_ROLE_KEY;`,
      `'use client';const x=process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;`,
      `// process.env.NEXT_PUBLIC_SECRET_KEY;`,
    ],
    ambiguous: `'use client';const x=getServerToken();`,
  },
  {
    id: "sql-rls-disabled",
    path: "migration.sql",
    positive: [
      "ALTER TABLE users DISABLE ROW LEVEL SECURITY;",
      "alter table public.profiles disable row level security;",
      'ALTER TABLE "private"."patients"\nDISABLE ROW LEVEL SECURITY;',
    ],
    negative: [
      "ALTER TABLE users ENABLE ROW LEVEL SECURITY;",
      "-- ALTER TABLE users DISABLE ROW LEVEL SECURITY;",
      "SELECT 'ALTER TABLE users DISABLE ROW LEVEL SECURITY;';",
    ],
    ambiguous: "CREATE TABLE users(id uuid);",
  },
  {
    id: "sql-policy-open",
    path: "migration.sql",
    positive: [
      "CREATE POLICY a ON users USING (true);",
      "CREATE POLICY b ON profiles FOR INSERT WITH CHECK(true);",
      "create policy c on posts for select to anon using ( true );",
    ],
    negative: [
      "CREATE POLICY a ON users USING (auth.uid()=user_id);",
      "-- CREATE POLICY a ON users USING (true);",
      "CREATE POLICY a ON users USING (false);",
    ],
    ambiguous: "CREATE POLICY a ON public_posts USING (is_published);",
  },
  {
    id: "firebase-open",
    path: "firestore.rules",
    positive: [
      "allow read: if true;",
      "allow read, write: if true;",
      "allow create, update, delete: if true;",
    ],
    negative: [
      "allow read: if request.auth != null;",
      "// allow write: if true;",
      "allow write: if false;",
    ],
    ambiguous: "allow read: if isPublic();",
  },
  {
    id: "sensitive-log",
    path: "server.ts",
    positive: [
      "console.log(user.email);",
      "console.error(request.body);",
      "console.info({token: auth.accessToken});",
    ],
    negative: [
      'console.log("email validation failed");',
      "console.info(statusCode);",
      "// console.log(user.password);",
    ],
    ambiguous: "logger.info(user);",
  },
  {
    id: "tracker-import",
    path: "app.tsx",
    positive: [
      'import posthog from "posthog-js";',
      'const mixpanel=require("mixpanel-browser");',
      'const Script=()=> <script src="https://www.googletagmanager.com/gtag/js" />;',
    ],
    negative: [
      'const description="We do not use posthog-js";',
      '// import x from "posthog-js";',
      'import {Button} from "./ui";',
    ],
    ambiguous: "const x=loadVendor(config);",
  },
  {
    id: "deletion-local-only",
    path: "account.ts",
    positive: [
      "function deleteAccount(){localStorage.clear()}",
      'const eraseUser=()=>{sessionStorage.removeItem("user")};',
      'async function removeAccount(){localStorage.removeItem("account")}',
    ],
    negative: [
      "function logout(){localStorage.clear()}",
      'async function deleteAccount(){await fetch("/api/delete",{method:"DELETE"});localStorage.clear()}',
      "function deleteAccount(){return remoteDeletion()}",
    ],
    ambiguous: "const removeUser=()=>remoteDelete();",
  },
  {
    id: "stripe-event-json",
    path: "stripe-webhook.ts",
    positive: [
      "async function POST(req){const event=await req.json();return stripe.process(event)}",
      "const webhook=async(request)=>{const e=await request.json();stripe.fulfill(e)}",
      "async function handler(request){stripe.log(await request.json())}",
    ],
    negative: [
      "async function POST(req){const e=stripe.webhooks.constructEvent(await req.text(),sig,secret);return e}",
      "async function POST(req){const e=await req.json();return stripe.webhooks.constructEvent(e,sig,secret)}",
      'const note="stripe"; // request.json()',
    ],
    ambiguous: "async function POST(req){return verifyAndHandleStripe(req)}",
  },
  {
    id: "image-alt",
    path: "view.tsx",
    positive: [
      'const x=<img src="a.png"/>;',
      "const x=<img/>;",
      "const X=()=> <div><img src={src}/></div>;",
    ],
    negative: [
      'const x=<img alt="" src="a.png"/>;',
      "const x=<img alt={description} src={src}/>;",
      "const x=<img {...props}/>;",
    ],
    ambiguous: "const x=<CustomImage src={src}/>;",
  },
  {
    id: "input-name",
    path: "form.tsx",
    positive: [
      "const x=<input/>;",
      'const x=<input type="email"/>;',
      'const x=<input id="email" type="text"/>;',
    ],
    negative: [
      "const x=<label>Email<input/></label>;",
      'const x=<><label htmlFor="email">Email</label><input id="email"/></>;',
      'const x=<input aria-label="Email"/>;',
    ],
    ambiguous: "const x=<input {...props}/>;",
  },
  {
    id: "blank-target",
    path: "link.tsx",
    positive: [
      'const x=<a href="/" target="_blank">Read</a>;',
      'const x=<a target="_blank" rel="external"/>;',
      'const x=<a target="_blank"/>;',
    ],
    negative: [
      'const x=<a target="_blank" rel="noopener"/>;',
      'const x=<a target="_blank" rel="noreferrer external"/>;',
      'const x=<a target="_self"/>;',
    ],
    ambiguous: "const x=<a {...props}/>;",
  },
];
for (const c of cases)
  describe(c.id, () => {
    for (const [i, text] of c.positive.entries())
      it(`positive ${i + 1}`, () =>
        expect(
          detect({ path: c.path, text, hash: "" }).some(
            (h) => h.rule_id === c.id,
          ),
        ).toBe(true));
    for (const [i, text] of c.negative.entries())
      it(`negative ${i + 1}`, () =>
        expect(
          detect({ path: c.path, text, hash: "" }).some(
            (h) => h.rule_id === c.id,
          ),
        ).toBe(false));
    it("ambiguous input stays unasserted", () =>
      expect(
        detect({ path: c.path, text: c.ambiguous, hash: "" }).some(
          (h) => h.rule_id === c.id,
        ),
      ).toBe(false));
  });
it("every shipped detector has independent positive, negative and ambiguous fixtures", () =>
  expect(cases.map((c) => c.id).sort()).toEqual(RULES.map((r) => r.id).sort()));
it("line evidence points to the actual JSX node", () =>
  expect(
    detect({ path: "a.tsx", text: "// header\n\nconst x=<img/>;", hash: "" }),
  ).toContainEqual({ rule_id: "image-alt", line: 3 }));
it("SQL dollar-quoted code and comments do not trigger RLS checks", () =>
  expect(
    detect({
      path: "a.sql",
      text: "SELECT $$ALTER TABLE users DISABLE ROW LEVEL SECURITY;$$;\n/* CREATE POLICY x ON users USING(true); */",
      hash: "",
    }),
  ).toEqual([]));

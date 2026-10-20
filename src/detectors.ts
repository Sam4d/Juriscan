import ts from "typescript";
import { SafeError, type FileRecord } from "./models.js";
export interface Hit {
  rule_id: string;
  line: number;
}
const extensions = /\.[cm]?[jt]sx?$/i;
const sensitive =
  /^(?:email|phone|password|passwd|token|accessToken|refreshToken|authorization|ssn|creditCard|cardNumber|healthData|medicalRecord|body)$/i;
const privileged =
  /(?:SERVICE_ROLE|SECRET_KEY|PRIVATE_KEY|DATABASE_PASSWORD|ADMIN_TOKEN)/i;
const provider =
  /(?:sk_live_[a-zA-Z0-9]{20,}|gh[pousr]_[a-zA-Z0-9]{30,}|AKIA[A-Z0-9]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)/;
const placeholder =
  /(?:example|placeholder|changeme|your[_-]|dummy|fake|test[_-]|xxxx|000000)/i;
const tracker =
  /(?:@vercel\/analytics|@segment\/analytics|mixpanel-browser|posthog-js|react-ga4?|googletagmanager\.com|google-analytics\.com|connect\.facebook\.net)/i;
function entropy(s: string) {
  const f = new Map<string, number>();
  for (const c of s) f.set(c, (f.get(c) ?? 0) + 1);
  return [...f.values()].reduce(
    (n, c) => n - (c / s.length) * Math.log2(c / s.length),
    0,
  );
}
export function detect(file: FileRecord): Hit[] {
  const hits: Hit[] = [];
  const line = (pos: number) => file.text.slice(0, pos).split("\n").length;
  const add = (rule_id: string, pos: number) => {
    const l = line(pos);
    if (!hits.some((h) => h.rule_id === rule_id && h.line === l))
      hits.push({ rule_id, line: l });
  };
  // Patterns are bounded by the scanner's per-file limit. Never emit captured text.
  if (
    /\.(?:env|json|ya?ml|toml|ini|pem|key)$|(?:^|\/)\.env(?:\.|$)/i.test(
      file.path,
    )
  ) {
    const rx = new RegExp(provider.source, "g");
    for (const m of file.text.matchAll(rx))
      if (!placeholder.test(m[0]) && entropy(m[0]) > 3)
        add("secret-literal", m.index);
  }
  if (/\.sql$/i.test(file.path)) {
    // Mask comments and quoted strings so code-looking prose is not treated as SQL.
    const text = file.text.replace(
      /--[^\n]*|\/\*[\s\S]*?\*\/|'(?:''|[^'])*'|\$([a-zA-Z_][a-zA-Z_0-9]*|)\$[\s\S]*?\$\1\$/g,
      (m) => m.replace(/[^\n]/g, " "),
    );
    for (const m of text.matchAll(
      /\bALTER\s+TABLE\b[^;]*?\bDISABLE\s+ROW\s+LEVEL\s+SECURITY\b/gi,
    ))
      add("sql-rls-disabled", m.index);
    for (const m of text.matchAll(
      /\bCREATE\s+POLICY\b[^;]*?\b(?:USING|WITH\s+CHECK)\s*\(\s*true\s*\)/gi,
    ))
      add("sql-policy-open", m.index);
  }
  if (/(?:firestore|storage).*\.rules$/i.test(file.path)) {
    const text = file.text.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g, (m) =>
      m.replace(/[^\n]/g, " "),
    );
    for (const m of text.matchAll(
      /\ballow\s+(?:read|write|get|list|create|update|delete)(?:\s*,\s*(?:read|write|get|list|create|update|delete))*\s*:\s*if\s+true\s*;/g,
    ))
      add("firebase-open", m.index);
  }
  if (!extensions.test(file.path)) return hits;
  const source = ts.createSourceFile(
    file.path,
    file.text,
    ts.ScriptTarget.Latest,
    true,
    /\.[jt]sx$/.test(file.path) ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
  );
  if (
    (source as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] })
      .parseDiagnostics?.length
  )
    throw new SafeError("PARSE_FAILED", "Source syntax could not be parsed.");
  const client = source.statements.some(
    (n) =>
      ts.isExpressionStatement(n) &&
      ts.isStringLiteral(n.expression) &&
      n.expression.text === "use client",
  );
  const labels = new Set<string>();
  const attr = (
    attrs: ts.JsxAttributes,
    name: string,
  ): ts.JsxAttribute | undefined =>
    attrs.properties.find(
      (a): a is ts.JsxAttribute =>
        ts.isJsxAttribute(a) && a.name.getText(source) === name,
    );
  const val = (a: ts.JsxAttribute | undefined) =>
    a?.initializer && ts.isStringLiteral(a.initializer)
      ? a.initializer.text
      : undefined;
  function collectLabels(n: ts.Node) {
    if (ts.isJsxOpeningElement(n) && n.tagName.getText(source) === "label") {
      const id = val(attr(n.attributes, "htmlFor"));
      if (id) labels.add(id);
    }
    ts.forEachChild(n, collectLabels);
  }
  collectLabels(source);
  function visit(n: ts.Node) {
    const at = n.getStart(source);
    if (ts.isStringLiteralLike(n)) {
      if (
        provider.test(n.text) &&
        !placeholder.test(n.text) &&
        entropy(n.text) > 3
      )
        add("secret-literal", at);
      const parent = n.parent;
      if (
        ts.isVariableDeclaration(parent) &&
        /password|secret|apiKey|accessToken/i.test(
          parent.name.getText(source),
        ) &&
        n.text.length >= 20 &&
        entropy(n.text) > 3.5 &&
        !placeholder.test(n.text)
      )
        add("secret-literal", at);
      if (
        tracker.test(n.text) &&
        (ts.isImportDeclaration(parent) ||
          ts.isCallExpression(parent) ||
          ts.isJsxAttribute(parent))
      )
        add("tracker-import", at);
    }
    if (ts.isPropertyAccessExpression(n) || ts.isElementAccessExpression(n)) {
      const text = n.getText(source);
      if (
        /^(?:process\.env|import\.meta\.env)[.[]/.test(text) &&
        privileged.test(text) &&
        (client || /(?:NEXT_PUBLIC_|VITE_|PUBLIC_)/.test(text))
      )
        add("client-privilege", at);
    }
    if (
      ts.isCallExpression(n) &&
      ts.isPropertyAccessExpression(n.expression) &&
      n.expression.expression.getText(source) === "console"
    ) {
      let found = false;
      const inspect = (a: ts.Node) => {
        if (ts.isIdentifier(a) && sensitive.test(a.text)) found = true;
        ts.forEachChild(a, inspect);
      };
      n.arguments.forEach(inspect);
      if (found) add("sensitive-log", at);
    }
    if (
      ts.isFunctionDeclaration(n) ||
      ts.isArrowFunction(n) ||
      ts.isFunctionExpression(n) ||
      ts.isMethodDeclaration(n)
    ) {
      const name = ts.isVariableDeclaration(n.parent)
        ? n.parent.name.getText(source)
        : "name" in n && n.name
          ? n.name.getText(source)
          : "";
      let localClear = false,
        remote = false,
        json = false,
        verified = false;
      const calls = (a: ts.Node) => {
        if (
          a !== n &&
          (ts.isFunctionDeclaration(a) ||
            ts.isArrowFunction(a) ||
            ts.isFunctionExpression(a))
        )
          return;
        if (ts.isCallExpression(a)) {
          const callee = a.expression.getText(source);
          if (
            /^(?:localStorage|sessionStorage)\.(?:clear|removeItem)$/.test(
              callee,
            )
          )
            localClear = true;
          if (/(?:fetch|axios|supabase|firebase|prisma|db\.)/.test(callee))
            remote = true;
          if (/\.json$/.test(callee)) json = true;
          if (/\.(?:constructEvent|constructEventAsync)$/.test(callee))
            verified = true;
        }
        ts.forEachChild(a, calls);
      };
      calls(n);
      if (/delete|removeAccount|erase/i.test(name) && localClear && !remote)
        add("deletion-local-only", at);
      if (
        (/webhook/i.test(name) || /webhook/i.test(file.path)) &&
        json &&
        !verified &&
        /stripe/i.test(file.text)
      )
        add("stripe-event-json", at);
    }
    if (ts.isJsxOpeningElement(n) || ts.isJsxSelfClosingElement(n)) {
      const tag = n.tagName.getText(source),
        attrs = n.attributes;
      if (!attrs.properties.some(ts.isJsxSpreadAttribute)) {
        if (tag === "img" && !attr(attrs, "alt")) add("image-alt", at);
        if (
          tag === "input" &&
          !["hidden", "submit", "reset", "button", "image"].includes(
            val(attr(attrs, "type")) ?? "",
          )
        ) {
          let nested = false;
          for (let p: ts.Node | undefined = n.parent; p; p = p.parent)
            if (
              ts.isJsxElement(p) &&
              p.openingElement.tagName.getText(source) === "label"
            )
              nested = true;
          if (
            !nested &&
            !attr(attrs, "aria-label") &&
            !attr(attrs, "aria-labelledby") &&
            !attr(attrs, "title") &&
            !labels.has(val(attr(attrs, "id")) ?? "")
          )
            add("input-name", at);
        }
        if (
          tag === "a" &&
          val(attr(attrs, "target")) === "_blank" &&
          !/\b(?:noopener|noreferrer)\b/.test(val(attr(attrs, "rel")) ?? "")
        )
          add("blank-target", at);
      }
    }
    ts.forEachChild(n, visit);
  }
  visit(source);
  return hits;
}

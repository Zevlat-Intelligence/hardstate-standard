// log.ts — the HardState Log: one append-only chain per issuer. Each event names the hash of the one before it and the
// next sequence number, so once any event is anchored nothing before it can be edited, reordered or deleted without
// the chain breaking. The issuer's keys live in the same chain (issuer.create, key.add, key.revoke), so who may sign
// is itself anchored history, not a database row someone can quietly change.
//
// Delegation lives there too. A person (admin or official) can open a session: a temporary Ed25519 key for a device
// or system, scoped and with an expiry, that signs procedure steps on their behalf (session.open). Everything it signs
// stays attributed to that person; it closes with session.close, expires on its own, and dies with the person's key.
//
// So do departments (dept.add, dept.update, key.move): an institution admin declares them, and they nest (a ministry's
// secretariats, their directorates, their offices). A department head (an admin key with a `dept`) manages the keys of
// that department and of every department under it, and may open sub-departments there; each department may limit the
// event types its keys sign, and a step must fit the limits of its department and of every one above it.

import { hex } from "./bytes.ts";
import { checkShape, eventHash, isReservedType, isSystemType, RESERVED_DOMAINS, SYSTEM_TYPES, type DeptInfo, type HssEvent, type KeyInfo, type KeyScope, type SignedEvent } from "./event.ts";
import { verifyEventSignature } from "./sig.ts";
import { keyCode } from "./ids.ts";

/** Longest a session may last, from its session.open. */
export const SESSION_MAX_MS = 30 * 24 * 3_600_000;
/** How late after a session's expiry a server may still accept an event signed before it (clock skew, retries). */
export const RECEIVE_GRACE_MS = 5 * 60_000;

export interface KeyState {
  info: KeyInfo;
  /** seq of the event that added it. */
  addedAt: number;
  /** seq of the key.revoke / session.close, once revoked. */
  revokedAt?: number;
  /** Session keys: the key id of the person who opened the session. */
  delegatedBy?: string;
  /** Its department now: `info.dept` when added, then whatever key.move set. Sessions have none of their own. */
  dept?: string;
  /** Its public code within the institution (ids.ts keyCode), unique in the log. Absent in states saved before codes. */
  code?: string;
}

export interface DeptState {
  name: string;
  /** The department it sits in; none = top level. Set once, by its dept.add. */
  parent?: string;
  /** Event types its keys may sign; none = any. */
  types?: string[];
  /** seq of its dept.add, and of the dept.update that closed it. */
  addedAt: number;
  closedAt?: number;
}

export interface LogState {
  issuer: string;
  /** From issuer.create / issuer.update: name, jurisdiction, location, website… */
  profile: Record<string, unknown>;
  head: { seq: number; hash: string };
  keys: Record<string, KeyState>;
  depts: Record<string, DeptState>;
}

/** What the authority rules need: the keys and departments at some point of the log (all of them, or a proof's chain). */
type View = Pick<LogState, "keys" | "depts">;

const TYPE_PATTERN = /^[a-z][a-z0-9_]*(\.([a-z][a-z0-9_]*|\*))+$/;
const DEPT_ID = /^[a-z0-9][a-z0-9-]{0,47}$/;
/** Levels of nesting: a top-level department and up to three below it (secretariat → directorate → office → unit). */
export const DEPT_MAX_DEPTH = 4;

/** A department and the ones above it, nearest first. */
export function deptChain(depts: Record<string, DeptState>, id: string): string[] {
  const out: string[] = [];
  for (let d: string | undefined = id; d && depts[d] && out.length <= DEPT_MAX_DEPTH; d = depts[d].parent) out.push(d);
  return out;
}

/** Is department `id` `root` itself or somewhere under it? */
export const deptWithin = (depts: Record<string, DeptState>, id: string | undefined, root: string) => !!id && deptChain(depts, id).includes(root);

/** Does `scope.types` allow `type`? Exact match, or a "domain.*" wildcard. No types listed = any type. */
export function typeAllowed(scope: KeyScope | undefined, type: string): boolean {
  if (!scope?.types) return true;
  return scope.types.some((p) => (p.endsWith(".*") ? type.startsWith(p.slice(0, -1)) : p === type));
}

/** The department a key answers to: its own, or for a session, its person's. */
export function deptOf(keys: Record<string, KeyState>, k: KeyState): string | undefined {
  return k.delegatedBy ? keys[k.delegatedBy]?.dept : k.dept;
}

/** An admin of the whole institution (not a department head). */
export const isInstitutionAdmin = (k: KeyState) => k.info.role === "admin" && !k.dept;

/** A list of issuer event types, as a key scope or a department declares it: never the protocol's own. */
function checkTypes(types: unknown, what: string) {
  if (!Array.isArray(types) || !types.length || types.some((t) => typeof t !== "string" || !TYPE_PATTERN.test(t))) {
    throw new Error(`${what} must be a non-empty list like ["fee.paid", "case.*"]`);
  }
  if (types.some((t: string) => isReservedType(t))) throw new Error(`${what} cannot grant ${RESERVED_DOMAINS.map((d) => `${d}.*`).join(", ")} events`);
}

function readKey(e: HssEvent): KeyInfo {
  const k = e.public.key as unknown as KeyInfo | undefined;
  if (!k || typeof k !== "object") throw new Error(`${e.type} needs public.key`);
  if (!k.id || !k.publicKey || !["passkey", "ed25519"].includes(k.kind) || ![-7, -257, -8].includes(k.alg)) throw new Error("public.key is malformed");
  if (!["admin", "official", "system", "session"].includes(k.role) || !k.label) throw new Error("public.key needs a role (admin|official|system|session) and a label");
  if (k.kind === "passkey" && !k.rpId) throw new Error("a passkey needs its rpId");
  if (k.kind === "ed25519" && k.alg !== -8) throw new Error("an ed25519 key has alg -8");
  if (k.scope !== undefined) {
    if (typeof k.scope !== "object" || k.scope === null) throw new Error("key scope must be an object");
    if (k.scope.types !== undefined) checkTypes(k.scope.types, "scope.types");
    if (k.scope.expires !== undefined && Number.isNaN(Date.parse(k.scope.expires))) throw new Error("scope.expires must be an ISO 8601 date");
  }
  if (k.dept !== undefined && (typeof k.dept !== "string" || !DEPT_ID.test(k.dept))) throw new Error("key dept must be a department id (a lowercase slug)");
  if (k.role === "system" && !k.scope?.types) throw new Error("a system key must be scoped to some event types (scope.types)");
  if (k.role === "session" && (k.kind !== "ed25519" || !k.scope?.expires)) throw new Error("a session key is an ed25519 key with scope.expires");
  if (k.role === "session" && k.dept !== undefined) throw new Error("a session answers to its person's department; it does not declare one");
  if (k.holder !== undefined && (typeof k.holder !== "string" || !/^[0-9a-f]{64}$/.test(k.holder))) throw new Error("key holder must be a 32-byte hex commitment");
  if (k.holder !== undefined && k.role !== "admin" && k.role !== "official") throw new Error("only a person's key commits to its holder");
  return k;
}

function readDept(e: HssEvent): DeptInfo {
  const d = e.public.dept as unknown as DeptInfo | undefined;
  if (!d || typeof d !== "object") throw new Error(`${e.type} needs public.dept`);
  if (typeof d.id !== "string" || !DEPT_ID.test(d.id)) throw new Error("dept.id must be a lowercase slug like \"permits\"");
  if (d.parent !== undefined && (e.type !== SYSTEM_TYPES.deptAdd || typeof d.parent !== "string" || !DEPT_ID.test(d.parent))) {
    throw new Error(e.type === SYSTEM_TYPES.deptAdd ? "dept.parent must be a department id" : "a department keeps the place its dept.add gave it");
  }
  if (e.type === SYSTEM_TYPES.deptAdd && !d.name) throw new Error("dept.add needs a name");
  if (d.name !== undefined && (typeof d.name !== "string" || !d.name.trim() || d.name.length > 120)) throw new Error("dept.name must be a short text");
  if (d.types !== undefined && d.types !== null) checkTypes(d.types, "dept.types");
  if (d.closed !== undefined && (d.closed !== true || e.type !== SYSTEM_TYPES.deptUpdate)) throw new Error("only dept.update closes a department, with closed: true");
  return d;
}

const isPerson = (k: KeyState) => k.info.role === "admin" || k.info.role === "official";

/**
 * May `signer` sign `e` at all (role, scope, department, expiry)? `receivedAt` is the operator's clock when it accepts
 * the event; verifiers replaying a log leave it out and rely on the event's own time and its Bitcoin anchor.
 */
function checkSigner(view: View, signer: KeyState, e: HssEvent, receivedAt?: string) {
  const role = signer.info.role;
  if (e.type === SYSTEM_TYPES.update) {
    if (!isInstitutionAdmin(signer)) throw new Error(`${e.type} needs an institution admin key${role === "admin" ? " (department heads manage only their department's keys)" : ""}`);
  } else if (e.type === SYSTEM_TYPES.keyAdd || e.type === SYSTEM_TYPES.keyRevoke || e.type === SYSTEM_TYPES.deptAdd || e.type === SYSTEM_TYPES.deptUpdate || e.type === SYSTEM_TYPES.keyMove) {
    // A department head's reach (its own department and those under it) is checked against the event in grant().
    if (role !== "admin") throw new Error(`${e.type} needs an admin key`);
  } else if (e.type === SYSTEM_TYPES.sessionOpen) {
    if (!isPerson(signer)) throw new Error("only a person (admin or official) can open a session");
  } else if (e.type !== SYSTEM_TYPES.sessionClose && isReservedType(e.type)) {
    throw new Error(`${e.type} cannot be signed here`);
  }
  if (!typeAllowed(signer.info.scope, e.type) && e.type !== SYSTEM_TYPES.sessionClose) {
    throw new Error(`${signer.info.label} may only sign ${signer.info.scope!.types!.join(", ")}`);
  }
  // A department's scope binds the procedure steps of everyone in it, of their sessions, and of every department under it.
  if (!isSystemType(e.type)) {
    const id = deptOf(view.keys, signer);
    for (const d of id ? deptChain(view.depts, id) : []) {
      const dept = view.depts[d];
      if (dept.types && !typeAllowed({ types: dept.types }, e.type)) throw new Error(`${signer.info.label} signs for ${dept.name}, which may only sign ${dept.types.join(", ")}`);
    }
  }
  const expires = signer.info.scope?.expires;
  if (expires) {
    if (Date.parse(e.ts) > Date.parse(expires)) throw new Error(`${signer.info.label} expired at ${expires}`);
    if (receivedAt && Date.parse(receivedAt) > Date.parse(expires) + RECEIVE_GRACE_MS) throw new Error(`${signer.info.label} expired at ${expires}`);
  }
}

/** Checks a session.open's key against the event that opens it. */
function readSessionKey(e: HssEvent): KeyInfo {
  const key = readKey(e);
  if (key.role !== "session") throw new Error("session.open declares a key with role session");
  const opens = Date.parse(e.ts), expires = Date.parse(key.scope!.expires!);
  if (expires <= opens) throw new Error("a session must expire after it opens");
  if (expires - opens > SESSION_MAX_MS) throw new Error("a session lasts at most 30 days");
  return key;
}

const openDept = (view: View, id: string) => {
  const d = view.depts[id];
  if (!d || d.closedAt !== undefined) throw new Error(`no open department ${id}`);
  return d;
};

/** A department head acts only in its own department and the ones under it. */
const reach = (view: View, signer: KeyState, dept: string | undefined, what: string) => {
  if (signer.dept && !deptWithin(view.depts, dept, signer.dept)) throw new Error(`${signer.info.label} heads ${view.depts[signer.dept]?.name ?? signer.dept} and may only ${what} in it or under it`);
};

/**
 * The events that grant or move authority (key.add, session.open, dept.add, dept.update, key.move), applied to `view`
 * in place. Shared by the full replay and by a proof's authority chain. A chain holds only some of the keys, so the
 * checks that need all of them (a department closes empty, the institution keeps an admin) run only on the full log.
 */
async function grant(view: View, e: HssEvent, signer: KeyState, full: boolean) {
  // A new key's public code must not be one the institution already uses (only the full log knows every key).
  const coded = async (id: string) => {
    const code = await keyCode(e.issuer, id);
    if (full && Object.values(view.keys).some((k) => k.code === code)) throw new Error(`key code ${code} is already taken in this log: generate another key`);
    return code;
  };
  if (e.type === SYSTEM_TYPES.keyAdd) {
    const key = readKey(e);
    if (key.role === "session") throw new Error("session keys are opened with session.open, not key.add");
    if (view.keys[key.id]) throw new Error(`key ${key.id} already exists`);
    if (key.dept) openDept(view, key.dept);
    reach(view, signer, key.dept, "add keys");
    view.keys[key.id] = { info: key, addedAt: e.seq, ...(key.dept ? { dept: key.dept } : {}), code: await coded(key.id) };
  } else if (e.type === SYSTEM_TYPES.sessionOpen) {
    const key = readSessionKey(e);
    if (view.keys[key.id]) throw new Error(`key ${key.id} already exists`);
    view.keys[key.id] = { info: key, addedAt: e.seq, delegatedBy: e.actor, code: await coded(key.id) };
  } else if (e.type === SYSTEM_TYPES.deptAdd) {
    const d = readDept(e);
    if (view.depts[d.id]) throw new Error(`department ${d.id} already exists`);
    if (d.parent) {
      openDept(view, d.parent);
      if (deptChain(view.depts, d.parent).length >= DEPT_MAX_DEPTH) throw new Error(`departments nest at most ${DEPT_MAX_DEPTH} levels deep`);
    }
    reach(view, signer, d.parent, "open departments");
    view.depts[d.id] = { name: d.name!.trim(), ...(d.parent ? { parent: d.parent } : {}), ...(d.types ? { types: d.types } : {}), addedAt: e.seq };
  } else if (e.type === SYSTEM_TYPES.deptUpdate) {
    const d = readDept(e);
    const cur = openDept(view, d.id);
    // A head shapes the departments under theirs, not their own (its limits are set from above).
    if (signer.dept && (d.id === signer.dept || !deptWithin(view.depts, d.id, signer.dept))) throw new Error(`${signer.info.label} heads ${view.depts[signer.dept]?.name ?? signer.dept} and may only change the departments under it`);
    const next: DeptState = { ...cur, ...(d.name ? { name: d.name.trim() } : {}) };
    if (d.types === null) delete next.types;
    else if (d.types) next.types = d.types;
    if (d.closed) {
      if (full && Object.values(view.keys).some((k) => k.revokedAt === undefined && k.info.role !== "session" && k.dept === d.id)) throw new Error("a department closes only once it has no active keys: revoke or move them first");
      if (Object.values(view.depts).some((x) => x.parent === d.id && x.closedAt === undefined)) throw new Error("a department closes only once the departments under it are closed");
      next.closedAt = e.seq;
    }
    view.depts[d.id] = next;
  } else if (e.type === SYSTEM_TYPES.keyMove) {
    const id = String(e.public.keyId ?? "");
    const k = view.keys[id];
    if (!k || k.revokedAt !== undefined || k.info.role === "session") throw new Error(`no active key ${id} to move`);
    const to = e.public.dept === null || e.public.dept === undefined ? undefined : String(e.public.dept);
    if (to !== undefined) openDept(view, to);
    reach(view, signer, k.dept, "move keys");
    reach(view, signer, to, "move keys");
    if (full && to && isInstitutionAdmin(k) && !Object.values(view.keys).some((x) => x !== k && x.revokedAt === undefined && isInstitutionAdmin(x))) {
      throw new Error("cannot move the last institution admin into a department");
    }
    const { dept: _d, ...rest } = k;
    view.keys[id] = to ? { ...rest, dept: to } : rest;
  }
}

/** Checks `signed` against `state` (null before issuer.create) and returns the state after it. Throws on any violation. */
export async function applyEvent(state: LogState | null, signed: SignedEvent, opts: { receivedAt?: string } = {}): Promise<LogState> {
  const e = signed.event;
  checkShape(e);
  const hash = hex.encode(await eventHash(e));

  if (!state) {
    if (e.seq !== 0) throw new Error("a log starts with issuer.create at seq 0");
    const key = readKey(e);
    if (key.role !== "admin" || key.scope || key.dept) throw new Error("the founding key must be an unscoped institution admin");
    if (e.actor !== key.id) throw new Error("issuer.create is signed by the key it declares");
    await verifyEventSignature(e, signed.sig, key);
    const { key: _k, ...profile } = e.public;
    return { issuer: e.issuer, profile, head: { seq: 0, hash }, keys: { [key.id]: { info: key, addedAt: 0, code: await keyCode(e.issuer, key.id) } }, depts: {} };
  }

  if (e.issuer !== state.issuer) throw new Error(`event belongs to ${e.issuer}, not ${state.issuer}`);
  if (e.seq !== state.head.seq + 1) throw new Error(`expected seq ${state.head.seq + 1}, got ${e.seq}`);
  if (e.prev !== state.head.hash) throw new Error("prev does not match the log head");
  if (e.type === SYSTEM_TYPES.create) throw new Error("issuer.create only at seq 0");

  // States saved before departments existed have none.
  const next: LogState = { ...state, head: { seq: e.seq, hash }, keys: { ...state.keys }, depts: { ...(state.depts ?? {}) } };
  const signer = next.keys[e.actor];
  if (!signer) throw new Error(`unknown signer ${e.actor}`);
  if (signer.revokedAt !== undefined) throw new Error(`signer ${e.actor} was revoked at seq ${signer.revokedAt}`);
  checkSigner(next, signer, e, opts.receivedAt);
  await verifyEventSignature(e, signed.sig, signer.info);

  if (e.type === SYSTEM_TYPES.keyRevoke) {
    const id = String(e.public.keyId ?? "");
    const k = next.keys[id];
    if (!k || k.revokedAt !== undefined) throw new Error(`no active key ${id} to revoke`);
    reach(next, signer, deptOf(next.keys, k), "revoke keys");
    if (isInstitutionAdmin(k) && !Object.values(next.keys).some((x) => x !== k && x.revokedAt === undefined && isInstitutionAdmin(x))) throw new Error("cannot revoke the last institution admin");
    next.keys[id] = { ...k, revokedAt: e.seq };
    // A person's sessions die with their key.
    for (const [sid, s] of Object.entries(next.keys)) if (s.delegatedBy === id && s.revokedAt === undefined) next.keys[sid] = { ...s, revokedAt: e.seq };
  } else if (e.type === SYSTEM_TYPES.update) {
    const { key: _k, ...profile } = e.public;
    next.profile = { ...state.profile, ...profile };
  } else if (e.type === SYSTEM_TYPES.sessionClose) {
    const id = String(e.public.keyId ?? "");
    const k = next.keys[id];
    if (!k || k.info.role !== "session" || k.revokedAt !== undefined) throw new Error(`no open session ${id} to close`);
    const admin = signer.info.role === "admin" && (!signer.dept || deptWithin(next.depts, deptOf(next.keys, k), signer.dept));
    if (e.actor !== id && e.actor !== k.delegatedBy && !admin) throw new Error("a session is closed by its owner, itself or an admin over it");
    next.keys[id] = { ...k, revokedAt: e.seq };
  } else {
    await grant(next, e, signer, true);
  }
  return next;
}

export interface ReplayResult {
  state: LogState | null;
  /** Events accepted before the first problem. */
  valid: number;
  error?: { seq: number; message: string };
}

/** Replays a whole log from seq 0. Stops at the first broken link: gap, fork, bad signature, unauthorized signer. */
export async function replay(events: SignedEvent[]): Promise<ReplayResult> {
  let state: LogState | null = null;
  for (let i = 0; i < events.length; i++) {
    try { state = await applyEvent(state, events[i]); } catch (err) {
      return { state, valid: i, error: { seq: events[i].event.seq, message: (err as Error).message } };
    }
  }
  return { state, valid: events.length };
}

/** The events a proof's authority chain may carry after issuer.create. */
const AUTHORITY_TYPES: string[] = [SYSTEM_TYPES.keyAdd, SYSTEM_TYPES.sessionOpen, SYSTEM_TYPES.deptAdd, SYSTEM_TYPES.deptUpdate, SYSTEM_TYPES.keyMove];

/**
 * The authority chain a proof carries: issuer.create, then only the key.add and session.open events needed to reach
 * the signer of `target` (and the department events that shape it: dept.add, dept.update, key.move), each signed by a
 * key established earlier in the chain. Checks signatures, roles, scope, department and expiry without the full log
 * (revocations are only visible with the full log — see verify.ts `log` step). Returns the signer's key, its
 * department and, for a session, the person who delegated it.
 */
export async function checkAuthority(chain: SignedEvent[], target: HssEvent): Promise<KeyState & { delegator?: KeyState; department?: DeptState & { id: string } }> {
  const view: View = { keys: {}, depts: {} };
  let genesis: string | null = null;
  for (const s of chain) {
    const e = s.event;
    checkShape(e);
    if (e.issuer !== target.issuer) throw new Error("authority chain is for another issuer");
    if (e.seq > target.seq) throw new Error("authority event is later than the event");
    if (e.seq === target.seq && hex.encode(await eventHash(e)) !== hex.encode(await eventHash(target))) throw new Error("authority chain forks at the event's seq");
    if (e.seq === 0) {
      const key = readKey(e);
      if (e.actor !== key.id || key.role !== "admin" || key.dept) throw new Error("bad issuer.create");
      await verifyEventSignature(e, s.sig, key);
      view.keys[key.id] = { info: key, addedAt: 0, code: await keyCode(e.issuer, key.id) };
      genesis = hex.encode(await eventHash(e));
      continue;
    }
    if (!genesis) throw new Error("authority chain must start at issuer.create");
    if (!AUTHORITY_TYPES.includes(e.type)) throw new Error("authority chain may only hold key.add, session.open, dept.* and key.move after issuer.create");
    const signer = view.keys[e.actor];
    if (!signer || signer.addedAt >= e.seq) throw new Error(`${e.type} at seq ${e.seq} is not signed by a key established earlier`);
    checkSigner(view, signer, e);
    await verifyEventSignature(e, s.sig, signer.info);
    await grant(view, e, signer, false);
  }
  const signer = view.keys[target.actor];
  if (!signer) throw new Error(`signer ${target.actor} is not established by the authority chain`);
  if (signer.addedAt > target.seq) throw new Error("signer was added after the event");
  if (target.seq !== signer.addedAt) checkSigner(view, signer, target);
  const deptId = deptOf(view.keys, signer);
  const department = deptId && view.depts[deptId] ? { id: deptId, ...view.depts[deptId] } : undefined;
  return { ...signer, ...(signer.delegatedBy ? { delegator: view.keys[signer.delegatedBy] } : {}), ...(department ? { department } : {}) };
}

import type {
  AccessPolicy,
  JsonValue,
  ObserveRequest,
  ObserveResponse,
  RecallRequest,
  RecallResponse,
  RecallTrace,
  RequestContext,
  RequestOptions,
} from "./types.js";

export interface MemoryClient {
  observe(request: ObserveRequest, options?: RequestOptions): Promise<ObserveResponse>;
  recall(request: RecallRequest, options?: RequestOptions): Promise<RecallResponse>;
}

export interface AgentSessionOptions {
  readonly context: RequestContext;
  readonly access: AccessPolicy;
  readonly agentId: string;
  readonly sessionId: string;
}

export interface BeforeTurnOptions extends RequestOptions {
  readonly pageSize?: number;
  readonly atCommit?: number | null;
  readonly continuation?: string | null;
}

export interface AfterTurnOptions extends RequestOptions {
  readonly metadata?: Readonly<Record<string, JsonValue>>;
  readonly idempotencyKey?: string;
}

async function turnKey(
  sessionId: string,
  agentId: string,
  sequence: number,
  userMessage: string,
  assistantResponse: string,
): Promise<string> {
  if (globalThis.crypto?.subtle === undefined) {
    throw new Error("Web Crypto SHA-256 is required for deterministic idempotency keys");
  }
  const encoder = new TextEncoder();
  const chunks: Uint8Array[] = [encoder.encode("contextdb-agent-turn-v1\0")];
  const addText = (value: string): void => {
    const bytes = encoder.encode(value);
    const length = new Uint8Array(8);
    new DataView(length.buffer).setBigUint64(0, BigInt(bytes.byteLength), false);
    chunks.push(length, bytes);
  };
  addText(sessionId);
  addText(agentId);
  const encodedSequence = new Uint8Array(8);
  new DataView(encodedSequence.buffer).setBigUint64(0, BigInt(sequence), false);
  chunks.push(encodedSequence);
  addText(userMessage);
  addText(assistantResponse);
  const size = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const encoded = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    encoded.set(chunk, offset);
    offset += chunk.byteLength;
  }
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", encoded));
  const hex = Array.from(digest, (item) => item.toString(16).padStart(2, "0")).join("");
  return `agent-session:${sessionId}:${sequence}:${hex}`;
}

// AgentSession is provider-neutral before/after-turn orchestration. It keeps
// RequestContext explicit and never treats it as authentication.
export class AgentSession {
  private readonly client: MemoryClient;
  private readonly context: RequestContext;
  private readonly access: AccessPolicy;
  private readonly agentId: string;
  private readonly sessionId: string;
  private sequenceValue = 0;
  private recallSequence = 0;
  private lastTraceValue: RecallTrace | null = null;
  private lastContinuationValue: string | null = null;
  private tail: Promise<void> = Promise.resolve();

  constructor(client: MemoryClient, options: AgentSessionOptions) {
    if (options.agentId === "" || options.sessionId === "") {
      throw new TypeError("agentId and sessionId must be non-empty");
    }
    if (options.context.workspace_id !== options.access.workspace_id) {
      throw new TypeError("access policy and request context workspace differ");
    }
    this.client = client;
    this.context = {
      ...options.context,
      audiences: [...options.context.audiences],
      scopes: [...options.context.scopes],
    };
    this.access = {
      ...options.access,
      scopes: [...options.access.scopes],
      owners: [...options.access.owners],
      audience: [...options.access.audience],
      audience_purpose_grants: Object.fromEntries(
        Object.entries(options.access.audience_purpose_grants).map(([audience, purposes]) => [
          audience,
          [...purposes],
        ]),
      ),
      purposes: [...options.access.purposes],
    };
    this.agentId = options.agentId;
    this.sessionId = options.sessionId;
  }

  get sequence(): number {
    return this.sequenceValue;
  }

  get lastTrace(): RecallTrace | null {
    return this.lastTraceValue;
  }

  get lastContinuation(): string | null {
    return this.lastContinuationValue;
  }

  beforeTurn(message: string, options: BeforeTurnOptions = {}): Promise<RecallResponse> {
    return this.exclusive(async () => {
      const request: RecallRequest = {
        context: {
          ...this.context,
          request_id: `session:${this.sessionId}:before:${this.recallSequence}`,
        },
        query: message,
        page_size: options.pageSize ?? 20,
        at_commit: options.atCommit ?? null,
        continuation: options.continuation ?? null,
      };
      const requestOptions: { signal?: AbortSignal } = {};
      if (options.signal !== undefined) requestOptions.signal = options.signal;
      const response = await this.client.recall(request, requestOptions);
      this.recallSequence += 1;
      this.lastTraceValue = response.trace;
      this.lastContinuationValue = response.continuation;
      return response;
    });
  }

  afterTurn(userMessage: string, assistantResponse: string, options: AfterTurnOptions = {}): Promise<ObserveResponse> {
    return this.exclusive(async () => {
      const sequence = this.sequenceValue;
      const content = {
        kind: "chat_turn",
        session_id: this.sessionId,
        agent_id: this.agentId,
        sequence,
        user_message: userMessage,
        assistant_response: assistantResponse,
      } satisfies JsonValue;
      const metadata = {
        ...(options.metadata ?? {}),
        kind: "agent_session_turn",
        session_id: this.sessionId,
        agent_id: this.agentId,
        sequence,
      } satisfies Record<string, JsonValue>;
      const request: ObserveRequest = {
        context: {
          ...this.context,
          request_id: `session:${this.sessionId}:after:${sequence}`,
        },
        idempotency_key:
          options.idempotencyKey ||
          (await turnKey(this.sessionId, this.agentId, sequence, userMessage, assistantResponse)),
        observation_id: `session:${this.sessionId}:turn:${sequence}`,
        metadata,
        content,
        access: this.access,
      };
      const requestOptions: { signal?: AbortSignal } = {};
      if (options.signal !== undefined) requestOptions.signal = options.signal;
      const response = await this.client.observe(request, requestOptions);
      this.sequenceValue += 1;
      return response;
    });
  }

  private async exclusive<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.tail;
    let release: (() => void) | undefined;
    this.tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release?.();
    }
  }
}

# kekkai-actor

結界 — a **zero-trust mesh-overlay coordination actor**: a Tailscale-equivalent
**control plane** built as a sealed-intelligence ⊣ independent-governor
StateGraph. It coordinates a private mesh ("tailnet") of machines — admitting
devices, publishing a deny-by-default **netmap** (who-can-reach-whom), approving
subnet/exit routes — but it is the *control plane only*: it **never carries a
packet and never pushes WireGuard config**. The nodes pull the netmap and open
their own tunnels; the append-only ledger is the tailnet's immutable zero-trust
genealogy.

Built on this workspace's
[`langgraph-clj`](https://github.com/com-junkawasaki/langgraph-clj) StateGraph
runtime — the same pattern as
[`robotaxi-actor`](../robotaxi-actor) (AR1 ⊣ SafetyGovernor),
[`vehicle-design-actor`](../vehicle-design-actor) and
[`ai-gftd-itonami`](../../gftdcojp/ai-gftd-itonami) (ops-LLM ⊣ CertGovernor).
Here it is **coord-LLM ⊣ TailnetGovernor**.

> Charter: **(G1)** coordinate → publish-netmap only, no data-plane actuation —
> the actor proposes reachability, the nodes apply it; **(G2)** machine
> approval and exit-node approval are **always a human call** (high-stakes);
> **(G3)** kotoba-native — node/key/ACL/route facts are durable EAVT ground
> datoms, decisions are transient until committed; **(G4)** anti-surveillance —
> there is **no `:traffic/*` or `:user/activity` namespace**: the control plane
> authorizes *reachability*, it never logs what flows through the tunnels.

## The core contract

```
tailnet facts (node/heartbeat/user/ACL/route)
        │  ingest = durable EAVT ground datoms (observe; always on)
        ▼
   ┌──────────┐  proposal: admit /  ┌─────────────────┐
   │ coord-LLM │  netmap / approve   │ TailnetGovernor │  (independent system)
   │ (sealed)  │ ─────────────────▶ │  zero-trust      │
   └──────────┘  + cited facts       └────────┬────────┘
                            commit ◀──────────┼──────▶ hold (invalid key /
                                │                  │      unowned tag / deny-by-
                          netmap/membership    escalate    default / route hijack;
                          + genealogy              │        un-overridable)
                                                   ▼
                                          人間 admin 承認
                                     (machine & exit approval は常に人間)
```

**The actor never installs a reachability edge / admits a device / approves a
route the TailnetGovernor would reject, and never actuates the data plane.**
HARD zero-trust invariants force **hold** (a human cannot approve past an
expired/revoked node key, a self-claimed unowned tag, an un-permitted edge, or a
route hijack); a clean admission / exit node still routes to a human admin.

The Tailscale parallel runs all the way down to identity: a Tailscale node *is*
its node key. Here the actor *is* its Ed25519 key — the key-derived IPNS name is
its kotoba graph, so it **self-mints its own CACAO** (no coordination-server
auth-key, no human-handed token). See ADR-0002.

## Run

```bash
clojure -M:dev:run     # drive a tailnet: admit / netmap / route through the actor
clojure -M:dev:test    # the zero-trust contract + store parity + CACAO crypto
clojure -M:lint        # clj-kondo (errors fail)
```

Demo: register a device + heartbeat (observe → datoms) → admit a clean device
(machine approval → admin approves) → **hold** a rogue device on `:tag-not-owned
:expired-key` → publish a deny-by-default **netmap** for a laptop → exit-node
route → human sign-off → phase-0 disables decisions → prints the genealogy
ledger → swaps to DatomicStore with identical results.

## Layout

| File | Role |
|---|---|
| `src/kekkai/store.cljc` | **Store** protocol — `MemStore` ‖ `DatomicStore` (`langchain.db`, swappable to Datomic Local / kotoba-server) + append-only **tailnet genealogy ledger** |
| `src/kekkai/acl.cljc` | pure **deny-by-default ACL** evaluation (tag ownership · edge grants · reachable peers) — shared by governor & coord-LLM, no I/O |
| `src/kekkai/coordllm.cljc` | **coord-LLM Advisor** — `mock-advisor` ‖ `llm-advisor` (`langchain.model`); admit / netmap / route proposals |
| `src/kekkai/governor.cljc` | **TailnetGovernor** — node-key validity · tag ownership · deny-by-default · route-no-hijack · no-actuation · high-stakes |
| `src/kekkai/phase.cljc` | **Phase 0→3** — observe-only → assisted → supervised (admission & exit always human) |
| `src/kekkai/operation.cljc` | **CoordinationActor** — langgraph-clj StateGraph; ingest vs assess flows |
| `src/kekkai/cacao.clj` | agent-side **CACAO self-mint** (JVM Ed25519 + did:key + CBOR; per-actor node key) |
| `src/kekkai/kotoba.clj` | wire `DatomicStore` to a kotoba-server pod (kotobase.net XRPC) |
| `src/kekkai/sim.cljc` | demo driver |
| `test/kekkai/*_test.clj` | zero-trust contract · store parity (Mem≡Datomic) · CACAO — **19 tests / 66 assertions** |

## Tailscale → kekkai mapping

| Tailscale | kekkai |
|---|---|
| coordination server (control plane) | the `CoordinationActor` (sealed coord-LLM) |
| node key (WireGuard / machine identity) | the node's `did:key`; the actor's own key = its kotoba graph |
| machine approval | `:node/admit` → high-stakes → human admin (`interrupt-before`) |
| ACL policy (HuJSON, deny-by-default) | `kekkai.acl` over the published `:policy` datom |
| netmap (peer map a node receives) | `:access/assess` → committed netmap assessment |
| subnet routes / exit nodes | `:route/advertise` (observe) → `:route/approve` (exit = human) |
| `tailscale up` actuating WireGuard | **out of scope by charter** — the node does this, not the actor |
| auth keys / SSO-issued tokens | **none** — the actor self-mints CACAO from its own key |

## 本番バックエンド（injection）

`DatomicStore` は `langchain.db` の `:db-api` マップ（`{:q :transact! :db :pull
:entid}`）越しにしか喋らない。`langchain.db/api`（in-process）と
`langchain.kotoba-db/kotoba-api`（kotoba-server XRPC）は同じマップを実装するので、
**同じ record が backend を選ばず動く**（`store_contract_test` で保証）。

```clojure
;; actor ごとに鍵を発行し、自分の鍵由来 graph を所有 → CACAO 自己発行（ADR-0002）
(require '[kekkai.kotoba :as k] '[kekkai.cacao :as cacao] '[clojure.data.json :as json])
(def me    (cacao/load-or-create-identity! ".kekkai/identity.edn"))  ; 初回生成→永続
;; me => {:did "did:key:z6Mk…" :graph "k51qzi5uqu5d…" …}  graph = 鍵由来 IPNS = node key
(def store (k/kotoba-store {:url "https://kotobase.net"
                            :json-write json/write-str
                            :json-read #(json/read-str % :key-fn keyword)
                            :identity me}))   ; graph 既定=me の鍵由来 IPNS、自己 mint

;; coord-LLM → 実LLM
(require '[langchain.model :as model] '[kekkai.operation :as op] '[kekkai.coordllm :as c])
(op/build store {:advisor (c/llm-advisor
                            (model/anthropic-model {:api-key … :http-fn … :json-write … :json-read …}))})
;; phase は context の :phase 0..3 で注入
```

不正・破損 LLM 応答は confidence 0 / noop に落ち、**TailnetGovernor が必ず
hold/escalate** する（LLM 不調が「ノード参加」「到達edge」になる経路は構造的に無い）。

## Status

設計実装 + **kotoba-server(kotobase.net) backend 配線**まで完了。runnable +
**19 tests / 66 assertions / 0 failures**、lint clean。Store は `:db-api` 駆動で
`MemStore ≡ DatomicStore(langchain.db) ≡ kotoba-store(kotobase.net)` が同一契約。
CACAO 自己発行はオフライン検証済み（did:key `z6Mk…`・graph `k51qzi5uqu5d…`・SIWE
署名 verify・CBOR map(3)・永続 round-trip）。**live は未確認**: kotobase.net の
datomic origin が 522（Cloudflare upstream timeout）の間はサーバ側検証が走らない
（ai-gftd-itonami ADR-0002 と同じ既知状況、owner 認可は不要）。

残り: kotobase.net origin 復帰時の live 結合 1 回・実 LLM（一般 API key）・
AT-Protocol XRPC（lexicon）境界の配線・WireGuard データ面エージェント（charter
外の別コンポーネント）との netmap 受け渡し。CI workflow は superproject 実行。

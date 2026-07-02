(ns kekkai.query
  "Pure zero-trust status lookups for a kekkai Store.

  No LLM/governor involved — `kekkai.operation`'s CoordinationActor is how a
  node GETS to `authorized` (coord-LLM proposes admission, TailnetGovernor
  censors it, high-stakes admission always routes to a human). This ns only
  READS that already-committed ground fact, for callers that need to gate on
  current admission state without running the actor (e.g. murakumo's fleet
  reachability — see kotoba-lang/murakumo's `murakumo.kekkai`)."
  (:require [kekkai.store :as store]))

(defn status-of
  "The node's kekkai admission status (\"authorized\"/\"pending\"/\"expired\"/
  \"revoked\"), or \"unknown\" if the node has never been registered in this
  store."
  [st node-id]
  (or (:status (store/node st node-id)) "unknown"))

(defn authorized?
  "True only when the node has been admitted (status = \"authorized\").
  Deny-by-default: unknown/pending/expired/revoked all fall through to false."
  [st node-id]
  (= "authorized" (status-of st node-id)))

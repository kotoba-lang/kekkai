(ns kekkai.acl
  "Pure, deny-by-default ACL evaluation over the published policy — the zero-
  trust core (the kekkai analog of a Tailscale HuJSON policy). No I/O, no store:
  it takes plain node/policy maps so BOTH the independent TailnetGovernor and
  the mock coord-LLM can evaluate the same rules without sharing code that would
  couple the censor to the proposer.

  A node 'matches' a selector if the selector names the node's owner (user) or
  any tag the node carries. An edge src→dst is allowed iff some grant's :src
  matches src and :dst matches dst — there is NO implicit allow."
  (:require [clojure.set :as set]))

(defn principals
  "The set of selector tokens a node satisfies: its owner login-id plus tags."
  [node]
  (into #{(:user node)} (:tags node)))

(defn- selector-matches? [selectors principals]
  (boolean (seq (set/intersection (set selectors) principals))))

(defn edge-allowed?
  "Does the policy permit `src-node` to reach `dst-node`? Returns the matching
  grant's allowed ports (a vector, possibly [\"*\"]) or nil if denied."
  [policy src-node dst-node]
  (let [sp (principals src-node) dp (principals dst-node)]
    (some (fn [{:keys [src dst ports]}]
            (when (and (selector-matches? src sp) (selector-matches? dst dp))
              (vec ports)))
          (:grants policy))))

(defn reachable-peers
  "Every authorized, key-valid peer `src-node` may reach under the policy, as
  [{:peer id :ports [...]}]. `now` gates expired keys; `peer-ok?` gates status."
  [policy src-node candidate-nodes now]
  (->> candidate-nodes
       (remove #(= (:id %) (:id src-node)))
       (keep (fn [dst]
               (when (and (= "authorized" (:status dst))
                          (number? (:key-expiry dst)) (> (:key-expiry dst) now))
                 (when-let [ports (edge-allowed? policy src-node dst)]
                   {:peer (:id dst) :ports ports}))))
       vec))

(defn tag-owned?
  "Is `tag` authorized for `user` by the policy's tag-owners? Untagged-but-owned
  selectors (a bare user) are always self-owned."
  [policy user tag]
  (boolean (some #{user} (get-in policy [:tag-owners tag]))))

(defn unowned-tags
  "Tags a node claims that its owner is NOT authorized to assume (privilege
  escalation via self-claimed tags)."
  [policy node]
  (vec (remove #(tag-owned? policy (:user node) %) (:tags node))))

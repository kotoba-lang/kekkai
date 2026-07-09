(ns kekkai.governor
  "TailnetGovernor — the independent zero-trust layer that earns the coord-LLM
  the right to *propose* netmaps. The LLM has no notion of node-key validity,
  deny-by-default ACLs, tag ownership or the no-actuation charter, so this MUST
  be a separate system (rules over the EAVT ground datoms) able to *reject* a
  proposal and fall back to HOLD — the kekkai analog of robotaxi's MRC /
  itonami's cert hold.

  The actor is **coordinate → publish-netmap only**. It never pushes WireGuard
  config to a node and never carries a packet; admitting a machine into the
  tailnet is ALWAYS routed to a human admin (the Tailscale 'machine approval'
  toggle), and so is approving an exit node. Below, HARD invariants force HOLD
  (a human cannot approve past an unowned tag, an expired/revoked key, an
  un-permitted reachability edge, or a route hijack); a clean admission/exit
  still routes to a human (high-stakes).

  HARD invariants:
    :node/admit
      1. Valid node key   — node presents a did:key, status ≠ revoked, key not
                            expired (key-expiry > now).
      2. Tag ownership     — every tag the node claims is authorized for its
                            owner by the policy's tag-owners (no self-escalation).
      3. No-actuation      — effect must be :netmap (a control-plane record),
                            never a data-plane / WireGuard push.
    :access/assess
      1. Valid node key on the subject AND every proposed peer.
      2. Deny-by-default   — every proposed reachability edge is backed by an
                            ACL grant; an unbacked edge is rejected.
      3. No-actuation.
    :route/approve
      1. Valid node key on the advertising node.
      2. No-hijack         — the cidr is not already approved for a DIFFERENT
                            node (no silent route takeover).
      3. No-actuation.
  SOFT:
    4. Confidence floor → escalate.
    5. Node admission and exit-route approval are high-stakes → ALWAYS human."
  (:require [clojure.string :as str]
            [kekkai.acl :as acl]
            [kekkai.store :as store]))

(def confidence-floor 0.6)

(defn- now-of [request] (:now request store/demo-now))

;; ───────────────────────── invariant checks ─────────────────────────

(defn- key-violations [nd now label]
  (cond-> []
    (nil? nd)
    (conj {:rule :no-node :detail (str "未登録ノード " label)})
    (and nd (str/blank? (:did nd)))
    (conj {:rule :no-node-key :detail "node key(did:key)未提示"})
    (and nd (= "revoked" (:status nd)))
    (conj {:rule :revoked-key :detail "ノード鍵が失効済み(revoked)"})
    (and nd (number? (:key-expiry nd)) (<= (:key-expiry nd) now))
    (conj {:rule :expired-key :detail "ノード鍵の有効期限切れ"})))

(defn- tag-violations [policy nd]
  (let [bad (acl/unowned-tags policy nd)]
    (when (seq bad)
      [{:rule :tag-not-owned
        :detail (str "所有者が認可されていない tag を主張: " bad)}])))

(defn- actuation-violations [proposal]
  ;; coordinate→publish-netmap: the actor writes a :netmap control-plane record,
  ;; never a WireGuard/data-plane push.
  (when (not= :netmap (:effect proposal))
    [{:rule :no-actuation
      :detail (str "actor はデータ面(WireGuard)を作動させない(coordinate→netmap)。effect="
                   (:effect proposal))}]))

(defn- deny-by-default-violations [policy subject proposal st now]
  ;; every proposed peer edge must be backed by a grant AND the peer must be a
  ;; live authorized node — zero-trust: no implicit allow.
  (->> (:peers proposal)
       (keep (fn [{:keys [peer]}]
               (let [pn (store/node st peer)]
                 (cond
                   (seq (key-violations pn now peer))
                   {:rule :peer-key-invalid :detail (str "到達先ノード鍵が無効: " peer)}
                   (not= "authorized" (:status pn))
                   {:rule :peer-unauthorized :detail (str "到達先が未認可: " peer)}
                   (nil? (acl/edge-allowed? policy subject pn))
                   {:rule :deny-by-default
                    :detail (str "ACL grant のない到達edgeを提案: → " peer)}))))
       vec))

(defn- hijack-violations [st node-id route]
  (when route
    (let [conflict (->> (store/all-routes st)
                        (filter #(and (= (:cidr route) (:cidr %))
                                      (not= node-id (:node %))
                                      (:approved? %))))]
      (when (seq conflict)
        [{:rule :route-hijack
          :detail (str (:cidr route) " は既に別ノードに承認済み: " (mapv :node conflict))}]))))

(defn check
  "Censors a coord-LLM proposal for a tailnet op. Returns
   {:ok? :violations :confidence :hard? :escalate? :high-stakes?}.

   Hard violations force HOLD and cannot be overridden. Node admission and exit-
   route approval are high-stakes → human admin sign-off even when clean."
  [request proposal st]
  (let [now    (now-of request)
        policy (store/policy st)
        subj   (store/node st (:node request))
        route  (when (= :route/approve (:op request))
                 (first (filter #(= (:route request) (:id %)) (store/routes-of st (:node request)))))
        hard (case (:op request)
               :node/admit
               (into [] (concat (key-violations subj now (:node request))
                                (tag-violations policy subj)
                                (actuation-violations proposal)))
               :access/assess
               (into [] (concat (key-violations subj now (:node request))
                                (deny-by-default-violations policy subj proposal st now)
                                (actuation-violations proposal)))
               :route/approve
               (into [] (concat (key-violations subj now (:node request))
                                (hijack-violations st (:node request) route)
                                (actuation-violations proposal)))
               ;; an unrecognized :op is itself a hard violation (fail-closed:
               ;; a not-yet-wired op must never silently pass as clean) --
               ;; same invariant denrei/koyomi/tayori's governors already
               ;; enforce for their own ops.
               [{:rule :unrecognized-op :detail (str "未対応 op: " (:op request))}])
        conf    (:confidence proposal 0.0)
        low?    (< conf confidence-floor)
        stakes? (or (= :node/admit (:op request))
                    (and (= :route/approve (:op request)) (= "exit" (:kind route))))
        hard?   (boolean (seq hard))]
    {:ok?          (and (not hard?) (not low?) (not stakes?))
     :violations   hard
     :confidence   conf
     :hard?        hard?
     :escalate?    (and (not hard?) (or low? stakes?))
     :high-stakes? stakes?}))

(defn hold-fact [request verdict]
  {:t :tailnet-hold :op (:op request) :node (:node request)
   :disposition :hold :basis (mapv :rule (:violations verdict))
   :violations (:violations verdict) :confidence (:confidence verdict)})

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
    :treasury/release (ADR-2607110300 Phase 3 -- widens this governor's remit
                       from network reachability to value: same deny-by-
                       default philosophy as acl.cljc's edge-allowed?, now
                       gating fund release on a witness-quorum verdict
                       instead of an ACL grant)
      1. Valid node key   — same identity check as every other op; the
                            requesting actor must be a live, non-revoked,
                            non-expired node (an actor has its own did:key,
                            per the CLAUDE.md Actor pattern).
      2. Witness quorum    — deny-by-default for value: an absent or
                            non-:witnessed witness-quorum verdict
                            (kotoba.lang.witness-quorum's :kind, injected via
                            the proposal, never vendored here) is a hard
                            violation, exactly like an unbacked reachability
                            edge is under :access/assess.
      3. No-actuation      — effect must be :treasury-release (a record for a
                            separate settlement step to read and execute);
                            this governor never moves funds itself.
    :witness/dispute (ADR-2607110300 Phase 4 -- a contested slashing
                      verdict; there is no automated dispute-resolution
                      algorithm anywhere in this system, deliberately: per
                      the ADR's own alternatives-considered section,
                      designing dispute economics against a hypothetical
                      counterparty is not verifiable today. This op
                      therefore has exactly one behavior: record the
                      dispute and ALWAYS escalate, unconditionally — never
                      auto-resolves, regardless of confidence or how clean
                      the proposal looks)
      1. Valid node key   — the disputing actor must itself be a live,
                            non-revoked, non-expired node.
      2. No-actuation      — effect must be :dispute-record (a record for
                            a human to read and decide); this governor
                            never resolves a dispute itself.
    :availability/slash (mirrors :treasury/release's shape exactly, but for
                         the punitive side of value: gates a slashing
                         action on a caller-supplied retrieval-availability
                         verdict from kotoba-lang/kotobase-peer's
                         availability.cljc `audit-outcome`
                         — `{:kotobase.availability/node ...
                            :kotobase.availability/cid ...
                            :kotobase.availability/epoch ...
                            :kotobase.availability/verdict ...}` —
                         instead of a witness-quorum verdict. This governor
                         does not run the retrieval audit itself, same
                         'caller collects, governor only censors' split as
                         witness-verdict-violations.)
      1. Valid node key   — same identity check as every other op; the
                            requesting actor must be a live, non-revoked,
                            non-expired node.
      2. Proof must have actually failed — deny-by-default for punitive
                            action: an absent verdict, or a verdict whose
                            `:kotobase.availability/verdict` is anything
                            other than :failed/:missed (i.e. :ok,
                            :malformed, or :verifier-lacks-replica — an
                            inconclusive outcome), is a hard violation.
                            Ambiguous evidence never authorizes a slash,
                            exactly like an unbacked reachability edge is
                            under :access/assess or a non-:witnessed
                            verdict is under :treasury/release.
      3. No-actuation      — effect must be :slash-record (a record for a
                            separate settlement step to read and execute);
                            this governor never adjusts balances or
                            reputation itself.
  SOFT:
    4. Confidence floor → escalate.
    5. Node admission, exit-route approval, treasury release, witness
       disputes, AND availability slashing are all high-stakes → ALWAYS
       human. Disputes go further than the others: confidence is
       irrelevant, there is no path to :ok? at all for this op."
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

(defn- ports-within-grant?
  "True iff every port the proposal claims for a peer is actually covered by
  the matching grant's `granted` ports. `[\"*\"]` in the GRANT is the only
  legitimate wildcard (matches anything); a wildcard/absent :ports on the
  PROPOSAL is never trusted on its own -- it must still be checked against
  what the grant actually allows.

  An omitted/empty `proposed` is NOT auto-accepted: (every? pred []) is
  vacuously true, which would silently trust an under-specified proposal
  (no :ports claimed at all) unless the grant itself is a full [\"*\"]
  wildcard -- matching this function's own documented intent rather than
  defaulting open on missing information."
  [granted proposed]
  (cond
    (= ["*"] (vec granted)) true
    (empty? proposed)       false
    :else                   (every? (set granted) proposed)))

(defn- deny-by-default-violations [policy subject proposal st now]
  ;; every proposed peer edge must be backed by a grant AND the peer must be a
  ;; live authorized node — zero-trust: no implicit allow. A grant existing at
  ;; all is not enough: the proposal's claimed :ports must also fit inside the
  ;; grant's actual allowed ports, or a proposal can silently over-claim
  ;; access (e.g. claiming ["*"] against a grant scoped to [22 443]) and still
  ;; pass as "backed by a grant."
  (->> (:peers proposal)
       (keep (fn [{:keys [peer ports]}]
               (let [pn (store/node st peer)
                     granted (acl/edge-allowed? policy subject pn)]
                 (cond
                   (seq (key-violations pn now peer))
                   {:rule :peer-key-invalid :detail (str "到達先ノード鍵が無効: " peer)}
                   (not= "authorized" (:status pn))
                   {:rule :peer-unauthorized :detail (str "到達先が未認可: " peer)}
                   (nil? granted)
                   {:rule :deny-by-default
                    :detail (str "ACL grant のない到達edgeを提案: → " peer)}
                   (not (ports-within-grant? granted (or ports [])))
                   {:rule :deny-by-default
                    :detail (str "grant の許可範囲(" granted ")を超えるportを提案: → " peer " " ports)}))))
       vec))

(defn- witness-verdict-violations
  "Deny-by-default for value release (ADR-2607110300 Phase 3): mirrors
  deny-by-default-violations' philosophy (no implicit allow) but the
  'grant' is a witness-quorum verdict instead of an ACL edge. `proposal`
  carries `:witness-verdict` — the caller's own witness-quorum result map
  (`{:kind :witnessed|:rejected|:pending|:escalated ...}`, the same shape
  kotoba.lang.witness-quorum.quorum/quorum-state returns and
  cloud-murakumo.ledger.witness/witness-run threads through as `:state`).
  This governor does not run quorum collection itself -- it only censors
  the verdict a caller already collected, same as it never runs ACL
  matching itself in isolation from acl.cljc."
  [proposal]
  (let [verdict (:witness-verdict proposal)]
    (cond
      (nil? verdict)
      [{:rule :no-witness-verdict :detail "witness quorum の検証結果が提示されていない"}]
      (not= :witnessed (:kind verdict))
      [{:rule :witness-quorum-not-reached
        :detail (str "witness quorum が到達していない: " (:kind verdict))}]
      :else [])))

(defn- treasury-actuation-violations
  "Same no-actuation philosophy as actuation-violations, scoped to the
  value-release effect: an approved proposal must resolve to a
  :treasury-release record for a separate settlement step, never a direct
  fund movement carried by this governor."
  [proposal]
  (when (not= :treasury-release (:effect proposal))
    [{:rule :no-actuation
      :detail (str "actor は treasury 残高を直接動かさない(govern は hold|commit のみ)。effect="
                   (:effect proposal))}]))

(defn- dispute-actuation-violations
  "Same no-actuation philosophy as actuation-violations/
  treasury-actuation-violations, scoped to disputes: an approved proposal
  must resolve to a :dispute-record for a human to read and decide, never
  a resolution this governor computes itself. There is deliberately no
  'dispute-resolved-in-favor-of-X' verdict shape anywhere in this
  namespace (ADR-2607110300 Phase 4)."
  [proposal]
  (when (not= :dispute-record (:effect proposal))
    [{:rule :no-actuation
      :detail (str "actor は異議申立ての記録のみを行い、判定は行わない(必ず human が最終判断)。effect="
                   (:effect proposal))}]))

(defn- retrieval-verdict-violations
  "Deny-by-default for punitive action: mirrors witness-verdict-violations'
  philosophy (no implicit allow) but the 'grant' is a retrieval-availability
  proof instead of a witness-quorum verdict. `proposal` carries
  `:retrieval-verdict` — the caller's own audit-outcome result map (same
  shape kotoba-lang/kotobase-peer's availability.cljc `audit-outcome`
  returns: `{:kotobase.availability/node ... :kotobase.availability/cid ...
  :kotobase.availability/epoch ... :kotobase.availability/verdict v}`).
  This governor does not run the retrieval audit itself -- it only censors
  the verdict a caller already collected, same as it never runs witness
  quorum collection in isolation from witness-verdict-violations. Only
  :failed/:missed authorize a slash; :ok, :malformed and
  :verifier-lacks-replica are inconclusive outcomes and must never
  authorize a punitive action."
  [proposal]
  (let [verdict (:retrieval-verdict proposal)]
    (cond
      (nil? verdict)
      [{:rule :no-retrieval-verdict :detail "retrieval-availability の検証結果が提示されていない"}]
      (not (#{:failed :missed} (:kotobase.availability/verdict verdict)))
      [{:rule :retrieval-proof-not-failed
        :detail (str "retrieval-availability 証明が失敗/未達ではない(slash不可): "
                     (:kotobase.availability/verdict verdict))}]
      :else [])))

(defn- slash-actuation-violations
  "Same no-actuation philosophy as actuation-violations/
  treasury-actuation-violations, scoped to slashing: an approved proposal
  must resolve to a :slash-record for a separate settlement step to read
  and execute, never a direct balance/reputation adjustment carried by
  this governor."
  [proposal]
  (when (not= :slash-record (:effect proposal))
    [{:rule :no-actuation
      :detail (str "actor はノードの残高/reputationを直接動かさない(govern は record のみ)。effect="
                   (:effect proposal))}]))

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
               :treasury/release
               (into [] (concat (key-violations subj now (:node request))
                                (witness-verdict-violations proposal)
                                (treasury-actuation-violations proposal)))
               :witness/dispute
               (into [] (concat (key-violations subj now (:node request))
                                (dispute-actuation-violations proposal)))
               :availability/slash
               (into [] (concat (key-violations subj now (:node request))
                                (retrieval-verdict-violations proposal)
                                (slash-actuation-violations proposal)))
               ;; an unrecognized :op is itself a hard violation (fail-closed:
               ;; a not-yet-wired op must never silently pass as clean) --
               ;; same invariant denrei/koyomi/tayori's governors already
               ;; enforce for their own ops.
               [{:rule :unrecognized-op :detail (str "未対応 op: " (:op request))}])
        conf    (:confidence proposal 0.0)
        low?    (< conf confidence-floor)
        stakes? (or (= :node/admit (:op request))
                    (= :treasury/release (:op request))
                    (= :witness/dispute (:op request))
                    (= :availability/slash (:op request))
                    (and (= :route/approve (:op request)) (= "exit" (:kind route))))
        hard?   (boolean (seq hard))]
    {:ok?          (and (not hard?) (not low?) (not stakes?))
     :violations   hard
     :confidence   conf
     :hard?        hard?
     :escalate?    (and (not hard?) (or low? stakes?))
     :high-stakes? stakes?}))

(defn hold-fact [request verdict]
  {:t (case (:op request)
        :treasury/release :treasury-hold
        :witness/dispute :witness-dispute-hold
        :availability/slash :availability-slash-hold
        :tailnet-hold)
   :op (:op request) :node (:node request)
   :disposition :hold :basis (mapv :rule (:violations verdict))
   :violations (:violations verdict) :confidence (:confidence verdict)})

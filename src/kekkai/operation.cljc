(ns kekkai.operation
  "CoordinationActor — one tailnet control-plane operation = one supervised
  actor run, a langgraph-clj StateGraph. Two flows share one auditable graph:

    ingest (record-op):  intake → record → END
        node/heartbeat/user/acl/route become durable EAVT ground datoms. This
        is the observe charter; always on, never an LLM call, never a data-plane
        push.

    assess (assess-op):  intake → advise → govern → decide → commit|hold|approval
        the coord-LLM (sealed) proposes an admission / netmap / route decision;
        the TailnetGovernor enforces zero-trust invariants (node-key validity,
        deny-by-default ACL, tag ownership, no route hijack, no actuation); the
        phase gate adds caution; admitting a machine or approving an exit node
        ALWAYS routes to a human admin (interrupt-before :request-approval).

  Single invariant (the kekkai analog of robotaxi's safety contract):
    the actor never installs a reachability edge / admits a device / approves a
    route the TailnetGovernor would reject, and never actuates the data plane
    (it publishes a netmap; the nodes open their own WireGuard tunnels)."
  (:require [langgraph.graph :as g]
            [langgraph.checkpoint :as cp]
            [kekkai.coordllm :as coordllm]
            [kekkai.governor :as gov]
            [kekkai.phase :as phase]
            [kekkai.store :as store]))

(defn- request->record
  "Map an ingest request to a store ground-datom record."
  [{:keys [op node user route value]}]
  (case op
    :node/register   {:kind :node      :id node  :value value}
    :node/heartbeat  {:kind :heartbeat :id node  :value value}
    :user/register   {:kind :user      :id user  :value value}
    :acl/publish     {:kind :policy     :id "the" :value value}
    :route/advertise {:kind :route     :id route :value value}))

(defn- subject [{:keys [node user]}] (or node user))

(defn- commit-effects!
  "Apply the op-specific control-plane write on commit. Admission flips the
  node to authorized (a membership record, NOT a data-plane push); route
  approval flips the advertised route's approved? flag. Both are recorded as
  ground datoms — never a WireGuard actuation."
  [store {:keys [op node route]}]
  (case op
    :node/admit    (store/record-datom! store {:kind :node :id node :value {:status "authorized"}})
    :route/approve (when-let [r (first (filter #(= route (:id %)) (store/routes-of store node)))]
                     (store/record-datom! store {:kind :route :id route
                                                 :value (assoc r :approved? true)}))
    nil))

(defn build
  "Compiles a CoordinationActor bound to `store` (any kekkai.store/Store).
  opts: :advisor (default mock), :checkpointer (default in-mem)."
  [store & [{:keys [advisor checkpointer]
             :or   {advisor      (coordllm/mock-advisor)
                    checkpointer (cp/mem-checkpointer)}}]]
  (-> (g/state-graph
       {:channels
        {:request     {:default nil}
         :context     {:default nil}   ; :phase + (future) authn
         :proposal    {:default nil}
         :verdict     {:default nil}
         :disposition {:default nil}
         :record      {:default nil}
         :approval    {:default nil}
         :audit       {:reducer into :default []}}})

      (g/add-node :intake (fn [s] s))

      ;; ── ingest path: record a ground datom (observe), no LLM/governor ──
      (g/add-node :record
        (fn [{:keys [request]}]
          (let [rec (request->record request)
                f   {:t :recorded :op (:op request) :subject (subject request)
                     :disposition :record :basis (:kind rec)}]
            (store/record-datom! store rec)
            (store/append-ledger! store f)
            {:disposition :record :audit [f]})))

      ;; ── assess path ──
      (g/add-node :advise
        (fn [{:keys [request]}]
          (let [p (coordllm/-advise advisor store request)]
            {:proposal p :audit [(coordllm/trace request p)]})))

      (g/add-node :govern
        (fn [{:keys [request proposal]}]
          {:verdict (gov/check request proposal store)}))

      (g/add-node :decide
        (fn [{:keys [request context proposal verdict]}]
          (let [base (phase/verdict->disposition verdict)
                ph   (:phase context phase/default-phase)
                {:keys [disposition reason]} (phase/gate ph request base)]
            (case disposition
              :hold
              {:disposition :hold
               :audit [(cond-> (gov/hold-fact request verdict)
                         reason (assoc :phase-reason reason :phase ph))]}
              :escalate
              {:disposition :escalate
               :audit [{:t :approval-requested :op (:op request) :node (subject request)
                        :reason (or reason (if (:high-stakes? verdict) :admin-signoff
                                               :low-confidence))
                        :recommendation (:recommendation proposal)
                        :phase ph :confidence (:confidence verdict)}]}
              :commit
              {:disposition :commit
               :record {:kind :assessment :id (subject request)
                        :value {:recommendation (:recommendation proposal)
                                :summary (:summary proposal)
                                :peers (:peers proposal) :route (:route proposal)
                                :by :auto}}}))))

      (g/add-node :request-approval
        (fn [{:keys [request proposal approval verdict]}]
          (if (= :approved (:status approval))
            {:disposition :commit
             :record {:kind :assessment :id (subject request)
                      :value {:recommendation (:recommendation proposal)
                              :summary (:summary proposal)
                              :peers (:peers proposal) :route (:route proposal)
                              :approved-by (:by approval)}}
             :audit [{:t :admin-signoff :op (:op request)
                      :node (subject request) :by (:by approval)
                      :recommendation (:recommendation proposal)}]}
            {:disposition :hold
             :audit [(merge (gov/hold-fact request
                                           (assoc verdict :violations
                                                  [{:rule :admin-rejected}]))
                            {:t :signoff-rejected})]})))

      ;; commit an assessment datom + op-specific control-plane write + ledger.
      (g/add-node :commit
        (fn [{:keys [request record]}]
          (store/record-datom! store record)
          (commit-effects! store request)
          (let [f {:t :committed :op (:op request) :subject (subject request)
                   :disposition :commit :basis (get-in record [:value :recommendation])}]
            (store/append-ledger! store f)
            {:audit [f]})))

      (g/add-node :hold
        (fn [{:keys [audit]}]
          (when-let [hf (last (filter #(#{:tailnet-hold :signoff-rejected} (:t %)) audit))]
            (store/append-ledger! store (assoc hf :disposition :hold)))
          {}))

      (g/set-entry-point :intake)
      ;; intake routes ingest vs assess.
      (g/add-conditional-edges :intake
        (fn [{:keys [request]}]
          (if (phase/record-op? (:op request)) :record :advise)))
      (g/add-edge :advise :govern)
      (g/add-edge :govern :decide)
      (g/add-conditional-edges :decide
        (fn [{:keys [disposition]}]
          (case disposition :commit :commit, :escalate :request-approval, :hold)))
      (g/add-conditional-edges :request-approval
        (fn [{:keys [disposition]}] (if (= :commit disposition) :commit :hold)))

      (g/set-finish-point :record)
      (g/set-finish-point :commit)
      (g/set-finish-point :hold)

      (g/compile-graph
       {:checkpointer checkpointer :interrupt-before #{:request-approval}})))

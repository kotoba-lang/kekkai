(ns kekkai.governor-contract-test
  "The zero-trust contract as executable tests — kekkai's analog of robotaxi's
  safety_contract_test. Invariant: the actor never installs a reachability edge
  / admits a device / approves a route the TailnetGovernor would reject, never
  auto-admits a machine, never actuates the data plane, and always records
  observations."
  (:require [clojure.test :refer [deftest is testing]]
            [langgraph.graph :as g]
            [kekkai.store :as store]
            [kekkai.coordllm :as coordllm]
            [kekkai.governor :as gov]
            [kekkai.operation :as op]))

(defn- fresh [] (let [s (store/seed-db)] [s (op/build s)]))
(defn- ctx [phase] {:phase phase})

(defn- run [actor tid req phase]
  (g/run* actor {:request req :context (ctx phase)} {:thread-id tid}))

(deftest ingest-always-records
  (testing "observe path records a ground datom regardless of phase"
    (let [[s actor] (fresh)
          res (run actor "i" {:op :node/heartbeat :node "n-server"
                              :value {:last-seen store/demo-now :endpoint "198.51.100.9:41641"}} 0)]
      (is (= :record (get-in res [:state :disposition])))
      (is (some #(= "198.51.100.9:41641" (:endpoint %)) (store/heartbeats-of s "n-server"))))))

(deftest clean-device-requires-machine-approval
  (testing "a clean device never auto-admits — it interrupts for a human admin"
    (let [[s actor] (fresh)
          r1 (run actor "a" {:op :node/admit :node "n-pending"} 3)]
      (is (= :interrupted (:status r1)) "admission is high-stakes → always human")
      (is (= "pending" (:status (store/node s "n-pending"))) "nothing flipped before sign-off")
      (let [r2 (g/run* actor {:approval {:status :approved :by "admin-alice"}}
                       {:thread-id "a" :resume? true})]
        (is (= :commit (get-in r2 [:state :disposition])))
        (is (= "authorized" (:status (store/node s "n-pending"))))
        (is (= "admin-alice" (:approved-by (store/assessment-of s "n-pending"))))))))

(deftest rogue-admission-is-held-and-unoverridable
  (testing "n-rogue: claims a tag it doesn't own AND its node key is expired"
    (let [[s actor] (fresh)
          res (run actor "b" {:op :node/admit :node "n-rogue"} 3)
          basis (-> (store/ledger s) last :basis)]
      (is (= :hold (get-in res [:state :disposition])))
      (is (some #{:tag-not-owned} basis))
      (is (some #{:expired-key} basis))
      (is (= "pending" (:status (store/node s "n-rogue"))) "rogue never authorized"))))

(deftest deny-by-default-edge-is-held
  (testing "a proposed reachability edge with no backing ACL grant is rejected"
    (let [[s _] (fresh)
          ;; advisor proposes n-server → n-laptop, which no grant permits
          bad-adv (reify coordllm/Advisor
                    (-advise [_ _ _] {:recommendation :reachable :effect :netmap
                                      :peers [{:peer "n-laptop" :ports [22]}]
                                      :summary "x" :rationale "x" :cites [] :confidence 0.9}))
          a2 (op/build s {:advisor bad-adv})
          res (g/run* a2 {:request {:op :access/assess :node "n-server"} :context (ctx 3)}
                      {:thread-id "dbd"})]
      (is (= :hold (get-in res [:state :disposition])))
      (is (some #{:deny-by-default} (-> (store/ledger s) last :basis))))))

(deftest deny-by-default-holds-a-proposal-exceeding-the-grants-ports
  (testing "a proposed edge IS backed by a grant, but claims broader ports than the grant allows"
    (let [[s _] (fresh)
          ;; grant tag:laptop→tag:server is scoped to ports [22 443] (store/seed-db) --
          ;; the advisor claims wildcard port access on the same edge
          bad-adv (reify coordllm/Advisor
                    (-advise [_ _ _] {:recommendation :reachable :effect :netmap
                                      :peers [{:peer "n-server" :ports ["*"]}]
                                      :summary "x" :rationale "x" :cites [] :confidence 0.9}))
          a2 (op/build s {:advisor bad-adv})
          res (g/run* a2 {:request {:op :access/assess :node "n-laptop"} :context (ctx 3)}
                      {:thread-id "port-scope"})]
      (is (= :hold (get-in res [:state :disposition]))
          "a grant existing at all is not enough -- the claimed ports must fit inside it")
      (is (some #{:deny-by-default} (-> (store/ledger s) last :basis))))))

(deftest deny-by-default-holds-a-proposal-omitting-ports-entirely
  (testing "a peer entry with no :ports claim at all must not vacuously pass the scope check"
    (let [[s _] (fresh)
          ;; (every? pred []) is vacuously true -- an omitted :ports must NOT
          ;; be silently trusted as "within grant" unless the grant itself is
          ;; a full ["*"] wildcard (it isn't, here: tag:laptop→tag:server is
          ;; scoped to [22 443])
          bad-adv (reify coordllm/Advisor
                    (-advise [_ _ _] {:recommendation :reachable :effect :netmap
                                      :peers [{:peer "n-server"}]
                                      :summary "x" :rationale "x" :cites [] :confidence 0.9}))
          a2 (op/build s {:advisor bad-adv})
          res (g/run* a2 {:request {:op :access/assess :node "n-laptop"} :context (ctx 3)}
                      {:thread-id "port-scope-empty"})]
      (is (= :hold (get-in res [:state :disposition]))
          "an under-specified proposal must not be treated as automatically within scope")
      (is (some #{:deny-by-default} (-> (store/ledger s) last :basis))))))

(deftest no-actuation-invariant
  (testing "a proposal that tries to actuate the data plane is held"
    (let [[s _] (fresh)
          bad-adv (reify coordllm/Advisor
                    (-advise [_ _ _] {:recommendation :admit :effect :wireguard-push
                                      :summary "x" :rationale "x" :peers [] :cites [] :confidence 0.9}))
          a2 (op/build s {:advisor bad-adv})
          res (g/run* a2 {:request {:op :node/admit :node "n-pending"} :context (ctx 3)}
                      {:thread-id "na"})]
      (is (= :hold (get-in res [:state :disposition])))
      (is (some #{:no-actuation} (-> (store/ledger s) last :basis))))))

(deftest phase0-disables-assessments
  (let [[s actor] (fresh)
        res (run actor "p0" {:op :node/admit :node "n-pending"} 0)]
    (is (= :hold (get-in res [:state :disposition])))
    (is (= :phase-disabled (-> (store/ledger s) last :phase-reason)))))

(deftest access-auto-commits-when-confident
  (testing "phase 3: a clean deny-by-default netmap is not high-stakes → auto"
    (let [[s actor] (fresh)
          res (run actor "x" {:op :access/assess :node "n-laptop"} 3)]
      (is (= :commit (get-in res [:state :disposition])))
      (is (some #(= "n-server" (:peer %)) (:peers (store/assessment-of s "n-laptop")))
          "n-laptop reaches n-server via the tag:laptop→tag:server grant"))))

(deftest missing-phase-context-does-not-grant-max-autonomy
  ;; default-phase is the fallback both when :phase is entirely absent
  ;; from context (kekkai.operation) and when an unrecognized phase
  ;; number is passed (phase/gate). It used to be 3 -- where
  ;; :access/assess can auto-commit -- so a caller that simply forgot
  ;; to set :phase silently got MAXIMUM autonomy instead of the safe
  ;; "start narrow" default.
  (testing "omitting :phase from context still requires human approval on a clean netmap assessment"
    (let [[s actor] (fresh)
          res (g/run* actor {:request {:op :access/assess :node "n-laptop"} :context {}}
                      {:thread-id "mp"})]
      (is (not= :commit (get-in res [:state :disposition]))
          "a clean assessment must not auto-commit when :phase is unset")
      (is (nil? (store/assessment-of s "n-laptop")) "SSoT untouched without explicit phase"))))

(deftest exit-route-requires-signoff
  (testing "approving an exit node is high-stakes → always human"
    (let [[_ actor] (fresh)
          r1 (run actor "ex" {:op :route/approve :node "n-gw" :route "r-exit"} 3)]
      (is (= :interrupted (:status r1))))))

(deftest reject-signoff-holds
  (testing "an admin rejection records a hold, not an admission"
    (let [[s actor] (fresh)
          _  (run actor "r" {:op :node/admit :node "n-pending"} 3)
          r2 (g/run* actor {:approval {:status :rejected :by "admin-alice"}}
                     {:thread-id "r" :resume? true})]
      (is (= :hold (get-in r2 [:state :disposition])))
      (is (= "pending" (:status (store/node s "n-pending")))))))

(deftest governor-check-fails-closed-on-an-unrecognized-op
  (testing "gov/check itself (not just the wrapping phase/gate) must reject an
            unrecognized/typo'd/not-yet-wired :op as a hard violation -- a
            confident, otherwise-clean proposal for a bogus op must never come
            back :ok? true, since gov/check is documented as the independent
            censor that decides commit/hold and any future direct caller
            (a new UI surface, a refactor, code outside operation.cljc) must
            not be able to slip an unhandled op past every zero-trust check"
    (let [[s _] (fresh)
          verdict (gov/check {:op :node/bogus :node "n-server"}
                              {:effect :netmap :confidence 0.99} s)]
      (is (false? (:ok? verdict)))
      (is (true? (:hard? verdict)))
      (is (some #{:unrecognized-op} (mapv :rule (:violations verdict)))))))

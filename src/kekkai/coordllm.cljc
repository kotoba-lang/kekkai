(ns kekkai.coordllm
  "coord-LLM — the contained intelligence node. It reads the tailnet's EAVT
  ground datoms (nodes, keys, the ACL policy, advertised routes) and returns a
  PROPOSAL: admit this device / this is node N's reachable-peer netmap / approve
  this route — plus a rationale and the facts it cited. It NEVER commits a
  membership or pushes WireGuard config; every output is censored by
  `kekkai.governor` before anything is recorded, and admission / exit-node
  approval always route to a human admin (charter: coordinate→publish-netmap,
  no data-plane actuation).

  Advisor is injected (mock | real LLM via langchain.model), same as
  robotaxi.ar1 / itonami.opsllm.

  Proposal shape:
    {:recommendation kw   ; :admit | :deny | :reachable | :approve
     :peers [{:peer id :ports [..]}]   ; for :access/assess
     :route id                          ; for :route/approve
     :summary str :rationale str :cites [kw ..]
     :effect :netmap     ; the actor only ever writes a control-plane record
     :confidence 0..1}"
  (:require #?(:clj  [clojure.edn :as edn]
               :cljs [cljs.reader :as edn])
            [clojure.string :as str]
            [langchain.model :as model]
            [kekkai.acl :as acl]
            [kekkai.store :as store]))

;; ───────────────────────── deterministic mock ─────────────────────────

(defn- assess-admit
  "Admission readiness from key validity + tag ownership. The mock mirrors what
  the governor will check, so a clean device yields :admit (then escalates to a
  human) and a rogue one yields :deny (governor also holds)."
  [st {:keys [node now] :or {now store/demo-now}}]
  (let [nd     (store/node st node)
        policy (store/policy st)
        key-ok? (and nd (not (str/blank? (:did nd))) (not= "revoked" (:status nd))
                     (number? (:key-expiry nd)) (> (:key-expiry nd) now))
        bad-tags (acl/unowned-tags policy nd)
        clean?  (and key-ok? (empty? bad-tags))]
    {:recommendation (if clean? :admit :deny)
     :summary    (str node " 参加可否: " (if clean? "適格" "不適格"))
     :rationale  (str "鍵: " (if key-ok? "有効" "無効/失効") "。tag所有: "
                      (if (empty? bad-tags) "OK" (str "未所有 " bad-tags)) "。")
     :cites      [:node :policy]
     :effect     :netmap
     :confidence (if clean? 0.9 0.85)}))

(defn- assess-access
  "Derive node N's reachable-peer netmap from the deny-by-default ACL."
  [st {:keys [node now] :or {now store/demo-now}}]
  (let [nd     (store/node st node)
        policy (store/policy st)
        peers  (acl/reachable-peers policy nd (store/all-nodes st) now)]
    {:recommendation :reachable
     :peers      peers
     :summary    (str node " netmap: " (count peers) " peer 到達可")
     :rationale  (str "ACL grant 由来の到達集合: "
                      (str/join ", " (map #(str (:peer %) (:ports %)) peers)))
     :cites      [:policy :node]
     :effect     :netmap
     :confidence (if nd 0.88 0.3)}))

(defn- assess-route
  "Approve/deny an advertised subnet/exit route the node carries."
  [st {:keys [node route]}]
  (let [r (first (filter #(= route (:id %)) (store/routes-of st node)))]
    {:recommendation (if r :approve :deny)
     :route      route
     :summary    (str node " route " (:cidr r) " (" (:kind r) ") 承認提案")
     :rationale  (str "広告経路 " (pr-str (select-keys r [:cidr :kind])) "。"
                      (when (= "exit" (:kind r)) "exit node は人間承認。"))
     :cites      [:routes]
     :effect     :netmap
     :confidence (if r 0.8 0.2)}))

(defn infer [st {:keys [op] :as req}]
  (case op
    :node/admit    (assess-admit st req)
    :access/assess (assess-access st req)
    :route/approve (assess-route st req)
    {:recommendation :unknown :summary "未対応" :rationale (str op)
     :cites [] :effect :noop :confidence 0.0}))

;; ───────────────────────── Advisor protocol ─────────────────────────

(defprotocol Advisor
  (-advise [advisor store request]))

(defn mock-advisor [] (reify Advisor (-advise [_ st req] (infer st req))))

(def ^:private system-prompt
  (str "あなたはゼロトラスト・メッシュ網(Tailscale 相当の制御面)の調整助言者です。"
       "与えられた事実(ノード/鍵/ACLポリシー/広告経路)のみに基づき、提案を1つ EDN マップで"
       "返します。EDN だけを出力。\n"
       "キー: :recommendation(:admit|:deny|:reachable|:approve) :peers([{:peer :ports}]) "
       ":route :summary :rationale :cites :effect(:netmap 固定) :confidence(0..1)。\n"
       "重要: WireGuard データ面の作動は提案しない(coordinate→netmap)。"
       "deny-by-default: ACL grant のない到達は提案しない。"))

(defn- facts-for [st {:keys [node]}]
  {:node (store/node st node) :policy (store/policy st)
   :nodes (store/all-nodes st) :routes (store/routes-of st node)})

(defn- parse-proposal [content]
  (let [p (try (edn/read-string (str/trim (str content)))
               (catch #?(:clj Exception :cljs :default) _ nil))]
    (if (map? p)
      (-> p (update :cites #(vec (or % [])))
            (update :peers #(vec (or % [])))
            (update :confidence #(if (number? %) (double %) 0.0))
            (update :effect #(or % :noop)))
      {:recommendation :unknown :summary "LLM応答を解釈できません" :rationale (str content)
       :peers [] :cites [] :effect :noop :confidence 0.0})))

(defn llm-advisor
  "Advisor backed by a langchain.model/ChatModel (Anthropic / OpenAI-compatible
  / mock-model). Output is parsed defensively → an unparseable response is a
  confidence-0 noop the governor will hold/escalate."
  ([chat-model] (llm-advisor chat-model {}))
  ([chat-model gen-opts]
   (reify Advisor
     (-advise [_ st req]
       (let [resp (model/-generate chat-model
                    [{:role :system :content system-prompt}
                     {:role :user :content (str "操作:" (:op req) " ノード:" (:node req)
                                                "\n事実:" (pr-str (facts-for st req)))}]
                    gen-opts)]
         (parse-proposal (:content resp)))))))

(defn trace [request proposal]
  {:t :coordllm-proposal :op (:op request) :node (:node request)
   :recommendation (:recommendation proposal) :summary (:summary proposal)
   :rationale (:rationale proposal) :cites (:cites proposal)
   :peers (:peers proposal) :confidence (:confidence proposal)})

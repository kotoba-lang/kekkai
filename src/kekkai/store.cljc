(ns kekkai.store
  "SSoT for the kekkai tailnet control plane, behind a `Store` protocol so the
  backend is a swap (MemStore default ‖ DatomicStore via langchain.db, itself
  swappable to real Datomic Local / kotoba-server).

  Domain = a zero-trust mesh overlay (a Tailscale-equivalent control plane).
  The actor is the COORDINATION/CONTROL plane only — it publishes a netmap
  (who-can-reach-whom); the WireGuard data plane lives in the nodes, which pull
  the netmap and open their own tunnels. The actor never carries packets.

    node     — a machine in the tailnet: did (node key did:key), user (owner),
               tags, os, key-expiry (epoch s), status (pending/authorized/
               expired/revoked). A node IS its key (Tailscale node-key model).
    user     — a tailnet member (login, role)
    policy   — the ACL: tag-owners {tag [users]} + deny-by-default grants
               [{:src [tag|user] :dst [tag|user] :ports [int|\"*\"]}]
    route    — a subnet/exit route a node advertises (cidr, kind, approved?)
    heartbeat— digital-twin liveness events (last-seen epoch s, endpoint)
    netmap   — the committed access assessment for a node (reachable peers)

  Charter: integers, not floats (epoch seconds, ports); EAVT ground datoms are
  canonical; the append-only **ledger is the tailnet's membership & access
  genealogy** — an immutable zero-trust audit trail (who joined, who could
  reach whom, on whose authority, when keys rotated), the property a mutable
  admin console can't give you. There is intentionally **no :traffic/* or
  :user/activity namespace** — the control plane authorizes reachability, it
  never logs what flows through the tunnels (anti-surveillance, Wellbecoming
  §1.13)."
  (:require #?(:clj  [clojure.edn :as edn]
               :cljs [cljs.reader :as edn])
            [clojure.string :as str]
            [langchain.db :as d]))

(defprotocol Store
  (node [s id])
  (all-nodes [s])
  (user [s id])
  (policy [s]              "the published ACL policy map, or nil")
  (heartbeats-of [s id]    "liveness events for a node, oldest→newest")
  (routes-of [s id]        "routes advertised by a node")
  (all-routes [s]          "every advertised route across the tailnet")
  (assessment-of [s id]    "committed netmap/membership/route assessment for a node, or nil")
  (ledger [s])
  (record-datom! [s record] "append/merge a tailnet ground fact to the SSoT")
  (append-ledger! [s fact]  "append one immutable genealogy fact")
  (seed! [s data]           "bulk-seed entity collections (idempotent upsert)"))

;; ───────────────────────── demo data ─────────────────────────
;; A fixed clock so key-expiry checks are deterministic and offline-verifiable.
(def demo-now 1750000000) ; ~2025-06-15Z, epoch seconds

(defn demo-data
  "A small tailnet owned by alice. n-pending is a clean device awaiting machine
  approval; n-rogue (mallory) claims a tag it doesn't own AND has an expired key
  → the TailnetGovernor must hold its admission, un-overridably."
  []
  {:users
   {"alice"   {:id "alice"   :login "alice@example.com"   :role "admin"}
    "mallory" {:id "mallory" :login "mallory@example.com" :role "member"}}
   :policy
   {:tag-owners {"tag:server" ["alice"] "tag:laptop" ["alice"] "tag:exit" ["alice"]}
    :grants [{:src ["tag:laptop"] :dst ["tag:server"] :ports [22 443]}
             {:src ["alice"]      :dst ["tag:server" "tag:exit"] :ports ["*"]}]}
   :nodes
   {"n-laptop"  {:id "n-laptop"  :hostname "alice-mbp" :os "macos" :did "did:key:zLaptop"
                 :user "alice" :tags ["tag:laptop"] :key-expiry (+ demo-now 7776000)
                 :status "authorized"}
    "n-server"  {:id "n-server"  :hostname "prod-db"   :os "linux" :did "did:key:zServer"
                 :user "alice" :tags ["tag:server"] :key-expiry (+ demo-now 7776000)
                 :status "authorized"}
    "n-gw"      {:id "n-gw"      :hostname "edge-gw"   :os "linux" :did "did:key:zGateway"
                 :user "alice" :tags ["tag:exit"] :key-expiry (+ demo-now 7776000)
                 :status "authorized"}
    "n-pending" {:id "n-pending" :hostname "alice-phone" :os "ios" :did "did:key:zPhone"
                 :user "alice" :tags ["tag:laptop"] :key-expiry (+ demo-now 7776000)
                 :status "pending"}
    "n-rogue"   {:id "n-rogue"   :hostname "evil-box"  :os "linux" :did "did:key:zRogue"
                 :user "mallory" :tags ["tag:server"] :key-expiry (- demo-now 3600)
                 :status "pending"}}
   :routes
   {"r-subnet" {:id "r-subnet" :node "n-server" :cidr "10.0.0.0/24" :kind "subnet" :approved? false}
    "r-exit"   {:id "r-exit"   :node "n-gw"     :cidr "0.0.0.0/0"   :kind "exit"   :approved? false}}
   :heartbeats
   {"n-laptop" [{:last-seen demo-now :endpoint "203.0.113.7:41641"}]}})

;; ───────────────────────── MemStore (default) ─────────────────────────

(defrecord MemStore [a]
  Store
  (node [_ id] (get-in @a [:nodes id]))
  (all-nodes [_] (sort-by :id (vals (:nodes @a))))
  (user [_ id] (get-in @a [:users id]))
  (policy [_] (:policy @a))
  (heartbeats-of [_ id] (get-in @a [:heartbeats id] []))
  (routes-of [_ id] (filterv #(= id (:node %)) (vals (:routes @a))))
  (all-routes [_] (sort-by :id (vals (:routes @a))))
  (assessment-of [_ id] (get-in @a [:assessments id]))
  (ledger [_] (:ledger @a))
  (record-datom! [s {:keys [kind id value]}]
    (case kind
      :user       (swap! a update-in [:users id] merge value)
      :node       (swap! a update-in [:nodes id] merge value)
      :policy     (swap! a assoc :policy value)
      :route      (swap! a assoc-in [:routes id] value)
      :heartbeat  (swap! a update-in [:heartbeats id] (fnil conj []) value)
      :assessment (swap! a assoc-in [:assessments id] value)
      nil)
    s)
  (append-ledger! [_ fact] (swap! a update :ledger conj fact) fact)
  (seed! [s data] (swap! a merge (select-keys data
                                              [:users :nodes :policy :routes :heartbeats])) s))

(defn seed-db []
  (->MemStore (atom (assoc (demo-data) :assessments {} :ledger []))))

;; ───────────────────────── DatomicStore (langchain.db) ─────────────────────────

(def ^:private schema
  {:node/id       {:db/unique :db.unique/identity}
   :user/id       {:db/unique :db.unique/identity}
   :route/id      {:db/unique :db.unique/identity}
   :policy/id     {:db/unique :db.unique/identity}
   :assessment/id {:db/unique :db.unique/identity}})

(defn- enc [v] (pr-str v))
(defn- dec* [s] (when s (edn/read-string s)))

;; The store talks to its backend ONLY through the langchain.db `:db-api` map
;; {:q :transact! :db :pull :entid}. langchain.db/api (in-process EAVT) and
;; langchain.kotoba-db/kotoba-api (kotoba-server XRPC, e.g. kotobase.net) both
;; implement it, so the same record runs on either by construction.

(defn- q* [{:keys [api conn]} query & inputs]
  (apply (:q api) query ((:db api) conn) inputs))
(defn- pull* [{:keys [api conn]} pattern eid] ((:pull api) ((:db api) conn) pattern eid))
(defn- tx* [{:keys [api conn]} txd] ((:transact! api) conn txd))

(defrecord DatomicStore [api conn]
  Store
  (node [this id]
    (-> (pull* this [:node/edn] [:node/id id]) :node/edn dec*))
  (all-nodes [this]
    (->> (q* this '[:find [?id ...] :where [?e :node/id ?id]])
         (map #(node this %)) (sort-by :id)))
  (user [this id]
    (-> (pull* this [:user/edn] [:user/id id]) :user/edn dec*))
  (policy [this]
    (-> (pull* this [:policy/edn] [:policy/id "the"]) :policy/edn dec*))
  (heartbeats-of [this id]
    (->> (q* this '[:find [?v ...] :in $ ?nid :where
                    [?r :hb/node ?nid] [?r :hb/edn ?v]] id)
         (mapv dec*)))
  (routes-of [this id] (filterv #(= id (:node %)) (all-routes this)))
  (all-routes [this]
    (->> (q* this '[:find [?v ...] :where [?r :route/id _] [?r :route/edn ?v]])
         (mapv dec*) (sort-by :id)))
  (assessment-of [this id]
    (-> (pull* this [:assessment/edn] [:assessment/id id]) :assessment/edn dec*))
  (ledger [this]
    ;; ordered by entity id (?e), never a client-precomputed :ledger/seq -- a
    ;; caller-side `(count (ledger s))` read followed by a separate `tx*` write
    ;; is a non-atomic read-modify-write; two concurrent append-ledger! calls
    ;; can compute the SAME seq, and since :ledger/seq was a :db.unique/identity
    ;; attr, the second transact! silently upserted onto (retracted +
    ;; replaced) the first call's entity -- verified data loss against the
    ;; real langchain.db transact! semantics. :db/id is allocated fresh per
    ;; entity map with no unique attr to collide on, so ordering by it can
    ;; never lose a fact this way.
    (->> (q* this '[:find ?e ?f :where [?e :ledger/fact ?f]])
         (sort-by first) (mapv (comp dec* second))))
  (record-datom! [s {:keys [kind id value]}]
    (case kind
      :user       (tx* s [{:user/id id :user/edn (enc (merge (user s id) value))}])
      :node       (tx* s [{:node/id id :node/edn (enc (merge (node s id) value))}])
      :policy     (tx* s [{:policy/id "the" :policy/edn (enc value)}])
      :route      (tx* s [{:route/id id :route/edn (enc value)}])
      :heartbeat  (tx* s [{:hb/node id :hb/edn (enc value)}])
      :assessment (tx* s [{:assessment/id id :assessment/edn (enc value)}])
      nil)
    s)
  (append-ledger! [s fact]
    (tx* s [{:ledger/fact (enc fact)}]) fact)
  (seed! [s data]
    (doseq [[id u] (:users data)]  (record-datom! s {:kind :user :id id :value u}))
    (doseq [[id n] (:nodes data)]  (record-datom! s {:kind :node :id id :value n}))
    (when-let [p (:policy data)]   (record-datom! s {:kind :policy :id "the" :value p}))
    (doseq [[id r] (:routes data)] (record-datom! s {:kind :route :id id :value r}))
    (doseq [[id hbs] (:heartbeats data) hb hbs]
      (record-datom! s {:kind :heartbeat :id id :value hb}))
    s))

(defn datomic-store
  "DatomicStore on the in-process langchain.db EAVT backend (default Datomic-
  shaped store; verifiable offline). For the kotoba-server pod (kotobase.net),
  see kekkai.kotoba/kotoba-store — same record, different :db-api."
  ([] (datomic-store nil))
  ([data] (let [s (->DatomicStore d/api (d/create-conn schema))]
            (when data (seed! s data)) s)))

(defn datomic-seed-db [] (datomic-store (demo-data)))

;; ───────────────────────── ledger formatting ─────────────────────────

(defn ledger-line [{:keys [op subject node disposition basis]}]
  (str/join " · " [(name (or disposition :record)) (str "op=" op)
                   (str "node=" (or subject node)) (str "basis=" (pr-str basis))]))

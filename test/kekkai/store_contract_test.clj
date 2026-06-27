(ns kekkai.store-contract-test
  "Store contract against both backends — proving MemStore ≡ DatomicStore makes
  'swap the SSoT for Datomic / kotoba-server' a config change, not a rewrite.
  Integer-scaled domain values (epoch-second key-expiry, ports) round-trip."
  (:require [clojure.test :refer [deftest is testing]]
            [kekkai.store :as store]))

(defn- backends [] [["MemStore" (store/seed-db)] ["DatomicStore" (store/datomic-seed-db)]])

(deftest read-parity
  (doseq [[label s] (backends)]
    (testing label
      (is (= "alice-mbp" (:hostname (store/node s "n-laptop"))))
      (is (= (+ store/demo-now 7776000) (:key-expiry (store/node s "n-laptop")))
          "epoch-second key-expiry preserved as integer")
      (is (= ["n-gw" "n-laptop" "n-pending" "n-rogue" "n-server"]
             (mapv :id (store/all-nodes s))))
      (is (= "admin" (:role (store/user s "alice"))))
      (is (= [22 443] (-> (store/policy s) :grants first :ports)) "ACL ports preserved")
      (is (= ["alice"] (get-in (store/policy s) [:tag-owners "tag:server"])))
      (is (= "10.0.0.0/24" (:cidr (first (store/routes-of s "n-server")))))
      (is (= 2 (count (store/all-routes s))))
      (is (= "203.0.113.7:41641" (:endpoint (first (store/heartbeats-of s "n-laptop")))))
      (is (nil? (store/node s "n-missing"))))))

(deftest write-and-ledger-parity
  (doseq [[label s] (backends)]
    (testing label
      (store/record-datom! s {:kind :node :id "n-pending" :value {:status "authorized"}})
      (is (= "authorized" (:status (store/node s "n-pending"))) "merge updates status")
      (is (= "alice-phone" (:hostname (store/node s "n-pending"))) "merge preserves other fields")
      (store/record-datom! s {:kind :heartbeat :id "n-server"
                              :value {:last-seen store/demo-now :endpoint "ep:1"}})
      (is (= 1 (count (store/heartbeats-of s "n-server"))))
      (store/record-datom! s {:kind :assessment :id "n-laptop"
                              :value {:recommendation :reachable :peers [{:peer "n-server"}]}})
      (is (= :reachable (:recommendation (store/assessment-of s "n-laptop"))))
      (store/append-ledger! s {:op :a :disposition :record})
      (store/append-ledger! s {:op :b :disposition :commit})
      (is (= [:record :commit] (mapv :disposition (store/ledger s)))))))

(deftest datomic-empty-store-usable
  (let [s (store/datomic-store)]
    (is (nil? (store/node s "nope")))
    (is (= [] (store/all-nodes s)))
    (is (nil? (store/policy s)))
    (store/record-datom! s {:kind :node :id "x"
                            :value {:id "x" :hostname "h" :did "did:key:zX" :user "u"
                                    :tags ["tag:laptop"] :key-expiry 9999999999 :status "pending"}})
    (is (= "h" (:hostname (store/node s "x"))))))

(ns kekkai.phase
  "Phase 0→3 staged rollout, gating only the ASSESS ops (netmap/admission/route
  decisions). Recording tailnet ground datoms (register a node, log a heartbeat,
  publish ACL, advertise a route) is always on — that is kekkai's observe
  charter (durable EAVT facts). The phase only decides how much autonomy the
  *control-plane decisions* have, and can only add caution.

    0 observe-only  — record join requests / heartbeats / ACL / advertised
                      routes; emit NO netmap decisions yet (shadow tailnet).
    1 assisted      — access netmaps allowed, but always human for admission.
    2 assisted-net  — access + subnet-route decisions may auto-commit when
                      clean; node admission and exit nodes stay human.
    3 supervised    — access/subnet auto-commit when clean+confident; node
                      admission and exit-node approval are high-stakes and
                      ALWAYS route to a human admin (machine approval is a human
                      call, like Tailscale).")

(def record-ops #{:node/register :node/heartbeat :user/register
                  :acl/publish :route/advertise})
(def assess-ops #{:node/admit :access/assess :route/approve})

(def phases
  {0 {:label "observe-only" :assess #{}        :auto #{}}
   1 {:label "assisted"     :assess assess-ops :auto #{}}
   2 {:label "assisted-net" :assess assess-ops :auto #{:access/assess :route/approve}}
   3 {:label "supervised"   :assess assess-ops :auto #{:access/assess :route/approve}}})

(def default-phase 3)

(defn record-op? [op] (contains? record-ops op))

(defn gate
  "Adjust an assess op's governor disposition for the rollout phase.
  Returns {:disposition kw :reason kw|nil}. :node/admit is never in :auto, so
  it always escalates; an exit-route approval is flagged high-stakes by the
  governor and likewise escalates."
  [phase {:keys [op]} disposition]
  (let [{:keys [assess auto]} (get phases phase (get phases default-phase))]
    (cond
      (= :hold disposition)        {:disposition :hold :reason nil}
      (not (contains? assess op))  {:disposition :hold :reason :phase-disabled}
      (and (= :commit disposition)
           (not (contains? auto op))) {:disposition :escalate :reason :phase-approval}
      :else                        {:disposition disposition :reason nil})))

(defn verdict->disposition [v]
  (cond (:hard? v) :hold (:escalate? v) :escalate :else :commit))

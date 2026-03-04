;; Tempo-Tracking Supply Chain Smart Contract

;; This contract implements core supply chain tracking with:
;;   - Shipment lifecycle management
;;   - Temporal compliance scoring
;;   - Milestone-based escrow payments
;;   - Carbon offset tracking
;;   - Role-based access control

;; ============================================================
;; CONSTANTS
;; ============================================================

(define-constant CONTRACT-OWNER tx-sender)

;; Error codes
(define-constant ERR-NOT-AUTHORIZED        (err u100))
(define-constant ERR-SHIPMENT-NOT-FOUND    (err u101))
(define-constant ERR-INVALID-STATUS        (err u102))
(define-constant ERR-ALREADY-EXISTS        (err u103))
(define-constant ERR-INVALID-SCORE         (err u104))
(define-constant ERR-INSUFFICIENT-ESCROW   (err u105))
(define-constant ERR-MILESTONE-NOT-FOUND   (err u106))
(define-constant ERR-MILESTONE-ALREADY-MET (err u107))
(define-constant ERR-INVALID-PARAM         (err u108))

;; Shipment status codes
(define-constant STATUS-CREATED    u0)
(define-constant STATUS-IN-TRANSIT u1)
(define-constant STATUS-INSPECTING u2)
(define-constant STATUS-DELIVERED  u3)
(define-constant STATUS-CANCELLED  u4)

;; Max risk score (0-100)
(define-constant MAX-RISK-SCORE u100)

;; ============================================================
;; DATA MAPS AND VARS
;; ============================================================

;; Global shipment counter
(define-data-var shipment-nonce uint u0)

;; Authorized oracle addresses (IoT / ML risk feed)
(define-map oracles principal bool)

;; Authorized logistics operators
(define-map operators principal bool)

;; Core shipment record
(define-map shipments
  { shipment-id: uint }
  {
    shipper:          principal,
    receiver:         principal,
    origin:           (string-ascii 64),
    destination:      (string-ascii 64),
    cargo-desc:       (string-ascii 128),
    status:           uint,
    risk-score:       uint,          ;; 0 = low risk, 100 = critical
    compliance-score: uint,          ;; 0 = non-compliant, 100 = perfect
    carbon-kg:        uint,          ;; estimated carbon footprint in kg
    carbon-offset-purchased: bool,
    created-at:       uint,          ;; block height
    updated-at:       uint
  }
)

;; Immutable audit trail entries per shipment
(define-map audit-log
  { shipment-id: uint, entry-index: uint }
  {
    actor:      principal,
    event:      (string-ascii 64),
    block:      uint,
    risk-score: uint
  }
)

;; Per-shipment audit log counters
(define-map audit-log-nonce
  { shipment-id: uint }
  uint
)

;; Escrow balances per shipment (in micro-STX)
(define-map escrow-balances
  { shipment-id: uint }
  uint
)

;; Milestone definitions
(define-map milestones
  { shipment-id: uint, milestone-id: uint }
  {
    description:  (string-ascii 64),
    payout:       uint,    ;; micro-STX to release on completion
    met:          bool,
    met-at-block: uint
  }
)

;; Per-shipment milestone counters
(define-map milestone-nonce
  { shipment-id: uint }
  uint
)

;; Carbon offsets purchased (lifetime totals per principal)
(define-map carbon-offsets-by-principal
  principal
  uint   ;; total kg offset
)

;; ============================================================
;; PRIVATE HELPERS
;; ============================================================

(define-private (is-contract-owner)
  (is-eq tx-sender CONTRACT-OWNER)
)

(define-private (is-oracle (addr principal))
  (default-to false (map-get? oracles addr))
)

(define-private (is-operator (addr principal))
  (default-to false (map-get? operators addr))
)

(define-private (shipment-exists (shipment-id uint))
  (is-some (map-get? shipments { shipment-id: shipment-id }))
)

;; Append an entry to the immutable audit log
(define-private (append-audit
  (shipment-id uint)
  (event (string-ascii 64))
  (score uint))
  (let (
    (idx (default-to u0 (map-get? audit-log-nonce { shipment-id: shipment-id })))
  )
    (map-set audit-log
      { shipment-id: shipment-id, entry-index: idx }
      {
        actor:      tx-sender,
        event:      event,
        block:      block-height,
        risk-score: score
      }
    )
    (map-set audit-log-nonce { shipment-id: shipment-id } (+ idx u1))
  )
)

;; ============================================================
;; ADMIN FUNCTIONS
;; ============================================================

;; Register an oracle address
(define-public (register-oracle (addr principal))
  (begin
    (asserts! (is-contract-owner) ERR-NOT-AUTHORIZED)
    (map-set oracles addr true)
    (ok true)
  )
)

;; Revoke an oracle address
(define-public (revoke-oracle (addr principal))
  (begin
    (asserts! (is-contract-owner) ERR-NOT-AUTHORIZED)
    (map-delete oracles addr)
    (ok true)
  )
)

;; Register a logistics operator
(define-public (register-operator (addr principal))
  (begin
    (asserts! (is-contract-owner) ERR-NOT-AUTHORIZED)
    (map-set operators addr true)
    (ok true)
  )
)

;; Revoke a logistics operator
(define-public (revoke-operator (addr principal))
  (begin
    (asserts! (is-contract-owner) ERR-NOT-AUTHORIZED)
    (map-delete operators addr)
    (ok true)
  )
)

;; ============================================================
;; SHIPMENT LIFECYCLE
;; ============================================================

;; Create a new shipment record
(define-public (create-shipment
  (receiver     principal)
  (origin       (string-ascii 64))
  (destination  (string-ascii 64))
  (cargo-desc   (string-ascii 128))
  (carbon-kg    uint))
  (let (
    (id (+ (var-get shipment-nonce) u1))
  )
    (asserts! (> (len origin) u0)      ERR-INVALID-PARAM)
    (asserts! (> (len destination) u0) ERR-INVALID-PARAM)
    (map-set shipments
      { shipment-id: id }
      {
        shipper:                  tx-sender,
        receiver:                 receiver,
        origin:                   origin,
        destination:              destination,
        cargo-desc:               cargo-desc,
        status:                   STATUS-CREATED,
        risk-score:               u0,
        compliance-score:         u100,
        carbon-kg:                carbon-kg,
        carbon-offset-purchased:  false,
        created-at:               block-height,
        updated-at:               block-height
      }
    )
    (var-set shipment-nonce id)
    (append-audit id "shipment-created" u0)
    (ok id)
  )
)

;; Transition shipment to in-transit
(define-public (start-transit (shipment-id uint))
  (let (
    (s (unwrap! (map-get? shipments { shipment-id: shipment-id })
                ERR-SHIPMENT-NOT-FOUND))
  )
    (asserts! (or (is-eq tx-sender (get shipper s)) (is-operator tx-sender))
              ERR-NOT-AUTHORIZED)
    (asserts! (is-eq (get status s) STATUS-CREATED) ERR-INVALID-STATUS)
    (map-set shipments { shipment-id: shipment-id }
      (merge s { status: STATUS-IN-TRANSIT, updated-at: block-height })
    )
    (append-audit shipment-id "transit-started" (get risk-score s))
    (ok true)
  )
)

;; Flag shipment for quality inspection
(define-public (flag-for-inspection (shipment-id uint))
  (let (
    (s (unwrap! (map-get? shipments { shipment-id: shipment-id })
                ERR-SHIPMENT-NOT-FOUND))
  )
    (asserts! (or (is-operator tx-sender) (is-oracle tx-sender))
              ERR-NOT-AUTHORIZED)
    (asserts! (is-eq (get status s) STATUS-IN-TRANSIT) ERR-INVALID-STATUS)
    (map-set shipments { shipment-id: shipment-id }
      (merge s { status: STATUS-INSPECTING, updated-at: block-height })
    )
    (append-audit shipment-id "flagged-for-inspection" (get risk-score s))
    (ok true)
  )
)

;; Mark shipment as delivered and release remaining escrow to receiver
(define-public (complete-delivery (shipment-id uint))
  (let (
    (s       (unwrap! (map-get? shipments { shipment-id: shipment-id })
                      ERR-SHIPMENT-NOT-FOUND))
    (balance (default-to u0 (map-get? escrow-balances { shipment-id: shipment-id })))
  )
    (asserts! (or (is-eq tx-sender (get shipper s)) (is-operator tx-sender))
              ERR-NOT-AUTHORIZED)
    (asserts! (or (is-eq (get status s) STATUS-IN-TRANSIT)
                  (is-eq (get status s) STATUS-INSPECTING))
              ERR-INVALID-STATUS)
    ;; Release any remaining escrow to the receiver
    (if (> balance u0)
      (begin
        (try! (as-contract (stx-transfer? balance tx-sender (get receiver s))))
        (map-set escrow-balances { shipment-id: shipment-id } u0)
      )
      true
    )
    (map-set shipments { shipment-id: shipment-id }
      (merge s { status: STATUS-DELIVERED, updated-at: block-height })
    )
    (append-audit shipment-id "delivered" (get risk-score s))
    (ok true)
  )
)

;; Cancel a shipment and refund escrow to shipper
(define-public (cancel-shipment (shipment-id uint))
  (let (
    (s       (unwrap! (map-get? shipments { shipment-id: shipment-id })
                      ERR-SHIPMENT-NOT-FOUND))
    (balance (default-to u0 (map-get? escrow-balances { shipment-id: shipment-id })))
  )
    (asserts! (or (is-eq tx-sender (get shipper s)) (is-contract-owner))
              ERR-NOT-AUTHORIZED)
    (asserts! (not (is-eq (get status s) STATUS-DELIVERED))  ERR-INVALID-STATUS)
    (asserts! (not (is-eq (get status s) STATUS-CANCELLED))  ERR-INVALID-STATUS)
    (if (> balance u0)
      (begin
        (try! (as-contract (stx-transfer? balance tx-sender (get shipper s))))
        (map-set escrow-balances { shipment-id: shipment-id } u0)
      )
      true
    )
    (map-set shipments { shipment-id: shipment-id }
      (merge s { status: STATUS-CANCELLED, updated-at: block-height })
    )
    (append-audit shipment-id "cancelled" u0)
    (ok true)
  )
)

;; ============================================================
;; ORACLE: RISK AND COMPLIANCE SCORING
;; ============================================================

;; Oracle pushes updated risk and compliance scores from ML/IoT feeds
(define-public (update-scores
  (shipment-id      uint)
  (new-risk-score   uint)
  (new-compliance   uint))
  (let (
    (s (unwrap! (map-get? shipments { shipment-id: shipment-id })
                ERR-SHIPMENT-NOT-FOUND))
  )
    (asserts! (is-oracle tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (<= new-risk-score MAX-RISK-SCORE)  ERR-INVALID-SCORE)
    (asserts! (<= new-compliance MAX-RISK-SCORE)  ERR-INVALID-SCORE)
    (map-set shipments { shipment-id: shipment-id }
      (merge s {
        risk-score:       new-risk-score,
        compliance-score: new-compliance,
        updated-at:       block-height
      })
    )
    (append-audit shipment-id "scores-updated" new-risk-score)
    (ok true)
  )
)

;; ============================================================
;; ESCROW AND MILESTONE PAYMENTS
;; ============================================================

;; Shipper deposits STX into escrow for a shipment
(define-public (deposit-escrow (shipment-id uint) (amount uint))
  (let (
    (s       (unwrap! (map-get? shipments { shipment-id: shipment-id })
                      ERR-SHIPMENT-NOT-FOUND))
    (current (default-to u0 (map-get? escrow-balances { shipment-id: shipment-id })))
  )
    (asserts! (is-eq tx-sender (get shipper s)) ERR-NOT-AUTHORIZED)
    (asserts! (> amount u0) ERR-INVALID-PARAM)
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    (map-set escrow-balances { shipment-id: shipment-id } (+ current amount))
    (ok true)
  )
)

;; Define a payment milestone tied to a shipment
(define-public (add-milestone
  (shipment-id uint)
  (description (string-ascii 64))
  (payout      uint))
  (let (
    (s   (unwrap! (map-get? shipments { shipment-id: shipment-id })
                  ERR-SHIPMENT-NOT-FOUND))
    (mid (default-to u0 (map-get? milestone-nonce { shipment-id: shipment-id })))
  )
    (asserts! (is-eq tx-sender (get shipper s)) ERR-NOT-AUTHORIZED)
    (asserts! (> payout u0) ERR-INVALID-PARAM)
    (map-set milestones
      { shipment-id: shipment-id, milestone-id: mid }
      {
        description:  description,
        payout:       payout,
        met:          false,
        met-at-block: u0
      }
    )
    (map-set milestone-nonce { shipment-id: shipment-id } (+ mid u1))
    (ok mid)
  )
)

;; Operator marks a milestone as complete and releases payout to receiver
(define-public (release-milestone
  (shipment-id  uint)
  (milestone-id uint))
  (let (
    (s  (unwrap! (map-get? shipments { shipment-id: shipment-id })
                 ERR-SHIPMENT-NOT-FOUND))
    (m  (unwrap! (map-get? milestones { shipment-id: shipment-id, milestone-id: milestone-id })
                 ERR-MILESTONE-NOT-FOUND))
    (bal (default-to u0 (map-get? escrow-balances { shipment-id: shipment-id })))
  )
    (asserts! (or (is-operator tx-sender) (is-contract-owner)) ERR-NOT-AUTHORIZED)
    (asserts! (not (get met m))                                 ERR-MILESTONE-ALREADY-MET)
    (asserts! (>= bal (get payout m))                           ERR-INSUFFICIENT-ESCROW)
    (try! (as-contract (stx-transfer? (get payout m) tx-sender (get receiver s))))
    (map-set escrow-balances { shipment-id: shipment-id } (- bal (get payout m)))
    (map-set milestones
      { shipment-id: shipment-id, milestone-id: milestone-id }
      (merge m { met: true, met-at-block: block-height })
    )
    (append-audit shipment-id "milestone-released" (get risk-score s))
    (ok true)
  )
)

;; ============================================================
;; CARBON OFFSET TRACKING
;; ============================================================

;; Mark carbon offset as purchased for a shipment.
;; In production this would integrate with an offset oracle.
(define-public (record-carbon-offset (shipment-id uint))
  (let (
    (s (unwrap! (map-get? shipments { shipment-id: shipment-id })
                ERR-SHIPMENT-NOT-FOUND))
    (current-offset (default-to u0 (map-get? carbon-offsets-by-principal (get shipper s))))
  )
    (asserts! (or (is-eq tx-sender (get shipper s)) (is-operator tx-sender))
              ERR-NOT-AUTHORIZED)
    (asserts! (not (get carbon-offset-purchased s)) ERR-ALREADY-EXISTS)
    (map-set shipments { shipment-id: shipment-id }
      (merge s { carbon-offset-purchased: true, updated-at: block-height })
    )
    (map-set carbon-offsets-by-principal
      (get shipper s)
      (+ current-offset (get carbon-kg s))
    )
    (append-audit shipment-id "carbon-offset-recorded" (get risk-score s))
    (ok true)
  )
)

;; ============================================================
;; READ-ONLY QUERIES
;; ============================================================

;; Get full shipment details
(define-read-only (get-shipment (shipment-id uint))
  (map-get? shipments { shipment-id: shipment-id })
)

;; Get current risk score for a shipment
(define-read-only (get-risk-score (shipment-id uint))
  (match (map-get? shipments { shipment-id: shipment-id })
    s (some (get risk-score s))
    none
  )
)

;; Get escrow balance for a shipment
(define-read-only (get-escrow-balance (shipment-id uint))
  (default-to u0 (map-get? escrow-balances { shipment-id: shipment-id }))
)

;; Get milestone details
(define-read-only (get-milestone (shipment-id uint) (milestone-id uint))
  (map-get? milestones { shipment-id: shipment-id, milestone-id: milestone-id })
)

;; Get a specific audit log entry
(define-read-only (get-audit-entry (shipment-id uint) (entry-index uint))
  (map-get? audit-log { shipment-id: shipment-id, entry-index: entry-index })
)

;; Get the number of audit entries for a shipment
(define-read-only (get-audit-count (shipment-id uint))
  (default-to u0 (map-get? audit-log-nonce { shipment-id: shipment-id }))
)

;; Get total carbon offset for a principal
(define-read-only (get-carbon-offset (addr principal))
  (default-to u0 (map-get? carbon-offsets-by-principal addr))
)

;; Get total shipments created
(define-read-only (get-shipment-count)
  (var-get shipment-nonce)
)

;; Check if an address is a registered oracle
(define-read-only (is-registered-oracle (addr principal))
  (is-oracle addr)
)

;; Check if an address is a registered operator
(define-read-only (is-registered-operator (addr principal))
  (is-operator addr)
)

;; Decentralized Document Verification Registry Smart Contract
;; 
;; This smart contract provides a blockchain-based system for registering and verifying
;; documents with cryptographic integrity. It enables document owners to register their
;; documents, assign verifiers, track revisions, and maintain an immutable audit trail.
;; The system supports multi-party verification workflows with granular access controls.

;; Error codes for operation failures
(define-constant ERR-UNAUTHORIZED-ACCESS (err u100))
(define-constant ERR-DOCUMENT-ALREADY-EXISTS (err u101))
(define-constant ERR-DOCUMENT-NOT-FOUND (err u102))
(define-constant ERR-VERIFICATION-ALREADY-COMPLETED (err u103))
(define-constant ERR-INVALID-DOCUMENT-ID (err u104))
(define-constant ERR-INVALID-HASH-FORMAT (err u105))
(define-constant ERR-INVALID-METADATA (err u106))
(define-constant ERR-INVALID-VERIFIER-ADDRESS (err u107))
(define-constant ERR-INVALID-PARAMETERS (err u108))
(define-constant ERR-INSUFFICIENT-PERMISSIONS (err u109))
(define-constant ERR-NULL-VALUE-ERROR (err u110))

;; Status values for document verification states
(define-constant status-pending "PENDING_REVIEW")
(define-constant status-verified "VERIFIED")
(define-constant status-rejected "REJECTED")

;; Validation constraints for input data
(define-constant hash-length-bytes u32)
(define-constant metadata-max-length u256)

;; Template structure for document records (used for type reference)
(define-data-var document-template 
    {
        owner: principal,
        hash: (buff 32),
        timestamp: uint,
        status: (string-ascii 20),
        verifier: (optional principal),
        metadata: (string-utf8 256),
        version: uint,
        locked: bool
    }
    {
        owner: tx-sender,
        hash: 0x0000000000000000000000000000000000000000000000000000000000000000,
        timestamp: u0,
        status: status-pending,
        verifier: none,
        metadata: u"",
        version: u0,
        locked: false
    }
)

;; Storage for registered documents indexed by unique identifier
(define-map documents
    { id: (buff 32) }
    {
        owner: principal,
        hash: (buff 32),
        timestamp: uint,
        status: (string-ascii 20),
        verifier: (optional principal),
        metadata: (string-utf8 256),
        version: uint,
        locked: bool
    }
)

;; Access control for verifiers on specific documents
(define-map access-control
    { doc-id: (buff 32), verifier: principal }
    { can-read: bool, can-verify: bool }
)

;; Validates that a buffer has the correct hash length
(define-private (valid-hash-length (hash (buff 32)))
    (is-eq (len hash) hash-length-bytes))

;; Validates that metadata meets length requirements
(define-private (valid-metadata-length (text (string-utf8 256)))
    (and 
        (<= (len text) metadata-max-length) 
        (> (len text) u0)))

;; Validates that a verifier address is different from sender and contract
(define-private (valid-verifier-address (address principal))
    (and 
        (not (is-eq address tx-sender))
        (not (is-eq address (as-contract tx-sender)))))

;; Validates document identifier format and returns it if valid
(define-private (validate-doc-id (doc-id (buff 32)))
    (if (valid-hash-length doc-id)
        (ok doc-id)
        ERR-INVALID-DOCUMENT-ID))

;; Validates content hash format and returns it if valid
(define-private (validate-hash (hash (buff 32)))
    (if (valid-hash-length hash)
        (ok hash)
        ERR-INVALID-HASH-FORMAT))

;; Validates metadata content and returns it if valid
(define-private (validate-metadata (text (string-utf8 256)))
    (if (valid-metadata-length text)
        (ok text)
        ERR-INVALID-METADATA))

;; Validates verifier principal address and returns it if valid
(define-private (validate-verifier (address principal))
    (if (valid-verifier-address address)
        (ok address)
        ERR-INVALID-VERIFIER-ADDRESS))

;; Performs document ID validation with assertion check
(define-private (check-doc-id (doc-id (buff 32)))
    (begin
        (asserts! (valid-hash-length doc-id) ERR-INVALID-DOCUMENT-ID)
        (validate-doc-id doc-id)))

;; Performs metadata validation with assertion check
(define-private (check-metadata (text (string-utf8 256)))
    (begin
        (asserts! (valid-metadata-length text) ERR-INVALID-METADATA)
        (validate-metadata text)))

;; Performs verifier validation with assertion check
(define-private (check-verifier (address principal))
    (begin
        (asserts! (valid-verifier-address address) ERR-INVALID-VERIFIER-ADDRESS)
        (validate-verifier address)))

;; Retrieves a document record by ID with validation
(define-private (fetch-document (doc-id (buff 32)))
    (begin
        (asserts! (valid-hash-length doc-id) ERR-INVALID-DOCUMENT-ID)
        (let ((validated-id (validate-doc-id doc-id)))
            (match validated-id
                valid-id 
                (match (map-get? documents { id: valid-id })
                    doc (ok doc)
                    ERR-DOCUMENT-NOT-FOUND)
                error (err error)))))

;; Checks if a principal is the owner of a document
(define-private (is-document-owner (doc-id (buff 32)) (user principal))
    (match (fetch-document doc-id)
        doc 
        (ok (is-eq (get owner doc) user))
        error (err error)))

;; Returns document information by ID
(define-read-only (get-document (doc-id (buff 32)))
    (begin
        (asserts! (valid-hash-length doc-id) ERR-INVALID-DOCUMENT-ID)
        (fetch-document doc-id)))

;; Returns verifier permissions for a specific document
(define-read-only (get-permissions (doc-id (buff 32)) (verifier-addr principal))
    (begin
        (asserts! (valid-hash-length doc-id) ERR-INVALID-DOCUMENT-ID)
        (asserts! (valid-verifier-address verifier-addr) ERR-INVALID-VERIFIER-ADDRESS)
        (let ((validated-id (check-doc-id doc-id))
              (validated-verifier (check-verifier verifier-addr)))
            (match validated-id
                valid-id 
                (match validated-verifier
                    valid-verifier 
                    (match (map-get? access-control 
                        { doc-id: valid-id, verifier: valid-verifier })
                        perms (ok perms)
                        (ok { can-read: false, can-verify: false }))
                    error (err error))
                error (err error)))))

;; Checks if a document exists in the registry
(define-read-only (document-exists (doc-id (buff 32)))
    (begin
        (asserts! (valid-hash-length doc-id) ERR-INVALID-DOCUMENT-ID)
        (ok (is-some (map-get? documents { id: doc-id })))))

;; Registers a new document in the system
(define-public (register-document 
    (doc-id (buff 32))
    (content-hash (buff 32))
    (description (string-utf8 256)))
    (begin
        (asserts! (valid-hash-length doc-id) ERR-INVALID-DOCUMENT-ID)
        (asserts! (valid-hash-length content-hash) ERR-INVALID-HASH-FORMAT)
        (asserts! (valid-metadata-length description) ERR-INVALID-METADATA)
        
        (let ((validated-id (check-doc-id doc-id))
              (validated-hash (validate-hash content-hash))
              (validated-meta (check-metadata description)))
            (match validated-id
                valid-id 
                (match validated-hash
                    valid-hash 
                    (match validated-meta
                        valid-meta 
                        (match (map-get? documents { id: valid-id })
                            existing ERR-DOCUMENT-ALREADY-EXISTS
                            (ok (map-set documents
                                { id: valid-id }
                                {
                                    owner: tx-sender,
                                    hash: valid-hash,
                                    timestamp: block-height,
                                    status: status-pending,
                                    verifier: none,
                                    metadata: valid-meta,
                                    version: u1,
                                    locked: false
                                })))
                        error (err error))
                    error (err error))
                error (err error)))))

;; Updates an existing document with new hash and metadata
(define-public (update-document
    (doc-id (buff 32))
    (new-hash (buff 32))
    (new-metadata (string-utf8 256)))
    (begin
        (asserts! (valid-hash-length doc-id) ERR-INVALID-DOCUMENT-ID)
        (asserts! (valid-hash-length new-hash) ERR-INVALID-HASH-FORMAT)
        (asserts! (valid-metadata-length new-metadata) ERR-INVALID-METADATA)
        
        (let ((validated-id (check-doc-id doc-id))
              (validated-hash (validate-hash new-hash))
              (validated-meta (check-metadata new-metadata)))
            (match validated-id
                valid-id 
                (begin
                    (asserts! (is-some (map-get? documents { id: valid-id })) ERR-DOCUMENT-NOT-FOUND)
                    (let ((current-doc (unwrap-panic (map-get? documents { id: valid-id }))))
                        (match validated-hash
                            valid-hash 
                            (match validated-meta
                                valid-meta 
                                (begin
                                    (asserts! (is-eq (get owner current-doc) tx-sender) ERR-UNAUTHORIZED-ACCESS)
                                    (asserts! (not (get locked current-doc)) ERR-VERIFICATION-ALREADY-COMPLETED)
                                    (ok (map-set documents
                                        { id: valid-id }
                                        (merge current-doc
                                            {
                                                hash: valid-hash,
                                                metadata: valid-meta,
                                                timestamp: block-height,
                                                version: (+ (get version current-doc) u1),
                                                status: status-pending,
                                                locked: false
                                            }))))
                                error (err error))
                            error (err error))))
                error (err error)))))

;; Marks a document as verified by an authorized verifier
(define-public (verify-document (doc-id (buff 32)))
    (begin
        (asserts! (valid-hash-length doc-id) ERR-INVALID-DOCUMENT-ID)
        
        (let ((validated-id (check-doc-id doc-id)))
            (match validated-id
                valid-id
                (begin
                    (asserts! (is-some (map-get? documents { id: valid-id })) ERR-DOCUMENT-NOT-FOUND)
                    (let ((current-doc (unwrap-panic (map-get? documents { id: valid-id }))))
                        (let ((perms (get-permissions valid-id tx-sender)))
                            (match perms
                                permission-data
                                (begin
                                    (asserts! (get can-verify permission-data) ERR-UNAUTHORIZED-ACCESS)
                                    (asserts! (not (get locked current-doc)) ERR-VERIFICATION-ALREADY-COMPLETED)
                                    (ok (map-set documents
                                        { id: valid-id }
                                        (merge current-doc
                                            {
                                                status: status-verified,
                                                verifier: (some tx-sender),
                                                locked: true
                                            }))))
                                error ERR-UNAUTHORIZED-ACCESS))))
                error (err error)))))

;; Marks a document as rejected by an authorized verifier
(define-public (reject-document (doc-id (buff 32)))
    (begin
        (asserts! (valid-hash-length doc-id) ERR-INVALID-DOCUMENT-ID)
        
        (let ((validated-id (check-doc-id doc-id)))
            (match validated-id
                valid-id
                (begin
                    (asserts! (is-some (map-get? documents { id: valid-id })) ERR-DOCUMENT-NOT-FOUND)
                    (let ((current-doc (unwrap-panic (map-get? documents { id: valid-id }))))
                        (let ((perms (get-permissions valid-id tx-sender)))
                            (match perms
                                permission-data
                                (begin
                                    (asserts! (get can-verify permission-data) ERR-UNAUTHORIZED-ACCESS)
                                    (asserts! (not (get locked current-doc)) ERR-VERIFICATION-ALREADY-COMPLETED)
                                    (ok (map-set documents
                                        { id: valid-id }
                                        (merge current-doc
                                            {
                                                status: status-rejected,
                                                verifier: (some tx-sender),
                                                locked: true
                                            }))))
                                error ERR-UNAUTHORIZED-ACCESS))))
                error (err error)))))

;; Grants specific permissions to a verifier for a document
(define-public (grant-access
    (doc-id (buff 32))
    (verifier-addr principal)
    (read-permission bool)
    (verify-permission bool))
    (begin
        (asserts! (valid-hash-length doc-id) ERR-INVALID-DOCUMENT-ID)
        (asserts! (valid-verifier-address verifier-addr) ERR-INVALID-VERIFIER-ADDRESS)
        
        (let ((validated-id (check-doc-id doc-id))
              (validated-verifier (check-verifier verifier-addr)))
            (match validated-id
                valid-id
                (begin
                    (asserts! (is-some (map-get? documents { id: valid-id })) ERR-DOCUMENT-NOT-FOUND)
                    (let ((current-doc (unwrap-panic (map-get? documents { id: valid-id }))))
                        (match validated-verifier
                            valid-verifier
                            (begin
                                (asserts! (is-eq (get owner current-doc) tx-sender) ERR-UNAUTHORIZED-ACCESS)
                                (ok (map-set access-control
                                    { doc-id: valid-id, verifier: valid-verifier }
                                    { 
                                        can-read: read-permission, 
                                        can-verify: verify-permission 
                                    })))
                            error (err error))))
                error (err error)))))

;; Revokes all permissions for a verifier on a document
(define-public (revoke-access
    (doc-id (buff 32))
    (verifier-addr principal))
    (begin
        (asserts! (valid-hash-length doc-id) ERR-INVALID-DOCUMENT-ID)
        (asserts! (valid-verifier-address verifier-addr) ERR-INVALID-VERIFIER-ADDRESS)
        
        (let ((validated-id (check-doc-id doc-id))
              (validated-verifier (check-verifier verifier-addr)))
            (match validated-id
                valid-id
                (begin
                    (asserts! (is-some (map-get? documents { id: valid-id })) ERR-DOCUMENT-NOT-FOUND)
                    (let ((current-doc (unwrap-panic (map-get? documents { id: valid-id }))))
                        (match validated-verifier
                            valid-verifier
                            (begin
                                (asserts! (is-eq (get owner current-doc) tx-sender) ERR-UNAUTHORIZED-ACCESS)
                                (ok (map-delete access-control
                                    { doc-id: valid-id, verifier: valid-verifier })))
                            error (err error))))
                error (err error)))))
# Decentralized Document Verification Registry

## Overview

The Decentralized Document Verification Registry is a blockchain-based smart contract system that provides cryptographic integrity for document registration and verification. Built on the Stacks blockchain using Clarity, this contract enables document owners to register documents, assign verifiers, track revisions, and maintain an immutable audit trail with granular access controls.

## Features

- **Document Registration**: Register documents with cryptographic hashes and metadata
- **Multi-Party Verification**: Support for designated verifiers with specific permissions
- **Version Control**: Track document revisions with incremental version numbers
- **Access Control**: Granular permission management for read and verify operations
- **Immutable Audit Trail**: All document states and verification actions are permanently recorded
- **Document Locking**: Verified or rejected documents are locked to prevent further modifications

## Contract Architecture

### Data Structures

**Documents Map**
- Stores registered documents indexed by unique 32-byte identifiers
- Contains owner address, content hash, timestamp, status, verifier, metadata, version, and lock state

**Access Control Map**
- Manages verifier permissions for specific documents
- Tracks read and verify capabilities per verifier-document pair

### Document States

- `PENDING_REVIEW`: Initial state after registration or update
- `VERIFIED`: Document has been approved by an authorized verifier
- `REJECTED`: Document has been rejected by an authorized verifier

## Public Functions

### register-document

Registers a new document in the system.

**Parameters:**
- `doc-id` (buff 32): Unique document identifier
- `content-hash` (buff 32): Cryptographic hash of document content
- `description` (string-utf8 256): Document metadata and description

**Returns:** `(response bool uint)`

**Errors:**
- `ERR-DOCUMENT-ALREADY-EXISTS`: Document ID is already registered
- `ERR-INVALID-DOCUMENT-ID`: Invalid document identifier format
- `ERR-INVALID-HASH-FORMAT`: Invalid hash format
- `ERR-INVALID-METADATA`: Invalid or empty metadata

### update-document

Updates an existing document with new content hash and metadata.

**Parameters:**
- `doc-id` (buff 32): Document identifier
- `new-hash` (buff 32): Updated content hash
- `new-metadata` (string-utf8 256): Updated metadata

**Returns:** `(response bool uint)`

**Requirements:**
- Caller must be the document owner
- Document must not be locked

**Effects:**
- Increments version number
- Resets status to `PENDING_REVIEW`
- Updates timestamp to current block height

### verify-document

Marks a document as verified by an authorized verifier.

**Parameters:**
- `doc-id` (buff 32): Document identifier

**Returns:** `(response bool uint)`

**Requirements:**
- Caller must have verify permissions
- Document must not be already locked

**Effects:**
- Sets status to `VERIFIED`
- Records verifier address
- Locks document from further modifications

### reject-document

Marks a document as rejected by an authorized verifier.

**Parameters:**
- `doc-id` (buff 32): Document identifier

**Returns:** `(response bool uint)`

**Requirements:**
- Caller must have verify permissions
- Document must not be already locked

**Effects:**
- Sets status to `REJECTED`
- Records verifier address
- Locks document from further modifications

### grant-access

Grants specific permissions to a verifier for a document.

**Parameters:**
- `doc-id` (buff 32): Document identifier
- `verifier-addr` (principal): Address of the verifier
- `read-permission` (bool): Whether to grant read access
- `verify-permission` (bool): Whether to grant verification rights

**Returns:** `(response bool uint)`

**Requirements:**
- Caller must be the document owner
- Verifier address must be valid and different from sender

### revoke-access

Revokes all permissions for a verifier on a document.

**Parameters:**
- `doc-id` (buff 32): Document identifier
- `verifier-addr` (principal): Address of the verifier

**Returns:** `(response bool uint)`

**Requirements:**
- Caller must be the document owner

## Read-Only Functions

### get-document

Retrieves complete document information.

**Parameters:**
- `doc-id` (buff 32): Document identifier

**Returns:** Document record with all fields

### get-permissions

Retrieves verifier permissions for a specific document.

**Parameters:**
- `doc-id` (buff 32): Document identifier
- `verifier-addr` (principal): Verifier address

**Returns:** Permission record with `can-read` and `can-verify` flags

### document-exists

Checks if a document exists in the registry.

**Parameters:**
- `doc-id` (buff 32): Document identifier

**Returns:** `(response bool uint)`

## Error Codes

- `u100`: Unauthorized access
- `u101`: Document already exists
- `u102`: Document not found
- `u103`: Verification already completed (document locked)
- `u104`: Invalid document ID format
- `u105`: Invalid hash format
- `u106`: Invalid metadata
- `u107`: Invalid verifier address
- `u108`: Invalid parameters
- `u109`: Insufficient permissions
- `u110`: Null value error

## Validation Rules

- Document IDs must be exactly 32 bytes
- Content hashes must be exactly 32 bytes
- Metadata must be between 1 and 256 UTF-8 characters
- Verifier addresses cannot be the transaction sender or contract address

## Usage Example

```clarity
;; Register a new document
(contract-call? .document-registry register-document
    0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
    0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321
    u"Legal contract for property transfer")

;; Grant verification rights to a verifier
(contract-call? .document-registry grant-access
    0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
    'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM
    true
    true)

;; Verifier approves the document
(contract-call? .document-registry verify-document
    0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef)
```
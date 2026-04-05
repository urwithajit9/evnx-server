// Blob key naming: vaults/{vault_id}/{version_num:08}/{uuid}.enc
// Always set: ContentType: application/octet-stream
// Always set: x-amz-server-side-encryption: AES256
// On upload: verify ETag matches BLAKE3(ciphertext) or abort
// On download: verify ETag + blob_hash from DB metadata
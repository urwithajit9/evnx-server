// src/services/storage.rs
// Blob key naming: vaults/{vault_id}/{version_num:08}/{uuid}.enc
// Always set: ContentType: application/octet-stream
// Always set: x-amz-server-side-encryption: AES256
// On upload: verify ETag matches BLAKE3(ciphertext) or abort
// On download: verify ETag + blob_hash from DB metadata

use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::{
    config::{Credentials, Region},
    Client,
};
use bytes::Bytes;
use uuid::Uuid;

#[derive(Clone)]
pub struct StorageService {
    client: Client,
    bucket: String,
}

impl StorageService {
    /// Build an S3 client from config.
    /// If `endpoint_url` is Some, connects to LocalStack/MinIO instead of AWS.
    pub async fn new(
        access_key_id: &str,
        secret_access_key: &str,
        region: &str,
        bucket: String,
        endpoint_url: Option<&str>,
    ) -> Self {
        let creds = Credentials::new(access_key_id, secret_access_key, None, None, "evnx-server");

        let mut builder = aws_sdk_s3::config::Builder::new()
            .credentials_provider(creds)
            .region(Region::new(region.to_string()))
            .force_path_style(endpoint_url.is_some()); // LocalStack needs path-style

        if let Some(url) = endpoint_url {
            builder = builder.endpoint_url(url);
        }

        let config = builder.build();
        Self {
            client: Client::from_conf(config),
            bucket,
        }
    }

    /// Generate S3 object key for a vault version blob.
    /// Format: `vaults/{vault_id}/{version:08}/{uuid}.enc`
    pub fn blob_key(vault_id: Uuid, version_num: i32) -> String {
        format!(
            "vaults/{}/{:08}/{}.enc",
            vault_id,
            version_num,
            Uuid::new_v4()
        )
    }

    /// Upload encrypted blob to S3.
    /// Returns the S3 ETag (content hash from AWS — use for upload verification).
    pub async fn upload_blob(&self, key: &str, data: Bytes) -> Result<String, StorageError> {
        let stream = ByteStream::from(data);

        let output = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_type("application/octet-stream")
            .server_side_encryption(aws_sdk_s3::types::ServerSideEncryption::Aes256)
            .body(stream)
            .send()
            .await
            .map_err(|e| StorageError::Upload(e.to_string()))?;

        output
            .e_tag()
            .map(|s| s.trim_matches('"').to_string())
            .ok_or_else(|| StorageError::Upload("No ETag returned".into()))
    }

    /// Download blob from S3. Returns raw bytes.
    pub async fn download_blob(&self, key: &str) -> Result<Bytes, StorageError> {
        let output = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| StorageError::Download(e.to_string()))?;

        output
            .body
            .collect()
            .await
            .map(|data| data.into_bytes())
            .map_err(|e| StorageError::Download(e.to_string()))
    }

    /// Delete a blob (used when hard-deleting vault versions).
    pub async fn delete_blob(&self, key: &str) -> Result<(), StorageError> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| StorageError::Delete(e.to_string()))?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("S3 upload failed: {0}")]
    Upload(String),
    #[error("S3 download failed: {0}")]
    Download(String),
    #[error("S3 delete failed: {0}")]
    Delete(String),
}

impl From<StorageError> for crate::errors::AppError {
    fn from(e: StorageError) -> Self {
        tracing::error!(error = %e, "S3 storage error");
        crate::errors::AppError::Internal(e.to_string())
    }
}

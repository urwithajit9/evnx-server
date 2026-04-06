// src/services/storage.rs

use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::{
    config::{BehaviorVersion, Credentials, Region},
    Client,
};
use bytes::Bytes;
use uuid::Uuid;

/// Storage provider type — determines addressing style and configuration.
#[derive(Clone, Debug)]
pub enum StorageProvider {
    /// AWS S3 — virtual-hosted style, no endpoint override
    Aws,
    /// Hetzner Object Storage — virtual-hosted style WITH endpoint override
    /// endpoint: e.g. "https://fsn1.your-objectstorage.com"
    Hetzner { endpoint: String },
    /// LocalStack (local dev) — path-style, endpoint override
    /// endpoint: e.g. "http://localhost:4566"
    LocalStack { endpoint: String },
}

#[derive(Clone)]
pub struct StorageService {
    client: Client,
    bucket: String,
    provider: StorageProvider,
}

impl StorageService {
    /// Build from configuration.
    ///
    /// # Provider detection logic:
    /// - `s3_endpoint` is None → AWS S3
    /// - `s3_endpoint` contains "your-objectstorage.com" → Hetzner
    /// - `s3_endpoint` contains "localhost" or "localstack" → LocalStack
    pub async fn from_config(
        access_key_id: &str,
        secret_access_key: &str,
        region: &str,
        bucket: String,
        s3_endpoint: Option<&str>,
    ) -> Self {
        let provider = match s3_endpoint {
            None => StorageProvider::Aws,
            Some(ep) if ep.contains("your-objectstorage.com") => StorageProvider::Hetzner {
                endpoint: ep.to_string(),
            },
            Some(ep) => StorageProvider::LocalStack {
                endpoint: ep.to_string(),
            },
        };

        let client = Self::build_client(access_key_id, secret_access_key, region, &provider).await;

        Self {
            client,
            bucket,
            provider,
        }
    }

    async fn build_client(
        access_key_id: &str,
        secret_access_key: &str,
        region: &str,
        provider: &StorageProvider,
    ) -> Client {
        let creds = Credentials::new(access_key_id, secret_access_key, None, None, "evnx-server");

        let mut builder = aws_sdk_s3::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .credentials_provider(creds)
            .region(Region::new(region.to_string()));

        match provider {
            StorageProvider::Aws => {
                // No endpoint override — uses AWS default virtual-hosted endpoints
            }
            StorageProvider::Hetzner { endpoint } => {
                // Hetzner: set endpoint override, use virtual-hosted style (default)
                // IMPORTANT: force_path_style must be FALSE for Hetzner
                // The bucket name goes in the subdomain: bucket.fsn1.your-objectstorage.com
                builder = builder.endpoint_url(endpoint).force_path_style(false);
            }
            StorageProvider::LocalStack { endpoint } => {
                // LocalStack: path-style required
                builder = builder.endpoint_url(endpoint).force_path_style(true);
            }
        }

        Client::from_conf(builder.build())
    }

    /// Generate S3 object key for a vault version blob.
    ///
    /// Format: `vaults/{vault_id}/{version_num:08}/{uuid}.enc`
    /// This structure gives O(1) lookup by vault+version and
    /// allows listing all versions of a vault efficiently.
    pub fn blob_key(vault_id: Uuid, version_num: i32) -> String {
        format!(
            "vaults/{}/{:08}/{}.enc",
            vault_id,
            version_num,
            Uuid::new_v4()
        )
    }

    /// Upload encrypted blob.
    ///
    /// For Hetzner: does NOT set ServerSideEncryption header (not supported).
    /// For AWS: SSE-S3 header included for compliance.
    /// All providers: Content-Type = application/octet-stream.
    pub async fn upload_blob(&self, key: &str, data: Bytes) -> Result<String, StorageError> {
        let content_length = data.len() as i64;
        let stream = ByteStream::from(data);

        let mut req = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_type("application/octet-stream")
            .content_length(content_length)
            .body(stream);

        // Only set SSE for AWS — Hetzner ignores it but it wastes bandwidth
        if matches!(self.provider, StorageProvider::Aws) {
            req = req.server_side_encryption(aws_sdk_s3::types::ServerSideEncryption::Aes256);
        }

        let output = req
            .send()
            .await
            .map_err(|e| StorageError::Upload(e.to_string()))?;

        output
            .e_tag()
            .map(|s| s.trim_matches('"').to_string())
            .ok_or_else(|| StorageError::Upload("No ETag returned from storage provider".into()))
    }

    /// Download blob and return raw bytes.
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

    /// Check if a blob exists (used for integrity verification).
    pub async fn blob_exists(&self, key: &str) -> Result<bool, StorageError> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                let service_err = e.into_service_error();
                if service_err.is_not_found() {
                    Ok(false)
                } else {
                    Err(StorageError::Download(service_err.to_string()))
                }
            }
        }
    }

    /// Delete a blob (called when hard-deleting vault versions after 30-day soft-delete period).
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

    /// Provider name for logging/health checks.
    pub fn provider_name(&self) -> &str {
        match &self.provider {
            StorageProvider::Aws => "aws-s3",
            StorageProvider::Hetzner { .. } => "hetzner-object-storage",
            StorageProvider::LocalStack { .. } => "localstack",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Upload failed: {0}")]
    Upload(String),
    #[error("Download failed: {0}")]
    Download(String),
    #[error("Delete failed: {0}")]
    Delete(String),
}

impl From<StorageError> for crate::errors::AppError {
    fn from(e: StorageError) -> Self {
        tracing::error!(error = %e, "Object storage error");
        crate::errors::AppError::Internal(e.to_string())
    }
}

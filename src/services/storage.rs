// src/services/storage.rs

//! Object storage for encrypted vault blobs.
//!
//! The backend is named explicitly in configuration — `STORAGE_BACKEND` is one of
//! `s3`, `gcs`, `azure` or `local` — and is **never inferred**. An earlier version
//! guessed the provider by sniffing the endpoint hostname
//! (`endpoint.contains("your-objectstorage.com")`), which silently misconfigured
//! anything it did not recognise.
//!
//! `s3` covers AWS and every S3-compatible service (Hetzner, MinIO, Cloudflare R2,
//! Wasabi, Backblaze B2) via `STORAGE_ENDPOINT`; some of those need path-style
//! addressing, which `STORAGE_PATH_STYLE` controls.
//!
//! Only four operations are needed — put, get, head, delete — because the server
//! handles nothing but opaque ciphertext it cannot read.

use bytes::Bytes;
use object_store::{
    aws::AmazonS3Builder, azure::MicrosoftAzureBuilder, gcp::GoogleCloudStorageBuilder,
    local::LocalFileSystem, path::Path as ObjectPath, ObjectStore, PutPayload,
};
// The ergonomic put/get/head/delete live on this extension trait in 0.14;
// `ObjectStore` itself only exposes the *_opts variants.
use object_store::ObjectStoreExt;
use std::sync::Arc;
use uuid::Uuid;

use crate::config::{Config, StorageBackend};

#[derive(Clone)]
pub struct StorageService {
    store: Arc<dyn ObjectStore>,
    backend: &'static str,
}

impl StorageService {
    /// Build the configured backend.
    ///
    /// # Errors
    /// Returns a message suitable for a startup failure. Misconfigured storage
    /// must stop the process, not surface later as a failed push.
    pub fn from_config(config: &Config) -> Result<Self, String> {
        let store: Arc<dyn ObjectStore> = match config.storage_backend {
            StorageBackend::S3 => {
                let mut builder = AmazonS3Builder::from_env()
                    .with_bucket_name(&config.storage_bucket)
                    // Path-style is required by MinIO and LocalStack; AWS and
                    // Hetzner use virtual-hosted style.
                    .with_virtual_hosted_style_request(!config.storage_path_style);

                if let Some(region) = &config.storage_region {
                    builder = builder.with_region(region);
                }
                if let Some(endpoint) = &config.storage_endpoint {
                    // Plain HTTP is only ever a local emulator (LocalStack/MinIO).
                    let insecure = endpoint.starts_with("http://");
                    builder = builder.with_endpoint(endpoint).with_allow_http(insecure);
                }
                // Credentials are optional: when absent, object_store resolves
                // them from the environment or the instance role, which is how a
                // production deployment should supply them.
                if let Some(key) = &config.storage_access_key_id {
                    builder = builder.with_access_key_id(key);
                }
                if let Some(secret) = &config.storage_secret_access_key {
                    builder = builder.with_secret_access_key(secret);
                }

                Arc::new(builder.build().map_err(|e| format!("S3 storage: {e}"))?)
            }

            StorageBackend::Gcs => Arc::new(
                // Reads GOOGLE_SERVICE_ACCOUNT / GOOGLE_SERVICE_ACCOUNT_KEY.
                GoogleCloudStorageBuilder::from_env()
                    .with_bucket_name(&config.storage_bucket)
                    .build()
                    .map_err(|e| format!("GCS storage: {e}"))?,
            ),

            StorageBackend::Azure => Arc::new(
                // Reads AZURE_STORAGE_ACCOUNT_NAME / AZURE_STORAGE_ACCESS_KEY.
                MicrosoftAzureBuilder::from_env()
                    .with_container_name(&config.storage_bucket)
                    .build()
                    .map_err(|e| format!("Azure storage: {e}"))?,
            ),

            StorageBackend::Local => {
                // Development and tests. Blobs are ciphertext, so a plain
                // directory is no less safe than a bucket — but it is not shared
                // between instances, so never use it for a real deployment.
                std::fs::create_dir_all(&config.storage_local_path)
                    .map_err(|e| format!("local storage {}: {e}", config.storage_local_path))?;
                Arc::new(
                    LocalFileSystem::new_with_prefix(&config.storage_local_path)
                        .map_err(|e| format!("local storage: {e}"))?,
                )
            }
        };

        Ok(Self {
            store,
            backend: config.storage_backend.as_str(),
        })
    }

    /// Backend name, for startup logging and health output.
    pub fn backend_name(&self) -> &'static str {
        self.backend
    }

    /// Object key for a vault version blob.
    ///
    /// `vaults/{vault_id}/{version:08}/{uuid}.enc` — sorts by version and keeps
    /// every version of a vault under one prefix. The trailing UUID means a retry
    /// never overwrites an existing blob.
    pub fn blob_key(vault_id: Uuid, version_num: i32) -> String {
        format!(
            "vaults/{}/{:08}/{}.enc",
            vault_id,
            version_num,
            Uuid::new_v4()
        )
    }

    pub async fn upload_blob(&self, key: &str, data: Bytes) -> Result<(), StorageError> {
        self.store
            .put(&ObjectPath::from(key), PutPayload::from_bytes(data))
            .await
            .map_err(|e| StorageError::Upload(e.to_string()))?;
        Ok(())
    }

    pub async fn download_blob(&self, key: &str) -> Result<Bytes, StorageError> {
        self.store
            .get(&ObjectPath::from(key))
            .await
            .map_err(|e| StorageError::Download(e.to_string()))?
            .bytes()
            .await
            .map_err(|e| StorageError::Download(e.to_string()))
    }

    pub async fn blob_exists(&self, key: &str) -> Result<bool, StorageError> {
        match self.store.head(&ObjectPath::from(key)).await {
            Ok(_) => Ok(true),
            Err(object_store::Error::NotFound { .. }) => Ok(false),
            Err(e) => Err(StorageError::Download(e.to_string())),
        }
    }

    pub async fn delete_blob(&self, key: &str) -> Result<(), StorageError> {
        self.store
            .delete(&ObjectPath::from(key))
            .await
            .map_err(|e| StorageError::Delete(e.to_string()))
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

//! Multi-Tenant Registry & Quota Management for AgentKernel.

use anyhow::Context;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Configuration and quotas for a registered tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantConfig {
    /// Unique tenant identifier
    pub id: String,
    /// Human-readable organization or tenant name
    pub name: String,
    /// Secret API Key used for Bearer authentication
    pub api_key: String,
    /// Maximum concurrent ephemeral micro-sandboxes allowed for this tenant
    pub max_sandboxes: usize,
    /// Timestamp when tenant was registered
    #[serde(default = "default_created_at")]
    pub created_at: String,
}

fn default_created_at() -> String {
    Utc::now().to_rfc3339()
}

/// Registry containing all tenants and their respective resource quotas.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TenantsRegistry {
    pub tenants: Vec<TenantConfig>,
}

impl TenantsRegistry {
    /// Load tenants registry from a JSON file.
    /// If the file does not exist, an empty registry is returned.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read tenants file: {}", path.display()))?;

        if content.trim().is_empty() {
            return Ok(Self::default());
        }

        // Support both {"tenants": [...]} format and direct array [...] format
        if let Ok(registry) = serde_json::from_str::<TenantsRegistry>(&content) {
            Ok(registry)
        } else if let Ok(tenants_list) = serde_json::from_str::<Vec<TenantConfig>>(&content) {
            Ok(Self { tenants: tenants_list })
        } else {
            anyhow::bail!("Invalid tenants JSON schema in {}", path.display());
        }
    }

    /// Save tenants registry to a JSON file.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("Failed to create directories for: {}", parent.display())
                })?;
            }
        }

        let json = serde_json::to_string_pretty(self)
            .context("Failed to serialize tenants registry to JSON")?;
        std::fs::write(path, json)
            .with_context(|| format!("Failed to write tenants file: {}", path.display()))?;
        Ok(())
    }

    /// Add a new tenant or update an existing tenant by ID.
    pub fn add_or_update(&mut self, mut tenant: TenantConfig) {
        if let Some(existing) = self.tenants.iter_mut().find(|t| t.id == tenant.id) {
            // Preserve creation date if already set
            tenant.created_at = existing.created_at.clone();
            *existing = tenant;
        } else {
            self.tenants.push(tenant);
        }
    }

    /// Find tenant configuration by API key.
    pub fn find_by_api_key(&self, key: &str) -> Option<&TenantConfig> {
        self.tenants.iter().find(|t| t.api_key == key)
    }

    /// Find tenant configuration by tenant ID.
    pub fn find_by_id(&self, id: &str) -> Option<&TenantConfig> {
        self.tenants.iter().find(|t| t.id == id)
    }
}

/// Handler for `agentkernel tenant list --tenants-file <path>`
pub fn handle_tenant_list(tenants_file: &Path) -> anyhow::Result<()> {
    let registry = TenantsRegistry::load(tenants_file)?;

    if registry.tenants.is_empty() {
        println!("No tenants registered in '{}'.", tenants_file.display());
        return Ok(());
    }

    println!("==========================================================================================================");
    println!("  AgentKernel Tenants Registry: {}", tenants_file.display());
    println!("==========================================================================================================");
    println!("  {:<16} {:<24} {:<32} {:<15} {:<20}", "ID", "NAME", "API KEY", "MAX SANDBOXES", "CREATED AT");
    println!("  {:-<16} {:-<24} {:-<32} {:-<15} {:-<20}", "", "", "", "", "");

    for t in &registry.tenants {
        println!(
            "  {:<16} {:<24} {:<32} {:<15} {:<20}",
            t.id, t.name, t.api_key, t.max_sandboxes, t.created_at
        );
    }

    println!("==========================================================================================================");
    println!("  Total: {} tenant(s) registered", registry.tenants.len());
    Ok(())
}

/// Handler for `agentkernel tenant add --tenants-file <path> --id <id> --name <name> --api-key <key> --max-sandboxes <num>`
pub fn handle_tenant_add(
    tenants_file: &Path,
    id: &str,
    name: &str,
    api_key: &str,
    max_sandboxes: usize,
) -> anyhow::Result<()> {
    let mut registry = TenantsRegistry::load(tenants_file)?;

    let tenant = TenantConfig {
        id: id.to_string(),
        name: name.to_string(),
        api_key: api_key.to_string(),
        max_sandboxes,
        created_at: Utc::now().to_rfc3339(),
    };

    registry.add_or_update(tenant);
    registry.save(tenants_file)?;

    println!(
        "Successfully registered tenant '{}' ('{}') with quota limit of {} sandboxes in '{}'.",
        id, name, max_sandboxes, tenants_file.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_tenants_registry_load_empty() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();
        let reg = TenantsRegistry::load(path).unwrap();
        assert!(reg.tenants.is_empty());
    }

    #[test]
    fn test_tenants_registry_add_and_load() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path();

        let mut reg = TenantsRegistry::default();
        reg.add_or_update(TenantConfig {
            id: "t-acme".to_string(),
            name: "Acme Corp".to_string(),
            api_key: "ak_test_secret123".to_string(),
            max_sandboxes: 5,
            created_at: "2026-10-31T20:00:00Z".to_string(),
        });
        reg.save(path).unwrap();

        let loaded = TenantsRegistry::load(path).unwrap();
        assert_eq!(loaded.tenants.len(), 1);
        assert_eq!(loaded.tenants[0].id, "t-acme");
        assert_eq!(loaded.tenants[0].name, "Acme Corp");
        assert_eq!(loaded.tenants[0].max_sandboxes, 5);

        let by_key = loaded.find_by_api_key("ak_test_secret123").unwrap();
        assert_eq!(by_key.id, "t-acme");

        assert!(loaded.find_by_api_key("wrong_key").is_none());
    }

    #[test]
    fn test_tenants_registry_update_existing() {
        let mut reg = TenantsRegistry::default();
        reg.add_or_update(TenantConfig {
            id: "t-1".to_string(),
            name: "Initial Name".to_string(),
            api_key: "key-1".to_string(),
            max_sandboxes: 2,
            created_at: "2026-10-31T10:00:00Z".to_string(),
        });

        // Update
        reg.add_or_update(TenantConfig {
            id: "t-1".to_string(),
            name: "Updated Name".to_string(),
            api_key: "key-updated".to_string(),
            max_sandboxes: 10,
            created_at: "2026-10-31T12:00:00Z".to_string(),
        });

        assert_eq!(reg.tenants.len(), 1);
        let t = &reg.tenants[0];
        assert_eq!(t.name, "Updated Name");
        assert_eq!(t.api_key, "key-updated");
        assert_eq!(t.max_sandboxes, 10);
        assert_eq!(t.created_at, "2026-10-31T10:00:00Z"); // preserved
    }
}

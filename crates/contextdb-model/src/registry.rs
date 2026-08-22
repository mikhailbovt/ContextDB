use std::collections::BTreeMap;
use std::fmt;
use std::sync::RwLock;

use contextdb_core::ModelProfileId;

use crate::{
    CapabilityRoute, ModelCapability, ModelProfile, ModelRuntimeError, ProviderId, Result,
    SchemaRef,
};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RouteKey {
    provider: ProviderId,
    model_profile: ModelProfileId,
    model_revision: crate::ModelRevision,
    capability: ModelCapability,
    schema: SchemaRef,
}

/// Provider-neutral registry of model profiles and specialized capability
/// routes. It contains descriptors only, never provider credentials.
#[derive(Default)]
pub struct CapabilityRegistry {
    profiles: RwLock<BTreeMap<ModelProfileId, ModelProfile>>,
    routes: RwLock<BTreeMap<RouteKey, CapabilityRoute>>,
}

impl fmt::Debug for CapabilityRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityRegistry")
            .finish_non_exhaustive()
    }
}

impl CapabilityRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an immutable model profile. Repeating an identical profile is
    /// idempotent; changing an existing ID is rejected.
    pub fn register_profile(&self, profile: ModelProfile) -> Result<()> {
        profile.validate()?;
        let mut profiles = self
            .profiles
            .write()
            .map_err(|_| ModelRuntimeError::LockPoisoned)?;
        match profiles.get(&profile.id) {
            Some(existing) if existing == &profile => Ok(()),
            Some(_) => Err(ModelRuntimeError::RegistryConflict(format!(
                "model profile {}",
                profile.id
            ))),
            None => {
                profiles.insert(profile.id, profile);
                Ok(())
            }
        }
    }

    /// Registers one provider/model/capability descriptor.
    pub fn register_route(&self, route: CapabilityRoute) -> Result<()> {
        route.validate()?;
        let profile = self.profile(route.descriptor.model_profile)?;
        if profile.revision != route.model_revision
            || !route
                .descriptor
                .input_modalities
                .is_subset(&profile.modalities)
            || !route.descriptor.languages.is_subset(&profile.languages)
        {
            return Err(ModelRuntimeError::RegistryConflict(
                "route is incompatible with its model profile".to_owned(),
            ));
        }
        let key = RouteKey {
            provider: route.provider.clone(),
            model_profile: route.descriptor.model_profile,
            model_revision: route.model_revision.clone(),
            capability: route.descriptor.capability.clone(),
            schema: route.descriptor.output_schema.clone(),
        };
        let mut routes = self
            .routes
            .write()
            .map_err(|_| ModelRuntimeError::LockPoisoned)?;
        match routes.get(&key) {
            Some(existing) if existing == &route => Ok(()),
            Some(_) => Err(ModelRuntimeError::RegistryConflict(format!(
                "provider capability route {}",
                route.provider
            ))),
            None => {
                routes.insert(key, route);
                Ok(())
            }
        }
    }

    /// Resolves a model profile.
    pub fn profile(&self, id: ModelProfileId) -> Result<ModelProfile> {
        self.profiles
            .read()
            .map_err(|_| ModelRuntimeError::LockPoisoned)?
            .get(&id)
            .cloned()
            .ok_or(ModelRuntimeError::ProfileUnavailable)
    }

    /// Returns all routes for an exact capability/schema pair in deterministic
    /// descriptor order. Policy routing performs the remaining filtering.
    pub fn routes_for(
        &self,
        capability: &ModelCapability,
        schema: &SchemaRef,
    ) -> Result<Vec<CapabilityRoute>> {
        capability.validate()?;
        Ok(self
            .routes
            .read()
            .map_err(|_| ModelRuntimeError::LockPoisoned)?
            .values()
            .filter(|route| {
                route.descriptor.capability == *capability
                    && route.descriptor.output_schema == *schema
            })
            .cloned()
            .collect())
    }

    /// Returns immutable profile snapshots for migration diagnostics.
    pub fn profiles(&self) -> Result<crate::ModelProfileMap> {
        Ok(self
            .profiles
            .read()
            .map_err(|_| ModelRuntimeError::LockPoisoned)?
            .clone())
    }
}

use std::{
    fmt,
    ops::{Deref, DerefMut},
};

use serde::{Deserialize, Deserializer, Serialize};

use crate::{ValidationError, ValidationResult};

/// A serializable vector that is guaranteed to contain at least one element.
#[derive(Clone, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct NonEmptyVec<T>(Vec<T>);

impl<T> NonEmptyVec<T> {
    /// Creates a non-empty vector.
    pub fn new(first: T) -> Self {
        Self(vec![first])
    }

    /// Validates and wraps an existing vector.
    pub fn try_from_vec(values: Vec<T>, field: &'static str) -> ValidationResult<Self> {
        if values.is_empty() {
            return Err(ValidationError::EmptyCollection { field });
        }
        Ok(Self(values))
    }

    /// Appends an element while preserving non-emptiness.
    pub fn push(&mut self, value: T) {
        self.0.push(value);
    }

    /// Consumes this wrapper and returns its vector.
    pub fn into_vec(self) -> Vec<T> {
        self.0
    }

    /// Returns the first element.
    pub fn first(&self) -> &T {
        // SAFETY is not involved: construction and deserialization reject empty values.
        &self.0[0]
    }
}

impl<T> Deref for NonEmptyVec<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for NonEmptyVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: fmt::Debug> fmt::Debug for NonEmptyVec<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("NonEmptyVec").field(&self.0).finish()
    }
}

impl<'de, T> Deserialize<'de> for NonEmptyVec<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Vec::<T>::deserialize(deserializer)?;
        if values.is_empty() {
            return Err(serde::de::Error::custom("expected at least one element"));
        }
        Ok(Self(values))
    }
}

impl<T> IntoIterator for NonEmptyVec<T> {
    type IntoIter = std::vec::IntoIter<T>;
    type Item = T;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a NonEmptyVec<T> {
    type IntoIter = std::slice::Iter<'a, T>;
    type Item = &'a T;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

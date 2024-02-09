// from https://stackoverflow.com/a/74483246
use serde::de;
use serde::ser;
use std::ops::Deref;

#[derive(Debug)]
pub struct LimitedString<const MAX_LENGTH: usize>(pub String);

impl<const MAX_LENGTH: usize> std::convert::From<String> for LimitedString<MAX_LENGTH> {
    fn from(value: String) -> Self {
        LimitedString(value)
    }
}

impl<const MAX_LENGTH: usize> Deref for LimitedString<MAX_LENGTH> {
    type Target = String;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'de, const MAX_LENGTH: usize> de::Deserialize<'de> for LimitedString<MAX_LENGTH> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        <String as de::Deserialize>::deserialize(deserializer).and_then(|inner| {
            if inner.len() > MAX_LENGTH {
                Err(de::Error::invalid_length(
                    inner.len(),
                    &"an integer lower than the maximum",
                ))
            } else {
                Ok(Self(inner))
            }
        })
    }
}

impl<const MAX_LENGTH: usize> ser::Serialize for LimitedString<MAX_LENGTH> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

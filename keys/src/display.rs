use ustd::{ops, prelude::*};

use super::error::Error;

pub trait DisplayLayout {
    type Target: ops::Deref<Target = [u8]>;

    fn layout(&self) -> Self::Target;

    fn from_layout(data: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;
}

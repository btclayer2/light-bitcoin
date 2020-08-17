extern crate proc_macro;

mod de;
mod ser;

use self::de::impl_deserializable;
use self::ser::impl_serializable;

#[proc_macro_derive(Serializable)]
pub fn serializable(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ast = syn::parse_macro_input!(input as syn::DeriveInput);
    let gen = impl_serializable(&ast);
    proc_macro::TokenStream::from(gen)
}

#[proc_macro_derive(Deserializable)]
pub fn deserializable(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ast = syn::parse_macro_input!(input as syn::DeriveInput);
    let gen = impl_deserializable(&ast);
    proc_macro::TokenStream::from(gen)
}

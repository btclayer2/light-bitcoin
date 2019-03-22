extern crate proc_macro;

mod de;
mod ser;

use proc_macro::TokenStream;

use self::de::impl_deserializable;
use self::ser::impl_serializable;

#[proc_macro_derive(Serializable)]
pub fn serializable(input: TokenStream) -> TokenStream {
    let s = input.to_string();
    let ast = syn::parse_derive_input(&s).unwrap();
    let gen = impl_serializable(&ast);
    gen.parse().unwrap()
}

#[proc_macro_derive(Deserializable)]
pub fn deserializable(input: TokenStream) -> TokenStream {
    let s = input.to_string();
    let ast = syn::parse_derive_input(&s).unwrap();
    let gen = impl_deserializable(&ast);
    gen.parse().unwrap()
}

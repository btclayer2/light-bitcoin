use quote::{format_ident, quote};

pub fn impl_deserializable(ast: &syn::DeriveInput) -> proc_macro2::TokenStream {
    let fields = match ast.data {
        syn::Data::Struct(ref data) => &data.fields,
        _ => panic!("#[derive(Deserializable)] is only defined for structs."),
    };

    let stmts = match fields {
        syn::Fields::Named(_) | syn::Fields::Unnamed(_) => fields
            .iter()
            .enumerate()
            .map(deserialize_field_map)
            .collect::<Vec<_>>(),
        syn::Fields::Unit => panic!("#[derive(Deserializable)] is not defined for Unit structs."),
    };

    let name = &ast.ident;

    let dummy_const = format_ident!("_IMPL_DESERIALIZABLE_FOR_{}", name);
    let impl_block = quote! {
        impl serialization::Deserializable for #name {
            fn deserialize<T>(reader: &mut serialization::Reader<T>) -> Result<Self, serialization::Error>
            where
                T: io::Read,
            {
                let result = #name {
                    #(#stmts)*
                };

                Ok(result)
            }
        }
    };

    quote! {
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const #dummy_const: () = {
            extern crate light_bitcoin_serialization as serialization;
            use serialization::primitives::io;
            #impl_block
        };
    }
}

fn deserialize_field_map(tuple: (usize, &syn::Field)) -> proc_macro2::TokenStream {
    deserialize_field(tuple.0, tuple.1)
}

fn deserialize_field(index: usize, field: &syn::Field) -> proc_macro2::TokenStream {
    let id = match field.ident {
        Some(ref ident) => format_ident!("{}", ident),
        None => format_ident!("{}", index),
    };

    match field.ty {
        syn::Type::Path(ref path) => {
            let ident = &path
                .path
                .segments
                .first()
                .expect("there must be at least 1 segment")
                .ident;
            if ident == "Vec" {
                quote! { #id: reader.read_list()?, }
            } else {
                quote! { #id: reader.read()?, }
            }
        }
        _ => panic!("serialization not supported"),
    }
}

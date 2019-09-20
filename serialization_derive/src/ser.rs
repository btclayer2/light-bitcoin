use quote::{format_ident, quote};

pub fn impl_serializable(ast: &syn::DeriveInput) -> proc_macro2::TokenStream {
    let fields = match ast.data {
        syn::Data::Struct(ref data) => &data.fields,
        _ => panic!("#[derive(Serializable)] is only defined for structs."),
    };

    let stmts = match fields {
        syn::Fields::Named(_) | syn::Fields::Unnamed(_) => fields
            .iter()
            .enumerate()
            .map(serialize_field_map)
            .collect::<Vec<_>>(),
        syn::Fields::Unit => panic!("#[derive(Serializable)] is not defined for Unit structs."),
    };

    let size_stmts = match fields {
        syn::Fields::Named(_) | syn::Fields::Unnamed(_) => fields
            .iter()
            .enumerate()
            .map(serialize_field_size_map)
            .collect::<Vec<_>>(),
        syn::Fields::Unit => panic!("#[derive(Serializable)] is not defined for Unit structs."),
    };

    let name = &ast.ident;

    let dummy_const = format_ident!("_IMPL_SERIALIZABLE_FOR_{}", name);
    let impl_block = quote! {
        impl serialization::Serializable for #name {
            fn serialize(&self, stream: &mut serialization::Stream) {
                #(#stmts)*
            }

            fn serialized_size(&self) -> usize {
                #(#size_stmts)+*
            }
        }
    };

    quote! {
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const #dummy_const: () = {
            extern crate serialization;
            #impl_block
        };
    }
}

fn serialize_field_size_map(tuple: (usize, &syn::Field)) -> proc_macro2::TokenStream {
    serialize_field_size(tuple.0, tuple.1)
}

fn serialize_field_size(index: usize, field: &syn::Field) -> proc_macro2::TokenStream {
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
                quote! { serialization::serialized_list_size(&self.#id) }
            } else {
                quote! { self.#id.serialized_size() }
            }
        }
        _ => panic!("serialization not supported"),
    }
}

fn serialize_field_map(tuple: (usize, &syn::Field)) -> proc_macro2::TokenStream {
    serialize_field(tuple.0, tuple.1)
}

fn serialize_field(index: usize, field: &syn::Field) -> proc_macro2::TokenStream {
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
                quote! { stream.append_list(&self.#id); }
            } else {
                quote! { stream.append(&self.#id); }
            }
        }
        _ => panic!("serialization not supported"),
    }
}

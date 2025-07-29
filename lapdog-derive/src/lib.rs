use std::{collections::HashMap, ops::BitOr};

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{DataStruct, DeriveInput, Field, Fields, Ident, parse_quote};

#[proc_macro_derive(Entry, attributes(lapdog))]
pub fn implement_from_entry(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(item as DeriveInput);
    let name = input.ident;
    let (fields, object_name_field) = match parse_fields(
        match input.data {
            syn::Data::Struct(DataStruct { fields, .. }) => match fields {
                Fields::Named(f) => f,
                _ => panic!("Structs fields/attributes must be named to be derivable"),
            },
            _ => unimplemented!("non-struct derives are not supported"),
        }
        .named,
    ) {
        Ok(f) => f,
        Err(e) => return e.into_compile_error().into(),
    };
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    // Generics' type parameters
    let generic_params: Vec<syn::Ident> = input
        .generics
        .params
        .iter()
        .filter_map(|param| match param {
            syn::GenericParam::Type(type_param) => Some(type_param.ident.clone()),
            _ => None,
        })
        .collect();

    // If a field has a generic parameter
    let mut generic_bounds = HashMap::<syn::Ident, NeedsBound>::new();
    for field in &fields {
        if let syn::Type::Path(type_path) = &field.field.ty {
            if let Some(ident) = type_path.path.get_ident() {
                if generic_params.contains(ident) {
                    let this_field = if field.multiple {
                        NeedsBound::Multiple
                    } else {
                        NeedsBound::Octet
                    };
                    generic_bounds
                        .entry(ident.clone())
                        .and_modify(|x| *x = *x | this_field)
                        .or_insert(this_field);
                }
            }
        }
    }

    let mut where_preds: Vec<syn::WherePredicate> = where_clause
        .map(|wc| wc.predicates.clone().into_iter().collect())
        .unwrap_or_default();

    for (ident, needs_bound) in generic_bounds {
        let multi = || {
            [
                parse_quote!(#ident: lapdog::search::FromMultipleOctetStrings),
                parse_quote!(<#ident as lapdog::search::FromMultipleOctetStrings>::Err: 'static),
            ]
        };
        let single = || {
            [
                parse_quote!(#ident: lapdog::search::FromOctetString),
                parse_quote!(<#ident as lapdog::search::FromOctetString>::Err: 'static),
            ]
        };
        match needs_bound {
            NeedsBound::Both => {
                where_preds.extend(multi());
                where_preds.extend(single());
            }
            NeedsBound::Multiple => {
                where_preds.extend(multi());
            }
            NeedsBound::Octet => {
                where_preds.extend(single());
            }
        }
    }

    let where_clause = if where_preds.is_empty() {
        quote!()
    } else {
        quote!(where #(#where_preds),*)
    };

    let insert_object_name = object_name_field.as_ref().map(insert_object_name);
    let field_quotes = fields.iter().map(field_line);
    let field_names = fields.iter().map(|x| x.ident());
    let attribute_names = fields.iter().map(|x| x.attribute_name.clone());
    quote!(
        impl #impl_generics lapdog::search::FromEntry for #name #type_generics #where_clause {
            fn from_entry(entry: lapdog::search::RawEntry) -> Result<#name #type_generics, lapdog::search::FailedToGetFromEntry> {
                #( #field_quotes )*
                Ok(#name { #(#field_names,)* #insert_object_name })
            }

            fn attributes() -> Option<impl Iterator<Item = &'static str>> {
                Some([#(#attribute_names,)*].into_iter())
            }
        }
    )
    .into()
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum NeedsBound {
    Octet,
    Multiple,
    Both,
}
impl BitOr for NeedsBound {
    type Output = NeedsBound;

    fn bitor(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (a, b) if a == b => a,
            _ => NeedsBound::Both,
        }
    }
}

fn insert_object_name(field: &Field) -> TokenStream {
    let field_name = field.ident.as_ref().expect("checked to be named field");
    let ty = &field.ty;
    quote! {
        #field_name: <#ty as From<String>>::from(entry.object_name)
    }
}

struct AttributeField {
    attribute_name: String,
    multiple: bool,
    default: bool,
    field: Field,
}
impl AttributeField {
    fn ident(&self) -> Ident {
        self.field.ident.clone().expect("checked to be named field")
    }
}
fn parse_fields(
    raw_fields: impl IntoIterator<Item = Field>,
) -> Result<(Vec<AttributeField>, Option<Field>), syn::Error> {
    let mut fields: Vec<AttributeField> = Vec::new();
    let mut object_name_field = None;
    'fields: for field in raw_fields {
        let mut multiple = false;
        let mut default = false;
        let mut replaced_attribute_name = None;
        for attr in &field.attrs {
            let mut has_set_object_name_field = false;
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("object_name") {
                    if object_name_field.replace(field.clone()).is_some() {
                        return Err(meta.error("\"object_name\" can only be declared on one field"));
                    };
                    has_set_object_name_field = true;
                    return Ok(());
                }
                if meta.path.require_ident()? == "rename" {
                    let lookahead = meta.input.lookahead1();
                    if lookahead.peek(syn::Token![=]) {
                        let expr = meta
                            .value()
                            .expect("Meta has no value")
                            .parse()
                            .expect("Meta is no expression");
                        let mut value = &expr;
                        while let syn::Expr::Group(e) = value {
                            value = &e.expr;
                        }
                        if let syn::Expr::Lit(syn::ExprLit {
                            lit: syn::Lit::Str(lit),
                            ..
                        }) = value
                        {
                            replaced_attribute_name = Some(lit.value());
                        } else {
                            return Err(meta.error("rename argument must be a string literal"));
                        }
                    } else {
                        return Err(meta.error("rename must be used like \"rename = <LDAP NAME>\""));
                    }
                }
                if meta.path.require_ident()? == "multiple" {
                    multiple = true;
                }
                if meta.path.require_ident()? == "default" {
                    default = true;
                }
                Ok(())
            })?;
            if has_set_object_name_field {
                continue 'fields;
            }
        }
        let attribute_name = replaced_attribute_name
            .unwrap_or_else(|| field.ident.as_ref().expect("checked as named field").to_string());
        fields.push(AttributeField {
            attribute_name,
            multiple,
            default,
            field,
        })
    }
    Ok((fields, object_name_field))
}

fn field_line(data: &AttributeField) -> TokenStream {
    let lookup_name = &data.attribute_name;
    let field_type = &data.field.ty;
    let varname = format_ident!("{}", data.ident());
    let fallback = if data.default {
        quote! { <#field_type as Default>::default() }
    } else {
        quote! { return Err(lapdog::search::FailedToGetFromEntry::MissingField(#lookup_name)) }
    };
    if data.multiple {
        quote! {
            let #varname = match entry.attributes.iter().find(|x| x.r#type == #lookup_name) {
                Some(attrs) => <#field_type as lapdog::search::FromMultipleOctetStrings>::from_multiple_octet_strings(attrs.values.iter().map(|x| x.as_ref()))
                    .map_err(|b| lapdog::search::FailedToGetFromEntry::FailedToParseField(#lookup_name, Box::new(b)))?,
                None => {#fallback},
            };
        }
    } else {
        quote! {
            let #varname = match entry.attributes.iter().find(|x| x.r#type == #lookup_name).map(|x| x.values.as_slice()) {
                Some([attr]) => <#field_type as lapdog::search::FromOctetString>::from_octet_string(attr).map_err(|b| lapdog::search::FailedToGetFromEntry::FailedToParseField(#lookup_name, Box::new(b)))?,
                Some([]) | None => {#fallback},
                Some(_) => {return Err(lapdog::search::FailedToGetFromEntry::TooManyValues(#lookup_name))}
            };
        }
    }
}

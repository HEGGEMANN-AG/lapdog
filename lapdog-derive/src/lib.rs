use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{DataStruct, DeriveInput, Field, Fields, Ident};

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

    let insert_object_name = object_name_field.as_ref().map(insert_object_name);
    let field_quotes = fields.iter().map(field_line);
    let field_names = fields.iter().map(|x| x.ident());
    let attribute_names = fields.iter().map(|x| x.attribute_name.clone());
    quote!(
        impl lapdog::search::FromEntry for #name {
            fn from_entry(entry: lapdog::search::RawEntry) -> Result<#name, lapdog::search::FailedToGetFromEntry> {
                #( #field_quotes )*
                Ok(#name { #(#field_names,)* #insert_object_name })
            }

            fn attributes() -> Option<impl Iterator<Item = &'static str>> {
                Some(vec![#(#attribute_names,)*].into_iter())
            }
        }
    )
    .into()
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

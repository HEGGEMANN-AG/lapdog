use proc_macro::TokenStream;

#[proc_macro_derive(Entry)]
pub fn implement_from_entry(_item: TokenStream) -> TokenStream {
    panic!()
}

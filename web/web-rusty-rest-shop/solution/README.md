# Rust is the way 🦀

+ Edit `API` constant in src/main.rs
+ `cargo run`

## Explaination

- Logical vulnerability in the balance validation
- Balance check is performed when adding to cart
- But cart is session specific and there is no check against multiple sessions
- Adding to cart with different sessions allows to add a total greater than available money
- Confirmation does not check the balance as it relies on the session check
- All confirmations go through, overspending and obtaining all the images

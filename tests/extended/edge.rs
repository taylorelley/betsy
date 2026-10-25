#[cfg(feature="x")]
pub async fn public() { let c = || |x| x+1; }
unsafe fn dangerous() {}
const fn constant() -> i32 {1}
struct S;
impl S { fn associated() -> Self {S} }
trait T { fn required(); fn defaulted() {} }
generate! { fn unseen() {} }

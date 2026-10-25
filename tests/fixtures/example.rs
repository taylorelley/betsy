fn top(x: i32) -> i32 {
    let inc = |n: i32| n + 1;
    inc(x)
}

trait T {
    fn required(&self);
    fn default(&self) -> i32 { 1 }
}

struct S;
impl S {
    fn new() -> Self { S }
    fn method(&self) -> i32 {
        let nested = || 3;
        nested()
    }
}

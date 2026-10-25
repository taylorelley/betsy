int add(int a, int b) { return a + b; }
auto f = [](int a) { return a * 2; };
struct S {
    S() {}
    ~S() {}
    int m() const { return 1; }
};
template<class T> T id(T x) { return x; }

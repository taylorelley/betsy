namespace N { int f(){return 1;} }
struct C { C(){} ~C(){} int in(){return 1;} int out(); C& operator+=(int x){return *this;} operator bool() const {return true;} };
int C::out(){return 2;}
C::C() try {} catch(...) {}
template<class T> T identity(T x){return x;}
auto l = [](){return [](){return 1;};};
[[nodiscard]] int attr(){return 0;}
#if A
int alt(){return 1;}
#else
int alt(){return 2;}
#endif

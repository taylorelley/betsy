int prototype(int);
#if FLAG
static inline int first(int a){return a;}
#else
int second(void){return 2;}
#endif
int old(a) int a; {return a;}
int (*factory(void))(int){return 0;}
#define MAKE(name) int name(){return 1;}

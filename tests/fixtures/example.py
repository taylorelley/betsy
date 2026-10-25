def outer(x):
    def inner(y):
        return y + x
    a = lambda z: z + 1
    return inner(a(x))

class C:
    @staticmethod
    def build():
        return C()

    async def run(self):
        return (lambda t: t * 2)(1)

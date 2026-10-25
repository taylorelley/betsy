@first
@second(1)
def café(
    x = lambda z: z + 2,
):
    def gen():
        yield x
    async def nested():
        return 2
    return gen
class Outer:
    class Inner:
        def method(self):
            return 3
long = lambda x: (x +
                  1)

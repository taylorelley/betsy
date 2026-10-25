export function outer(x) {
  const arrow = (y) => y + x;
  function nested(z) { return z * 2; }
  return [1, 2].map(item => arrow(item) + nested(x));
}

const expression = function namedExpression(a) { return a; };
const generator = function* gen() { yield 1; };
const config = {
  method() { return 1; },
  get value() { return 2; },
  set value(v) { this._value = v; },
};
class C {
  constructor() {}
  async run() { return async () => 42; }
}

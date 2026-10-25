export function parse(x: string): number;
export function parse(x: number): number;
export function parse(x: string | number): number { return Number(x); }
type Fn = (n: number) => number;
interface I { run(): void; }
class Box {
  private x = 0;
  get value() { return this.x; }
  set value(v: number) { this.x = v; }
}
const cb = (x: number) => x * 2;
[1, 2].map((x) => x + 1);

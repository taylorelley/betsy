const generic = <T,>(x:T):T => x;
function load(x:string):string;
function load(x:any){ return x; }
declare function absent():void;
declare class Ambient { absent():void; }
interface I { m():void; (x:number):number; new():I; }
namespace N { export function f(){ function inner<T>(x:T){return x;} return inner(1); } }
class C { @logged m(){return 1;} }
const view = <div onClick={()=>2}/>;

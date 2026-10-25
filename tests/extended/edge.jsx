async function* stream(){ yield 1; }
const a = x => x+1;
const b = x => ({value:x});
const o = {short(){return 1;}, *gen(){yield 2;}};
o?.short();
class X { #private(){return 3;} field = () => 4; static { console.log(1); } }
const ui = <button onClick={()=>1}/>;
const chained = [1].map(x=>x+1).filter(x=>x>0);

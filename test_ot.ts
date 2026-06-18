import { runFullOT, generateDDHPoints } from './src/ot.ts';

async function main() {
  try {
    const res0 = await runFullOT("message 0", "message 1", 0);
    console.log("b=0:", res0);
    const res1 = await runFullOT("message 0", "message 1", 1);
    console.log("b=1:", res1);

    const ddh = generateDDHPoints();
    console.log("ddh:", ddh);
  } catch (e) {
    console.error(e);
  }
}
main();

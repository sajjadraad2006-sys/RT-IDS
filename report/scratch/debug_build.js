import fs from 'fs';
import path from 'path';
import { marked } from 'marked';

const chapters = fs.readdirSync('report/chapters').filter(f => f.endsWith('.md')).sort();
let fullMarkdown = '';
chapters.forEach(f => {
  fullMarkdown += fs.readFileSync(path.join('report/chapters', f), 'utf-8') + '\n\n';
});

let pm = fullMarkdown;
// Step 7: math block stash
const blockMath = [];
pm = pm.replace(/\$\$([\s\S]+?)\$\$/g, (m, math) => {
  blockMath.push(math);
  return '\n\nKATEXBLOCK' + (blockMath.length-1) + 'KATEXBLOCK\n\n';
});

// Step 7b: inline math stash
const inlineMath = [];
pm = pm.replace(/(?<!\\)\$([^\$\n]+?)(?<!\\)\$/g, (m, math) => {
  inlineMath.push(math);
  return 'KATEXINLINE' + (inlineMath.length-1) + 'KATEXINLINE';
});

const idx = pm.indexOf('SYSTEM TESTBED SPECIFICATIONS');
console.log('pm around Table VI:');
console.log(pm.slice(idx - 100, idx + 200));

const outHtml = marked.parse(pm);
const idxHtml = outHtml.indexOf('SYSTEM TESTBED SPECIFICATIONS');
console.log('outHtml around Table VI:');
console.log(outHtml.slice(idxHtml - 100, idxHtml + 200));

// Check where the first &lt;div appears
const firstEscape = outHtml.indexOf('&lt;div');
if (firstEscape !== -1) {
  console.log('First &lt;div at:', firstEscape);
  console.log('Snippet:', outHtml.slice(firstEscape - 100, firstEscape + 200));
} else {
  console.log('No &lt;div found in outHtml!');
}

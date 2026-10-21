import fs from 'fs';
import path from 'path';
import { marked } from 'marked';

const chapters = fs.readdirSync('chapters').filter(f => f.endsWith('.md')).sort();
let fullMarkdown = '';
chapters.forEach(f => {
  fullMarkdown += fs.readFileSync(path.join('chapters', f), 'utf-8') + '\n\n';
});

let pm = fullMarkdown;
console.log('1. fullMarkdown table count:', (marked.parse(pm).match(/<table/g) || []).length);

// Step 7: block math
const blockMath = [];
pm = pm.replace(/\$\$([\s\S]+?)\$\$/g, (m, math) => {
  blockMath.push(math);
  return '\n\nKATEXBLOCK' + (blockMath.length-1) + 'KATEXBLOCK\n\n';
});
console.log('2. After blockMath stash table count:', (marked.parse(pm).match(/<table/g) || []).length);

// Step 7b: inline math
const inlineMath = [];
pm = pm.replace(/(?<!\\)\$([^\$\n]+?)(?<!\\)\$/g, (m, math) => {
  inlineMath.push(math);
  return 'KATEXINLINE' + (inlineMath.length-1) + 'KATEXINLINE';
});
console.log('3. After inlineMath stash table count:', (marked.parse(pm).match(/<table/g) || []).length);

import fs from 'fs';
import path from 'path';
import { marked } from 'marked';

const chapters = fs.readdirSync('chapters').filter(f => f.endsWith('.md')).sort();
let fullMarkdown = '';
chapters.forEach(f => {
  fullMarkdown += fs.readFileSync(path.join('chapters', f), 'utf-8') + '\n\n';
});

let pm = fullMarkdown;

// Stash code blocks and inline code
const codeBlocks = [];
pm = pm.replace(/(```[\s\S]*?```|`[^`\n]+`)/g, (match) => {
  codeBlocks.push(match);
  return `CODEBLOCK${codeBlocks.length - 1}CODEBLOCK`;
});

// Stash block math
const blockMath = [];
pm = pm.replace(/\$\$([\s\S]+?)\$\$/g, (m, math) => {
  blockMath.push(math);
  return `\n\nKATEXBLOCK${blockMath.length - 1}KATEXBLOCK\n\n`;
});

// Stash inline math
const inlineMath = [];
pm = pm.replace(/(?<!\\)\$([^\$\n]+?)(?<!\\)\$/g, (m, math) => {
  inlineMath.push(math);
  return `KATEXINLINE${inlineMath.length - 1}KATEXINLINE`;
});

// Restore code blocks before marked
pm = pm.replace(/CODEBLOCK(\d+)CODEBLOCK/g, (match, id) => codeBlocks[parseInt(id, 10)]);

const outHtml = marked.parse(pm);
const tableCount = (outHtml.match(/<table/g) || []).length;
console.log('Resulting table count parsed by marked:', tableCount);
console.log('Total block math items stashed:', blockMath.length);
console.log('Total inline math items stashed:', inlineMath.length);

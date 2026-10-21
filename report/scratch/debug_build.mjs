import fs from 'fs';
import path from 'path';
import { marked } from 'marked';

const chapters = fs.readdirSync('chapters').filter(f => f.endsWith('.md')).sort();
let fullMarkdown = '';
chapters.forEach(f => {
  fullMarkdown += fs.readFileSync(path.join('chapters', f), 'utf-8') + '\n\n';
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

const outHtml = marked.parse(pm);

// Check where the first &lt;div appears
const firstEscape = outHtml.indexOf('&lt;div');
if (firstEscape !== -1) {
  console.log('First &lt;div at:', firstEscape);
  console.log('Snippet in outHtml:');
  console.log(outHtml.slice(firstEscape - 150, firstEscape + 250));
  
  // Find where that was in pm
  const snippetText = outHtml.slice(firstEscape, firstEscape + 50);
  console.log('Snippet searching for in pm:', snippetText);
} else {
  console.log('No &lt;div found in outHtml!');
}

import fs from 'fs';
import path from 'path';
import mermaid from 'mermaid';

mermaid.initialize({ startOnLoad: false });

const chaptersDir = 'chapters';
const files = fs.readdirSync(chaptersDir).filter(f => f.endsWith('.md')).sort();

let total = 0;
let errors = 0;

for (const file of files) {
  const content = fs.readFileSync(path.join(chaptersDir, file), 'utf-8');
  const regex = /```mermaid([\s\S]*?)```/g;
  let match;
  let index = 0;
  while ((match = regex.exec(content)) !== null) {
    total++;
    index++;
    const code = match[1].trim();
    try {
      await mermaid.parse(code);
      console.log(`[PASS] ${file} - Diagram #${index}`);
    } catch (err) {
      errors++;
      console.error(`\n[FAIL] ${file} - Diagram #${index}:`);
      console.error(err.message || err);
      console.log('--- Code snippet ---');
      console.log(code.split('\n').slice(0, 15).join('\n'));
      console.log('--------------------\n');
    }
  }
}

console.log(`\nChecked ${total} diagrams. Total errors: ${errors}`);

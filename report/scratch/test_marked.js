import { marked } from 'marked';
const bad = '<div>test</div>\n1. First\n### Heading';
const good = '<div>test</div>\n\n1. First\n\n### Heading';
console.log('--- WITHOUT BLANK LINE ---');
console.log(marked.parse(bad));
console.log('--- WITH BLANK LINE ---');
console.log(marked.parse(good));

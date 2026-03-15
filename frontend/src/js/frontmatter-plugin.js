import { $prose } from '@milkdown/utils';
import { Plugin, PluginKey } from '@milkdown/prose/state';
import { Decoration, DecorationSet } from '@milkdown/prose/view';

const frontmatterPluginKey = new PluginKey('frontmatter');

export const frontmatterPlugin = $prose(() => {
  return new Plugin({
    key: frontmatterPluginKey,
    state: {
      init(_, { doc }) {
        return findFrontmatter(doc);
      },
      apply(tr, old) {
        return tr.docChanged ? findFrontmatter(tr.doc) : old;
      }
    },
    props: {
      decorations(state) {
        return this.getState(state);
      }
    }
  });
});

function findFrontmatter(doc) {
  const decorations = [];

  doc.descendants((node, pos) => {
    if (node.type.name === 'code_block') {
      const text = node.textContent;

      // Check if this is a frontmatter block (starts with ---)
      if (text.trim().startsWith('---')) {
        const lines = text.split('\n');
        let isFrontmatter = false;

        // Check if it's a valid frontmatter block
        if (lines.length >= 3 && lines[0].trim() === '---') {
          const endIndex = lines.slice(1).findIndex(line => line.trim() === '---');
          if (endIndex !== -1) {
            isFrontmatter = true;
          }
        }

        if (isFrontmatter) {
          // Add decoration to style frontmatter blocks
          decorations.push(
            Decoration.node(pos, pos + node.nodeSize, {
              class: 'frontmatter-block'
            })
          );
        }
      }
    }
    return true;
  });

  return DecorationSet.create(doc, decorations);
}

import { Crepe } from '@milkdown/crepe';
import { collab, collabServiceCtx } from '@milkdown/plugin-collab';
import { Doc } from 'yjs';
import { WebsocketProvider } from 'y-websocket';

export class CollaborativeEditor {
  constructor(options) {
    this.container = options.container;
    this.fileId = options.fileId;
    this.initialContent = options.initialContent || '';
    this.readonly = options.readonly || false;
    this.onContentChange = options.onContentChange || (() => {});
    this.onConnectionStatusChange = options.onConnectionStatusChange || (() => {});
    this.onUsersChange = options.onUsersChange || (() => {});

    this.crepe = null;
    this.ydoc = null;
    this.wsProvider = null;
    this.destroyed = false;

    this.init();
  }

  async init() {
    this.ydoc = new Doc();

    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsBaseUrl = `${wsProtocol}//${window.location.host}/ws`;

    this.wsProvider = new WebsocketProvider(
      wsBaseUrl,
      `editor/${this.fileId}/`,
      this.ydoc
    );

    this.wsProvider.on('status', (event) => {
      if (!this.destroyed) {
        this.onConnectionStatusChange(event.status === 'connected');
      }
    });

    this.wsProvider.awareness.on('change', () => {
      if (!this.destroyed && this.wsProvider) {
        this.onUsersChange(this.wsProvider.awareness.getStates().size);
      }
    });

    const colors = ['#30bced', '#6eeb83', '#ffbc42', '#e84855', '#8458B3', '#0d7377'];
    const color = colors[Math.floor(Math.random() * colors.length)];
    this.wsProvider.awareness.setLocalStateField('user', {
      name: window.currentUser?.email || 'Anonymous',
      color,
    });

    this.crepe = new Crepe({
      root: this.container,
      defaultValue: '',
    });

    this.crepe.editor.use(collab);
    await this.crepe.create();

    if (this.destroyed) return;

    this.crepe.editor.action((ctx) => {
      const collabService = ctx.get(collabServiceCtx);
      collabService
        .bindDoc(this.ydoc)
        .setAwareness(this.wsProvider.awareness);

      collabService.applyTemplate(this.initialContent).connect();
    });

    if (this.readonly) {
      this.crepe.setReadonly(true);
    }

    this.crepe.on((listener) => {
      listener.markdownUpdated((_ctx, markdown) => {
        if (!this.destroyed) {
          this.onContentChange(markdown);
        }
      });
    });
  }

  getMarkdown() {
    return this.crepe?.getMarkdown() ?? '';
  }

  destroy() {
    this.destroyed = true;
    this.crepe?.destroy();
    this.crepe = null;
    this.wsProvider?.disconnect();
    this.wsProvider?.destroy();
    this.wsProvider = null;
    this.ydoc?.destroy();
    this.ydoc = null;
  }
}

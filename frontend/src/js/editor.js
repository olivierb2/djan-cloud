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
    this.userName = options.userName || 'Anonymous';
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

    const updateUsers = () => {
      if (!this.destroyed && this.wsProvider) {
        // Count unique users excluding self
        const states = this.wsProvider.awareness.getStates();
        const uniqueUsers = new Set();
        states.forEach((state, clientId) => {
          if (state.user && state.user.name) {
            uniqueUsers.add(state.user.name);
          }
        });
        this.onUsersChange(uniqueUsers.size);
      }
    };

    this.wsProvider.awareness.on('change', updateUsers);
    this.wsProvider.awareness.on('update', updateUsers);

    const colors = ['#30bced', '#6eeb83', '#ffbc42', '#e84855', '#8458B3', '#0d7377'];
    const color = colors[Math.floor(Math.random() * colors.length)];
    this.wsProvider.awareness.setLocalStateField('user', {
      name: this.userName,
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

      // Apply initial content only if we're the first client connecting
      // and there's no content in Yjs yet
      const checkAndApplyTemplate = () => {
        const ydocContent = this.ydoc.share.get('prosemirror');
        const isYjsEmpty = !ydocContent || ydocContent.length === 0;
        const clientCount = this.wsProvider.awareness.getStates().size;

        if (isYjsEmpty && this.initialContent && clientCount === 1) {
          collabService.applyTemplate(this.initialContent);
        }
      };

      // Wait a bit for initial sync, then check
      setTimeout(checkAndApplyTemplate, 300);

      collabService.connect();
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

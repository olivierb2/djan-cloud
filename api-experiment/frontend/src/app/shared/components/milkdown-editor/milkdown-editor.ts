import {
  Component,
  Input,
  Output,
  EventEmitter,
  OnDestroy,
  ElementRef,
  ViewChild,
  AfterViewInit,
} from '@angular/core';
import { Crepe } from '@milkdown/crepe';
import { collab, collabServiceCtx } from '@milkdown/plugin-collab';
import { Doc } from 'yjs';
import { WebsocketProvider } from 'y-websocket';
import { environment } from '../../../../environments/environment';

@Component({
  selector: 'app-milkdown-editor',
  standalone: true,
  template: `<div #editorHost class="editor-host"></div>`,
  styleUrl: './milkdown-editor.scss',
})
export class MilkdownEditorComponent implements AfterViewInit, OnDestroy {
  @ViewChild('editorHost') editorHostRef!: ElementRef<HTMLDivElement>;

  @Input() fileId!: number;
  @Input() initialContent = '';
  @Input() readonly = false;
  @Input() token = '';
  @Input() userName = '';

  @Output() contentChanged = new EventEmitter<string>();
  @Output() connectionStatusChanged = new EventEmitter<boolean>();
  @Output() usersChanged = new EventEmitter<number>();

  private crepe: Crepe | null = null;
  private ydoc: Doc | null = null;
  private wsProvider: WebsocketProvider | null = null;
  private destroyed = false;

  ngAfterViewInit(): void {
    this.initEditor();
  }

  ngOnDestroy(): void {
    this.destroyed = true;
    this.destroyEditor();
  }

  private async initEditor(): Promise<void> {
    this.ydoc = new Doc();

    const wsBaseUrl = environment.wsUrl ||
      `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws`;

    this.wsProvider = new WebsocketProvider(
      wsBaseUrl,
      `editor/${this.fileId}/`,
      this.ydoc,
      { params: { token: this.token } },
    );

    this.wsProvider.on('status', (event: { status: string }) => {
      if (!this.destroyed) {
        this.connectionStatusChanged.emit(event.status === 'connected');
      }
    });

    this.wsProvider.awareness.on('change', () => {
      if (!this.destroyed && this.wsProvider) {
        this.usersChanged.emit(this.wsProvider.awareness.getStates().size);
      }
    });

    // Set local user info for remote cursors
    const colors = ['#30bced', '#6eeb83', '#ffbc42', '#e84855', '#8458B3', '#0d7377'];
    const color = colors[Math.floor(Math.random() * colors.length)];
    this.wsProvider.awareness.setLocalStateField('user', {
      name: this.userName || 'Anonymous',
      color,
    });

    this.crepe = new Crepe({
      root: this.editorHostRef.nativeElement,
      defaultValue: '',
    });

    this.crepe.editor.use(collab);
    await this.crepe.create();

    if (this.destroyed) return;

    this.crepe.editor.action((ctx) => {
      const collabService = ctx.get(collabServiceCtx);
      collabService
        .bindDoc(this.ydoc!)
        .setAwareness(this.wsProvider!.awareness);

      collabService.applyTemplate(this.initialContent).connect();
    });

    if (this.readonly) {
      this.crepe.setReadonly(true);
    }

    this.crepe.on((listener) => {
      listener.markdownUpdated((_ctx: any, markdown: string) => {
        if (!this.destroyed) {
          this.contentChanged.emit(markdown);
        }
      });
    });
  }

  getMarkdown(): string {
    return this.crepe?.getMarkdown() ?? '';
  }

  private destroyEditor(): void {
    // Destroy crepe first (removes ProseMirror plugins that reference awareness)
    this.crepe?.destroy();
    this.crepe = null;
    this.wsProvider?.disconnect();
    this.wsProvider?.destroy();
    this.wsProvider = null;
    this.ydoc?.destroy();
    this.ydoc = null;
  }
}

import { Component, OnInit, OnDestroy, ViewChild, inject } from '@angular/core';
import { CommonModule, KeyValuePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { Subject, takeUntil, switchMap, filter, first, debounceTime } from 'rxjs';
import { NgIcon } from '@ng-icons/core';
import { FileService, PreviewResponse } from '../../core/services/file.service';
import { Auth } from '../../core/services/auth';
import { UserService } from '../../core/services/user.service';
import { MilkdownEditorComponent } from '../../shared/components/milkdown-editor/milkdown-editor';
import { RawEditorComponent } from '../../shared/components/raw-editor/raw-editor';
import { RoutePaths } from '../../core/constants/routes';

@Component({
  selector: 'app-editor-page',
  standalone: true,
  imports: [CommonModule, FormsModule, NgIcon, MilkdownEditorComponent, RawEditorComponent],
  templateUrl: './editor.html',
  styleUrl: './editor.scss',
})
export class EditorPage implements OnInit, OnDestroy {
  private route = inject(ActivatedRoute);
  private router = inject(Router);
  private fileService = inject(FileService);
  private auth = inject(Auth);
  private userService = inject(UserService);
  private destroy$ = new Subject<void>();
  private autoSave$ = new Subject<void>();

  @ViewChild(MilkdownEditorComponent)
  editorComponent!: MilkdownEditorComponent;

  @ViewChild(RawEditorComponent)
  rawEditorComponent!: RawEditorComponent;

  fileId = 0;
  fileName = '';
  initialContent = '';
  canWrite = false;
  loading = true;
  saving = false;
  connected = false;
  connectedUsers = 0;
  hasUnsavedChanges = false;
  lastSavedAt = '';
  token = '';
  userName = '';
  frontmatter: { key: string; value: string }[] = [];
  showFrontmatter = false;
  rawMode = false;
  private parentPath = '';
  lastMarkdown = '';

  protected readonly RoutePaths = RoutePaths;

  ngOnInit(): void {
    this.token = this.auth.getToken() || '';

    this.userService.currentUser$.pipe(
      filter(u => u !== null),
      first(),
      takeUntil(this.destroy$),
    ).subscribe(user => {
      this.userName = user.email;
    });

    this.autoSave$.pipe(
      debounceTime(2000),
      takeUntil(this.destroy$),
    ).subscribe(() => this.save());

    this.route.params
      .pipe(
        takeUntil(this.destroy$),
        switchMap(params => {
          this.fileId = +params['fileId'];
          this.loading = true;
          return this.fileService.getPreview(this.fileId);
        }),
      )
      .subscribe({
        next: (preview: PreviewResponse) => {
          this.fileName = preview.display_name;
          const raw = preview.content || '';
          const parsed = this.parseFrontmatter(raw);
          this.frontmatter = parsed.frontmatter;
          this.showFrontmatter = this.frontmatter.length > 0;
          this.initialContent = parsed.body;
          this.canWrite = preview.can_write ?? false;
          this.parentPath = preview.parent_path ?? '';
          this.fileService.setActiveBrowsePath(this.parentPath);
          this.loading = false;
        },
        error: () => {
          this.loading = false;
          this.router.navigate(['/', RoutePaths.APP, RoutePaths.BROWSE]);
        },
      });
  }

  ngOnDestroy(): void {
    if (this.hasUnsavedChanges && this.canWrite && this.lastMarkdown) {
      const content = this.serializeFrontmatter() + this.lastMarkdown;
      this.fileService.saveFile(this.fileId, content).subscribe();
    }
    this.destroy$.next();
    this.destroy$.complete();
  }

  onContentChanged(markdown: string): void {
    this.lastMarkdown = markdown;
    this.hasUnsavedChanges = true;
    if (this.canWrite) {
      this.autoSave$.next();
    }
  }

  onConnectionStatusChanged(connected: boolean): void {
    this.connected = connected;
  }

  onUsersChanged(count: number): void {
    this.connectedUsers = count;
  }

  save(): void {
    if (this.saving) return;
    this.saving = true;
    const md = this.rawMode
      ? (this.rawEditorComponent?.getContent() ?? this.lastMarkdown)
      : (this.editorComponent?.getMarkdown() ?? this.lastMarkdown);
    const content = this.serializeFrontmatter() + md;
    this.fileService.saveFile(this.fileId, content).subscribe({
      next: () => {
        this.saving = false;
        this.hasUnsavedChanges = false;
        this.lastSavedAt = new Date().toLocaleTimeString();
      },
      error: () => {
        this.saving = false;
      },
    });
  }

  onFrontmatterChanged(): void {
    this.hasUnsavedChanges = true;
    if (this.canWrite) {
      this.autoSave$.next();
    }
  }

  addFrontmatterField(): void {
    this.frontmatter.push({ key: '', value: '' });
    this.onFrontmatterChanged();
  }

  removeFrontmatterField(index: number): void {
    this.frontmatter.splice(index, 1);
    this.onFrontmatterChanged();
  }

  toggleRawMode(): void {
    if (this.rawMode) {
      // Switching from raw to WYSIWYG: get content from CodeMirror
      const rawContent = this.rawEditorComponent?.getContent() ?? this.lastMarkdown;
      this.lastMarkdown = rawContent;
      this.initialContent = rawContent;
      this.rawMode = false;
    } else {
      // Switching from WYSIWYG to raw: get content from Milkdown
      const md = this.editorComponent?.getMarkdown() ?? this.lastMarkdown;
      this.lastMarkdown = md;
      this.rawMode = true;
    }
  }

  onRawContentChanged(content: string): void {
    this.lastMarkdown = content;
    this.hasUnsavedChanges = true;
    if (this.canWrite) {
      this.autoSave$.next();
    }
  }

  goBack(): void {
    if (this.parentPath) {
      this.router.navigate(['/', RoutePaths.APP, RoutePaths.BROWSE, this.parentPath]);
    } else {
      this.router.navigate(['/', RoutePaths.APP, RoutePaths.BROWSE]);
    }
  }

  private parseFrontmatter(content: string): { frontmatter: { key: string; value: string }[]; body: string } {
    const match = content.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/);
    if (!match) {
      return { frontmatter: [], body: content };
    }
    const yamlBlock = match[1];
    const body = match[2];
    const fields: { key: string; value: string }[] = [];
    for (const line of yamlBlock.split('\n')) {
      const colonIndex = line.indexOf(':');
      if (colonIndex > 0) {
        const key = line.substring(0, colonIndex).trim();
        let value = line.substring(colonIndex + 1).trim();
        // Remove surrounding quotes
        if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
          value = value.slice(1, -1);
        }
        fields.push({ key, value });
      }
    }
    return { frontmatter: fields, body };
  }

  private serializeFrontmatter(): string {
    if (this.frontmatter.length === 0) return '';
    const lines = this.frontmatter
      .filter(f => f.key.trim())
      .map(f => `${f.key}: "${f.value}"`);
    if (lines.length === 0) return '';
    return `---\n${lines.join('\n')}\n---\n`;
  }
}

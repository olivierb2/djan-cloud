import {
  Component,
  Input,
  Output,
  EventEmitter,
  OnDestroy,
  ElementRef,
  ViewChild,
  AfterViewInit,
  OnChanges,
  SimpleChanges,
} from '@angular/core';
import { NgIcon } from '@ng-icons/core';
import { Compartment, EditorState } from '@codemirror/state';
import { EditorView, keymap, lineNumbers, highlightActiveLine, drawSelection } from '@codemirror/view';
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands';
import { markdown } from '@codemirror/lang-markdown';
import { syntaxHighlighting, defaultHighlightStyle, bracketMatching } from '@codemirror/language';

@Component({
  selector: 'app-raw-editor',
  standalone: true,
  imports: [NgIcon],
  templateUrl: './raw-editor.html',
  styleUrl: './raw-editor.scss',
})
export class RawEditorComponent implements AfterViewInit, OnDestroy, OnChanges {
  @ViewChild('editorHost') editorHostRef!: ElementRef<HTMLDivElement>;

  @Input() content = '';
  @Input() readonly = false;

  @Output() contentChanged = new EventEmitter<string>();

  private view: EditorView | null = null;
  private editableCompartment = new Compartment();

  ngAfterViewInit(): void {
    this.createEditor();
  }

  ngOnChanges(changes: SimpleChanges): void {
    if (changes['readonly'] && this.view && !changes['readonly'].firstChange) {
      this.view.dispatch({
        effects: this.editableCompartment.reconfigure(EditorView.editable.of(!this.readonly)),
      });
    }
  }

  ngOnDestroy(): void {
    this.view?.destroy();
    this.view = null;
  }

  getContent(): string {
    return this.view?.state.doc.toString() ?? '';
  }

  setContent(content: string): void {
    if (!this.view) return;
    this.view.dispatch({
      changes: { from: 0, to: this.view.state.doc.length, insert: content },
    });
  }

  wrapSelection(before: string, after: string): void {
    if (!this.view || this.readonly) return;
    const { from, to } = this.view.state.selection.main;
    const selected = this.view.state.sliceDoc(from, to);
    this.view.dispatch({
      changes: { from, to, insert: before + selected + after },
      selection: { anchor: from + before.length, head: to + before.length },
    });
    this.view.focus();
  }

  insertAtLineStart(prefix: string): void {
    if (!this.view || this.readonly) return;
    const { from } = this.view.state.selection.main;
    const line = this.view.state.doc.lineAt(from);
    this.view.dispatch({
      changes: { from: line.from, to: line.from, insert: prefix },
    });
    this.view.focus();
  }

  insertBlock(text: string): void {
    if (!this.view || this.readonly) return;
    const { from } = this.view.state.selection.main;
    this.view.dispatch({
      changes: { from, to: from, insert: text },
      selection: { anchor: from + text.length },
    });
    this.view.focus();
  }

  bold(): void { this.wrapSelection('**', '**'); }
  italic(): void { this.wrapSelection('*', '*'); }
  strikethrough(): void { this.wrapSelection('~~', '~~'); }
  inlineCode(): void { this.wrapSelection('`', '`'); }
  link(): void { this.wrapSelection('[', '](url)'); }
  image(): void { this.insertBlock('![alt](url)'); }
  heading(level: number): void { this.insertAtLineStart('#'.repeat(level) + ' '); }
  bulletList(): void { this.insertAtLineStart('- '); }
  numberedList(): void { this.insertAtLineStart('1. '); }
  blockquote(): void { this.insertAtLineStart('> '); }
  codeBlock(): void { this.insertBlock('\n```\n\n```\n'); }
  horizontalRule(): void { this.insertBlock('\n---\n'); }

  private createEditor(): void {
    const updateListener = EditorView.updateListener.of((update) => {
      if (update.docChanged) {
        this.contentChanged.emit(update.state.doc.toString());
      }
    });

    const state = EditorState.create({
      doc: this.content,
      extensions: [
        lineNumbers(),
        history(),
        drawSelection(),
        highlightActiveLine(),
        bracketMatching(),
        syntaxHighlighting(defaultHighlightStyle),
        markdown(),
        keymap.of([...defaultKeymap, ...historyKeymap]),
        this.editableCompartment.of(EditorView.editable.of(!this.readonly)),
        EditorView.lineWrapping,
        updateListener,
      ],
    });

    this.view = new EditorView({
      state,
      parent: this.editorHostRef.nativeElement,
    });
  }
}

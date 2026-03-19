import {
  WASI,
  OpenFile,
  File,
  Directory,
  ConsoleStdout,
  PreopenDirectory,
} from "@bjorn3/browser_wasi_shim";

const PANDOC_WASM_URL = "/static/file/pandoc.wasm";

const EXPORT_FORMATS = [
  { id: "pdf", label: "PDF", ext: "pdf", binary: true, viaTypst: true },
  { id: "html", label: "HTML", ext: "html", binary: false },
  { id: "latex", label: "LaTeX", ext: "tex", binary: false },
  { id: "docx", label: "Word (DOCX)", ext: "docx", binary: true },
  { id: "odt", label: "OpenDocument (ODT)", ext: "odt", binary: true },
  { id: "epub", label: "EPUB", ext: "epub", binary: true },
  { id: "rst", label: "reStructuredText", ext: "rst", binary: false },
  { id: "asciidoc", label: "AsciiDoc", ext: "adoc", binary: false },
  { id: "org", label: "Org Mode", ext: "org", binary: false },
  { id: "mediawiki", label: "MediaWiki", ext: "wiki", binary: false },
  { id: "plain", label: "Plain Text", ext: "txt", binary: false },
];

let typstLoaded = false;
let typstLoadingPromise = null;

async function loadTypst() {
  if (typstLoaded && typeof window.$typst !== "undefined") return;
  if (typstLoadingPromise) return typstLoadingPromise;

  typstLoadingPromise = new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.type = "module";
    script.src =
      "https://cdn.jsdelivr.net/npm/@myriaddreamin/typst-all-in-one.ts@0.7.0-rc2/dist/esm/index.js";
    script.onload = () => {
      const check = () => {
        if (typeof window.$typst !== "undefined") {
          typstLoaded = true;
          resolve();
        } else {
          setTimeout(check, 100);
        }
      };
      check();
    };
    script.onerror = () => reject(new Error("Failed to load Typst library"));
    document.head.appendChild(script);
  });
  return typstLoadingPromise;
}

let pandocInstance = null;
let pandocLoading = false;
let pandocLoadPromise = null;

async function loadPandoc() {
  if (pandocInstance) return pandocInstance;
  if (pandocLoadPromise) return pandocLoadPromise;

  pandocLoading = true;
  pandocLoadPromise = (async () => {
    const args = ["pandoc.wasm", "+RTS", "-H64m", "-RTS"];
    const env = [];
    const in_file = new File(new Uint8Array(), { readonly: true });
    const out_file = new File(new Uint8Array(), { readonly: false });
    const fds = [
      new OpenFile(new File(new Uint8Array(), { readonly: true })),
      ConsoleStdout.lineBuffered((msg) => console.log(`[pandoc stdout] ${msg}`)),
      ConsoleStdout.lineBuffered((msg) => console.warn(`[pandoc stderr] ${msg}`)),
      new PreopenDirectory("/", [
        ["in", in_file],
        ["out", out_file],
        ["tmp", new Directory([])],
      ]),
    ];
    const options = { debug: false };
    const wasi = new WASI(args, env, fds, options);

    const { instance } = await WebAssembly.instantiateStreaming(
      fetch(PANDOC_WASM_URL),
      { wasi_snapshot_preview1: wasi.wasiImport }
    );

    wasi.initialize(instance);
    instance.exports.__wasm_call_ctors();

    function memory_data_view() {
      return new DataView(instance.exports.memory.buffer);
    }

    const argc_ptr = instance.exports.malloc(4);
    memory_data_view().setUint32(argc_ptr, args.length, true);
    const argv = instance.exports.malloc(4 * (args.length + 1));
    for (let i = 0; i < args.length; ++i) {
      const arg = instance.exports.malloc(args[i].length + 1);
      new TextEncoder().encodeInto(
        args[i],
        new Uint8Array(instance.exports.memory.buffer, arg, args[i].length)
      );
      memory_data_view().setUint8(arg + args[i].length, 0);
      memory_data_view().setUint32(argv + 4 * i, arg, true);
    }
    memory_data_view().setUint32(argv + 4 * args.length, 0, true);
    const argv_ptr = instance.exports.malloc(4);
    memory_data_view().setUint32(argv_ptr, argv, true);

    instance.exports.hs_init_with_rtsopts(argc_ptr, argv_ptr);

    pandocInstance = { instance, in_file, out_file, memory_data_view };
    pandocLoading = false;
    return pandocInstance;
  })();

  return pandocLoadPromise;
}

function runPandoc(pandoc, argsStr, inputStr) {
  const { instance, in_file, out_file, memory_data_view } = pandoc;

  const args_ptr = instance.exports.malloc(argsStr.length);
  new TextEncoder().encodeInto(
    argsStr,
    new Uint8Array(instance.exports.memory.buffer, args_ptr, argsStr.length)
  );
  in_file.data = new TextEncoder().encode(inputStr);
  out_file.data = new Uint8Array();

  instance.exports.wasm_main(args_ptr, argsStr.length);

  return out_file.data;
}

function downloadFile(data, filename, mimeType) {
  const blob = new Blob([data], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

const MIME_TYPES = {
  pdf: "application/pdf",
  html: "text/html",
  tex: "application/x-latex",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  odt: "application/vnd.oasis.opendocument.text",
  epub: "application/epub+zip",
  rst: "text/x-rst",
  adoc: "text/plain",
  org: "text/plain",
  wiki: "text/plain",
  txt: "text/plain",
};

export async function exportMarkdown(markdown, formatId, baseFilename) {
  const format = EXPORT_FORMATS.find((f) => f.id === formatId);
  if (!format) throw new Error(`Unknown format: ${formatId}`);

  const pandoc = await loadPandoc();

  if (format.viaTypst) {
    await loadTypst();
    const typstArgs = `-f markdown -t typst --standalone`;
    let typstMarkup = new TextDecoder("utf-8", { fatal: true }).decode(
      runPandoc(pandoc, typstArgs, markdown)
    );
    // Remove font parameter from conf() and set text() since system fonts are unavailable in WASM
    typstMarkup = typstMarkup.replace(/font:\s*\(\),\n/g, "");
    typstMarkup = typstMarkup.replace(/\s*font:\s*font,/g, "");
    window.$typst.resetShadow();
    window.$typst.mapShadow("/main.typ", new TextEncoder().encode(typstMarkup));
    const pdfData = await window.$typst.pdf({ mainFilePath: "/main.typ" });
    if (!pdfData || pdfData.length === 0) {
      throw new Error("PDF generation failed");
    }
    downloadFile(pdfData, `${baseFilename}.pdf`, "application/pdf");
    return;
  }

  const argsStr = `-f markdown -t ${format.id}`;
  const outputData = runPandoc(pandoc, argsStr, markdown);

  const filename = `${baseFilename}.${format.ext}`;
  const mimeType = MIME_TYPES[format.ext] || "application/octet-stream";

  if (format.binary) {
    downloadFile(outputData, filename, mimeType);
  } else {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(outputData);
    downloadFile(new TextEncoder().encode(text), filename, mimeType);
  }
}

export function getExportFormats() {
  return EXPORT_FORMATS;
}

export function isPandocLoaded() {
  return pandocInstance !== null;
}

export function isPandocLoading() {
  return pandocLoading;
}

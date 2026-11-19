// Defangs attack examples where the site quotes them (rule titles and fixtures, the sample report,
// diagrams), the way security write-ups do, so no page presents a working payload or reads as a live
// "run this" lure to a visitor or a phishing classifier:
//
//   https://get.example.invalid/x.sh  → hxxps://get[.]example[.]invalid/x.sh   (scheme and host broken)
//   posts to webhook.site             → posts to webhook[.]site                (known exfiltration hosts)
//   curl … | sh,  iwr … | iex         → curl … [|] sh,  iwr … [|] iex          (pipe into a shell)
//   before first use, in your terminal, Win+R → before [first use], in [your terminal], Win[+]R
//
// Each example stays readable; only what would let it be copied and run, or be taken for a real
// instruction, is visibly broken. The fixtures and the engine are unchanged: this runs at render time.
// It is idempotent, and leaves a bare scheme in prose ("use https://") alone, since that has no host.

// An http(s) or ftp(s) URL: the scheme, then the host (with any user or port) up to the path.
const URL_HOST = /\b(https?|ftps?)(:\/\/)([\p{L}\p{N}_~%@:.-]+)/giu;
// Services attacks use to receive stolen data or reach a machine, defanged even without a scheme.
const EXFIL_HOST = /\b(?:[a-z0-9-]+\.)*(?:webhook|pastebin|requestbin|pipedream|ngrok(?:-free)?|burpcollaborator)\.(?:site|com|net|io|app|dev)\b/gi;
// A pipe into a shell or a script interpreter, optionally through sudo.
const PIPE_TO_SHELL = /(?<!\[)\|(?=\s*(?:sudo\s+(?:-\S+\s+)*)?(?:(?:ba|z|da|k|fi)?sh|iex|invoke-expression|pwsh|powershell|python[0-9.]*|perl|ruby|node)\b)/gi;
// The cue that turns a quoted step into an instruction aimed at the reader.
const LURES: [RegExp, string][] = [
  [/\b(before) (first use)\b/gi, "$1 [$2]"],
  [/\b(in|into) (your terminal)\b/gi, "$1 [$2]"],
  [/\b(win(?:dows)?\s*)\+(\s*r)\b/gi, "$1[+]$2"],
];

// Every dot that separates labels; a sentence's closing period after a bare host is left as is.
const dots = (host: string) => host.replace(/\.(?=.)/g, "[.]");

export function defang(text: string | null | undefined): string {
  if (!text) return "";
  let out = text
    .replace(URL_HOST, (_m, scheme: string, sep: string, host: string) =>
      `${scheme.replace(/^(h)tt/i, "$1xx").replace(/^(f)t/i, "$1x")}${sep}${dots(host)}`)
    .replace(EXFIL_HOST, dots)
    .replace(PIPE_TO_SHELL, "[|]");
  for (const [re, to] of LURES) out = out.replace(re, to);
  return out;
}

// Defangs the text of an HTML document, never its markup: tags and attribute values (links keep
// working), comments, and the contents of <style> and <script> (whose CSP hashes must not change).
export function defangHtml(html: string): string {
  return html.replace(
    /(<style\b[\s\S]*?<\/style>|<script\b[\s\S]*?<\/script>|<!--[\s\S]*?-->|<[^>]*>)|([^<]+)/gi,
    (_m, markup: string | undefined, text: string | undefined) => markup ?? defang(text),
  );
}

// /sample-report.html: the real HTML report that scripts/gen_site_data.py renders from a synthetic
// malicious fixture, with the URLs, hosts and commands quoted in its evidence defanged
// (src/lib/defang.ts). Only text changes; the markup and the <style> its CSP hash covers do not.
import report from "../data/generated/sample-report.html?raw";
import { defangHtml } from "../lib/defang";

export function GET() {
  return new Response(defangHtml(report), { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

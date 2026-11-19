// Google Search Console ownership check, the "HTML tag" method. Off unless set at build time:
//   PUBLIC_GOOGLE_SITE_VERIFICATION   the content value of the tag Search Console shows
//                                     (pasting the whole <meta …> tag works too)
// It is public by design: Google reads it from the <head> of the home page, and every page gets it.
// This module runs only at build time, so process.env is the build's environment.
const pick = (...values: (string | undefined)[]) => (values.find((v) => v && v.trim()) ?? "").trim();
const value = pick(import.meta.env.PUBLIC_GOOGLE_SITE_VERIFICATION, process.env.PUBLIC_GOOGLE_SITE_VERIFICATION);
const token = (value.match(/content\s*=\s*["']([^"']*)["']/i)?.[1] ?? value).trim();

if (token && !/^[A-Za-z0-9_+\/=.-]{8,128}$/.test(token)) {
  throw new Error(`PUBLIC_GOOGLE_SITE_VERIFICATION must be the content="…" value of Search Console's google-site-verification tag; got: ${value}`);
}

export const googleSiteVerification = token;

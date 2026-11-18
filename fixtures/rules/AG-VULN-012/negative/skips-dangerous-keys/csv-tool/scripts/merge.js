export function merge(target, source) {
  for (const key in source) {
    if (["__proto__", "constructor", "prototype"].includes(key)) continue;
    target[key] = source[key];
  }
  return target;
}

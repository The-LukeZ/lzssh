const MOD_KEYS = ["Control", "Alt", "Shift", "Meta", "AltGraph"];

/** Formats a key press as "Ctrl+Alt+P". Null unless it has Ctrl, Alt or Win plus a letter, digit or F-key. */
export function comboOf(e: KeyboardEvent): string | null {
  if (MOD_KEYS.includes(e.key) || !(e.ctrlKey || e.altKey || e.metaKey)) return null;
  const k = e.code.startsWith("Key") ? e.code.slice(3) : e.code.startsWith("Digit") ? e.code.slice(5) : /^F\d+$/.test(e.code) ? e.code : null;
  if (!k) return null;
  return [e.ctrlKey && "Ctrl", e.altKey && "Alt", e.shiftKey && "Shift", e.metaKey && "Win", k].filter(Boolean).join("+");
}

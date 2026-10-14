.pragma library

// The search field's categories and tags (docs: features spec 3 and 5b). Pure functions over
// the list the daemon already sent after the first dialog (tier-1 Meta: tags, has_totp,
// is_wifi, has_passkey, kind, recently_deleted). Nothing here reads a secret or asks for one.
//
// A tag is { kind: "cat", key: "codes" | "wifi" | "passkeys" | "deleted", label } or
// { kind: "tag", key: <fold key>, label: <display> }; null is All.

// The synced categories, in Apple's sidebar order. Passkeys and Deleted wait for their
// feature flags from the unlock reply (both stay false until verified on live data).
// Icons are JetBrainsMono Nerd Font glyphs (Omarchy's font; found by fontconfig fallback).
const CATEGORIES = [
    { key: "passkeys", label: "Passkeys", icon: "󰀄", tint: "#34c759", flag: "passkeys" },
    { key: "codes", label: "Codes", icon: "󰥿", tint: "#e6b422", flag: "" },
    { key: "wifi", label: "Wi-Fi", icon: "", tint: "#4aa8e8", flag: "" },
    { key: "deleted", label: "Deleted", icon: "", tint: "#f0932b", flag: "apple_deleted" }
];
const ALL_ICON = "";
const ALL_TINT = "#3478f6";
const MAX_TAGS = 16;
const MAX_TAG_LEN = 32;

// Comparison key: NFKC, then Python's str.casefold(), so a tag the daemon calls one tag is one
// row here too. JavaScript has no casefold(). Per code point, upper-then-lower case is the
// same fold (ß to ss, either sigma, long s) except for the 174 code points mapped below: a
// whole string would get the final-sigma rule, which casefold does not have.
// test_qml_category_tag checks this against Python for every code point with a case mapping.
function foldChar(c) {
    const n = c.codePointAt(0);
    if (n === 0x131) return c;                                      // dotless i stays
    if (n === 0x1e9e) return "ss";                                  // capital sharp s
    // Cherokee folds to its capitals, the other way round from every other script.
    if (n >= 0x13a0 && n <= 0x13f5) return c;
    if (n >= 0x13f8 && n <= 0x13fd) return String.fromCodePoint(n - 8);
    if (n >= 0xab70 && n <= 0xabbf) return String.fromCodePoint(n - 0xab70 + 0x13a0);
    return c.toUpperCase().toLowerCase();
}
function fold(t) {
    let out = "";
    for (const c of String(t).normalize("NFKC")) out += foldChar(c);
    return out;
}

// What a typed tag is stored as: NFC, lower case, no leading '#'. "" when it cannot be a tag:
// empty, too long, or holding a character the grammar never allows (whitespace, '#', ':',
// ',', controls). Which letters count is left to the field's validator (PCRE \p{L}\p{M}\p{N})
// and, finally, to the daemon, which checks every tag again.
function canonTag(raw) {
    const t = String(raw).replace(/^#/, "").normalize("NFC").toLowerCase();
    // Code points, as the daemon's len() counts them, not UTF-16 units.
    const n = [...t].length;
    if (n < 1 || n > MAX_TAG_LEN) return "";
    if (/[\s#:,\u0000-\u001f\u007f-\u009f]/.test(t)) return "";
    return t;
}

function features_(f) {
    return { passkeys: !!(f && f.passkeys), apple_deleted: !!(f && f.apple_deleted) };
}

// The one predicate. The list filter and every count in the drop-down call it, so a row's
// count is always the number of entries clicking it shows (with an empty query).
function matches(e, tag) {
    if (!tag) return !e.recently_deleted;
    if (tag.kind === "tag") {
        if (e.recently_deleted) return false;
        const tags = e.tags || [];
        for (let i = 0; i < tags.length; i++)
            if (fold(tags[i]) === tag.key) return true;
        return false;
    }
    switch (tag.key) {
    case "codes": return !!e.has_totp && !e.recently_deleted;
    case "wifi": return !!e.is_wifi && !e.recently_deleted;
    case "passkeys": return (!!e.has_passkey || e.kind === "passkey") && !e.recently_deleted;
    case "deleted": return !!e.recently_deleted;
    }
    return false;
}

function count(entries, tag) {
    let n = 0;
    for (let i = 0; i < entries.length; i++) if (matches(entries[i], tag)) n++;
    return n;
}

function sameTag(a, b) {
    if (!a || !b) return !a && !b;
    return a.kind === b.kind && a.key === b.key;
}

// Every distinct tag on a live entry: fold key -> the first spelling seen.
function tagLabels(entries) {
    const seen = {};
    const out = [];
    for (let i = 0; i < entries.length; i++) {
        const e = entries[i];
        if (e.recently_deleted) continue;
        const tags = e.tags || [];
        for (let j = 0; j < tags.length; j++) {
            const k = fold(tags[j]);
            if (seen[k] === undefined) { seen[k] = true; out.push({ key: k, label: String(tags[j]) }); }
        }
    }
    out.sort(function (a, b) { return a.key < b.key ? -1 : a.key > b.key ? 1 : 0; });
    return out;
}

// Whether a tag can still be shown after a sync: a category while its flag is on (a count of
// 0 is still a category, as Apple shows "Deleted 0"), a custom tag while an entry has it.
function stillValid(entries, features, tag) {
    if (!tag) return true;
    if (tag.kind === "tag") return count(entries, tag) > 0;
    const f = features_(features);
    for (let i = 0; i < CATEGORIES.length; i++)
        if (CATEGORIES[i].key === tag.key) return !CATEGORIES[i].flag || f[CATEGORIES[i].flag];
    return false;
}

// The drop-down: All, the synced categories, a divider, then the tags (sorted by fold key,
// only those in use). `filter` (typed after a leading '#') keeps the categories and tags whose
// label starts with it, and drops All.
function rows(entries, features, filter) {
    const f = features_(features);
    const want = filter ? fold(filter) : "";
    const starts = function (label) { return !want || fold(label).indexOf(want) === 0; };
    const out = [];
    if (!want)
        out.push({ kind: "all", key: "", label: "All", count: count(entries, null),
                   icon: ALL_ICON, tint: ALL_TINT });
    for (let i = 0; i < CATEGORIES.length; i++) {
        const c = CATEGORIES[i];
        if (c.flag && !f[c.flag]) continue;
        if (!starts(c.label)) continue;
        const tag = { kind: "cat", key: c.key, label: c.label };
        out.push({ kind: "cat", key: c.key, label: c.label, count: count(entries, tag),
                   icon: c.icon, tint: c.tint });
    }
    const tags = tagLabels(entries);
    let divided = false;
    for (let i = 0; i < tags.length; i++) {
        if (!starts(tags[i].label)) continue;
        const tag = { kind: "tag", key: tags[i].key, label: tags[i].label };
        const n = count(entries, tag);
        if (n === 0) continue;
        if (!divided && out.length) { out.push({ kind: "divider", key: "", label: "", count: 0 }); }
        divided = true;
        out.push({ kind: "tag", key: tags[i].key, label: tags[i].label, count: n, icon: "#", tint: "" });
    }
    return out;
}

// A row as the tag it sets (All is null).
function tagOf(row) {
    if (!row || row.kind === "all" || row.kind === "divider") return null;
    return { kind: row.kind, key: row.key, label: row.label };
}

// The chip's text: a custom tag reads "#work", a category its own name.
function chipText(tag) {
    return !tag ? "" : tag.kind === "tag" ? "#" + tag.label : tag.label;
}

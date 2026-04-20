// Entry point for the CodeMirror + vim bundle.
// Run build.sh to regenerate static/cm-bundle.js from this file.
import { basicSetup } from "codemirror";
import { EditorView, Decoration, WidgetType, hoverTooltip, keymap, gutter, GutterMarker } from "@codemirror/view";
import { EditorState, StateEffect, StateField, Compartment, RangeSet } from "@codemirror/state";
import { foldService, StreamLanguage } from "@codemirror/language";
import { indentWithTab } from "@codemirror/commands";
import { vim } from "@replit/codemirror-vim";

const _nftKeywords = new Set([
  "table","chain","rule","type","hook","policy","include","define","redefine",
  "undefine","add","delete","flush","list","get","rename","create","insert",
  "replace","reset","handle","comment","priority","device","devices","flags",
  "timeout","size","elements","gc-interval","auto-merge","index","position",
  "quota","map","set","flowtable","secmark","synproxy","element","typeof",
  "interval","constant","named",
]);

const _nftAtoms = new Set([
  // address families
  "ip","ip6","inet","arp","bridge","netdev",
  // verdicts
  "accept","drop","reject","return","continue","goto","jump","queue",
  // chain types
  "filter","route","nat",
  // hooks
  "prerouting","input","forward","output","postrouting","ingress","egress",
]);

const _nftBuiltins = new Set([
  "tcp","udp","udplite","sctp","dccp","ah","esp","comp","icmp","icmpv6",
  "icmpx","igmp","mh","ct","meta","iif","oif","iifname","oifname","iiftype",
  "oiftype","ether","vlan","payload","exthdr","fib","osf","socket","tproxy",
  "numgen","jhash","symhash","log","limit","counter","notrack","dup","fwd",
  "saddr","daddr","sport","dport","ll","rt","hbh","frag","dst",
]);

export const nftLanguage = StreamLanguage.define({
  token(stream) {
    if (stream.eatSpace()) return null;

    // comment
    if (stream.eat("#")) { stream.skipToEnd(); return "comment"; }

    // string
    if (stream.eat('"')) {
      while (!stream.eol()) {
        if (stream.eat("\\")) { stream.next(); continue; }
        if (stream.eat('"')) break;
        stream.next();
      }
      return "string";
    }

    // $variable or @set-ref
    if (stream.eat("$") || stream.eat("@")) {
      stream.eatWhile(/[\w-]/);
      return "variable-2";
    }

    // hex number
    if (stream.match(/^0x[0-9a-fA-F]+/)) return "number";

    // decimal / prefix-length number
    if (stream.match(/^[0-9]+/)) return "number";

    // identifier (may contain hyphens: gc-interval, auto-merge, ip6, etc.)
    if (stream.match(/^[a-zA-Z_][\w-]*/)) {
      const word = stream.current();
      if (_nftKeywords.has(word)) return "keyword";
      if (_nftAtoms.has(word)) return "atom";
      if (_nftBuiltins.has(word)) return "builtin";
      return null;
    }

    // braces / brackets
    const ch = stream.next();
    if (ch === "{" || ch === "}" || ch === "[" || ch === "]") return "bracket";
    if (ch === "=" || ch === "!" || ch === "<" || ch === ">") {
      stream.eat("=");
      return "operator";
    }
    if (ch === ";" || ch === "," || ch === "." || ch === ":") return "punctuation";

    return null;
  },
});

export { basicSetup, EditorView, Decoration, WidgetType, hoverTooltip, keymap, indentWithTab, EditorState, StateEffect, StateField, Compartment, RangeSet, foldService, StreamLanguage, vim, gutter, GutterMarker };

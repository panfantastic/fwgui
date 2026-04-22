import { basicSetup } from "codemirror";
import { EditorView, Decoration, WidgetType, hoverTooltip, keymap, gutter, GutterMarker } from "@codemirror/view";
import { EditorState, StateEffect, StateField, Compartment, RangeSet } from "@codemirror/state";
import { foldService, StreamLanguage } from "@codemirror/language";
import { indentWithTab } from "@codemirror/commands";
import { vim } from "@replit/codemirror-vim";
import { nftLanguage } from "./nft-language.js";

export {
  basicSetup,
  EditorView, Decoration, WidgetType, hoverTooltip, keymap, gutter, GutterMarker,
  EditorState, StateEffect, StateField, Compartment, RangeSet,
  foldService, StreamLanguage,
  indentWithTab,
  vim,
  nftLanguage,
};

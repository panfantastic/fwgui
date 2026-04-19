// Entry point for the CodeMirror + vim bundle.
// Run build.sh to regenerate static/cm-bundle.js from this file.
import { basicSetup } from "codemirror";
import { EditorView, Decoration, WidgetType, hoverTooltip, keymap, gutter, GutterMarker } from "@codemirror/view";
import { EditorState, StateEffect, StateField, Compartment, RangeSet } from "@codemirror/state";
import { foldService } from "@codemirror/language";
import { indentWithTab } from "@codemirror/commands";
import { vim } from "@replit/codemirror-vim";
export { basicSetup, EditorView, Decoration, WidgetType, hoverTooltip, keymap, indentWithTab, EditorState, StateEffect, StateField, Compartment, RangeSet, foldService, vim, gutter, GutterMarker };

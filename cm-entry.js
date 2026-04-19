// Entry point for the CodeMirror + vim bundle.
// Run build.sh to regenerate static/cm-bundle.js from this file.
import { basicSetup } from "codemirror";
import { EditorView, Decoration, WidgetType, hoverTooltip, keymap } from "@codemirror/view";
import { EditorState, StateEffect, StateField, Compartment } from "@codemirror/state";
import { foldService } from "@codemirror/language";
import { indentWithTab } from "@codemirror/commands";
import { vim } from "@replit/codemirror-vim";
export { basicSetup, EditorView, Decoration, WidgetType, hoverTooltip, keymap, indentWithTab, EditorState, StateEffect, StateField, Compartment, foldService, vim };

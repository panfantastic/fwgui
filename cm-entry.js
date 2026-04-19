// Entry point for the CodeMirror + vim bundle.
// Run build.sh to regenerate static/cm-bundle.js from this file.
import { basicSetup } from "codemirror";
import { EditorView, Decoration, WidgetType } from "@codemirror/view";
import { EditorState, StateEffect, StateField } from "@codemirror/state";
import { foldService } from "@codemirror/language";
import { vim } from "@replit/codemirror-vim";
export { basicSetup, EditorView, Decoration, WidgetType, EditorState, StateEffect, StateField, foldService, vim };

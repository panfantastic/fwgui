// Entry point for the CodeMirror + vim bundle.
// Run build.sh to regenerate static/cm-bundle.js from this file.
import { basicSetup } from "codemirror";
import { EditorView, Decoration } from "@codemirror/view";
import { EditorState, StateEffect, StateField } from "@codemirror/state";
import { vim } from "@replit/codemirror-vim";
export { basicSetup, EditorView, Decoration, EditorState, StateEffect, StateField, vim };

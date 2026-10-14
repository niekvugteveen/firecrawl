import { Meta } from "..";
import { Document } from "../../../controllers/v1/types";

// Matches exactly one markdown image whose URL is a single base64 data URI:
//   ![alt](data:image/<subtype>[;param=value]*;base64,<data>[ "title"])
// Every part is bounded so a match cannot run past its own closing parenthesis.
// The previous pattern used lazy `.*?` for the MIME part, so a non-base64
// data:image URI (e.g. a URL-encoded SVG icon) earlier on the same line made the
// match run on to the next `;base64,` and swallow the text and table cells in
// between (firecrawl#5022).
const regex =
  /(!\[[^\]\n]*\])\(data:image\/[\w.+-]+(?:;[\w.+-]+=[^;,)\s]*)*;base64,[^)\s]*(?:\s+"[^"\n]*")?\)/g;

export function removeBase64Images(meta: Meta, document: Document): Document {
  if (meta.options.removeBase64Images && document.markdown !== undefined) {
    document.markdown = document.markdown.replace(
      regex,
      "$1(<Base64-Image-Removed>)",
    );
  }
  return document;
}

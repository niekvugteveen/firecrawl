import { removeBase64Images } from "./removeBase64Images";

const run = (markdown: string, enabled = true) =>
  removeBase64Images(
    { options: { removeBase64Images: enabled } } as any,
    { markdown, metadata: {} } as any,
  ).markdown;

const SVG = "data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%2F%3E";
const PNG = "data:image/png;base64,iVBORw0KGgo=";

describe("removeBase64Images", () => {
  it("replaces a base64 image", () => {
    expect(run(`before ![logo](${PNG}) after`)).toBe(
      "before ![logo](<Base64-Image-Removed>) after",
    );
  });

  it("keeps table cells when a non-base64 data:image precedes a base64 one (firecrawl#5022)", () => {
    const row = `| SSO | ![no](${SVG}) No | ![yes](${PNG}) Yes |`;
    expect(run(row)).toBe(
      `| SSO | ![no](${SVG}) No | ![yes](<Base64-Image-Removed>) Yes |`,
    );
  });

  it("keeps text between a non-base64 and a base64 image", () => {
    const line = `![icon](${SVG}) Price: $42, in stock. ![logo](${PNG})`;
    expect(run(line)).toBe(
      `![icon](${SVG}) Price: $42, in stock. ![logo](<Base64-Image-Removed>)`,
    );
  });

  it("replaces several base64 images on one line independently", () => {
    expect(run(`![a](${PNG}) x ![b](${PNG}) y`)).toBe(
      "![a](<Base64-Image-Removed>) x ![b](<Base64-Image-Removed>) y",
    );
  });

  it("handles MIME parameters and a title", () => {
    expect(
      run(`![a](data:image/svg+xml;charset=utf-8;base64,PHN2Zz4= "icon")`),
    ).toBe("![a](<Base64-Image-Removed>)");
  });

  it("leaves non-base64 data URIs and normal images alone", () => {
    const md = `![s](${SVG}) ![n](https://example.com/a.png)`;
    expect(run(md)).toBe(md);
  });

  it("does nothing when the option is off", () => {
    const md = `![logo](${PNG})`;
    expect(run(md, false)).toBe(md);
  });
});

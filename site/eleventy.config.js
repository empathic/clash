const markdownIt = require("markdown-it");
const markdownItAnchor = require("markdown-it-anchor");
const Prism = require("prismjs");
// Load additional Prism languages
require("prismjs/components/prism-json");
require("prismjs/components/prism-bash");
require("prismjs/components/prism-lisp");

function slugify(s) {
  return s
    .toLowerCase()
    .replace(/[^\w\s-]/g, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .trim();
}

module.exports = function (eleventyConfig) {
  eleventyConfig.addPassthroughCopy("css");
  eleventyConfig.addPassthroughCopy("js");

  const md = markdownIt({
    html: true,
    linkify: true,
    highlight: function (str, lang) {
      if (lang && Prism.languages[lang]) {
        return `<pre class="language-${lang}"><code class="language-${lang}">${Prism.highlight(str, Prism.languages[lang], lang)}</code></pre>`;
      }
      // Use lisp for unlabeled fenced blocks that look like s-expressions
      if (!lang && str.trimStart().startsWith("(")) {
        return `<pre class="language-lisp"><code class="language-lisp">${Prism.highlight(str, Prism.languages.lisp, "lisp")}</code></pre>`;
      }
      return `<pre><code>${md.utils.escapeHtml(str)}</code></pre>`;
    },
  }).use(markdownItAnchor, { slugify });

  eleventyConfig.setLibrary("md", md);

  return {
    dir: {
      input: ".",
      includes: "_includes",
      data: "_data",
      output: "_site",
    },
    markdownTemplateEngine: "njk",
    htmlTemplateEngine: "njk",
  };
};

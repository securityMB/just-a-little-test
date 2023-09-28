'use strict';
var domino = require('../lib');
var puppeteer = require("puppeteer");

exports = exports.xss = {};

// Tests for HTML serialization concentrating on possible "Mutation based
// XSS vectors"; see https://cure53.de/fp170.pdf

// If we change HTML serialization such that any of these tests fail, please
// review the change very carefully for potential XSS vectors!

async function alertFired(html) {
  let alerted = false;
  const page = await incognito.newPage();
  page.on("dialog", async dialog => {
    alerted = true;
    await dialog.accept();
  });
  await page.goto("data:text/html," + html, {waitUntil: 'load'});
  return alerted;
}

/** @type {puppeteer.Browser} */
let browser;
/** @type {puppeteer.BrowserContext} */
let incognito;

exports.before = async function() {
  browser = await puppeteer.launch({headless:"new"});
  incognito = await browser.createIncognitoBrowserContext();
}

exports.after = async function() {
  await incognito.close();
  await browser.close();
}

exports.fp170_31 = function() {
  var document = domino.createDocument(
    '<img src="test.jpg" alt="``onload=xss()" />'
  );
  // In particular, ensure alt attribute is quoted, not: ...alt=``onload=xss()
  document.body.innerHTML.should.equal(
    '<img src="test.jpg" alt="``onload=xss()">'
  );
  const html = document.serialize();
  return alertFired(html).should.eventually.be.false('alert fired for: ' + html);
};

exports.fp170_32 = function() {
  var document = domino.createDocument(
    '<article  xmlns="urn:img src=x onerror=xss()//">123'
  );
  // XXX check XML serialization as well, once that's implemented
  // In particular, ensure that the xmlns string isn't used as an XML prefix
  // when serializing (and, of course, that attribute value is quoted)
  document.body.innerHTML.should.equal(
    '<article xmlns="urn:img src=x onerror=xss()//">123</article>'
  );

  const html = document.serialize();
  return alertFired(html).should.eventually.be.false('alert fired for: ' + html);
};

exports.fp170_33 = function() {
  var document = domino.createDocument(
    '<p style="font -family:\'ar\\27\\3bx\\3aexpression\\28xss\\28\\29\\29\\3bial\'"></p>'
  );
  // Be sure domino doesn't decode the backslash escapes
  // (especially in the future if we parse the CSS values more fully)
  document.body.innerHTML.should.equal(
    '<p style="font -family:\'ar\\27\\3bx\\3aexpression\\28xss\\28\\29\\29\\3bial\'"></p>'
  );

  const html = document.serialize();
  return alertFired(html).should.eventually.be.false('alert fired for: ' + html);
};

exports.fp170_34 = function() {
  var document = domino.createDocument(
    '<p style="font -family:\'ar&quot;;x=expression(xss())/*ial\'"></p>'
  );
  // Be sure domino re-encodes the entities correctly
  // (especially in the future if we parse the CSS values more fully)
  document.body.innerHTML.should.equal(
    '<p style="font -family:\'ar&quot;;x=expression(xss())/*ial\'"></p>'
  );

  const html = document.serialize();
  return alertFired(html).should.eventually.be.false('alert fired for: ' + html);
};

exports.fp170_35 = function() {
  var document = domino.createDocument(
    '<img style="font-fa\\22onload\\3dxss\\28\\29\\20mily:\'arial\'" src="test.jpg" />'
  );
  // Again, ensure domino doesn't decode the backslash escapes
  // (especially in the future if we parse the CSS values more fully)
  document.body.innerHTML.should.equal(
    '<img style="font-fa\\22onload\\3dxss\\28\\29\\20mily:\'arial\'" src="test.jpg">'
  );

  const html = document.serialize();
  return alertFired(html).should.eventually.be.false('alert fired for: ' + html);
};

exports.fp170_36 = function() {
  var document = domino.createDocument(
    '<style>*{font-family:\'ar&lt;img src=&quot;test.jpg&quot; onload=&quot;xss()&quot;/&gt;ial\'}</style>'
  );
  // Ensure that HTML entities are properly encoded inside <style>
  document.head.innerHTML.should.equal(
    '<style>*{font-family:\'ar&lt;img src=&quot;test.jpg&quot; onload=&quot;xss()&quot;/&gt;ial\'}</style>'
  );

  const html = document.serialize();
  return alertFired(html).should.eventually.be.false('alert fired for: ' + html);
};

exports.fp170_37 = function() {
  var document = domino.createDocument(
    '<p><svg><style>*{font-family:\'&lt;&sol;style&gt;&lt;img/src=x&Tab;onerror=xss()&sol;&sol;\'}</style></svg></p>'
  );
  // Ensure that HTML entities are properly encoded inside <style>
  document.body.innerHTML.should.equal(
    '<p><svg><style>*{font-family:\'&lt;/style&gt;&lt;img/src=x\tonerror=xss()//\'}</style></svg></p>'
  );

  const html = document.serialize();
  return alertFired(html).should.eventually.be.false('alert fired for: ' + html);
};

exports.styleMatchingClosingTagInRawText = function() {
  const document = domino.createDocument('');
  const style = document.createElement("style");
  style.textContent = "abc</style><script>alert(1)</script>";
  document.body.appendChild(style);

  // Ensure that HTML entities are properly encoded inside <style>
  document.body.serialize().should.equal(
    '<style>abc&lt;/style><script>alert(1)</script></style>'
  );

  const html = document.serialize();
  return alertFired(html).should.eventually.be.false('alert fired for: ' + html);
};

exports.styleMatchingClosingTagSkipsCommentedContent = function() {
  const document = domino.createDocument('');
  const style = document.createElement("style");
  style.textContent = "abc<!--</style>--><script>alert(1)</script>";
  document.body.appendChild(style);

  // No escaping in this case, since </style> is inside a comment block.
  document.body.serialize().should.equal(
    '<style>abc<!--</style>--><script>alert(1)</script></style>'
  );

  const html = document.serialize();
  return alertFired(html).should.eventually.be.false('alert fired for: ' + html);
};

exports.styleMatchingClosingTagAfterClosingComment = function() {
  const document = domino.createDocument('');
  const style = document.createElement("style");
  style.textContent = "abc--></style><script>alert(1)</script>";
  document.body.appendChild(style);

  // Ensure that HTML entities are properly encoded inside <style>
  document.body.serialize().should.equal(
    '<style>abc-->&lt;/style><script>alert(1)</script></style>'
  );

  const html = document.serialize();
  return alertFired(html).should.eventually.be.false('alert fired for: ' + html);
};

exports.styleMatchingClosingTagSkipsUnclosedCommentedContent = function() {
  const document = domino.createDocument('');
  const style = document.createElement("style");
  style.textContent = "abc<!--</style><script>alert(1)</script>";
  document.body.appendChild(style);

  // No escaping in this case, since </style> is located after
  // an open comment tag (thus the contents after it would remain
  // in a comment block after parsing).
  document.body.serialize().should.equal(
    '<style>abc<!--</style><script>alert(1)</script></style>'
  );

  const html = document.serialize();
  return alertFired(html).should.eventually.be.false('alert fired for: ' + html);
};

exports.scriptMatchingClosingTagInRawText = function() {
  const document = domino.createDocument('');
  const script = document.createElement("script");
  script.textContent = "abc</script><script>alert(1)</script>";
  document.body.appendChild(script);

  // Ensure that HTML entities are properly encoded inside <script>
  // Note: the `</script>` is encoded in both places.
  document.body.serialize().should.equal(
    '<script>abc&lt;/script><script>alert(1)&lt;/script></script>'
  );

  const html = document.serialize();
  return alertFired(html).should.eventually.be.false('alert fired for: ' + html);
};

exports.oneRawTextTagInsideAnotherOne = function() {
  const document = domino.createDocument('');
  const xmp = document.createElement("xmp");
  const style = document.createElement("style");
  xmp.textContent = "</style><script>alert(1)</script>";
  style.appendChild(xmp);
  document.body.appendChild(style);

  const html = document.serialize();
  return alertFired(html).should.eventually.be.false('alert fired for: ' + html);
}

exports.xssInAttributeInsideRawTextTag = function() {
  const document = domino.createDocument('');
  const xmp = document.createElement("xmp");
  const div = document.createElement("div");
  div.title = "</xmp><script>alert(1)</script>";
  xmp.appendChild(div);
  document.body.appendChild(xmp);

  const html = document.serialize();
  return alertFired(html).should.eventually.be.false('alert fired for: ' + html);
}

exports.commentNodeInsideRawTextTag = function() {
  const document = domino.createDocument('');
  const xmp = document.createElement("xmp");
  const comment = document.createComment('</xmp><script>alert(1)</script>');
  xmp.appendChild(comment);
  document.body.appendChild(xmp);

  const html = document.serialize();
  return alertFired(html).should.eventually.be.false('alert fired for: ' + html);
}

exports.alternativeEndTagForRawTextTag = function() {
  const document = domino.createDocument('');
  const style = document.createElement("style");
  style.textContent = "</style  /foobar><script>alert(1)</script>";
  document.body.appendChild(style);

  const html = document.serialize();
  return alertFired(html).should.eventually.be.false('alert fired for: ' + html);
}

exports.badCommentNode = function() {
  const document = domino.createDocument('');
  const comment = document.createComment('--><script>alert(1)</script>');
  document.body.appendChild(comment);

  const html = document.serialize();
  return alertFired(html).should.eventually.be.false('alert fired for: ' + html);
}

exports.anotherBadCommentNode = function() {
  const document = domino.createDocument('');
  const comment = document.createComment('--!><script>alert(1)</script>');
  document.body.appendChild(comment);

  const html = document.serialize();
  return alertFired(html).should.eventually.be.false('alert fired for: ' + html);
}

exports.badProcessingInstruction = function() {
  const document = domino.createDocument('');
  const pi = document.createProcessingInstruction("bad", "><script>alert(1)</script>");
  document.body.appendChild(pi);

  const html = document.serialize();
  return alertFired(html).should.eventually.be.false('alert fired for: ' + html);
}
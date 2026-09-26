/*
 * This file is part of GADS.
 *
 * Copyright (c) 2022-2025 Nikola Shabanov
 *
 * This source code is licensed under the GNU Affero General Public License v3.0.
 * You may obtain a copy of the license at https://www.gnu.org/licenses/agpl-3.0.html.
 */

package router

import (
	"bytes"
	"net/http"

	"github.com/gin-gonic/gin"
)

const uiOverridesPath = "/gads-ui-overrides.js"

// uiOverridesScript is served by the hub so small branding/customization
// changes do not require access to the private hub-ui source repository.
// The selectors intentionally target the known header icon assets instead of
// every GitHub/Discord link in the application.
const uiOverridesScript = `(function () {
  "use strict";

  var unwantedIconParts = ["kofi", "github.png", "discord.png"];

  function hideHeaderExternalLinks() {
    document.querySelectorAll("a").forEach(function (anchor) {
      var image = anchor.querySelector("img");
      var href = (anchor.getAttribute("href") || "").toLowerCase();
      var source = image ? (image.getAttribute("src") || "").toLowerCase() : "";
      var unwanted = unwantedIconParts.some(function (part) {
        return source.indexOf(part) >= 0;
      }) || href.indexOf("ko-fi.com") >= 0 || href.indexOf("discord.gg") >= 0;

      if (unwanted) {
        // Do not remove or move nodes owned by React. Mutating the inline
        // style leaves the DOM structure intact and avoids reconciliation
        // errors such as NotFoundError/insertBefore.
        anchor.style.setProperty("display", "none", "important");
      }
    });
  }

  function start() {
    hideHeaderExternalLinks();
    new MutationObserver(hideHeaderExternalLinks).observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, { once: true });
  } else {
    start();
  }
})();
`

func registerUIOverrides(r *gin.Engine) {
	r.GET(uiOverridesPath, func(c *gin.Context) {
		c.Data(http.StatusOK, "application/javascript; charset=utf-8", []byte(uiOverridesScript))
	})
}

func injectUIOverrides(index []byte) []byte {
	scriptTag := []byte(`<script src="` + uiOverridesPath + `"></script>`)
	closingHead := []byte("</head>")
	if indexEnd := bytes.Index(bytes.ToLower(index), closingHead); indexEnd >= 0 {
		result := make([]byte, 0, len(index)+len(scriptTag))
		result = append(result, index[:indexEnd]...)
		result = append(result, scriptTag...)
		result = append(result, index[indexEnd:]...)
		return result
	}

	return append(index, scriptTag...)
}

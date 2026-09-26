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
	"strings"
	"testing"
)

func TestInjectUIOverridesAddsScriptBeforeHeadClose(t *testing.T) {
	index := []byte(`<!doctype html><html><head><title>GADS</title></head><body></body></html>`)

	patched := string(injectUIOverrides(index))

	if !strings.Contains(patched, `<script src="/gads-ui-overrides.js"></script></head>`) {
		t.Fatalf("expected UI override script before </head>, got %q", patched)
	}
}

func TestUIOverridesScriptTargetsOnlyConfiguredExternalLinks(t *testing.T) {
	for _, expected := range []string{"kofi", "github.png", "discord.png", "ko-fi.com", "discord.gg"} {
		if !strings.Contains(uiOverridesScript, expected) {
			t.Errorf("UI override script does not target %q", expected)
		}
	}

	if !strings.Contains(uiOverridesScript, `setProperty("display", "none", "important")`) {
		t.Fatal("UI override script must hide matching links with CSS")
	}
	for _, forbidden := range []string{".remove(", "removeChild(", "insertBefore(", "appendChild("} {
		if strings.Contains(uiOverridesScript, forbidden) {
			t.Fatalf("UI override script must not mutate DOM structure using %q", forbidden)
		}
	}
}

"""
Regression & Integrity Tests for Frontend Assets & GitHub Pages Deployment
Ensures JS scripts have valid syntax, all referenced DOM elements exist,
and fallback offline demo initializes correctly without exceptions.
"""

import os
import re
import subprocess
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class TestFrontendAssets(unittest.TestCase):

    def test_javascript_syntax_validity(self):
        """Verifies that all frontend and docs JavaScript files pass syntax check."""
        js_files = [
            BASE_DIR / "frontend" / "js" / "topology.js",
            BASE_DIR / "frontend" / "js" / "charts.js",
            BASE_DIR / "frontend" / "js" / "app.js",
            BASE_DIR / "docs" / "js" / "topology.js",
            BASE_DIR / "docs" / "js" / "charts.js",
            BASE_DIR / "docs" / "js" / "app.js",
        ]

        for js_file in js_files:
            self.assertTrue(js_file.exists(), f"Missing JS file: {js_file}")
            res = subprocess.run(
                ["node", "--check", str(js_file)],
                capture_output=True,
                text=True
            )
            self.assertEqual(
                res.returncode, 0,
                f"JavaScript syntax error in {js_file.name}:\n{res.stderr}"
            )

    def test_dom_elements_present_in_html(self):
        """Ensures all DOM element IDs manipulated by app.js exist in index.html."""
        html_files = [
            BASE_DIR / "frontend" / "index.html",
            BASE_DIR / "docs" / "index.html"
        ]

        required_ids = [
            "soc-clock",
            "mode-badge",
            "badge-telemetry-mode",
            "kpi-total-nodes",
            "kpi-online-nodes",
            "kpi-critical-nodes",
            "kpi-active-threats",
            "alerts-table-body",
            "devices-table-body",
            "topology-canvas",
            "chart-bandwidth",
            "chart-latency",
            "chart-loss",
            "btn-open-attack-modal",
            "btn-close-attack-modal",
            "btn-close-device-modal",
            "modal-dev-hostname",
            "modal-dev-ip",
            "modal-dev-tier",
            "modal-dev-role",
            "modal-dev-vendor",
            "modal-dev-status",
            "modal-probe-results",
            "btn-execute-probe",
            "btn-toggle-quarantine"
        ]

        for html_file in html_files:
            self.assertTrue(html_file.exists(), f"Missing HTML file: {html_file}")
            content = html_file.read_text(encoding="utf-8")
            for elem_id in required_ids:
                pattern = f'id=["\']{elem_id}["\']'
                self.assertTrue(
                    re.search(pattern, content),
                    f"DOM element id '{elem_id}' not found in {html_file.name}"
                )

    def test_headless_node_dom_initialization_regression(self):
        """
        Executes complete JS startup loop in headless Node DOM simulation.
        Asserts fallback demo populates tables and sets mode to STATIC DEMO (SIMULATED).
        """
        node_script = """
        const fs = require('fs');
        const elements = {};
        function getEl(id) {
          if (!elements[id]) {
            elements[id] = {
              id,
              textContent: '--',
              innerHTML: '',
              style: {},
              classList: { add: () => {}, remove: () => {}, contains: () => false },
              parentElement: { getBoundingClientRect: () => ({ width: 800, height: 400 }) },
              getContext: () => ({
                scale: () => {}, clearRect: () => {}, beginPath: () => {},
                moveTo: () => {}, lineTo: () => {}, stroke: () => {}, fill: () => {},
                arc: () => {}, closePath: () => {}, createLinearGradient: () => ({ addColorStop: () => {} }),
                fillText: () => {}
              }),
              addEventListener: () => {}
            };
          }
          return elements[id];
        }

        global.document = { getElementById: getEl };
        global.requestAnimationFrame = (fn) => setTimeout(fn, 16);
        global.window = {
          devicePixelRatio: 1,
          addEventListener: (ev, fn) => { global.onDomReady = fn; },
          requestAnimationFrame: global.requestAnimationFrame
        };
        global.fetch = async () => ({
          ok: false, status: 404,
          json: async () => { throw new SyntaxError('Unexpected token <'); },
          text: async () => '404'
        });

        const topo = fs.readFileSync('docs/js/topology.js', 'utf-8');
        const charts = fs.readFileSync('docs/js/charts.js', 'utf-8');
        const app = fs.readFileSync('docs/js/app.js', 'utf-8');

        new Function('global', topo + '\\n' + charts + '\\n' + app)(global);
        if (global.onDomReady) global.onDomReady();

        setTimeout(() => {
          const total = elements['kpi-total-nodes'].textContent;
          const rows = (elements['devices-table-body'].innerHTML.match(/<tr>/g) || []).length;
          const alerts = (elements['alerts-table-body'].innerHTML.match(/<tr>/g) || []).length;
          const mode = elements['mode-badge'].textContent;

          if (total === '--' || rows === 0 || alerts === 0 || mode.indexOf('STATIC DEMO') === -1) {
            console.error('FAIL: total=' + total + ', rows=' + rows + ', alerts=' + alerts + ', mode=' + mode);
            process.exit(1);
          }
          console.log('PASS: total=' + total + ', rows=' + rows + ', alerts=' + alerts + ', mode=' + mode);
          process.exit(0);
        }, 300);
        """

        res = subprocess.run(
            ["node", "-e", node_script],
            capture_output=True,
            text=True,
            cwd=str(BASE_DIR)
        )
        self.assertEqual(
            res.returncode, 0,
            f"Node DOM startup simulation failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
        )
        self.assertIn("PASS:", res.stdout)


if __name__ == "__main__":
    unittest.main()

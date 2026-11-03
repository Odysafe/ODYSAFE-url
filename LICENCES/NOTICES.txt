# Third-party notices

ODYSAFE-URL installs these local dependencies in its container images:

- PlaywrightCapture, BSD 3-Clause. Its license is copied to
  `/usr/share/licenses/odysafe-url/PlaywrightCapture-LICENSE` in browser images.
- har2tree, BSD 3-Clause. Its license is copied to
  `/usr/share/licenses/odysafe-url/har2tree-LICENSE`.
- Xpra is installed as a signed Debian package in the interactive image. Debian
  package copyright and license data remain under `/usr/share/doc/`.
- htmx 2.0.8, Zero-Clause BSD. The unmodified browser asset is served locally;
  its license is stored in `app/web/static/HTMX-LICENSE.txt`.
- Lookyloo, BSD 3-Clause. The resource-type icons copied from
  `repo/lookyloo/website/web/static/` and the adapted tree presentation are
  used in the ODYSAFE investigation views. The license is stored in
  `app/web/static/lookyloo/LICENSE.txt`. Lookyloo branding and logo are not used.
- ODYSAFE-CTI, AGPL-3.0. Its ODYSAFE logo, favicon, sphere background and the
  adapted glass-card, navigation, form, button and table styles are reused with
  the project owner's authorization. The source license is stored in
  `app/web/static/cti/LICENSE.txt`.

Other Python and Debian packages retain their package metadata and license data.

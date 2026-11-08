"""Static checks of the plugin's stylesheets. Regression: .tc-block-dropdown-wrapper is shared by the type selector AND the tag picker;
hiding it made the tag dropdown of the editor open empty (0x0)."""
import os, re, unittest
SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'plugin', 'src')
SHARED = ['.tc-block-dropdown-wrapper', '.tc-block-dropdown', '.tc-edit-add-tag', '.tc-edit-tags', '.tc-popup-handle']

class Css(unittest.TestCase):
    def test_shared_editor_widgets_never_hidden(self):
        for f in os.listdir(SRC):
            if not f.endswith('.tid') or 'css' not in f: continue
            css = open(os.path.join(SRC, f), encoding='utf-8').read()
            for m in re.finditer(r'([^{}]+)\{([^{}]*display\s*:\s*none[^{}]*)\}', css):
                sels = [s.strip() for s in m.group(1).split(',')]
                for s in sels:
                    for shared in SHARED:
                        self.assertFalse(re.search(re.escape(shared) + r'(?![\w-])', s), '%s hides shared editor element %s via %r' % (f, shared, s))

if __name__ == '__main__': unittest.main(verbosity=1)

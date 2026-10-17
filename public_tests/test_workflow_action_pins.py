"""Offline enforcement of the manually reviewed template action selection."""
from pathlib import Path
import re
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
PINS = {
    'actions/checkout': ('3d3c42e5aac5ba805825da76410c181273ba90b1', 'v7.0.1'),
    'actions/setup-python': ('ece7cb06caefa5fff74198d8649806c4678c61a1', 'v6.3.0'),
    'actions/cache': ('55cc8345863c7cc4c66a329aec7e433d2d1c52a9', 'v6.1.0'),
    'actions/upload-artifact': ('043fb46d1a93c77aae656e7c1c64a875d1fc6a0a', 'v7.0.1'),
    'codecov/codecov-action': ('303a32d7a59b442fa8d48b6a1cc6825c09c847a5', 'v7.1.1'),
}


class UniqueLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in result:
                raise ValueError(f'Duplicate YAML key: {key}')
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def validate(text):
    parsed = yaml.load(text, Loader=UniqueLoader)
    if not isinstance(parsed.get('jobs'), dict):
        raise ValueError('Workflow lacks jobs')
    # Node marks bind each version comment to its actual uses mapping value.
    nodes = yaml.compose(text)
    lines = text.splitlines()
    def visit(node):
        if isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                if key.value == 'uses':
                    reference = value.value
                    repository, _, commit = reference.partition('@')
                    if repository not in PINS or commit != PINS[repository][0]:
                        raise ValueError(f'Unreviewed/floating action reference: {reference}')
                    tail = lines[value.end_mark.line][value.end_mark.column:]
                    if not re.fullmatch(r'\s+#\s*' + re.escape(PINS[repository][1]) + r'\s*', tail):
                        raise ValueError(f'Missing reviewed release comment: {reference}')
                visit(value)
        elif isinstance(node, yaml.SequenceNode):
            for child in node.value:
                visit(child)
    visit(nodes)


class WorkflowActionPinsTests(unittest.TestCase):
    def test_every_shipped_template_and_example_has_reviewed_pins(self):
        paths = sorted((ROOT / 'templates/workflows').glob('*.yml*'))
        self.assertTrue(paths)
        for path in paths:
            with self.subTest(path=path.name):
                validate(path.read_text())

    def test_floating_unknown_and_mismatched_pins_are_rejected(self):
        commit, version = PINS['actions/checkout']
        for reference in ('actions/checkout@v4', 'actions/upload-artifact@v3',
                          'unknown/action@' + commit, 'actions/checkout@' + '0' * 40,
                          'actions/checkout@' + commit + ' # v0.0.0'):
            text = 'jobs:\n  test:\n    steps:\n      - uses: ' + reference + '\n'
            with self.subTest(reference=reference), self.assertRaises(ValueError):
                validate(text)
        validate('jobs:\n  test:\n    steps:\n      - uses: actions/checkout@' + commit + ' # ' + version + '\n')
        for text in (
            'jobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n'
            '        uses: actions/checkout@' + commit + ' # ' + version + '\n',
            '# actions/checkout@' + commit + ' # ' + version + '\n'
            'jobs:\n  test:\n    steps:\n      - uses: actions/checkout@' + commit + '\n',
        ):
            with self.assertRaises(ValueError):
                validate(text)

    def test_optional_codec_upload_requires_explicit_opt_in_and_current_input(self):
        workflow = yaml.safe_load((ROOT / 'templates/workflows/ci.yml').read_text())
        steps = [step for job in workflow['jobs'].values() for step in job.get('steps', [])]
        upload = next(step for step in steps if str(step.get('uses', '')).startswith('codecov/'))
        self.assertEqual(upload['if'], "${{ vars.NAOS_ENABLE_CODECOV == 'true' }}")
        self.assertIn('files', upload['with'])
        self.assertNotIn('file', upload['with'])


if __name__ == '__main__':
    unittest.main()

"""Select all current-source profiles without executing or authenticating them."""
import copy
import hashlib
from pathlib import Path

from qualification import nom_dev_661b5ef_legacy as legacy
from qualification import nom_dev_661b5ef_reclaim as reclaim
from qualification import nom_dev_661b5ef_runtime as runtime
from qualification import nom_embedded_argument_pricing as pricing

ROOT = legacy.ROOT
CORE, TREE = legacy.CORE, legacy.TREE
earlier = legacy.earlier
require = earlier.require
MANIFEST = 'compatibility/nom_dev_661b5ef_manifest.json'
PROFILES = ('all',)
MAX_TOTAL = legacy.MAX_TOTAL + reclaim.MAX_STDOUT + reclaim.MAX_STDERR + runtime.MAX_TOTAL + pricing.MAX_STDOUT + pricing.MAX_STDERR
TRANSPORT_PINS = {
    'scripts/prepare_nom_5cb.py':'4dce6b27300a6eaa56d4412ca5336e9d617a574f747c2c33724be145850132bd',
    'scripts/qualify_nom_5cb_native.py':'39aa50206a89594c884fe1745ce99465a8dc34b2734cccf0d2e81f5b7eb7e4d1',
    'scripts/nom_5cb_command.py':'22a8d66c57622c83f754a77881d1d817bf4e48b0e25ef83de3d1b8295fbb9cc0',
    'scripts/check_nom_5cb_evidence.py':'b0d12c627aafbb04ece36622770d4bcd622df8e588d0037f0d016c63982c74e7',
}
TRANSPORT_EDITS = {'prepare_nom_5cb.py': (('zenon-network-go-zenon-661b5ef5aac', 'zenon-network-go-zenon-661b5ef'), ('1941926', '2053008'), ('d4f8e26ce3d8cba37c30e166a11b63423218b6e47451d4c31507b520f5e61f39', '9ccc6b8aaa4c4f5a28d11236a3393727bd2f4959c13385c05a0fb81fe4c09acd'), ('502', '543'), ('original_source_files=482', 'original_source_files=518'), ('project_producers=20', 'project_producers=25')), 'qualify_nom_5cb_native.py': (('nom_dev_661b5ef_reproduction as reproduction', 'nom_dev_661b5ef as reproduction'), ("== 502 and len(plan['units']) == 20", "== 543 and len(plan['units']) == 31"), ('selected_commands=20', 'selected_commands=31'), ('complete_profiles=20', 'complete_profiles=31'), ('selected_parent_and_child_outcomes=479', "selected_parent_and_child_outcomes=642, reference_outcome_scope='PROJECT_PRODUCERS_ONLY', required_runtime_tests=58"), ('complete_original_profile_streams=40', 'complete_original_profile_streams=62'), ('actual_native_commands=24', 'actual_native_commands=35'), ("environment['SDKROOT'] = str(sdk)", "environment['SDKROOT'] = str(sdk)\n        environment['CGO_CFLAGS'] = reproduction.runtime.DARWIN_CGO_CFLAGS"), ('compiler_workspaces=1, source_views=1, selected_commands=31,', 'cgo_diagnostic_profile=reproduction.runtime.diagnostic_profile(sdk),\n        compiler_workspaces=1, source_views=1, selected_commands=31,'), ("GOFLAGS=''", "GOFLAGS='-trimpath'"), ('        cgo_diagnostic_profile=reproduction.runtime.diagnostic_profile(sdk),', "        cgo_diagnostic_profile=reproduction.runtime.diagnostic_profile(sdk),\n        go_source_path_profile='GOFLAGS_TRIMPATH',")), 'nom_5cb_command.py': (("'keyless-supervisor',", "'keyless-supervisor', 'reclaim-current', 'runtime-manager-guards', 'runtime-node-stop', 'runtime-spork-tombstone', 'runtime-decode-limits', 'runtime-manager-close', 'runtime-cache-close', 'runtime-request-budget', 'argument-pricing', 'runtime-embedded-pricing', 'runtime-quote-snapshot',"),), 'check_nom_5cb_evidence.py': (('nom_dev_661b5ef_reproduction as reproduction', 'nom_dev_661b5ef as reproduction'), ('len(result) == 24', 'len(result) == 35'), ('upstream_files=482', 'upstream_files=518'), ('project_producers=20, combined_files=502', 'project_producers=25, combined_files=543'), ("report['complete_profiles'] == 20", "report['complete_profiles'] == 31"), ("report['selected_parent_and_child_outcomes'] == 479", "report['selected_parent_and_child_outcomes'] == 642\n            and report['reference_outcome_scope'] == 'PROJECT_PRODUCERS_ONLY'\n            and report['required_runtime_tests'] == 58"), ("report['complete_original_profile_streams'] == 40", "report['complete_original_profile_streams'] == 62"), ("report['actual_native_commands'] == 24", "report['actual_native_commands'] == 35"), ("'compiler_unchanged', 'elapsed_seconds',", "'compiler_unchanged', 'elapsed_seconds', 'reference_outcome_scope', 'required_runtime_tests',"), ("    'schema', 'outcome', 'core_commit', 'core_tree', 'profile', 'source_before',", "    'schema', 'outcome', 'core_commit', 'core_tree', 'profile', 'source_before',\n    'cgo_diagnostic_profile',"), ("    if report['platform_sdk'] != 'NOT_SELECTED' and 'go_version' in report:", "    require(report['cgo_diagnostic_profile'] == (selected.runtime.DEFAULT_CGO_PROFILE\n        if report['platform_sdk'] == 'NOT_SELECTED' else selected.runtime.DARWIN_CGO_PROFILE))\n    if report['platform_sdk'] != 'NOT_SELECTED' and 'go_version' in report:"), ("def privacy(raw):\n    require(type(raw) is bytes)\n    text = raw.decode('ascii')\n    roots = ('Users', 'Volumes', 'private', 'home', 'tmp', 'var',\n             'opt', 'Applications', 'Library', 'usr')\n    # Inspect escaped representations too. Retained originals are never decoded,\n    # redacted, replaced or rewritten. Each view is bounded by the input length.\n    for unused_depth in range(8):\n        require(text.isascii())\n        require(not any(pattern.search(text) for unused, pattern in PATTERNS))\n        require(not re.search(r'(?i)/(?:' + '|'.join(roots) + r')/', text))\n        require(not re.search(r'(?i)localhost|\\b[A-Za-z0-9_-]+[.]local\\b|127[.]0[.]0[.]1', text))\n        decoded = re.sub(r'\\\\u([0-9a-fA-F]{4})',\n                         lambda match: chr(int(match.group(1), 16)), text)\n        decoded = decoded.replace(chr(92) * 2, chr(92))\n        if decoded == text:\n            return\n        text = decoded\n    require(False)", 'def ascii_privacy_view(text):\n    """Inspect one exact upstream NBSP diagnostic without rewriting originals."""\n    require(type(text) is str)\n    if text.isascii():\n        return text\n    require({char for char in text if not char.isascii()} == {\'\\u00a0\'})\n\n    def unique(values):\n        result = {}\n        for key, value in values:\n            require(key not in result)\n            result[key] = value\n        return result\n\n    for line in text.split(\'\\n\'):\n        if line.isascii():\n            continue\n        event = json.loads(line, object_pairs_hook=unique)\n        require(type(event) is dict\n            and set(event) == {\'Time\', \'Action\', \'Package\', \'Test\', \'Output\'})\n        require(type(event[\'Time\']) is str and re.fullmatch(\n            r\'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\'\n            r\'(?:[.][0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})\', event[\'Time\']))\n        require(event[\'Action\'] == \'output\'\n            and event[\'Package\'] == \'github.com/zenon-network/go-zenon/chain/cache/storage\'\n            and event[\'Test\'] == \'TestGetFrontierIdentifierCorrupted\'\n            and event[\'Output\'] == \'proto:\\u00a0cannot parse invalid wire-format data\\n\')\n    # This temporary audit view cannot escape this function into retention.\n    # Retention still hashes and selects the original, unmodified byte string.\n    return text.replace(\'\\u00a0\', \' \')\n\n\ndef privacy(raw):\n    require(type(raw) is bytes)\n    text = raw.decode(\'utf-8\')\n    roots = (\'Users\', \'Volumes\', \'private\', \'home\', \'tmp\', \'var\',\n             \'opt\', \'Applications\', \'Library\', \'usr\')\n    # Inspect escaped representations too. Retained originals are never decoded,\n    # redacted, replaced or rewritten. Each view is bounded by the input length.\n    for unused_depth in range(8):\n        inspected = ascii_privacy_view(text)\n        require(not any(pattern.search(inspected) for unused, pattern in PATTERNS))\n        require(not re.search(r\'(?i)/(?:\' + \'|\'.join(roots) + r\')/\', inspected))\n        require(not re.search(r\'(?i)localhost|\\b[A-Za-z0-9_-]+[.]local\\b|127[.]0[.]0[.]1\', inspected))\n        decoded = re.sub(r\'\\\\u([0-9a-fA-F]{4})\',\n                         lambda match: chr(int(match.group(1), 16)), text)\n        decoded = decoded.replace(chr(92) * 2, chr(92))\n        if decoded == text:\n            return\n        text = decoded\n    require(False)'), ("    'cgo_diagnostic_profile',", "    'cgo_diagnostic_profile', 'go_source_path_profile',"), ("        if report['platform_sdk'] == 'NOT_SELECTED' else selected.runtime.DARWIN_CGO_PROFILE))", "        if report['platform_sdk'] == 'NOT_SELECTED' else selected.runtime.DARWIN_CGO_PROFILE))\n    require(report['go_source_path_profile'] == 'GOFLAGS_TRIMPATH')"))}
OWN_INPUTS = {
    'qualification/nom_dev_661b5ef.py','tests/test_nom_dev_661b5ef.py',
    legacy.MANIFEST,reclaim.MANIFEST,runtime.MANIFEST,pricing.MANIFEST,
} | {name.replace('5cb','661b5ef') for name in TRANSPORT_PINS}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_json(path):
    return legacy.read_json(path)


def transport_variants(root=ROOT):
    """Prove the complete allowed textual descent and its exact inverse."""
    root = Path(root)
    rows = read_json(root / MANIFEST)['transport_variants']
    require(set(rows) == set(TRANSPORT_PINS))
    for parent, pin in TRANSPORT_PINS.items():
        original = earlier.regular(root / parent, 2 * earlier.MIB)
        require(sha(original) == pin)
        selected = parent.replace('5cb','661b5ef')
        raw = earlier.regular(root / selected, 2 * earlier.MIB)
        body, edits = original, []
        replacements = (('5cb','661b5ef'),) + TRANSPORT_EDITS[Path(parent).name]
        for before, after in replacements:
            before, after = before.encode('ascii'), after.encode('ascii')
            count = body.count(before)
            require(count > 0)
            body = body.replace(before, after)
            edits.append(dict(before=before.decode('ascii'),after=after.decode('ascii'),occurrences=count))
        require(body == raw)
        inverse = raw
        for edit in reversed(edits):
            before, after = edit['before'].encode('ascii'), edit['after'].encode('ascii')
            require(inverse.count(after) == edit['occurrences'])
            inverse = inverse.replace(after, before)
        require(inverse == original)
        earlier.rebase.exact(dict(selected=selected,original_sha256=pin,
            selected_sha256=sha(raw),edits=edits,
            scope='SOURCE SELECTION, PROFILE COUNTS, EXPLICIT DIAGNOSTIC SETTINGS AND EXACT PROTOBUF DIAGNOSTIC INSPECTION ONLY'), rows[parent])
    return rows


def inputs(root=ROOT):
    root = earlier.physical(root)
    manifest = read_json(root / MANIFEST)
    fixed = dict(schema='ptlc-nom-dev-661b5ef-combined-selection-v1',core_commit=CORE,core_tree=TREE,
        upstream_source_files=518,project_producers=25,combined_source_files=543,
        reference_producers=22,runtime_log_initializers=3,
        legacy_profiles=20,legacy_outcomes=479,reclaim_cases=76,reclaim_outcomes=77,
        complete_profiles=31,selected_parent_and_child_outcomes=642,
        reference_outcome_scope='PROJECT_PRODUCERS_ONLY',runtime_profiles=9,required_runtime_tests=58,
        complete_original_profile_streams=62,actual_native_commands=35,
        historical_results_reclassified=False,journal_source_upgrade='NOT_SELECTED',
        application='NO-GO',core='NO-GO',independent_assessment='UNFILLED')
    require(set(manifest) == set(fixed) | {'input_sha256','transport_variants'})
    earlier.rebase.exact(fixed, {key:manifest[key] for key in fixed})
    require(set(manifest['input_sha256']) == OWN_INPUTS)
    for name, pin in manifest['input_sha256'].items():
        require(sha(earlier.regular(root / name, 2 * earlier.MIB)) == pin)
    runtime.inputs(root)
    pricing.inputs(root)
    transport_variants(root)
    reclaim.inputs(root)
    unused, index = legacy.source.inputs(root)
    return manifest, index


def probes(root=ROOT,profile='all'):
    require(profile == 'all')
    selected = dict(reclaim.probes(root))
    require(pricing.DESTINATION not in selected)
    selected[pricing.DESTINATION] = pricing.DRIVER
    extra = runtime.probes(root)
    require(not set(selected)&set(extra) and len(selected)==22 and len(extra)==3)
    selected.update(extra)
    return selected


def units(profile='all'):
    require(profile == 'all')
    return legacy.units('all') | {reclaim.UNIT,pricing.UNIT} | set(runtime.SPECS)


def plan(root=ROOT,profile='all'):
    require(profile == 'all')
    inputs(root)
    value = copy.deepcopy(legacy.prior_reproduction.plan(root,'all'))
    row = dict(unit=reclaim.UNIT,package='vm',parent=reclaim.PARENT,
        parent_and_child_outcomes=77,prior_streams_required=[],
        arguments=['test','-json','-p','2','-mod=readonly','-count=1',
                   '-run','^'+reclaim.PARENT+'$','./vm'])
    value['units'].append(row)
    value['units'].append(pricing.plan(root))
    value['units'].extend(runtime.plan(root))
    require({item['unit'] for item in value['units']} == units()
        and len(value['units']) == 31
        and sum(item['parent_and_child_outcomes'] for item in value['units'][:22]) == 642
        and sum(item['parent_and_child_outcomes'] for item in value['units'][22:]) == 58)
    value.update(schema='ptlc-nom-dev-661b5ef-combined-plan-v1',core_commit=CORE,core_tree=TREE,
        producers=probes(root),reclaim_profile='ADDITIVE_FINITE_REFERENCE_ONLY',
        historical_results_reclassified=False,journal_source_upgrade='NOT_SELECTED')
    return value


def input_bindings(unit,prior_streams=None,root=ROOT):
    require(type(unit) is str and unit in units())
    if unit in runtime.SPECS:
        runtime.inputs(root)
        return {}
    if unit == pricing.UNIT:
        return pricing.input_bindings(root)
    if unit == reclaim.UNIT:
        reclaim.inputs(root)
        return {'PTLC_NOM_RECLAIM_CURRENT_INPUT':{'repository_file':reclaim.INPUT}}
    # The legacy provider validates its complete selected inputs itself. Avoid
    # repeating the joint check for each of twenty bindings; no result is cached.
    return legacy.input_bindings(unit,prior_streams,root)


def compare_source(directory,root=ROOT,profile='all'):
    require(profile == 'all')
    inputs(root)
    namespace=dict(vars(legacy.prior))
    namespace.update(CORE=CORE,TREE=TREE,inputs=inputs,probes=probes)
    bound,unused=legacy._functions(root,legacy.prior,{'compare_source'},namespace)
    return bound['compare_source'](directory,root,profile)


def compare_payloads(payloads,root=ROOT,profile='all'):
    require(profile == 'all')
    required = {unit+suffix for unit in units() for suffix in ('.stdout','.stderr')}
    require(type(payloads) is dict and set(payloads) == required)
    require(all(type(raw) is bytes for raw in payloads.values())
        and sum(map(len,payloads.values())) <= MAX_TOTAL)
    inputs(root)
    old = {name:raw for name,raw in payloads.items() if name.rsplit('.',1)[0] in legacy.units()}
    added = {name:raw for name,raw in payloads.items() if name.rsplit('.',1)[0] == reclaim.UNIT}
    legacy_result = legacy.compare_payloads(old,root)
    reclaim_result = reclaim.compare_payloads(added,root)
    pricing_result = pricing.compare_payloads({name:raw for name,raw in payloads.items()
        if name.rsplit('.',1)[0] == pricing.UNIT},root)
    runtime_result = runtime.compare_payloads({name:raw for name,raw in payloads.items()
        if name.rsplit('.',1)[0] in runtime.SPECS},root)
    require(legacy_result['outcome'] == 'PASS_SELECTED_LEGACY_VALUES_ONLY'
        and reclaim_result['outcome'] == 'PASS_FINITE_RECLAIM_VALUES_ONLY')
    return dict(schema='ptlc-nom-dev-661b5ef-combined-values-v1',outcome='PASS_SELECTED_FINITE_VALUES_ONLY',
        core_commit=CORE,core_tree=TREE,profile='all',complete_profiles=31,
        selected_parent_and_child_outcomes=642,complete_original_profile_streams=62,
        reference_outcome_scope='PROJECT_PRODUCERS_ONLY',required_runtime_tests=58,
        legacy=legacy_result,reclaim=reclaim_result,pricing=pricing_result,runtime=runtime_result,historical_results_reclassified=False,
        native_execution='NOT_PERFORMED_BY_READER',execution_origin='NOT_ESTABLISHED_BY_READER',
        actual_command_exit='NOT_ESTABLISHED_BY_READER',journal_source_upgrade='NOT_SELECTED',
        recovery_action='NONE',application='NO-GO',core='NO-GO',independent_assessment='UNFILLED')

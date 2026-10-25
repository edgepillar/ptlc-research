"""Select all current-source profiles without executing or authenticating them."""
import copy
import hashlib
from pathlib import Path

from qualification import nom_dev_5a2593_legacy as legacy
from qualification import nom_dev_5a2593_reclaim as reclaim

ROOT = legacy.ROOT
CORE, TREE = legacy.CORE, legacy.TREE
earlier = legacy.earlier
require = earlier.require
MANIFEST = 'compatibility/nom_dev_5a2593_manifest.json'
PROFILES = ('all',)
MAX_TOTAL = legacy.MAX_TOTAL + reclaim.MAX_STDOUT + reclaim.MAX_STDERR
TRANSPORT_PINS = {
    'scripts/prepare_nom_5cb.py':'4dce6b27300a6eaa56d4412ca5336e9d617a574f747c2c33724be145850132bd',
    'scripts/qualify_nom_5cb_native.py':'39aa50206a89594c884fe1745ce99465a8dc34b2734cccf0d2e81f5b7eb7e4d1',
    'scripts/nom_5cb_command.py':'22a8d66c57622c83f754a77881d1d817bf4e48b0e25ef83de3d1b8295fbb9cc0',
    'scripts/check_nom_5cb_evidence.py':'b0d12c627aafbb04ece36622770d4bcd622df8e588d0037f0d016c63982c74e7',
}
TRANSPORT_EDITS = {
    'prepare_nom_5cb.py': (
        ('5a25935aac','5a2593a'),
        ('1941926','1997424'),
        ('d4f8e26ce3d8cba37c30e166a11b63423218b6e47451d4c31507b520f5e61f39',
         '13219b44f2f0a0947d23b90b8c2214dccacfe39e1689ff1c7bf18a5948d03b9b'),
        ('502','521'),('original_source_files=482','original_source_files=500'),
        ('project_producers=20','project_producers=21'),
    ),
    'qualify_nom_5cb_native.py': (
        ('nom_dev_5a2593_reproduction as reproduction','nom_dev_5a2593 as reproduction'),
        ("== 502 and len(plan['units']) == 20","== 521 and len(plan['units']) == 21"),
        ('selected_commands=20','selected_commands=21'),
        ('complete_profiles=20','complete_profiles=21'),
        ('selected_parent_and_child_outcomes=479','selected_parent_and_child_outcomes=556'),
        ('complete_original_profile_streams=40','complete_original_profile_streams=42'),
        ('actual_native_commands=24','actual_native_commands=25'),
    ),
    'nom_5cb_command.py': (("'keyless-supervisor',","'keyless-supervisor', 'reclaim-current',"),),
    'check_nom_5cb_evidence.py': (
        ('nom_dev_5a2593_reproduction as reproduction','nom_dev_5a2593 as reproduction'),
        ('len(result) == 24','len(result) == 25'),
        ('upstream_files=482','upstream_files=500'),
        ('project_producers=20, combined_files=502','project_producers=21, combined_files=521'),
        ("report['complete_profiles'] == 20","report['complete_profiles'] == 21"),
        ("report['selected_parent_and_child_outcomes'] == 479","report['selected_parent_and_child_outcomes'] == 556"),
        ("report['complete_original_profile_streams'] == 40","report['complete_original_profile_streams'] == 42"),
        ("report['actual_native_commands'] == 24","report['actual_native_commands'] == 25"),
    ),
}
OWN_INPUTS = {
    'qualification/nom_dev_5a2593.py','tests/test_nom_dev_5a2593.py',
    legacy.MANIFEST,reclaim.MANIFEST,
} | {name.replace('5cb','5a2593') for name in TRANSPORT_PINS}


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
        selected = parent.replace('5cb','5a2593')
        raw = earlier.regular(root / selected, 2 * earlier.MIB)
        body, edits = original, []
        replacements = (('5cb','5a2593'),) + TRANSPORT_EDITS[Path(parent).name]
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
            scope='SOURCE SELECTION, SCHEMA LABELS AND ADDITIVE PROFILE COUNTS ONLY'), rows[parent])
    return rows


def inputs(root=ROOT):
    root = earlier.physical(root)
    manifest = read_json(root / MANIFEST)
    fixed = dict(schema='ptlc-nom-dev-5a2593-combined-selection-v1',core_commit=CORE,core_tree=TREE,
        upstream_source_files=500,project_producers=21,combined_source_files=521,
        legacy_profiles=20,legacy_outcomes=479,reclaim_cases=76,reclaim_outcomes=77,
        complete_profiles=21,selected_parent_and_child_outcomes=556,
        complete_original_profile_streams=42,actual_native_commands=25,
        historical_results_reclassified=False,journal_source_upgrade='NOT_SELECTED',
        application='NO-GO',core='NO-GO',independent_assessment='UNFILLED')
    require(set(manifest) == set(fixed) | {'input_sha256','transport_variants'})
    earlier.rebase.exact(fixed, {key:manifest[key] for key in fixed})
    require(set(manifest['input_sha256']) == OWN_INPUTS)
    for name, pin in manifest['input_sha256'].items():
        require(sha(earlier.regular(root / name, 2 * earlier.MIB)) == pin)
    transport_variants(root)
    reclaim.inputs(root)
    unused, index = legacy.source.inputs(root)
    return manifest, index


def probes(root=ROOT,profile='all'):
    require(profile == 'all')
    return reclaim.probes(root)


def units(profile='all'):
    require(profile == 'all')
    return legacy.units('all') | {reclaim.UNIT}


def plan(root=ROOT,profile='all'):
    require(profile == 'all')
    inputs(root)
    value = copy.deepcopy(legacy.prior_reproduction.plan(root,'all'))
    row = dict(unit=reclaim.UNIT,package='vm',parent=reclaim.PARENT,
        parent_and_child_outcomes=77,prior_streams_required=[],
        arguments=['test','-json','-p','2','-mod=readonly','-count=1',
                   '-run','^'+reclaim.PARENT+'$','./vm'])
    value['units'].append(row)
    require({item['unit'] for item in value['units']} == units()
        and len(value['units']) == 21
        and sum(item['parent_and_child_outcomes'] for item in value['units']) == 556)
    value.update(schema='ptlc-nom-dev-5a2593-combined-plan-v1',core_commit=CORE,core_tree=TREE,
        producers=probes(root),reclaim_profile='ADDITIVE_FINITE_REFERENCE_ONLY',
        historical_results_reclassified=False,journal_source_upgrade='NOT_SELECTED')
    return value


def input_bindings(unit,prior_streams=None,root=ROOT):
    require(type(unit) is str and unit in units())
    if unit == reclaim.UNIT:
        reclaim.inputs(root)
        return {'PTLC_NOM_RECLAIM_CURRENT_INPUT':{'repository_file':reclaim.INPUT}}
    # The legacy provider validates its complete selected inputs itself. Avoid
    # repeating the joint check for each of twenty bindings; no result is cached.
    return legacy.input_bindings(unit,prior_streams,root)


def compare_source(directory,root=ROOT,profile='all'):
    require(profile == 'all')
    inputs(root)
    return reclaim.compare_source(directory,root)


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
    require(legacy_result['outcome'] == 'PASS_SELECTED_LEGACY_VALUES_ONLY'
        and reclaim_result['outcome'] == 'PASS_FINITE_RECLAIM_VALUES_ONLY')
    return dict(schema='ptlc-nom-dev-5a2593-combined-values-v1',outcome='PASS_SELECTED_FINITE_VALUES_ONLY',
        core_commit=CORE,core_tree=TREE,profile='all',complete_profiles=21,
        selected_parent_and_child_outcomes=556,complete_original_profile_streams=42,
        legacy=legacy_result,reclaim=reclaim_result,historical_results_reclassified=False,
        native_execution='NOT_PERFORMED_BY_READER',execution_origin='NOT_ESTABLISHED_BY_READER',
        actual_command_exit='NOT_ESTABLISHED_BY_READER',journal_source_upgrade='NOT_SELECTED',
        recovery_action='NONE',application='NO-GO',core='NO-GO',independent_assessment='UNFILLED')

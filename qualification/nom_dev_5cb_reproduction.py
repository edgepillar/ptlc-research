"""Describe offline reproduction inputs; never launch, download, sign or write.

The caller must use its approved owned storage, retain actual exits and original
streams, and validate source contents before and after execution. A plan or a
handoff parsed here does not authenticate execution origin.
"""
import importlib
import json
from pathlib import Path

from qualification import nom_dev_5cb as selected
from qualification import nom_keyless_supervisor as keyless
from scripts import qualify_nom_wire_core as wire

ROOT = selected.ROOT
common = selected.earlier
vm = selected.vm


def plan(root=ROOT, profile='all'):
    selected.inputs(root)
    assert profile in selected.PROFILES
    rows = []
    if profile != 'keyless':
        unused, unused_fixtures, identities = common.profiles(root)
        for unit, packages in identities.items():
            assert len(packages) == 1
            package, names = next(iter(packages.items()))
            parent = [name for name in names if '/' not in name]
            assert len(parent) == 1
            rows.append(dict(unit=unit, package=package.removeprefix(common.PREFIX),
                parent=parent[0], parent_and_child_outcomes=common.COUNTS[unit]))
        for kind, count in selected.AUXILIARY.items():
            module = importlib.import_module('qualification.nom_dev_'+kind)
            rows.append(dict(unit=kind.replace('_','-'),
                package=module.PACKAGE.removeprefix(common.PREFIX),
                parent=module.PARENT, parent_and_child_outcomes=count+1))
    if profile != 'components':
        rows.append(dict(unit='keyless-supervisor', package='vm', parent=keyless.PARENT,
                         parent_and_child_outcomes=25))
    assert {row['unit'] for row in rows} == selected.units(profile)
    for row in rows:
        row['arguments'] = ['test','-json','-p','2','-mod=readonly','-count=1',
                            '-run','^'+row['parent']+'$','./'+row['package']]
        row['prior_streams_required'] = (
            ['vm-path.stdout','account-authorization.stdout'] if row['unit']=='account-context'
            else ['vm-path.stdout'] if row['unit'] in ('vm-verifier','account-authorization') else [])
    return dict(schema='ptlc-nom-dev-5cb-reproduction-plan-v1', core_commit=selected.CORE,
        core_tree=selected.TREE, profile=profile, producers=selected.probes(root,profile),
        units=rows, go_version='go1.23.12', normal_default_vet=True,
        execution='NOT_PERFORMED', source_acquisition='SEPARATE_VERIFIED_INPUT',
        module_proxy='SEPARATE_VERIFIED_READ_ONLY_OFFLINE_INPUT',
        compiler_workspace='ONE_OWNED_CACHE_PER_ATTEMPT',
        source_check='REQUIRED_BEFORE_AND_AFTER', actual_exits='REQUIRED_SEPARATELY',
        application='NO-GO', core='NO-GO', independent_assessment='UNFILLED')


def input_bindings(unit, prior=None, root=ROOT):
    """Return relative repository inputs or generated JSON values, without I/O writes.

The VM and authorization handoffs require supplied streams, never a substitution
of the parser-control reference fixture. Their provenance remains the caller's
independent obligation; synthetic streams can also pass a value reader.
"""
    selected.inputs(root)
    assert unit in selected.units()
    prior = {} if prior is None else prior
    assert type(prior) is dict
    # Keep the historical profile checks inside selected.inputs(). Importing
    # binding providers here avoids an additional full fixture-validation pass.
    # No source or verification result is cached between calls.
    modules = {name:importlib.import_module('scripts.qualify_nom_'+name) for name in common.MODULES}
    bindings = {}
    def file(name, path, directory=False):
        assert name not in bindings and type(path) is str and not Path(path).is_absolute()
        assert all(part not in ('','.','..') for part in path.split('/'))
        bindings[name] = {'repository_directory' if directory else 'repository_file':path}
    def generated(name, value):
        assert name not in bindings
        bindings[name] = dict(generated_json=value)
    baseline = records = None
    if unit in ('vm-verifier','account-authorization','account-context'):
        raw = prior['vm-path.stdout']
        fixture = vm.inputs(root)[1]
        vm_package = common.PREFIX+'vm'
        common.event_stream(raw,{vm_package:vm.expected_tests(fixture)[vm_package]})
        funding = selected.read_json(Path(root)/vm.FUNDING)
        records = vm.collect_vm_records(raw,fixture,funding)
        baseline = {leg:records[leg+'-direct-success'] for leg in ('long','short')}
    if unit == 'pr138-corpus':
        file('PTLC_COMPAT_FIXTURE_ROOT','compatibility/fixtures',True)
    elif unit == 'wire-corpus':
        file('PTLC_NOM_WIRE_FIXTURE',wire.FIXTURE)
    elif unit in ('vm-path','vm-verifier'):
        for key, path in (('FIXTURE',vm.FIXTURE),('FUNDING',vm.FUNDING),
                          ('COMPLETIONS',vm.COMPLETIONS),
                          ('OLD_COMPLETIONS','compatibility/fixtures/nom_completions_v1.json')):
            file('PTLC_NOM_VM_'+('PATH_FIXTURE' if key=='FIXTURE' else key),path)
        if unit == 'vm-verifier':
            generated('PTLC_NOM_VM_SOURCE_RESULTS',dict(schema='zenon-nom-vm-verifier-input-v1',baseline=baseline))
    elif unit == 'account-authorization':
        generated('PTLC_NOM_ACCOUNT_AUTH_SOURCE',dict(schema='zenon-nom-vm-verifier-input-v1',baseline=baseline))
        generated('PTLC_NOM_ACCOUNT_AUTH_PLAN',dict(schema='zenon-nom-account-authorization-plan-v1',
                                                  vectors=modules['account_authorization'].vectors()))
    elif unit == 'account-context':
        raw = prior['account-authorization.stdout']
        common.event_stream(raw,modules['account_authorization'].expected_tests())
        auth = modules['account_authorization'].collect_records(raw,records)
        patches = {leg:baseline[leg]['receipt_patches'] for leg in ('long','short')}
        generated('PTLC_NOM_CONTEXT_SOURCE',dict(schema='zenon-nom-account-context-input-v1',records=auth,patches=patches))
        generated('PTLC_NOM_CONTEXT_PLAN',dict(schema='zenon-nom-account-context-plan-v1',vectors=selected.vectors()))
    elif unit in ('bilateral-graph','supervisor-plasma'):
        kind = unit.replace('-','_'); module = modules[kind]
        paths = [('INPUT',module.INPUT),('COMPLETIONS',module.COMPLETIONS),
            ('OLD',vm.COMPLETIONS if kind=='bilateral_graph' else modules['bilateral_graph'].COMPLETIONS)]
        if kind == 'supervisor_plasma':paths.append(('RAW',modules['bilateral_graph'].FIXTURE))
        tag = 'BILATERAL' if kind=='bilateral_graph' else 'SUPERVISOR'
        for key,path in paths:file('PTLC_NOM_'+tag+'_'+key,path)
    elif unit == 'account-pool':
        file('PTLC_NOM_POOL_INPUT',modules['supervisor_plasma'].INPUT)
        file('PTLC_NOM_POOL_ORIGINALS',modules['supervisor_plasma'].FIXTURE)
    elif unit in ('batched-rollback','content-cap','multi-rollback','rollback-refusal'):
        kind = unit.replace('-','_')
        tag = {'batched_rollback':'BATCH','content_cap':'CAP','multi_rollback':'MULTI','rollback_refusal':'REFUSAL'}[kind]
        generated('PTLC_NOM_'+tag+'_INPUT',modules[kind].selected_inputs(root)[0])
    elif unit == 'keyless-supervisor':
        file('PTLC_NOM_KEYLESS_ORIGINAL_INPUT',selected.KEYLESS_INPUT)
    return bindings


if __name__ == '__main__':
    print(json.dumps(plan(),sort_keys=True))

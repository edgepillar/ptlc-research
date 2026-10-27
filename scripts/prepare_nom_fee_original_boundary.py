#!/usr/bin/env python3
"""Prepare a fresh source view for one selected fee-original component.

The caller separately owns storage, quotas, compiler selection and evidence.
This obtains no source, installs no software and executes no node or Go command.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from qualification import nom_fee_original_boundary as selected
from scripts import prepare_nom_661b5ef as baseline


def prepare(archive,destination,*,root=ROOT):
    assert sys.dont_write_bytecode and not sys.flags.optimize
    selected.inputs(root)
    prior = baseline.prepare(archive,destination,root=root)
    assert prior['source']['combined_files'] == 543 and prior['original_source_files'] == 518
    target = Path(destination)/selected.DESTINATION
    raw = selected.common.regular(Path(root)/selected.DRIVER,128*1024)
    descriptor = os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'wb') as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    source = selected.compare_source(destination,root)
    return dict(schema='ptlc-nom-fee-original-source-preparation-v1',
        outcome='PASS_PINNED_COMPONENT_SOURCE_PREPARATION_ONLY',
        core_commit=selected.CORE,core_tree=selected.TREE,source=source,
        original_archive=prior['original_archive'],source_views=1,source_extractions=1,
        upstream_files=518,reused_project_files=25,additional_project_files=1,
        compiler_execution='NOT_PERFORMED',source_build_authentication='UNFILLED',
        source_license='PINNED UPSTREAM GPL VERSION 3; NOT VENDORED OR RELICENSED',
        application='NO-GO',core='NO-GO',recovery_action='NONE',independent_assessment='UNFILLED')


def main():
    class QuietParser(argparse.ArgumentParser):
        def error(self,message):
            raise ValueError('bounded component preparation arguments required')
    parser = QuietParser(description=__doc__)
    parser.add_argument('--archive',type=Path,required=True)
    parser.add_argument('--destination',type=Path,required=True)
    try:
        args = parser.parse_args()
        result = prepare(args.archive,args.destination)
    except (AssertionError,OSError,ValueError,KeyError,TypeError,zipfile.BadZipFile,RuntimeError):
        print('REFUSED: fee-original source preparation; preserve partial owned output',file=sys.stderr)
        return 1
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

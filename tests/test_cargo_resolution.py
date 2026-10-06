"""Synthetic metadata claims and owned source copies, never authenticated builds."""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import check_cargo_resolution as check
from scripts import prepare_cargo_resolution as preparation
from scripts import qualify_cargo_resolution as qualification


class Fixture:
    def __init__(self, parent):
        self.root = parent/"project"
        self.workspace = parent/"workspace"
        self.home = parent/"cache"
        self.registry = self.home/"registry/src/selected"
        self.archive = self.home/"registry/cache/selected"
        self.checkouts = {"1"*40: self.home/"git/musig", "2"*40: self.home/"git/schnorr"}
        self.commit, self.manifest = "3"*40, "4"*64
        self.platform = check.PLATFORMS[0]
        for path in (self.root, self.workspace, self.registry, self.archive, *self.checkouts.values()):
            path.mkdir(parents=True)
        self.packages = [dict(name="ptlc-primitive-qualification", version="0.0.0", kind="local-record",
                              dependencies=["bitcoin", "musig2", "schnorr_fun", "serde_json", "sha2"])]
        for name, version in (("bitcoin", "0.32.7"), ("serde_json", "1.0.151"), ("sha2", "0.10.9"),
                              ("helper", "1.0.0"), ("unused", "1.0.0")):
            self.packages.append(dict(name=name, version=version, source=check.inputs.REGISTRY,
                                      kind="registry-archive", checksum="5"*64, dependencies=[]))
        for name, version, pin in (("musig2", "0.4.1", "1"*40), ("schnorr_fun", "0.13.0", "2"*40)):
            source="git+https://github.com/synthetic/"+name+"?rev="+pin+"#"+pin
            self.packages.append(dict(name=name, version=version, source=source, kind="git-record", dependencies=[]))
        next(p for p in self.packages if p["name"] == "bitcoin")["dependencies"] = ["helper"]
        self.locations = check.package_locations(self.packages, self.workspace, self.registry, self.checkouts)
        self.ids = {p["name"]: "synthetic-package-id-"+str(i) for i,p in enumerate(self.packages)}
        reported=[]
        for p in self.packages:
            directory, manifest = self.locations[check.key(p)]
            directory.mkdir(parents=True, exist_ok=True)
            manifest.write_bytes(b"# Synthetic package manifest.\n")
            local = p["kind"] == "local-record"
            source = "examples/verify_original_read_response.rs" if local else "src/lib.rs"
            path=directory/source;path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"// Synthetic source only.\n")
            target=dict(name="verify_original_read_response" if local else p["name"],
                        kind=["example"] if local else ["lib"], crate_types=["bin"] if local else ["lib"],
                        src_path=str(path), edition="2024" if local else "2021", doc=True, doctest=False, test=True)
            row={field:None for field in check.PACKAGE_FIELDS}
            row.update(name=p["name"], version=p["version"], id=self.ids[p["name"]], source=p.get("source"),
                       dependencies=[], targets=[target], features={"default": [], "alternate": []},
                       manifest_path=str(manifest), authors=[], categories=[], keywords=[], edition=target["edition"])
            if local:
                for name,(requirement,features) in check.ROOT_DEPENDENCIES.items():
                    selected=next(p for p in self.packages if p["name"] == name)
                    src=selected.get("source")
                    if selected["kind"] == "git-record":src=src.split("#")[0]
                    row["dependencies"].append(dict(name=name, source=src, req=requirement, kind="dev", rename=None,
                                                    optional=False, uses_default_features=False, features=features,
                                                    target=None, registry=None))
            if p["name"] != "unused":reported.append(row)
        nodes=[]
        for p in self.packages:
            if p["name"] == "unused":continue
            destinations=p.get("dependencies", [])
            nodes.append(dict(id=self.ids[p["name"]], dependencies=[self.ids[n] for n in destinations], features=["default"],
                              deps=[dict(name=n, pkg=self.ids[n], dep_kinds=[dict(kind="dev" if p["kind"] == "local-record" else None, target=None)]) for n in destinations]))
        root_id=self.ids["ptlc-primitive-qualification"]
        self.value=dict(version=1, packages=reported, workspace_members=[root_id], workspace_default_members=[root_id],
                        workspace_root=str(self.workspace/"qualification"), target_directory=str(self.workspace/"target"),
                        metadata=None, resolve=dict(root=root_id, nodes=nodes))
        self.baseline=self.normalize()
        baseline=dict(schema="ptlc-selected-cargo-resolution-baseline-v1", source_commit=self.commit,
                      manifest_sha256=self.manifest,
                      selection="PROJECT SELECTED CARGO 1.90.0 OBSERVATIONS; NOT INDEPENDENT ATTESTATION",
                      profiles={p:deepcopy(self.baseline) for p in check.PLATFORMS})
        self.baseline_file=self.root/check.BASELINE
        self.baseline_file.parent.mkdir(parents=True)
        self.baseline_file.write_bytes(check.encoded(baseline))
        self.digest=hashlib.sha256(self.baseline_file.read_bytes()).hexdigest()
        self.metadata_file=self.workspace/"metadata.json"
        self.save()

    def raw(self, value=None):
        return json.dumps(self.value if value is None else value, ensure_ascii=False).encode("utf-8")

    def normalize(self, value=None):
        return check.normalize(self.raw(value), self.packages, self.workspace, self.registry, self.checkouts)

    def save(self):
        self.metadata_file.write_bytes(self.raw())

    def package(self,name):
        return next(p for p in self.value["packages"] if p["name"] == name)

    def node(self,name):
        return next(n for n in self.value["resolve"]["nodes"] if n["id"] == self.ids[name])


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.fixture=Fixture(Path(self.temporary.name))

    def refuses(self, change):
        value=deepcopy(self.fixture.value)
        change(value)
        with self.assertRaises(check.InputError):self.fixture.normalize(value)

    def test_positive_logical_profile_preserves_unreported_lock_records(self):
        profile=self.fixture.normalize()
        self.assertEqual((profile["package_count"],profile["node_count"],profile["edge_count"],profile["target_count"]),(7,7,6,7))
        self.assertEqual(len(profile["not_reported_lock_packages"]),1)
        self.assertEqual(profile,self.fixture.baseline)
        self.assertNotIn(str(self.fixture.workspace),check.encoded(profile).decode())

    def test_nonoperative_author_metadata_is_discarded_without_authenticating_it(self):
        value=deepcopy(self.fixture.value)
        value["packages"][0]["authors"]=["Synthetic author"]
        value["packages"][0]["description"]="Synthetic \u2603 metadata"
        value["metadata"]={"synthetic_private_observation":"not a resolution credential"}
        profile=self.fixture.normalize(value)
        self.assertEqual(profile,self.fixture.baseline)
        self.assertNotIn("Synthetic author",check.encoded(profile).decode())

    def test_opaque_ids_can_change_coherently_and_order_does_not_select_authority(self):
        value=deepcopy(self.fixture.value)
        mapping={p["id"]:"opaque-selected-"+str(i) for i,p in enumerate(value["packages"])}
        for p in value["packages"]:p["id"]=mapping[p["id"]]
        for n in value["resolve"]["nodes"]:
            n["id"]=mapping[n["id"]];n["dependencies"]=[mapping[d] for d in n["dependencies"]]
            for e in n["deps"]:e["pkg"]=mapping[e["pkg"]]
            n["deps"].reverse();n["dependencies"].reverse()
        value["resolve"]["root"]=mapping[value["resolve"]["root"]]
        for name in ("workspace_members","workspace_default_members"):value[name]=[mapping[v] for v in value[name]]
        value["packages"].reverse();value["resolve"]["nodes"].reverse()
        self.assertEqual(self.fixture.normalize(value),self.fixture.baseline)

    def test_version_and_source_substitution_and_inexact_identity_types_refuse(self):
        for field,new in (("name","replacement"),("version","9.9.9"),("source",None),("name",[]),("version",True)):
            self.refuses(lambda v,f=field,n=new:v["packages"][1].update({f:n}))

    def test_duplicate_logical_packages_and_opaque_ids_refuse(self):
        self.refuses(lambda v:v["packages"].append(deepcopy(v["packages"][1])))
        self.refuses(lambda v:v["packages"][1].update(id=v["packages"][0]["id"]))

    def test_source_and_manifest_location_aliases_and_escape_refuse(self):
        for suffix in ("/../Cargo.toml","//Cargo.toml","/substitute.toml"):
            self.refuses(lambda v,s=suffix:v["packages"][1].update(manifest_path=str(self.fixture.registry)+s))
        self.refuses(lambda v:v["packages"][0].update(manifest_path=str(self.fixture.workspace/"Cargo.toml")))

    def test_workspace_membership_root_and_format_aliases_refuse(self):
        for name in ("workspace_members","workspace_default_members"):
            self.refuses(lambda v,n=name:v.update({n:[]}))
            self.refuses(lambda v,n=name:v[n].append(v[n][0]))
        self.refuses(lambda v:v.update(version=True))
        self.refuses(lambda v:v.update(version=2))
        self.refuses(lambda v:v["resolve"].update(root=None))
        self.refuses(lambda v:v.update(workspace_root=str(self.fixture.root)))

    def test_missing_extra_and_unknown_schema_fields_refuse(self):
        self.refuses(lambda v:v.update(unreviewed_field=True))
        self.refuses(lambda v:v.pop("resolve"))
        self.refuses(lambda v:v["packages"][0].update(unreviewed_field=True))
        self.refuses(lambda v:v["resolve"]["nodes"][0].update(unreviewed_field=True))

    def test_target_path_escapes_missing_files_and_symlinks_refuse(self):
        self.refuses(lambda v:v["packages"][1]["targets"][0].update(src_path=str(self.fixture.workspace/"outside.rs")))
        self.refuses(lambda v:v["packages"][1]["targets"][0].update(src_path=str(self.fixture.locations[check.key(self.fixture.packages[1])][0]/"missing.rs")))
        target=Path(self.fixture.package("bitcoin")["targets"][0]["src_path"])
        target.unlink();target.symlink_to(self.fixture.locations[check.key(self.fixture.packages[2])][1])
        with self.assertRaises(check.InputError):self.fixture.normalize()

    def test_target_kind_boolean_edition_and_duplicate_declarations_refuse(self):
        for field,value in (("kind",["unsupported"]),("test",1),("edition",[]),("edition","2099"),("crate_types",[])):
            self.refuses(lambda v,f=field,n=value:v["packages"][1]["targets"][0].update({f:n}))
        self.refuses(lambda v:v["packages"][1]["targets"].append(deepcopy(v["packages"][1]["targets"][0])))

    def test_original_worker_target_selection_and_required_features_refuse(self):
        for field,value in (("name","another_worker"),("kind",["bin"]),("edition","2021"),("required-features",["default"])):
            self.refuses(lambda v,f=field,n=value:v["packages"][0]["targets"][0].update({f:n}))

    def test_unknown_required_target_and_enabled_features_refuse(self):
        self.refuses(lambda v:v["packages"][1]["targets"][0].update({"required-features":["unknown"]}))
        self.refuses(lambda v:v["resolve"]["nodes"][1].update(features=["unknown"]))
        self.refuses(lambda v:v["resolve"]["nodes"][1].update(features=["default","default"]))

    def test_feature_definition_changes_are_bound_by_digest_without_source_copy(self):
        value=deepcopy(self.fixture.value)
        value["packages"][1]["features"]["alternate"]=["dep:synthetic"]
        changed=self.fixture.normalize(value)
        self.assertNotEqual(changed,self.fixture.baseline)
        self.assertNotIn("dep:synthetic",check.encoded(changed).decode())

    def test_all_five_root_dependency_declarations_are_independently_bound(self):
        for field,new in (("req","*"),("optional",True),("uses_default_features",True),("rename","substitute"),
                          ("kind",None),("target","cfg(windows)"),("registry","synthetic"),("features",[])):
            self.refuses(lambda v,f=field,n=new:v["packages"][0]["dependencies"][0].update({f:n}))
        self.refuses(lambda v:v["packages"][0]["dependencies"].pop())

    def test_missing_duplicate_and_dangling_resolution_nodes_refuse(self):
        self.refuses(lambda v:v["resolve"]["nodes"].pop())
        self.refuses(lambda v:v["resolve"]["nodes"][1].update(id=v["resolve"]["nodes"][0]["id"]))
        self.refuses(lambda v:v["resolve"]["nodes"][1].update(id="unselected"))

    def test_dangling_and_duplicate_typed_edges_and_redundant_lists_refuse(self):
        self.refuses(lambda v:v["resolve"]["nodes"][0]["deps"][0].update(pkg="unselected"))
        self.refuses(lambda v:v["resolve"]["nodes"][0]["deps"].append(deepcopy(v["resolve"]["nodes"][0]["deps"][0])))
        self.refuses(lambda v:v["resolve"]["nodes"][0]["dependencies"].pop())
        self.refuses(lambda v:v["resolve"]["nodes"][0]["dependencies"].append(v["resolve"]["nodes"][0]["dependencies"][0]))

    def test_reported_edge_absent_from_selected_lock_refuses(self):
        value=deepcopy(self.fixture.value)
        node=next(n for n in value["resolve"]["nodes"] if n["id"] == self.fixture.ids["sha2"])
        node["deps"]=[dict(name="bitcoin",pkg=self.fixture.ids["bitcoin"],dep_kinds=[dict(kind=None,target=None)])]
        node["dependencies"]=[self.fixture.ids["bitcoin"]]
        with self.assertRaises(check.InputError):self.fixture.normalize(value)

    def test_dependency_kind_platform_bounds_and_duplicates_refuse(self):
        for field,new in (("kind","optional"),("kind",True),("target","synthetic/path"),("target",[]),("target","a"*513)):
            self.refuses(lambda v,f=field,n=new:v["resolve"]["nodes"][0]["deps"][0]["dep_kinds"][0].update({f:n}))
        self.refuses(lambda v:v["resolve"]["nodes"][0]["deps"][0]["dep_kinds"].append(deepcopy(v["resolve"]["nodes"][0]["deps"][0]["dep_kinds"][0])))

    def test_unreachable_packages_refuse_even_when_node_inventories_agree(self):
        value=deepcopy(self.fixture.value)
        node=next(n for n in value["resolve"]["nodes"] if n["id"] == self.fixture.ids["bitcoin"])
        node["dependencies"]=[];node["deps"]=[]
        with self.assertRaises(check.InputError):self.fixture.normalize(value)

    def test_package_edge_and_target_aggregate_bounds_refuse(self):
        for name,bound in (("MAX_EDGES",5),("MAX_TARGETS",6)):
            with patch.object(check,name,bound),self.assertRaises(check.InputError):self.fixture.normalize()
        with patch.object(check.inputs,"MAX_PACKAGES",6),self.assertRaises(check.InputError):self.fixture.normalize()

    def test_source_measurement_bounds_and_repeated_file_deduplication(self):
        for name,bound in (("MAX_SELECTED_FILES",13),("MAX_SELECTED_FILE_BYTES",8)):
            with patch.object(check,name,bound),self.assertRaises(check.InputError):self.fixture.normalize()
        value=deepcopy(self.fixture.value)
        target=value["packages"][1]["targets"][0]
        for i in range(3):
            alias=deepcopy(target);alias["name"]="synthetic_alias_"+str(i);value["packages"][1]["targets"].append(alias)
        with patch.object(check,"MAX_SELECTED_FILES",14),patch.object(check.content,"digest_stream",wraps=check.content.digest_stream) as measured:
            result=self.fixture.normalize(value)
        self.assertEqual(result["target_count"],10)
        self.assertEqual(measured.call_count,14)

    def test_lock_edge_version_source_ambiguity_and_duplicate_controls(self):
        packages=deepcopy(self.fixture.packages)
        packages.append(dict(name="helper",version="2.0.0",source=check.inputs.REGISTRY,kind="registry-archive",dependencies=[]))
        with self.assertRaises(check.InputError):check.lock_edges(packages)
        next(p for p in packages if p["name"] == "bitcoin")["dependencies"]=["helper 1.0.0"]
        check.lock_edges(packages)
        next(p for p in packages if p["name"] == "bitcoin")["dependencies"]=["helper 1.0.0","helper 1.0.0"]
        with self.assertRaises(check.InputError):check.lock_edges(packages)


class JsonClaimTests(unittest.TestCase):
    def test_duplicate_keys_trailing_input_invalid_utf8_and_surrogates_refuse(self):
        for raw in (b'{"x":1,"x":2}',b'{} {}',b'\xff',b'{"x":"\\ud800"}'):
            with self.assertRaises(check.InputError):check.json_claim(raw)

    def test_depth_bound_ignores_escaped_brackets_inside_strings(self):
        self.assertEqual(check.json_claim(b'{"x":"[\\\"{}]"}'),{"x":'["{}]'})
        with self.assertRaises(check.InputError):check.json_claim(b'['*(check.MAX_DEPTH+1)+b'0'+b']'*(check.MAX_DEPTH+1))

    def test_byte_key_value_and_string_bounds_refuse(self):
        for raw in (b'{"'+b'k'*257+b'":0}',b'{"x":"'+b'a'*8193+b'"}'):
            with self.assertRaises(check.InputError):check.json_claim(raw)
        with patch.object(check,"MAX_JSON_BYTES",2),self.assertRaises(check.InputError):check.json_claim(b'[] ')
        with patch.object(check,"MAX_VALUES",2),self.assertRaises(check.InputError):check.json_claim(b'[0,1]')

    def test_float_nonfinite_and_excessive_integer_encodings_refuse(self):
        for raw in (b'1.0',b'1e0',b'NaN',b'Infinity',b'-Infinity',b'1'*21):
            with self.assertRaises(check.InputError):check.json_claim(raw)

    def test_nonexact_bytes_and_foreign_objects_run_no_hooks(self):
        class Foreign:
            def __str__(self):raise AssertionError("foreign hook")
        class Bytes(bytes):pass
        for raw in (Foreign(),Bytes(b'{}'),bytearray(b'{}'),None):
            with self.assertRaises(check.InputError):check.json_claim(raw)


class SourceCopyTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.parent=Path(self.temporary.name);self.root=self.parent/"project";self.root.mkdir()
        self.destination=self.parent/"new-workspace";self.destination.mkdir(mode=0o700)
        self.bodies={"qualification/Cargo.toml":b"# Synthetic manifest.\n",
                     "qualification/examples/verify_original_read_response.rs":b"// Synthetic source.\n"}
        self.rows=[dict(path=n) for n in self.bodies]
        for n,b in self.bodies.items():
            path=self.root/n;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b)
        self.index=dict(self.bodies)
        for target,new in (("selected_source",lambda *a:None),("_inventory",lambda *a:("1"*40,self.rows,self.bodies)),
                           ("_index",lambda root,name:self.index[name])):
            obj=check.inputs if target=="selected_source" else check.inputs.source
            patcher=patch.object(obj,target,new);patcher.start();self.addCleanup(patcher.stop)

    def test_real_owned_copy_preserves_original_bytes_and_has_exact_inventory(self):
        original={n:(self.root/n).read_bytes() for n in self.bodies}
        with patch("subprocess.Popen",side_effect=AssertionError("native tool not authorized")):
            self.assertEqual(preparation.prepare(self.root,self.destination,"1"*40,"2"*64),2)
        self.assertEqual(original,{n:(self.root/n).read_bytes() for n in self.bodies})
        self.assertEqual(original,{n:(self.destination/n).read_bytes() for n in self.bodies})

    def test_nonempty_nonprivate_and_symlink_destinations_refuse(self):
        marker=self.destination/"existing";marker.write_bytes(b"synthetic")
        with self.assertRaises(check.InputError):preparation.prepare(self.root,self.destination,"1"*40,"2"*64)
        self.assertEqual(marker.read_bytes(),b"synthetic");marker.unlink()
        self.destination.chmod(0o755)
        with self.assertRaises(check.InputError):preparation.prepare(self.root,self.destination,"1"*40,"2"*64)
        self.destination.chmod(0o700)
        link=self.parent/"link";link.symlink_to(self.destination,target_is_directory=True)
        with self.assertRaises(check.InputError):preparation.prepare(self.root,link,"1"*40,"2"*64)

    def test_index_or_working_source_changes_refuse_before_destination_write(self):
        self.index["qualification/Cargo.toml"]=b"changed"
        with self.assertRaises(check.InputError):preparation.prepare(self.root,self.destination,"1"*40,"2"*64)
        self.assertEqual(list(self.destination.iterdir()),[])
        self.index=dict(self.bodies);(self.root/"qualification/Cargo.toml").write_bytes(b"changed")
        with self.assertRaises(check.InputError):preparation.prepare(self.root,self.destination,"1"*40,"2"*64)
        self.assertEqual(list(self.destination.iterdir()),[])

    def test_prepared_source_omission_change_extra_and_link_refuse(self):
        preparation.prepare(self.root,self.destination,"1"*40,"2"*64)
        path=self.destination/"qualification/Cargo.toml";original=path.read_bytes()
        for mode in ("missing","changed","link"):
            path.unlink()
            if mode == "changed":path.write_bytes(b"changed")
            elif mode == "link":path.symlink_to(self.root/"qualification/Cargo.toml")
            with self.assertRaises(check.InputError):check.selected_copy(self.root,"1"*40,self.destination)
            if path.exists() or path.is_symlink():path.unlink()
            path.write_bytes(original)
        extra=self.destination/"qualification/extra.rs";extra.write_bytes(b"synthetic")
        with self.assertRaises(check.InputError):check.selected_copy(self.root,"1"*40,self.destination)


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.fixture=Fixture(Path(self.temporary.name));f=self.fixture
        self.calls=[]
        def source(*a):self.calls.append("source");return "6"*40,[],{"qualification/Cargo.lock":b"synthetic"}
        def contents(*a):self.calls.append("contents");return {"registry":[{}]*5,"git":[{}]*2}
        def copy(*a):self.calls.append("copy");return 2
        patches=[patch.object(check.inputs,"selected_source",source),patch.object(check.inputs,"cargo_records",return_value=f.packages),
                 patch.object(check.content,"inspect_cargo",contents),patch.object(check,"selected_copy",copy),
                 patch.object(check.caches,"select_checkouts",return_value=f.checkouts),
                 patch.object(check.inputs.source,"_index",side_effect=lambda root,name:(root/name).read_bytes())]
        for p in patches:p.start();self.addCleanup(p.stop)

    def inspect(self):
        f=self.fixture
        return check.inspect(f.root,f.commit,f.manifest,f.workspace,f.metadata_file,f.home,f.platform,f.digest)

    def test_matching_synthetic_claim_has_explicit_unverified_boundaries_and_no_native_launch(self):
        with patch("subprocess.Popen",side_effect=AssertionError("native query not authorized")):
            report=self.inspect()
        self.assertEqual(self.calls,["source","contents","copy"])
        self.assertEqual(report["resolution"],self.fixture.baseline)
        for k,v in (("generator_origin","NOT AUTHENTICATED"),("compiled_closure","NOT DETERMINED"),
                    ("source_to_worker","NOT VERIFIED"),("independent_assessment","NOT ASSESSED"),("application_and_core","NO-GO")):
            self.assertEqual(report[k],v)
        self.assertNotIn(str(self.fixture.workspace),check.encoded(report).decode())

    def test_source_content_and_copy_refusals_precede_positive_report(self):
        for obj,name in ((check.inputs,"selected_source"),(check.content,"inspect_cargo"),(check,"selected_copy")):
            with patch.object(obj,name,side_effect=check.InputError("synthetic unavailable selection")),self.assertRaises(check.InputError):self.inspect()

    def test_report_omission_can_be_structurally_valid_but_selected_baseline_refuses(self):
        f=self.fixture
        f.value["packages"]=[p for p in f.value["packages"] if p["name"] != "helper"]
        f.value["resolve"]["nodes"]=[n for n in f.value["resolve"]["nodes"] if n["id"] != f.ids["helper"]]
        node=f.node("bitcoin");node["dependencies"]=[];node["deps"]=[]
        self.assertEqual(f.normalize()["package_count"],6)
        f.save()
        with self.assertRaises(check.InputError):self.inspect()

    def test_paired_report_and_baseline_changes_cannot_replace_selected_hash(self):
        f=self.fixture;f.node("bitcoin")["features"]=["alternate"];f.save()
        baseline=json.loads(f.baseline_file.read_bytes())
        baseline["profiles"][f.platform]=f.normalize();f.baseline_file.write_bytes(check.encoded(baseline))
        with self.assertRaises(check.InputError):self.inspect()

    def test_baseline_index_source_disposition_schema_and_profile_fields_refuse(self):
        f=self.fixture;original=f.baseline_file.read_bytes()
        with patch.object(check.inputs.source,"_index",return_value=b"changed"),self.assertRaises(check.InputError):self.inspect()
        for field,new in (("source_commit","0"*40),("manifest_sha256","0"*64),("selection","INDEPENDENTLY APPROVED"),
                          ("schema","other"),("profiles",{})):
            value=json.loads(original);value[field]=new;raw=check.encoded(value)
            f.baseline_file.write_bytes(raw);f.digest=hashlib.sha256(raw).hexdigest()
            with self.assertRaises(check.InputError):self.inspect()
        f.baseline_file.write_bytes(original);f.digest=hashlib.sha256(original).hexdigest()

    def test_unselected_platform_and_bad_hash_refuse_before_cache_inspection(self):
        f=self.fixture
        for platform,digest in (("unselected",f.digest),(f.platform,"invalid")):
            with self.assertRaises(check.InputError):check.inspect(f.root,f.commit,f.manifest,f.workspace,f.metadata_file,f.home,platform,digest)
        self.assertEqual(self.calls,[])

    def test_declared_feature_and_target_file_changes_cannot_match_baseline(self):
        f=self.fixture;f.package("bitcoin")["features"]["alternate"]=["dep:synthetic"];f.save()
        with self.assertRaises(check.InputError):self.inspect()
        f.package("bitcoin")["features"]["alternate"]=[];f.save()
        Path(f.package("bitcoin")["targets"][0]["src_path"]).write_bytes(b"// Changed synthetic source.\n")
        with self.assertRaises(check.InputError):self.inspect()

    def test_checked_in_baseline_is_canonical_bound_and_explicitly_unassessed(self):
        root=Path(__file__).resolve().parents[1]
        raw=(root/check.BASELINE).read_bytes();baseline=check.inputs.source._json(raw)
        self.assertEqual(hashlib.sha256(raw).hexdigest(),qualification.BASELINE_SHA256)
        self.assertEqual(raw,check.encoded(baseline))
        self.assertEqual(baseline["source_commit"],qualification.COMMIT)
        self.assertEqual(baseline["manifest_sha256"],qualification.MANIFEST_SHA256)
        self.assertEqual(baseline["selection"],"PROJECT SELECTED CARGO 1.90.0 OBSERVATIONS; NOT INDEPENDENT ATTESTATION")
        self.assertEqual(set(baseline["profiles"]),set(check.PLATFORMS))
        for platform,profile in baseline["profiles"].items():
            self.assertEqual((profile["package_count"],profile["node_count"],profile["target_count"]),(70,70,333))
            self.assertEqual(profile["edge_count"],110 if platform==check.PLATFORMS[0] else 109)
            self.assertEqual(len(profile["not_reported_lock_packages"]),5)
            self.assertEqual(set(profile["packages"]),set(profile["nodes"]))
            for package in profile["packages"].values():
                self.assertNotIn("authors",package)
                self.assertNotIn("manifest_path",package)
                self.assertNotIn("declared_features",package)

    def test_cli_and_companion_failures_emit_sanitized_stderr_and_no_positive_output(self):
        root=Path(__file__).resolve().parents[1]
        commands=[("check_cargo_resolution.py",["--expect-commit","0"*40,"--expect-manifest-sha256","0"*64,"--expect-baseline-sha256","0"*64,
                                             "--workspace",str(self.fixture.workspace),"--metadata",str(self.fixture.metadata_file),
                                             "--cargo-home",str(self.fixture.home),"--platform",self.fixture.platform]),
                  ("qualify_cargo_resolution.py",["--workspace",str(self.fixture.workspace),"--metadata",str(self.fixture.metadata_file),
                                                "--cargo-home",str(self.fixture.home),"--platform",self.fixture.platform]),
                  ("prepare_cargo_resolution.py",["--output",str(self.fixture.workspace)])]
        for name,args in commands:
            result=subprocess.run([sys.executable,"-B",str(root/"scripts"/name),"--root",str(self.fixture.root),*args],
                                  capture_output=True,timeout=10)
            self.assertEqual(result.returncode,1);self.assertEqual(result.stdout,b"")
            self.assertTrue(result.stderr.startswith(b"FAIL: "));self.assertLess(len(result.stderr),100)
            self.assertNotIn(str(self.fixture.root).encode(),result.stderr)


if __name__ == "__main__":
    unittest.main()

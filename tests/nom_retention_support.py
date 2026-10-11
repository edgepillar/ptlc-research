"""Public synthetic inputs shared by offline retention tests and death actors."""

import copy
import json
from pathlib import Path

from offline_session.nom_recovery import synthetic_claim
from offline_session.nom_retention import NomEvidenceRetention

ROOT = Path(__file__).resolve().parents[1]
TERMS = json.loads((ROOT / "compatibility/fixtures/nom_terms_v1.json").read_text("ascii"))
COMPLETIONS = json.loads((ROOT / "compatibility/fixtures/nom_completions_v1.json").read_text("ascii"))
MOMENTA = json.loads((ROOT / "compatibility/fixtures/nom_momentum_v1.json").read_text("ascii"))


def selection():
    return {"selected_anchor_claim": copy.deepcopy(MOMENTA["baseline"]["anchor"]),
            "retained_inclusions": copy.deepcopy(MOMENTA["required_inclusions"])}


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def original(leg):
    return synthetic_claim(TERMS, leg, COMPLETIONS[leg + "_signature_hex"])


def open_store(path, *, cls=NomEvidenceRetention):
    return cls.open(path, TERMS, **selection())

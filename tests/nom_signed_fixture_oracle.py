"""Named positive fixture oracle for journal faults; never native cryptographic evidence."""
from offline_session import nom_recovery as base

class FixturePublicMath:
    """A named fixture oracle, not mathematical or independent security evidence."""
    def __init__(self, terms, completions):
        self.completions = base.decode(base.canonical(completions))
        self.context_digest_hex = base.verification_context_digest(terms, completions['pair'])
        self.recovery_entries = 0
        self.recovery_hook = None
        self.recovery_result = None

    def verify_pair(self):
        return True

    def verify_claim(self, leg, signature):
        return signature == self.completions[leg+'_signature_hex']

    def recover_long(self, signature):
        if signature != self.completions['short_signature_hex']:
            raise base.RecoveryError('fixture short witness refused')
        self.recovery_entries += 1
        if self.recovery_hook is not None: self.recovery_hook()
        return self.recovery_result or self.completions['long_signature_hex']

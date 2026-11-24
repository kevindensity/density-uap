"""Writes campaigns, affordances, settlements, projections, envelopes and ladder moves through the database guards."""
import json, uuid, hashlib
def sj(o): return hashlib.sha256(json.dumps(o, sort_keys=True, default=str).encode()).hexdigest()

class Store:
    def __init__(self, conn): self.c = conn; self.c.autocommit = True; self.cur = conn.cursor()
    def q(self, sql, args=()): self.cur.execute(sql, args); return self.cur.fetchone() if self.cur.description else None
    def system(self, name): return self.q("insert into core.systems(name) values (%s) returning id", (name,))[0]
    def epoch(self, sysid, no, roots): return self.q("insert into uap.port_epochs(system_id,epoch_no,roots_hash) values (%s,%s,%s) returning id", (sysid, no, roots))[0]
    def campaign(self, sysid, cls, lvl):
        rid = f"{cls}-{uuid.uuid4().hex}"
        return self.q("insert into uap.discovery_campaigns(system_id,carrier_class,descent_level,run_id) values (%s,%s,%s,%s) returning id", (sysid, cls, lvl, rid))[0], rid
    def stage(self, camp, stage, nxt=None):
        self.q("insert into uap.stage_starts(campaign_id,stage) values (%s,%s)", (camp, stage))
        if nxt: self.q("insert into uap.stage_receipts(campaign_id,completed_stage,next_stage) values (%s,%s,%s)", (camp, stage, nxt))
    def affordances(self, camp, synth):
        for i in synth["inputs"]: self.q("insert into uap.affordances(campaign_id,surface,role) values (%s,%s,'INPUT')", (camp, i))
        for o in synth["outputs"]:
            flags = (["NONDETERMINISTIC"] if o in synth["nondeterministic"] else []) + (["SILENT_IN_PASSIVE"] if o in synth["silent_in_passive"] else []) + \
                    (["ECHO"] if any(e.startswith(o + "<-") for e in synth["echo_like"]) else [])
            self.q("insert into uap.affordances(campaign_id,surface,role,observed_kind,flags) values (%s,%s,'OUTPUT','OBSERVATION',%s)", (camp, o, flags))
    def bank(self, cls, kind, nulls, stat="pair_sensitivity"):
        rid = self.q("insert into uap.negative_references(carrier_class,kind,descriptor) values (%s,%s,'{}') returning id", (cls, kind))[0]
        for s in nulls: self.q("insert into uap.negative_scores values (%s,%s,%s)", (rid, stat, s))
    def lock_threshold(self, cls, eps, stat="pair_sensitivity"):
        self.q("insert into uap.threshold_frontiers(carrier_class,statistic_id,epsilon) values (%s,%s,%s) on conflict do nothing", (cls, stat, eps))
    def conformal_p(self, cls, score, stat="pair_sensitivity"): return float(self.q("select uap.conformal_p(%s,%s,%s)", (cls, stat, score))[0])
    def settle(self, epoch, receipt, live, ok_sig):
        rid = self.q("""insert into verify.refinement_receipts(port_epoch_id,consequence_key,live_class_hash,constant_value,
                verifier_key_id,synthesizer_key_id,signature_verified) values (%s,%s,%s,'true','ver-uap','syn-uap',%s) returning id""",
                (epoch, receipt["consequence"], live, ok_sig))[0]
        return self.q("""insert into sem.settlements(port_epoch_id,consequence_key,status,live_class_hash,refinement_id)
                values (%s,%s,'SETTLED_TRUE',%s,%s) returning id""", (epoch, receipt["consequence"], live, rid))[0]
    def projection(self, epoch, settlement, consequence, echo):
        env = self.q("insert into uap.use_envelopes(representation,qualified_uses,excluded_uses) values (%s,%s,%s) returning id",
                     (consequence, ["MONITOR", "EXPLAIN", "REVERSIBLE_REROUTE"], ["DELETE", "IRREVERSIBLE_WRITE", "FINANCIAL_POSTING"]))[0]
        o, i = consequence[4:].split("<-")
        return self.q("""insert into uap.projection_standings(port_epoch_id,projection_kind,spec,forbidden_inferences,settlement_id,use_envelope_id)
                values (%s,'DEPENDENCY',%s,%s,%s,%s) returning id""",
                (epoch, json.dumps({"output": o, "input": i, "echo": echo}),
                 json.dumps(["functional form", "magnitude", "absence of other dependencies", "total ontology"]), settlement, env))[0]
    def effect_port(self, sysid, epoch):
        return self.q("insert into uap.ports(system_id,port_type,current_epoch) values (%s,'EFFECT',%s) on conflict (system_id,port_type) do update set current_epoch=excluded.current_epoch, ladder_level='CONNECTED' returning id", (sysid, epoch))[0]
    def settle_key(self, epoch, key, live, ok_sig):
        return self.settle(epoch, {"consequence": key}, live, ok_sig)
    def projection_of(self, epoch, settlement, kind, spec, forbidden, qualified, excluded):
        env = self.q("insert into uap.use_envelopes(representation,qualified_uses,excluded_uses) values (%s,%s,%s) returning id",
                     (json.dumps(spec, default=str)[:200], qualified, excluded))[0]
        return self.q("""insert into uap.projection_standings(port_epoch_id,projection_kind,spec,forbidden_inferences,settlement_id,use_envelope_id)
                values (%s,%s,%s,%s,%s,%s) returning id""", (epoch, kind, json.dumps(spec, default=str), json.dumps(forbidden), settlement, env))[0]
    def port(self, sysid, epoch):
        return self.q("insert into uap.ports(system_id,port_type,current_epoch) values (%s,'OBSERVATION',%s) on conflict (system_id,port_type) do update set current_epoch=excluded.current_epoch, ladder_level='CONNECTED' returning id", (sysid, epoch))[0]
    def ladder(self, port, level): self.q("update uap.ports set ladder_level=%s where id=%s", (level, port))

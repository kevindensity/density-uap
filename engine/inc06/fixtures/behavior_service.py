"""A legacy acceptance service whose only observable outputs are behaviour: it returns ACCEPTED or REJECTED and
takes time. Processing time depends on the batch size and the priority lane; acceptance on the order value."""
import random, time
_r = random.Random()
def call(q, mode="real"):
    if mode == "constant": time.sleep(0.003 + _r.uniform(0, 0.0004)); return True
    if mode == "constant_b": time.sleep(0.007 + _r.uniform(0, 0.0004)); return False
    if mode == "constant_c": time.sleep(0.010 + _r.uniform(0, 0.0004)); return True
    ms = 3.0 + (6.0 if q["qty"] > 50 else 0.0) + (2.0 if q["priority"] == "LOW" else 0.0) + _r.uniform(0, 0.4)
    time.sleep(ms / 1000.0); return q["qty"] * q["unit_price"] <= 20000

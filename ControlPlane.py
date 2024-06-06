reg_ecn_marking_threshold = bfrt.multi_switch_SL.pipe.Egress.reg_ecn_marking_threshold # cells
reg_ecn_marking_cntr = bfrt.multi_switch_SL.pipe.Egress.reg_ecn_marking_cntr # cells
def dump_registers():
    global reg_ecn_marking_threshold
    global reg_ecn_marking_cntr
    #ingress_reg_ecn_marking_cntr = bfrt.multi_switch_SL.pipe.Ingress.reg_ecn_marking_cntr # cells
    val_reg_ecn_marking_threshold = reg_ecn_marking_threshold.get(from_hw=True, print_ents=False).data[b'Egress.reg_ecn_marking_threshold.f1'][0]
    val_reg_ecn_marking_cntr = reg_ecn_marking_cntr.get(from_hw=True, print_ents=False).data[b'Egress.reg_ecn_marking_cntr.f1'][0]
    #val_ingress_reg_ecn_marking_cntr = ingress_reg_ecn_marking_cntr.get(from_hw=True, print_ents=False).data[b'Ingress.reg_ecn_marking_cntr.f1'][1]
    print( json.loads(reg_ecn_marking_cntr.dump(from_hw=True,json=True)))
    print(json.loads(reg_ecn_marking_threshold.dump(from_hw=True,json=True)))
    #val_ecn_marking_cntr = json_reg_ecn_marking_cntr['data']['Egress.reg_ecn_marking_cntr.f1'][1]
    #val_ecn_marking_threshold = json_reg_ecn_marking_threshold['data']['Egress.reg_ecn_marking_threshold.f1'][1]
    print("\tECN-threshold: {}".format(val_reg_ecn_marking_threshold))
    print("\tECN-Marked packet number: {}".format(val_reg_ecn_marking_cntr))

def mod_register():
    global reg_ecn_marking_threshold
    global reg_ecn_marking_cntr
    reg_ecn_marking_threshold.mod(register_index=0,f1=2048)

dump_registers()
mod_register()
dump_registers()
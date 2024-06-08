import math
Egress_ctx = bfrt.multi_switch_SL.pipe.Egress
def dump_registers(): 
    global Egress_ctx
    reg_ecn_marking_threshold = Egress_ctx.reg_ecn_marking_threshold
    reg_ecn_marking_cntr = Egress_ctx.reg_ecn_marking_cntr
    #ingress_reg_ecn_marking_cntr = bfrt.multi_switch_SL.pipe.Ingress.reg_ecn_marking_cntr # cells
    #val_reg_ecn_marking_threshold = reg_ecn_marking_threshold.get(from_hw=True, print_ents=False).data[b'Egress.reg_ecn_marking_threshold.f1'][0]
    #val_reg_ecn_marking_cntr = reg_ecn_marking_cntr.get(from_hw=True, print_ents=False).data[b'Egress.reg_ecn_marking_cntr.f1'][0]
    #val_ingress_reg_ecn_marking_cntr = ingress_reg_ecn_marking_cntr.get(from_hw=True, print_ents=False).data[b'Ingress.reg_ecn_marking_cntr.f1'][1]
    print(json.loads(reg_ecn_marking_cntr.dump(from_hw=True,json=True)))
    print(json.loads(reg_ecn_marking_threshold.dump(from_hw=True,json=True)))
    print(json.loads(Egress_ctx.reg_cc_mode.dump(from_hw=True,json=True)))
    print(json.loads(Egress_ctx.reg_dcqcn_probout_cntr.dump(from_hw=True,json=True)))
    #print(json.loads(Egress_ctx.reg_dcqcn_compare_cntr.dump(from_hw=True,json=True)))
    #print(json.loads(Egress_ctx.reg_dcqcn_ce_mark_cntr.dump(from_hw=True,json=True)))
    print(json.loads(Egress_ctx.reg_dcqcn_random_vl.dump(from_hw=True,json=True)))
    print(json.loads(Egress_ctx.reg_dcqcn_qdepth_vl.dump(from_hw=True,json=True)))
    #val_ecn_marking_cntr = json_reg_ecn_marking_cntr['data']['Egress.reg_ecn_marking_cntr.f1'][1]
    #val_ecn_marking_threshold = json_reg_ecn_marking_threshold['data']['Egress.reg_ecn_marking_threshold.f1'][1]
def clear_cnt_register():
    global Egress_ctx
    Egress_ctx.reg_ecn_marking_cntr.mod(register_index=0, f1=0)
    Egress_ctx.reg_dcqcn_probout_cntr.mod(register_index=0, f1=0)
    #Egress_ctx.reg_dcqcn_compare_cntr.mod(register_index=0, f1=0)
    #Egress_ctx.reg_dcqcn_ce_mark_cntr.mod(register_index=0, f1=0)


def dump_table():
    global Egress_ctx
    tab_dcqcn_get_ecn_probability = Egress_ctx.dcqcn_get_ecn_probability
    print(json.loads(tab_dcqcn_get_ecn_probability.dump(from_hw=True,json=True)))

def set_cc_mod(cc_mod:int):
    global Egress_ctx
    reg_cc_mode = Egress_ctx.reg_cc_mode
    reg_cc_mode.mod(register_index=0, f1=cc_mod)

def set_ecn_threshold(threshold:int):
    global Egress_ctx
    reg_ecn_marking_threshold = Egress_ctx.reg_ecn_marking_threshold # cells
    reg_ecn_marking_threshold.mod(register_index=0, f1=threshold)

def config_DCTCP(threshold:int):
    # Setup ECN marking for DCTCP
    global set_cc_mod
    global set_ecn_threshold
    set_cc_mod(5)
    set_ecn_threshold(threshold)
    
def config_DCQCN(Kmin:int, Kmax: int, Pmax: float):
    global math
    global set_cc_mod
    global set_ecn_threshold
    
    # reg_ecn_marking_threshold.mod(REGISTER_INDEX=0, f1=375) # 375 x 80 = 30KB (20 pkts) | 1 Gbps
    set_ecn_threshold(Kmin) # 1250 x 80 = 100KB (65 pkts) | 10 Gbps
    # Set up ECN mode in DCQCN
    set_cc_mod(9)
    # Setup RED-based ECN marking for DCQCN
    DCQCN_K_MIN = Kmin # 100KB
    DCQCN_K_MAX = Kmax # 240KB  # 400KB - 5000
    DCQCN_P_MAX = Pmax # 20%
    QDEPTH_RANGE_MAX = 2**19
    SEED_RANGE_MAX = 256 # random number range ~ [0, 255] (8bits)
    SEED_K_MAX = math.ceil(DCQCN_P_MAX * SEED_RANGE_MAX) # 52
    QDEPTH_STEPSIZE = math.floor((DCQCN_K_MAX - DCQCN_K_MIN) / SEED_K_MAX) # 72

    last_range = DCQCN_K_MIN
    #####################
    # PROBABILITY TABLE #
    #####################
    dcqcn_get_ecn_probability = Egress_ctx.dcqcn_get_ecn_probability
    # clear the probability table
    dcqcn_get_ecn_probability.clear()
    # < K_MIN
    print("DCQCN Table -- Adding qdepth:[{}, {}] -> probability:{:.2f}% ({}/{})".format(0, DCQCN_K_MIN - 1, float(0/SEED_RANGE_MAX)*100, 0, SEED_RANGE_MAX))
    dcqcn_get_ecn_probability.add_with_dcqcn_mark_probability(deq_qdepth_start=0, deq_qdepth_end=DCQCN_K_MIN - 1, value=0)
    # K_MIN < qDepth < K_MAX
    for i in range(1, SEED_K_MAX):
        print("DCQCN Table -- Adding qdepth:[{}, {}] -> probability:{:.2f}% ({}/{})".format(last_range, last_range + QDEPTH_STEPSIZE - 1, float(i/SEED_RANGE_MAX)*100, i, SEED_RANGE_MAX))
        dcqcn_get_ecn_probability.add_with_dcqcn_mark_probability(deq_qdepth_start=last_range, deq_qdepth_end=last_range + QDEPTH_STEPSIZE - 1, value=i)
        last_range += QDEPTH_STEPSIZE
    # > K_MAX
    print("DCQCN Table -- Adding qdepth:[{}, {}] -> probability:{:.2f}%".format(last_range, QDEPTH_RANGE_MAX - 1, float(SEED_RANGE_MAX/SEED_RANGE_MAX)*100))
    dcqcn_get_ecn_probability.add_with_dcqcn_mark_probability(deq_qdepth_start=last_range, deq_qdepth_end=QDEPTH_RANGE_MAX - 1, value=SEED_RANGE_MAX - 1)

    ####################
    # COMPARISON TABLE #
    ####################
    dcqcn_compare_probability = Egress_ctx.dcqcn_compare_probability
    #clear the compare table
    dcqcn_compare_probability.clear()
    # Less than 100%
    for prob_output in range(1, SEED_K_MAX): 
        for random_number in range(SEED_RANGE_MAX): # 0 ~ 255
            if random_number < prob_output:
                print("Comparison Table -- ECN Marking for Random Number {}, Output Value {}".format(random_number, prob_output))
                Egress_ctx.dcqcn_compare_probability.add_with_dcqcn_check_ecn_marking(dcqcn_prob_output=prob_output, dcqcn_random_number=random_number)
    # 100% ECN Marking
    for random_number in range(SEED_RANGE_MAX):
        prob_output = SEED_RANGE_MAX - 1
        print("Comparison Table -- ECN Marking for Random Number {} < Output Value {}".format(random_number, prob_output))
        Egress_ctx.dcqcn_compare_probability.add_with_dcqcn_check_ecn_marking(dcqcn_prob_output=prob_output, dcqcn_random_number=random_number)

def setup_DCQCN():
    global config_DCQCN
    config_DCQCN(1250,3000,0.2)

def setup_DCTCP():
    global config_DCTCP
    config_DCTCP(1250)
#dump_registers()
#setup_ECN()
#mod_register()

#dump_registers()
#dump_table()
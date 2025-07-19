import idautils
import idc
import ida_bytes
import ida_funcs
import ida_ua

DATA_DEFS = {"DCD", "DCQ", "DCB", "DCW", "ALIGN", "SPACE", "FILL", "ASCII", "ASCIZ", "BYTE", "WORD", "DWORD", "QWORD", "DATA", ""}

import ida_ua
import ida_idp
import ida_allins
import ida_funcs
import ida_name

def find_stack_check_fail_pattern(start_ea, end_ea):
    """
    在指定地址范围内查找特定的指令模式：
    BL __stack_chk_fail
    后跟
    SUB SP, SP, #<imm>
    
    :param start_ea: 起始地址
    :param end_ea: 结束地址
    :return: 匹配地址列表 [(bl_ea, sub_ea)]
    """
    matches = []
    current_ea = start_ea
    
    # 遍历指定地址范围
    while current_ea < end_ea:
        # 解码当前指令
        insn = ida_ua.insn_t()
        insn_len = ida_ua.decode_insn(insn, current_ea)
        
        # 如果解码失败，跳到下一个地址
        if insn_len <= 0:
            current_ea = ida_bytes.next_head(current_ea, end_ea)
            continue
        
        # 检查是否是BL指令
        if insn.itype == ida_allins.ARM_bl:
            # print("found bl")
            # 获取目标地址
            target_ea = insn.Op1.addr
            
            # 获取目标函数名
            func_name = ida_name.get_name(target_ea)
            
            # 检查是否是stack_chk_fail函数
            if func_name and "__stack_chk_fail" in func_name:
                # print("found __stack_chk_fail", current_ea)

                bl_addr = current_ea
                while True:

                    # 获取下一条指令地址
                    next_ea = current_ea + insn_len
                    
                    # 解码下一条指令
                    next_insn = ida_ua.insn_t()
                    next_len = ida_ua.decode_insn(next_insn, next_ea)

                    if idc.print_insn_mnem(next_ea) != "SUB" and idc.print_insn_mnem(next_ea) != "STP" and idc.print_insn_mnem(next_ea) != "PACIASP": # 继续添加, 加强判断函数开始
                        print(f"error:{idc.print_insn_mnem(next_ea), hex(next_ea)}")
                        flags = idaapi.get_flags(next_ea)
                        if not idaapi.is_code(flags):
                            current_ea = next_ea
                            continue
                        else:
                            return None, None
                    print(f"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:{hex(next_ea)}")
                    # print(idc.print_insn_mnem(next_ea))
                    reg_dst = ida_idp.get_reg_name(next_insn.Op1.reg, 1)
                    # print(reg_dst)
                    reg_dst = ida_idp.get_reg_name(next_insn.Op2.reg, 2)
                    # print(reg_dst)
                    return (bl_addr + 4, next_ea)
                
                # if next_len > 0:
                #     # 检查是否是SUB指令
                #     if next_insn.itype == ida_allins.ARM_sub:
                #         # 检查目标寄存器是否为SP
                #         reg_dst = ida_idp.get_reg_name(next_insn.Op1.reg, 1)
                #         if reg_dst == "SP":
                #             # 检查源寄存器是否为SP
                #             reg_src = ida_idp.get_reg_name(next_insn.Op2.reg, 2)
                #             if reg_src == "SP":
                #                 # 检查操作数类型为立即数
                #                 if next_insn.Op3.type == ida_ua.o_imm:
                #                     # 记录匹配对
                #                     matches.append((current_ea, next_ea))
                #                     print(f"Found pattern at {hex(current_ea)} -> {hex(next_ea)}")
        
        # 移动到下一条指令
        current_ea += insn_len
    
    return None, None

def patch_nop(ea):
    # 先删除任何数据/指令定义
    ida_bytes.del_items(ea, 4, ida_bytes.DELIT_SIMPLE)
    # 写入NOP
    ida_bytes.patch_dword(ea, 0xD503201F)
    # 强制反汇编为指令
    ida_ua.create_insn(ea)
    idc.set_cmt(ea, "Patched with NOP (AutoRepairJump)", 0)

def is_normal_insn(ea):
    mnem = idc.print_insn_mnem(ea)
    return mnem.upper() not in DATA_DEFS

patched_count = 0
func_addrs = list(idautils.Functions())
total_funcs = len(func_addrs)

for idx, func_ea in enumerate(func_addrs):
    func_name = idc.get_func_name(func_ea)
    end_ea = idc.find_func_end(func_ea)
    ea = func_ea
    found_in_func = False
    while ea < end_ea:
        mnem = idc.print_insn_mnem(ea)
        if mnem == "BR":
            op = idc.print_operand(ea, 0).strip().upper()
            if op.startswith("X") and op != "X30":
                # 检查前5条指令
                prev_ea = ea
                for _ in range(5):
                    prev_ea = idc.prev_head(prev_ea, func_ea)
                    if prev_ea == idc.BADADDR or prev_ea < func_ea:
                        break
                    prev_mnem = idc.print_insn_mnem(prev_ea)
                    if prev_mnem == "ADD":
                        dst = idc.print_operand(prev_ea, 0).strip().upper()
                        src = idc.print_operand(prev_ea, 1).strip().upper()
                        if dst == op and src == op:
                            # 1. NOP掉BR Xn本身
                            patch_nop(ea)
                            patched_count += 1
                            print(f"[修复] {func_name} @ {hex(ea)} -> BR {op} 已被NOP")
                            # 2. 顺序NOP掉BR Xn后面的所有数据定义，直到遇到第一个正常指令或函数结尾
                            next_ea = ea + 4
                            # while next_ea < end_ea:
                            #     if is_normal_insn(next_ea):
                            #         break
                            #     patch_nop(next_ea)
                            #     patched_count += 1
                            #     print(f"[修复] {func_name} @ {hex(next_ea)} -> 数据定义已被NOP")
                            #     next_ea += 4

                            for ea in range(next_ea, next_ea + 100, 4):
                                # 确保地址对齐
                                if ea % 4 != 0:
                                    print(f"Warning: Address {hex(ea)} is not 4-byte aligned")
                                import idaapi
                                flags = idaapi.get_flags(ea)
                                if idaapi.is_code(flags):   #关键点
                                    break

                                # 写入NOP指令
                                NOP = 0xD503201F
                                ida_bytes.patch_dword(ea, NOP)
                                
                                # 强制创建指令
                                ida_ua.create_insn(ea)

                            # 3. 检查并修复BL __stack_chk_fail，并调整函数结尾
                            search_ea = ea
                            is_except_func = False
                            
                            bl_addr, next_ea = find_stack_check_fail_pattern(search_ea, end_ea + 10000)
                            if bl_addr != None:
                                ida_funcs.set_func_end(func_ea, bl_addr)
                                print("found bl:", hex(bl_addr))
                            found_in_func = True
                            break
                if found_in_func:
                    break  # 一个函数只修一次
        ea = idc.next_head(ea, end_ea)
    if (idx+1) % 100 == 0 or idx == total_funcs-1:
        print(f"已检测 {idx+1}/{total_funcs} 个函数...")

print(f"共修复 {patched_count} 处可疑BR跳转及其后垃圾数据，并自动调整函数结尾（如有必要）。")
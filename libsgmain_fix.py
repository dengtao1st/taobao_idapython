import idautils
import idaapi
import idc
import ida_bytes

# 修复前:
# LOAD:0000000000057B18 E8 16 80 52                                       MOV             W8, #0xB7
# LOAD:0000000000057B1C E8 1B 00 B9                                       STR             W8, [SP,#0x30+var_18]
# LOAD:0000000000057B20 A8 53 00 D1                                       SUB             X8, X29, #-var_14
# LOAD:0000000000057B24 E9 63 00 91                                       ADD             X9, SP, #0x30+var_18
# LOAD:0000000000057B28 34 00 00 10                                       ADR             X20, loc_57B2C
# LOAD:0000000000057B2C
# LOAD:0000000000057B2C                                                 loc_57B2C                               ; DATA XREF: JNI_OnUnload+3C↑o
# LOAD:0000000000057B2C 19 01 00 98                                       LDRSW           X25, =0x112
# LOAD:0000000000057B30 39 3F 02 D1                                       SUB             X25, X25, #0x8F
# LOAD:0000000000057B34 38 01 80 B9                                       LDRSW           X24, [X9]
# LOAD:0000000000057B38 39 03 18 CA                                       EOR             X25, X25, X24
# LOAD:0000000000057B3C 94 02 19 8B                                       ADD             X20, X20, X25
# LOAD:0000000000057B40 1B 0D 80 52                                       MOV             W27, #0x68 ; 'h'
# LOAD:0000000000057B44 1B 01 00 B9                                       STR             W27, [X8]
# LOAD:0000000000057B48 80 02 1F D6                                       BR              X20
# LOAD:0000000000057B48                                                 ; End of function JNI_OnUnload
# LOAD:0000000000057B48
# LOAD:0000000000057B48                                                 ; ---------------------------------------------------------------------------
# LOAD:0000000000057B4C 12 01 00 00                                     dword_57B4C DCD 0x112                   ; DATA XREF: JNI_OnUnload:loc_57B2C↑r
# LOAD:0000000000057B50 11 94 67 8A FD C0 D3 36 E9 EC 3F E2 D5 18 AB 8E   DCQ 0x36D3C0FD8A679411, 0x8EAB18D5E23FECE9
# LOAD:0000000000057B60                                                 ; ---------------------------------------------------------------------------
# LOAD:0000000000057B60 C8 13 00 B0 08 81 03 91                           ADRL            X8, byte_2D00E0
# LOAD:0000000000057B68 08 01 40 39                                       LDRB            W8, [X8]
# LOAD:0000000000057B6C 08 01 00 12                                       AND             W8, W8, #1
# LOAD:0000000000057B70 48 00 00 36                                       TBZ             W8, #0, loc_57B78
# LOAD:0000000000057B74 14 00 00 14                                       B               loc_57BC4
# 修复后:
# LOAD:0000000000057B18 E8 16 80 52                                       MOV             W8, #0xB7
# LOAD:0000000000057B1C E8 1B 00 B9                                       STR             W8, [SP,#0x30+var_18]
# LOAD:0000000000057B20 A8 53 00 D1                                       SUB             X8, X29, #-var_14
# LOAD:0000000000057B24 E9 63 00 91                                       ADD             X9, SP, #0x30+var_18
# LOAD:0000000000057B28 34 00 00 10                                       ADR             X20, loc_57B2C
# LOAD:0000000000057B2C
# LOAD:0000000000057B2C                                                 loc_57B2C                               ; DATA XREF: JNI_OnUnload+3C↑o
# LOAD:0000000000057B2C 19 01 00 98                                       LDRSW           X25, loc_57B4C
# LOAD:0000000000057B30 39 3F 02 D1                                       SUB             X25, X25, #0x8F
# LOAD:0000000000057B34 38 01 80 B9                                       LDRSW           X24, [X9]
# LOAD:0000000000057B38 39 03 18 CA                                       EOR             X25, X25, X24
# LOAD:0000000000057B3C 94 02 19 8B                                       ADD             X20, X20, X25
# LOAD:0000000000057B40 1B 0D 80 52                                       MOV             W27, #0x68 ; 'h'
# LOAD:0000000000057B44 1B 01 00 B9                                       STR             W27, [X8]
# LOAD:0000000000057B48 1F 20 03 D5                                       NOP                                   ; Patched with NOP
# LOAD:0000000000057B48                                                 ; End of function JNI_OnUnload
# LOAD:0000000000057B48
# LOAD:0000000000057B4C                                                 ; ---------------------------------------------------------------------------
# LOAD:0000000000057B4C
# LOAD:0000000000057B4C                                                 loc_57B4C                               ; DATA XREF: JNI_OnUnload:loc_57B2C↑r
# LOAD:0000000000057B4C 1F 20 03 D5                                       NOP                                   ; Patched with NOP
# LOAD:0000000000057B50 1F 20 03 D5                                       NOP                                   ; Patched with NOP
# LOAD:0000000000057B54 1F 20 03 D5                                       NOP
# LOAD:0000000000057B58 1F 20 03 D5                                       NOP
# LOAD:0000000000057B5C 1F 20 03 D5                                       NOP
# LOAD:0000000000057B60 C8 13 00 B0 08 81 03 91                           ADRL            X8, byte_2D00E0
# LOAD:0000000000057B68 08 01 40 39                                       LDRB            W8, [X8]
# LOAD:0000000000057B6C 08 01 00 12                                       AND             W8, W8, #1
# LOAD:0000000000057B70 48 00 00 36                                       TBZ             W8, #0, loc_57B78
# LOAD:0000000000057B74 14 00 00 14                                       B               loc_57BC4

import ida_bytes
import ida_segment
import ida_ua
import ida_idp
import ida_nalt
import ida_allins
import idaapi

def patch_after_br_x20(br_ea, end_ea, check_reg_name):
    """
    在BR X20指令后打补丁，将其后的区域改为NOP并重新分析
    :param br_ea: BR X20指令的地址
    :param end_ea: 补丁结束地址
    :return: 操作是否成功
    """
    # 检查处理器架构
    proc_id = ida_idp.ph_get_id()
    if proc_id != ida_idp.PLFM_ARM and proc_id != ida_idp.PLFM_ARM64:
        print(f"Error: This script requires ARM/ARM64 architecture, current is {ida_nalt.get_abi_name()}")
        return False
    
    # 验证BR指令及其操作数
    insn = ida_ua.insn_t()
    insn_len = ida_ua.decode_insn(insn, br_ea)
    
    if insn_len != 4:
        print(f"Error: Failed to decode instruction at {hex(br_ea)}")
        return False
    
    # 检查指令是否为BR
    if insn.itype != ida_allins.ARM_br:
        print(f"Error: Instruction at {hex(br_ea)} is not BR (type: {insn.get_canon_mnem()})")
        return False
    
    # 检查操作数是否为X20
    if insn.Op1.type != ida_ua.o_reg:
        print(f"Error: BR operand is not a register at {hex(br_ea)}")
        return False
    
    reg_name = ida_idp.get_reg_name(insn.Op1.reg, 1)
    if reg_name != check_reg_name:
        print(f"Error: Expected BR X20 but found BR {reg_name} at {hex(br_ea)}")
        return False
    
    # 检查BR之后的区域是否包含数据定义
    start_ea = br_ea + 4
    if start_ea >= end_ea:
        print(f"Error: End address {hex(end_ea)} must be greater than BR address + 4")
        return False
    
    # 验证是否在代码段
    seg = ida_segment.getseg(br_ea)
    if not seg:
        print(f"Error: Address {hex(br_ea)} is not in any segment")
        return False
    
    if not seg.perm & ida_segment.SEGPERM_EXEC:
        print(f"Warning: Segment at {hex(seg.start_ea)} is not executable")
    
    print(f"Patching from {hex(start_ea)} to {hex(end_ea-1)}")
    
    # 删除现有定义
    ida_bytes.del_items(start_ea, end_ea - start_ea, ida_bytes.DELIT_SIMPLE)
    
    # 定义ARM64 NOP指令
    NOP = 0xD503201F
    ida_bytes.patch_dword(br_ea, NOP)
    
    # 用NOP填充区域
    for ea in range(start_ea, end_ea, 4):
        # 确保地址对齐
        if ea % 4 != 0:
            print(f"Warning: Address {hex(ea)} is not 4-byte aligned")
        
        flags = idaapi.get_flags(ea)
        if idaapi.is_code(flags):
            break

        # 写入NOP指令
        ida_bytes.patch_dword(ea, NOP)
        
        # 强制创建指令
        ida_ua.create_insn(ea)
    
    # 重新分析区域
    # ida_bytes.analyze_area(start_ea, end_ea)
    
    # 刷新显示
    # ida_segment.refresh_prog_view()
    
    print(f"Successfully patched {hex(start_ea)} to {hex(end_ea-1)} with NOPs")
    return True

def patch_range_with_nops(start_ea, end_ea):
    """
    将指定地址范围内的所有指令用NOP指令替换
    NOP机器码: 1F 20 03 D5 (ARM64)
    
    参数:
        start_ea: 起始地址 (包含)
        end_ea: 结束地址 (不包含)
    """
    # 确保地址范围有效
    if start_ea >= end_ea:
        print(f"错误: 无效的地址范围 ({hex(start_ea)} - {hex(end_ea)})")
        return False
    
    # 计算需要NOP的字节数
    nop_count = (end_ea - start_ea) // 4
    
    # NOP指令的机器码 (小端序)
    nop_instruction = 0xD503201F  # 对应字节序列: 1F 20 03 D5
    
    print(f"准备从 {hex(start_ea)} 到 {hex(end_ea)} 写入 {nop_count} 个NOP指令...")
    
    # 循环写入NOP指令
    for i in range(nop_count):
        ea = start_ea + i * 4
        # 写入NOP指令
        ida_bytes.patch_dword(ea, nop_instruction)
        # 设置注释
        idc.set_cmt(ea, "Patched with NOP", 0)
        print(f"在地址 {hex(ea)} 写入NOP指令")
    
    # 刷新IDA的显示
    ida_bytes.analyze_area(start_ea, end_ea)
    
    print(f"成功从 {hex(start_ea)} 到 {hex(end_ea)} 写入了 {nop_count} 个NOP指令")
    return True

def find_pattern_in_range(start_ea, end_ea, pattern):
    """在指定地址范围内搜索指令模式"""
    matches = []
    for ea in range(start_ea, end_ea, 4):
        if idc.print_insn_mnem(ea) == pattern[0] and all(
            idc.print_insn_mnem(ea + i*4) == mnem for i, mnem in enumerate(pattern[1:])
        ):
            matches.append(ea)
    return matches


# LOAD:00000000001108F8 E8 07 80 52                                       MOV             W8, #0x3F ; '?'     标记1
# LOAD:00000000001108FC E8 FF 01 B9                                       STR             W8, [SP,#0x1FC]     标记2
# LOAD:0000000000110900 E8 03 08 91                                       ADD             X8, SP, #0x200
# LOAD:0000000000110904 E9 F3 07 91                                       ADD             X9, SP, #0x1FC      标记3
# LOAD:0000000000110908 39 00 00 10                                       ADR             X25, loc_11090C
# LOAD:000000000011090C
# LOAD:000000000011090C                                                 loc_11090C                              ; DATA XREF: sub_1108CC+3C↑o
# LOAD:000000000011090C 00 01 00 98                                       LDRSW           X0, =0x26           标记4
# LOAD:0000000000110910 00 5C 00 D1                                       SUB             X0, X0, #0x17       标记5
# LOAD:0000000000110914 2C 01 80 B9                                       LDRSW           X12, [X9]           标记6
# LOAD:0000000000110918 00 00 0C CA                                       EOR             X0, X0, X12         标记7 
# LOAD:000000000011091C 39 03 00 8B                                       ADD             X25, X25, X0        标记8
# LOAD:0000000000110920 1B 0E 80 52                                       MOV             W27, #0x70 ; 'p'
# LOAD:0000000000110924 1B 01 00 B9                                       STR             W27, [X8]
# LOAD:0000000000110928 20 03 1F D6                                       BR              X25                 标记9 

def calculate_br_x25_target(start_ea, end_ea):
    """计算BR X25的目标地址"""
    # 1. 查找MOV W8, #imm指令（标记1）
    mov_ea = None
    for ea in range(start_ea, end_ea, 4):
        if idc.print_insn_mnem(ea) == "MOV" and \
           idc.get_operand_type(ea, 0) == idc.o_reg and \
           idc.get_operand_type(ea, 1) == idc.o_imm:
            mov_ea = ea
            break
    
    if not mov_ea:
        print("Error: MOV W8, #imm not found")
        return None
    
    # 获取立即数 (0x3F)
    stored_value = idc.get_operand_value(ea, 1)
    print(f"Found MOV W8, #{hex(stored_value)} at {hex(mov_ea)}")
    
    # 2. 查找STR W8, [SP,#0x1FC]（标记2）
    str_ea = mov_ea + 4
    if not (idc.print_insn_mnem(str_ea) == "STR" and 
            "SP,#0x1FC" in idc.GetDisasm(str_ea)):
        print("Error: STR W8, [SP,#0x1FC] not found")
        return None
    print(f"Found STR at {hex(str_ea)}")
    
    # 3. 查找ADD X9, SP, #0x1FC（标记3）
    add_x9_ea = str_ea + 8  # 跳过中间的ADD X8
    if not (idc.print_insn_mnem(add_x9_ea) == "ADD" and 
            idc.print_insn_mnem(add_x9_ea) == "ADD" and 
            "X9,SP,#0x1FC" in idc.GetDisasm(add_x9_ea).replace(" ", "")):
        print("Error: ADD X9, SP, #0x1FC not found")
        return None
    print(f"Found ADD X9 at {hex(add_x9_ea)}")
    
    # 4. 查找ADR X25（标记8前一条）
    adr_ea = add_x9_ea + 4
    if idc.print_insn_mnem(adr_ea) != "ADR":
        print("Error: ADR X25 not found")
        return None
    
    # 获取ADR加载的基地址
    adr_target = idc.get_operand_value(adr_ea, 1)
    print(f"Found ADR X25, {hex(adr_target)} at {hex(adr_ea)}")
    
    # 5. 查找LDRSW X0, =imm（标记4）
    ldr_ea = adr_ea + 4
    if not (idc.print_insn_mnem(ldr_ea) == "LDRSW" and 
            idc.get_operand_type(ldr_ea, 1) == idc.o_mem):
        print("Error: LDRSW X0, =imm not found")
        return None

    # 读取内存中的值
    mem_addr = idc.get_operand_value(ldr_ea, 1)
    ldr_value = idc.get_wide_dword(mem_addr)  # 读取32位值
    print(f"Found LDRSW X0, [mem:{hex(mem_addr)}] -> value={hex(ldr_value)} at {hex(ldr_ea)}")

    
    # 6. 查找SUB X0, X0, #imm（标记5）并动态获取立即数
    sub_ea = ldr_ea + 4
    if not (idc.print_insn_mnem(sub_ea) == "SUB" and 
            idc.get_operand_type(sub_ea, 0) == idc.o_reg and 
            idc.get_operand_type(sub_ea, 1) == idc.o_reg and 
            idc.get_operand_type(sub_ea, 2) == idc.o_imm):
        print("Error: SUB X0, X0, #imm not found")
        return None
    
    # 动态获取立即数值
    sub_imm = idc.get_operand_value(sub_ea, 2)
    print(f"Found SUB X0, X0, #{hex(sub_imm)} at {hex(sub_ea)}")
    
    # 7. 查找LDRSW X12, [X9]（标记6）
    ldr_x12_ea = sub_ea + 4
    if not (idc.print_insn_mnem(ldr_x12_ea) == "LDRSW" and 
            "[X9]" in idc.GetDisasm(ldr_x12_ea)):
        print("Error: LDRSW X12, [X9] not found")
        return None
    print(f"Found LDRSW X12, [X9] at {hex(ldr_x12_ea)}")
    
    # 8. 查找EOR X0, X0, X12（标记7）
    eor_ea = ldr_x12_ea + 4
    if not (idc.print_insn_mnem(eor_ea) == "EOR" and 
            "X0,X0,X12" in idc.GetDisasm(eor_ea).replace(" ", "")):
        print("Error: EOR X0, X0, X12 not found")
        return None
    print(f"Found EOR at {hex(eor_ea)}")
    
    # 9. 查找ADD X25, X25, X0（标记8）
    add_x25_ea = eor_ea + 4
    if not (idc.print_insn_mnem(add_x25_ea) == "ADD" and 
            "X25,X25,X0" in idc.GetDisasm(add_x25_ea).replace(" ", "")):
        print("Error: ADD X25, X25, X0 not found")
        return None
    print(f"Found ADD X25 at {hex(add_x25_ea)}")
    
    # 10. 计算最终跳转地址
    # 公式: target = adr_target + ((ldr_value - 0x17) ^ stored_value)
    temp = (ldr_value - sub_imm) ^ stored_value
    target = adr_target + temp
    
    print("\nCalculation:")
    print(f"  ldr_value = {hex(ldr_value)}")
    print(f"  stored_value = {hex(stored_value)}")
    print(f"  temp = ({hex(ldr_value)} - 0x17) ^ {hex(stored_value)} = {hex(temp)}")
    print(f"  base = {hex(adr_target)}")
    print(f"  Target = {hex(adr_target)} + {hex(temp)} = {hex(target)}")
    
    return target

# LOAD:000000000005763C E8 0A 80 52                                       MOV             W8, #0x57 ; 'W'
# LOAD:0000000000057640 A8 03 1F B8                                       STUR            W8, [X29,#-0x10]
# LOAD:0000000000057644 A8 33 00 D1                                       SUB             X8, X29, #0xC
# LOAD:0000000000057648 AA 43 00 D1                                       SUB             X10, X29, #0x10
# LOAD:000000000005764C 23 00 00 10                                       ADR             X3, loc_57650
# LOAD:0000000000057650
# LOAD:0000000000057650                                                 loc_57650                               ; DATA XREF: JNI_OnLoad+34↑o
# LOAD:0000000000057650 09 01 00 98                                       LDRSW           X9, =0x96
# LOAD:0000000000057654 29 BD 00 D1                                       SUB             X9, X9, #0x2F ; '/'
# LOAD:0000000000057658 47 01 80 B9                                       LDRSW           X7, [X10]
# LOAD:000000000005765C 29 01 07 CA                                       EOR             X9, X9, X7
# LOAD:0000000000057660 63 00 09 8B                                       ADD             X3, X3, X9
# LOAD:0000000000057664 1B 01 80 52                                       MOV             W27, #8
# LOAD:0000000000057668 1B 01 00 B9                                       STR             W27, [X8]
# LOAD:000000000005766C 60 00 1F D6                                       BR              X3

def calculate_br_w8_common(start_ea, end_ea):
    """计算BR X25的目标地址"""
    # 1. 查找MOV W8, #imm指令（标记1）
    mov_ea = None
    for ea in range(start_ea, end_ea, 4):
        if idc.print_insn_mnem(ea) == "MOV" and \
           idc.get_operand_type(ea, 0) == idc.o_reg and \
           idc.get_operand_type(ea, 1) == idc.o_imm:
            mov_ea = ea
            break
    
    if not mov_ea:
        print("Error: MOV W8, #imm not found")
        return None
    
    # 获取立即数 (0x3F)
    stored_value = idc.get_operand_value(ea, 1)
    print(f"Found MOV W8, #{hex(stored_value)} at {hex(mov_ea)}")
    
    # # 2. 查找STR W8, [SP,#0x1FC]（标记2）
    str_ea = mov_ea + 4
    # if not (idc.print_insn_mnem(str_ea) == "STR" and 
    #         "SP,#0x1FC" in idc.GetDisasm(str_ea)):
    #     print("Error: STR W8, [SP,#0x1FC] not found")
    #     return None
    # print(f"Found STR at {hex(str_ea)}")
    
    # # 3. 查找ADD X9, SP, #0x1FC（标记3）
    add_x9_ea = str_ea + 8  # 跳过中间的ADD X8
    # if not (idc.print_insn_mnem(add_x9_ea) == "ADD" and 
    #         idc.print_insn_mnem(add_x9_ea) == "ADD" and 
    #         "X9,SP,#0x1FC" in idc.GetDisasm(add_x9_ea).replace(" ", "")):
    #     print("Error: ADD X9, SP, #0x1FC not found")
    #     return None
    # print(f"Found ADD X9 at {hex(add_x9_ea)}")
    
    # 4. 查找ADR X25（标记8前一条）
    adr_ea = add_x9_ea + 4
    if idc.print_insn_mnem(adr_ea) != "ADR":
        print("Error: ADR X25 not found")
        return None
    
    # 获取ADR加载的基地址
    adr_target = idc.get_operand_value(adr_ea, 1)
    print(f"Found ADR X25, {hex(adr_target)} at {hex(adr_ea)}")
    
    # 5. 查找LDRSW X0, =imm（标记4）
    ldr_ea = adr_ea + 4
    if not (idc.print_insn_mnem(ldr_ea) == "LDRSW" and 
            idc.get_operand_type(ldr_ea, 1) == idc.o_mem):
        print("Error: LDRSW X0, =imm not found")
        return None

    # 读取内存中的值
    mem_addr = idc.get_operand_value(ldr_ea, 1)
    ldr_value = idc.get_wide_dword(mem_addr)  # 读取32位值
    print(f"Found LDRSW X0, [mem:{hex(mem_addr)}] -> value={hex(ldr_value)} at {hex(ldr_ea)}")

    
    # 6. 查找SUB X0, X0, #imm（标记5）并动态获取立即数
    sub_ea = ldr_ea + 4
    if not (idc.print_insn_mnem(sub_ea) == "SUB" and 
            idc.get_operand_type(sub_ea, 0) == idc.o_reg and 
            idc.get_operand_type(sub_ea, 1) == idc.o_reg and 
            idc.get_operand_type(sub_ea, 2) == idc.o_imm):
        print("Error: SUB X0, X0, #imm not found")
        return None
    
    # 动态获取立即数值
    sub_imm = idc.get_operand_value(sub_ea, 2)
    print(f"Found SUB X0, X0, #{hex(sub_imm)} at {hex(sub_ea)}")
    
    # 7. 查找LDRSW X12, [X9]（标记6）
    ldr_x12_ea = sub_ea + 4
    if not (idc.print_insn_mnem(ldr_x12_ea) == "LDRSW" and 
        idc.get_operand_type(ldr_x12_ea, 0) == idc.o_reg and 
        idc.get_operand_type(ldr_x12_ea, 1) == idc.o_displ):
        print("Error: LDRSW X12, [X9] not found")
        return None
    print(f"Found LDRSW X12, [X9] at {hex(ldr_x12_ea)}")
    
    # 8. 查找EOR X0, X0, X12（标记7）
    eor_ea = ldr_x12_ea + 4
    if not (idc.print_insn_mnem(eor_ea) == "EOR" and 
            idc.get_operand_type(eor_ea, 0) == idc.o_reg and 
            idc.get_operand_type(eor_ea, 1) == idc.o_reg and 
            idc.get_operand_type(eor_ea, 2) == idc.o_reg):
        print("Error: EOR X0, X0, X12 not found")
        return None
    print(f"Found EOR at {hex(eor_ea)}")
    
    # 9. 查找ADD X25, X25, X0（标记8）
    add_x25_ea = eor_ea + 4
    if not (idc.print_insn_mnem(add_x25_ea) == "ADD" and 
            idc.get_operand_type(add_x25_ea, 0) == idc.o_reg and 
            idc.get_operand_type(add_x25_ea, 1) == idc.o_reg and 
            idc.get_operand_type(add_x25_ea, 2) == idc.o_reg):
        print("Error: ADD X25, X25, X0 not found")
        return None
    print(f"Found ADD X25 at {hex(add_x25_ea)}")
    
    # 10. 计算最终跳转地址
    # 公式: target = adr_target + ((ldr_value - 0x17) ^ stored_value)
    temp = (ldr_value - sub_imm) ^ stored_value
    target = adr_target + temp
    
    print("\nCalculation:")
    print(f"  ldr_value = {hex(ldr_value)}")
    print(f"  stored_value = {hex(stored_value)}")
    print(f"  temp = ({hex(ldr_value)} - 0x17) ^ {hex(stored_value)} = {hex(temp)}")
    print(f"  base = {hex(adr_target)}")
    print(f"  Target = {hex(adr_target)} + {hex(temp)} = {hex(target)}")
    
    return target

def is_br_x20(ea):
    """
    检查指定地址是否是BR X20指令
    :param ea: 要检查的地址
    :return: 如果是有效的BR X20指令返回True，否则返回False
    """
    # 解码指令
    insn = ida_ua.insn_t()
    insn_len = ida_ua.decode_insn(insn, ea)
    
    if insn_len != 4:
        return False  # 不是4字节指令
    
    # 检查指令是否为BR
    if insn.itype != ida_allins.ARM_br:
        return False
    
    # 检查操作数是否为寄存器
    if insn.Op1.type != ida_ua.o_reg:
        return False
    
    # 检查寄存器名称是否为X20
    reg_name = ida_idp.get_reg_name(insn.Op1.reg, 1)
    return reg_name == "W20"

def scan_code_seg():
    for n in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(n)
        
        # 只处理可执行段
        if not seg.perm & ida_segment.SEGPERM_EXEC:
            continue

        print(f"\nScanning segment: {ida_segment.get_segm_name(seg)} ({hex(seg.start_ea)}-{hex(seg.end_ea)})")
        ea = seg.start_ea
        while ea < seg.end_ea:
            if is_br_x20(ea):
                patch_after_br_x20(ea, ea + 100, "W20")
                
            insn = ida_ua.insn_t()
            insn_len = ida_ua.decode_insn(insn, ea)
            if insn_len > 0:
                ea += insn_len
            else:
                # 解码失败，移动到下一个对齐位置
                ea = ida_bytes.next_head(ea, seg.end_ea)

# 使用示例
if __name__ == "__main__":
    # # 设置分析范围（根据你的实际地址修改）
    # start_ea = 0x5763C  # MOV W8, #0x3F
    # end_ea   = 0x5766C  # BR X25
    
    # target = calculate_br_w8_common(start_ea, end_ea)
    
    # if target:
    #     print(f"\n[+] BR X25 jumps to: {hex(target)}")
    #     # 在IDA中跳转到目标地址
    #     idc.jumpto(target)
    # else:
    #     print("[-] Failed to calculate target address")

    # # 根据您的需求设置地址范围
    # start_ea = 0x5766C  # BR X3 指令地址
    # end_ea = 0x57680    # 0x57678 + 8 = 0x57680

    # start_ea = 0x57B48
    # end_ea = 0x57B60

    # start_ea = 0x193884
    # end_ea = 0x19389C

    # start_ea = 0x1938FC
    # end_ea = 0x193914
    
    # # 执行补丁
    # patch_range_with_nops(start_ea, end_ea)


    # 示例地址 - 根据实际情况修改
    # br_address = 0x57F08
    # end_address = br_address + 100
    
    # success = patch_after_br_x20(br_address, end_address, "W3")
    
    # if success:
    #     print("Patch applied successfully!")
    # else:
    #     print("Patch failed. See previous messages for details.")

    scan_code_seg()
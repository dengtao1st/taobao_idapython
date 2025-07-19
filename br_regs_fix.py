import idautils
import idc
import ida_segment
import ida_ua
import ida_bytes

def is_br_with_register(ea):
    """检查指令是否为BR寄存器格式"""
    mnem = idc.print_insn_mnem(ea)
    if mnem != "BR":
        return False
    
    op = idc.print_operand(ea, 0)
    # print(f"op:{op}")
    return op.startswith(('X', 'W')) and op[1:].isdigit()

def comment_matches_next_addr(ea):
    """检查注释是否匹配下一条指令地址"""
    next_ea = idc.next_head(ea, idc.BADADDR)
    # print(f"next_ea:{hex(next_ea)}")
    if next_ea == idc.BADADDR:
        return False
    
    # 获取当前指令的常规注释
    cmt = idc.get_cmt(ea, 1)
    print(f"cmt:{cmt} ea:{hex(ea)}")
    if not cmt:
        return False
    
    # 检查注释是否包含下一条指令的地址或标签
    hex_addr = f"{next_ea:X}".lower()
    name = idc.get_name(next_ea)

    print(f"next_ea:{next_ea} cmt:{cmt}")
    
    return (hex_addr in cmt.lower() or 
            (name and name in cmt) or
            f"loc_{hex_addr}" in cmt.lower())

def has_xref_to_next_insn(ea):
    """检查指令是否有交叉引用指向下一条指令"""
    next_ea = idc.next_head(ea, idc.BADADDR)
    if next_ea == idc.BADADDR:
        return False
    
    # 获取当前指令的所有交叉引用
    for xref in idautils.XrefsFrom(ea):
        # 只关心代码交叉引用
        # if xref.type not in (ida_xref.fl_CF, ida_xref.fl_CN):
        #     continue
        
        # 检查交叉引用是否指向下一条指令或者上一条指令
        # print(f"xref.to:{hex(xref.to)} ea:{hex(ea)}")
        if xref.to == next_ea:
            return True
    
    return False

def main():
    # 获取所有代码段
    code_segments = [seg for seg in idautils.Segments() 
                    if idc.get_segm_attr(seg, idc.SEGATTR_TYPE) == idc.SEG_CODE]
    
    if not code_segments:
        print("No code segments found!")
        return
    
    print(f"Processing {len(code_segments)} code segments...")
    patched_count = 0
    
    for seg_start in code_segments:
        seg_end = idc.get_segm_end(seg_start)
        ea = seg_start
        
        while ea < seg_end and ea != idc.BADADDR:
            # 确保是有效指令
            if not ida_ua.can_decode(ea):
                ea = idc.next_head(ea, seg_end)
                continue
            
            # 检查BR指令和注释条件
            if is_br_with_register(ea) and has_xref_to_next_insn(ea):
                # ARM64 NOP指令: D503201F (小端序: 1F 20 03 D5)
                nop_bytes = b"\x1F\x20\x03\xD5"
                
                # 原始指令长度应为4字节
                ins_len = idc.get_item_size(ea)
                if ins_len != 4:
                    print(f"Warning: BR at {ea:X} has unexpected length {ins_len}")
                    ea = idc.next_head(ea, seg_end)
                    continue
                
                # 修补指令
                NOP = 0xD503201F
                ida_bytes.patch_dword(ea, NOP)
                print(f"Patched BR at {ea:X} with NOP")
                patched_count += 1
            
            ea = idc.next_head(ea, seg_end)
    
    print(f"Done. Patched {patched_count} instructions.")

if __name__ == "__main__":
    main()
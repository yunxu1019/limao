var { flag_byname } = 狸猫;
/*
 * assemble.c   code generation for the Netwide Assembler
 *
 * Bytecode specification
 * ----------------------
 *
 *
 * Codes            Mnemonic        Explanation
 *
 * \0                                       终止代码。（当然，除非是字面意思。）
 * \1..\4                                   代码流中跟随的许多文字字节
 * \5                                       主操作数加4（b，低位八位数字）
 * \6                                       将第二个操作数加4（a，中间的八位数字）
 * \7                                       主操作数和辅助操作数加4
 * \10..\13                                 要添加的代码流后面跟着一个文字字节
 *                                          到操作数0..3的寄存器值
 * \14..\17                                 MIB中索引寄存器操作数的位置（BND insns）
 * \20..\23         ib                      字节立即数操作数，来自操作数0..3
 * \24..\27         ib,u                    从操作数0..3开始的零扩展字节立即数操作数
 * \30..\33         iw                      字立即数操作数，来自操作数0..3
 * \34..\37         iwd                     根据16/32位在\3[0-3]和\4[0-3]之间进行选择
 *                                          汇编模式或操作数上的操作数大小重写
 * \40..\43         id                      长立即数操作数，来自操作数0..3
 * \44..\47         iwdq                    在\3[0-3]、\4[0-3]和\5[4-7]之间选择
 *                                          这取决于指令的地址大小。
 * \50..\53         rel8                    字节相对操作数，来自操作数0..3
 * \54..\57         iq                      qword立即数操作数，来自操作数0..3
 * \60..\63         rel16                   相对于字的操作数，来自操作数0..3
 * \64..\67         rel                     根据16/32位在\6[0-3]和\7[0-3]之间进行选择
 *                                          汇编模式或操作数上的操作数大小重写
 * \70..\73         rel32                   长相对操作数，来自操作数0..3
 * \74..\77         seg                     字常量，来自操作数0..3的_segment_部分
 * \1ab             /r                      ModRM，在操作数a中的EA上计算，带有reg
 *                                          字段操作数b的寄存器值。
 * \171\mab         /mrb (e.g /3r0)         ModRM，reg字段取自操作数a，m
 *                                          以及b个字段被设置为指定的值。
 * \172\ab          /is4                    操作数a中第7..4位的寄存器号，其中
 *                                          从操作数b开始的位3..0的4位立即数。
 * \173\xab                                 操作数a中第7..4位的寄存器号，其中
 *                                          位3..0中的值b。
 * \174..\177                               位7..4中操作数0..3的寄存器号，以及
 *                                          位3..0中的任意值（组装为零）
 * \2ab             /b                      ModRM，在操作数a中的EA上计算，带有reg
 *                                          等于数字b的字段。
 * \240..\243                               该指令使用EVEX而不是REX或VEX/XOP
 *                                          V字段取自操作数0..3。
 * \250                                     该指令使用EVEX而不是REX或VEX/XOP
 *                                          V字段设置为1111b。
 *
 * EVEX前缀后面跟着序列:
 * \cm\wlp\tup    where cm is:
 *                  cc 00m mmm
 *                  c = 2 for EVEX and mmmm is the M field (EVEX.P0[3:0])
 *                and wlp is:
 *                  00 wwl lpp
 *                  [l0]  ll = 0 (.128, .lz)
 *                  [l1]  ll = 1 (.256)
 *                  [l2]  ll = 2 (.512)
 *                  [lig] ll = 3 for EVEX.L'L don't care (always assembled as 0)
 *
 *                  [w0]  ww = 0 for W = 0
 *                  [w1]  ww = 1 for W = 1
 *                  [wig] ww = 2 for W don't care (always assembled as 0)
 *                  [ww]  ww = 3 for W used as REX.W
 *
 *                  [p0]  pp = 0 for no prefix
 *                  [60]  pp = 1 for legacy prefix 60
 *                  [f3]  pp = 2
 *                  [f2]  pp = 3
 *
 *                tup is tuple type for Disp8*N from %tuple_codes in insns.pl
 *                    (compressed displacement encoding)
 *
 * \254..\257       id,s                    要扩展到64位的有符号32位操作数。
 * \260..\263                               该指令使用VEX/XOP而不是REX
 *                                          V字段取自操作数0..3。
 * \270                                     该指令使用VEX/XOP而不是REX
 *                                          V字段设置为1111b。
 * VEX/XOP prefixes are followed by the sequence:
 * \tmm\wlp        where mm is the M field; and wlp is:
 *                 00 wwl lpp
 *                 [l0]  ll = 0 for L = 0 (.128, .lz)
 *                 [l1]  ll = 1 for L = 1 (.256)
 *                 [lig] ll = 2 for L don't care (always assembled as 0)
 *
 *                 [w0]  ww = 0 for W = 0
 *                 [w1 ] ww = 1 for W = 1
 *                 [wig] ww = 2 for W don't care (always assembled as 0)
 *                 [ww]  ww = 3 for W used as REX.W
 *
 * t = 0 for VEX (C4/C5), t = 1 for XOP (8F).
 *
 * \271             hlexr                       指令使用带锁或不带锁的XRELEASE（F3）
 * \272             hlenl                       指令采用带锁或不带锁的XACQUIRE/XRELEASE
 * \273             hle                         指令只使用带锁的XACQUIRE/XRELEASE
 * \274..\277       ib,s                        字节立即数操作数，从操作数0..3开始，符号扩展
 *                                              操作数大小（如果存在o16/o32/o64）或位大小
 * \310             a16                         表示固定的16位地址大小，即可选的0x67。
 * \311             a32                         表示固定的32位地址大小，即可选的0x67。
 * \312             adf                         （仅限反汇编程序）对于非默认地址大小无效。
 * \313             a64                         表示固定的64位地址大小，0x67无效。
 * \314             norexb                      （仅限反汇编程序）与REX.B一起无效
 * \315             norexx                      （仅限反汇编程序）与REX.X一起无效
 * \316             norexr                      （仅限反汇编程序）与REX.R一起无效
 * \317             norexw                      （仅限反汇编程序）与REX.W一起无效
 * \320             o16                         表示固定的16位操作数大小，即可选的0x66。
 * \321             o32                         表示固定的32位操作数大小，即可选的0x66。
 * \322             odf                         指示此指令仅在
 *                                              操作数大小是默认值（指令到反汇编程序，
 *                                              在汇编程序中不生成代码）
 * \323             o64nw                       表示固定的64位操作数大小，REX仅适用于扩展。
 * \324             o64                         指示需要REX前缀的64位操作数大小。
 * \325             nohi                        始终使用spl/bpl/sil/dil的指令
 * \326             nof3                        前缀为0xF3 REP的指令无效。提示
                                                仅反汇编程序；用于SSE指令。
 * \330                                         要添加的代码流后面跟着一个文字字节
 *                                              到指令的条件代码值。
 * \331             norep                       带有REP前缀的指令无效。提示
 *                                              仅反汇编程序；用于SSE指令。
 * \332             f2i                         REP前缀（0xF2字节）用作操作码扩展。
 * \333             f3i                         REP前缀（0xF3字节）用作操作码扩展。
 * \334             rex.l                       用作REX.R的LOCK前缀（用于非64位模式）
 * \335             repe                        将rep（0xF3字节）前缀反汇编为repe而非rep。
 * \336             mustrep                     即使未指定，也强制使用REP（E）前缀（0xF3）。
 * \337             mustrepne                   即使未指定，也强制使用REPNE前缀（0xF2）。
 *                                              \336-\337仍然被列为反汇编程序中的前缀。
 * \340             resb                        保留未初始化存储的＜操作数0＞字节。
 *                                              操作数0最好是一个无分段常量。
 * \341             wait                        此指令需要WAIT“前缀”
 * \360             np                          无SSE前缀（==\364\331）
 * \361                                         66 SSE前缀（==\366\331）
 * \364             !osp                        不允许使用操作数大小前缀（0x66）
 * \365             !asp                        不允许使用地址大小前缀（0x67）
 * \366                                         操作数大小前缀（0x66）用作操作码扩展
 * \367                                         地址大小前缀（0x67）用作操作码扩展
 * \370,\371        jcc8                        仅当操作数0满足字节跳转条件时匹配。
 *                  jmp8                        370用于Jcc，371用于JMP。
 * \373             jlen                        如果位==16则组装0x03，如果位==32则组装0x05；
 *                                              用于条件跳跃而不是较长的跳跃
 * \374             vsibx|vm32x|vm64x           此指令占用XMM VSIB内存EA
 * \375             vsiby|vm32y|vm64y           此指令占用YMM VSIB内存EA
 * \376             vsibz|vm32z|vm64z           此指令占用ZMM VSIB内存EA
 */
var names = [];
var changed = [];
var insns = 狸猫.getInsns("386");
var write = function (t, k, o, i) {
    var a = o[i];
}
for (var k in insns) {
    for (var o of insns[k]) {
        var b = o.bytecode.slice();
        var c = [];
        while (b.length) {
            while (b[0] > 4) b.shift();
            c.push(...b.splice(0, b.splice(0, 1)[0]));
        }
        var [a] = c;
        if (names[a] !== k) {
            if (names[a]) {
                changed[a] = true;
            }
        }
        names[a] = k;
    }
}
// console.log(insns.add)
for (var k in changed) delete names[k];
console.log(names)

import insns_flag_index from "./insns-iflags.mjs";
"use ./insns.dat";
// console.log(nasmInsns)
// var fs = require('fs');
// var path = require("path");
// var readline = require('readline');
var disasm_prefixes = "0F24 0F25 0F38 0F3A 0F7A 0FA6 0FA7 0F".split(/\s+/).map(a => "0x" + a);
var MAX_OPERANDS = 5;
var imm_codes = {
    //对照表来自 nasm-2.07: x86/insns.pl -> sub byte_code_compile()
    'ib': 020,     // imm8
    'ib,u': 024,     // Unsigned imm8
    'iw': 030,     // imm16
    'ib,s': 0274,    // imm8 sign-extended to opsize or bits
    'iwd': 034,     // imm16 or imm32, depending on opsize
    'id': 040,     // imm32
    'id,s': 0254,    // imm32 sign-extended to 64 bits
    'iwdq': 044,     // imm16/32/64, depending on addrsize
    'rel8': 050,
    'iq': 054,
    'rel16': 060,
    'rel': 064,     // 16 or 32 bit relative operand
    'rel32': 070,
    'seg': 074,
};
var plain_codes = {
    //对照表来自 nasm-2.07: x86/insns.pl -> sub byte_code_compile()
    'o16': 0320,    // 16-bit operand size
    'o32': 0321,    // 32-bit operand size
    'odf': 0322,    // Operand size is default
    'o64': 0324,    // 64-bit operand size requiring REX.W
    'o64nw': 0323,    // Implied 64-bit operand size (no REX.W)
    'a16': 0310,
    'a32': 0311,
    'adf': 0312,    // Address size is default
    'a64': 0313,
    '!osp': 0364,
    '!asp': 0365,
    'f2i': 0332,    // F2 prefix, but 66 for operand size is OK
    'f3i': 0333,    // F3 prefix, but 66 for operand size is OK
    'mustrep': 0336,
    'mustrepne': 0337,
    'rex.l': 0334,
    'norexb': 0314,
    'norexx': 0315,
    'norexr': 0316,
    'norexw': 0317,
    'repe': 0335,
    'nohi': 0325,    // Use spl/bpl/sil/dil even without REX
    'nof3': 0326,    // No REP 0xF3 prefix permitted
    'norep': 0331,    // No REP prefix permitted
    'wait': 0341,    // Needs a wait prefix
    'resb': 0340,
    'np': 0360,    // No prefix
    'jcc8': 0370,    // Match only if Jcc possible with single byte
    'jmp8': 0371,    // Match only if JMP possible with single byte
    'jlen': 0373,    // Length of jump
    'hlexr': 0271,
    'hlenl': 0272,
    'hle': 0273,

    // This instruction takes XMM VSIB
    'vsibx': 0374,
    'vm32x': 0374,
    'vm64x': 0374,

    // This instruction takes YMM VSIB
    'vsiby': 0375,
    'vm32y': 0375,
    'vm64y': 0375,

    // This instruction takes ZMM VSIB
    'vsibz': 0376,
    'vm32z': 0376,
    'vm64z': 0376,
};
var vex_class = 'vex,xop,evex'.split(',');
var vex_classes = vex_class.length;
var vexlist = [];
var vexmap = {};
for (let c = 0; c < vex_classes; c++) {
    vexmap[vex_class[c]] = c;
    for (let m = 0; m < 32; m++) {
        for (let p = 0; p < 4; p++) {
            vexlist.push(`${vex_class[c]}0x${m < 16 ? '0' + m.toString(16) : m.toString(16)}0x${p}`);
        }
    }
}
disasm_prefixes.unshift.apply(disasm_prefixes, vexlist);
var bytecode_count = Array(256).fill(0);
// 下边的注释来自nasm的脚本，凑合着看吧，我也不翻译了
// This function takes a series of byte codes in a format which is more
// typical of the Intel documentation, and encode it.
//
// The format looks like:
//
// [operands: opcodes]
//
// The operands word lists the order of the operands:
//
// r = register field in the modr/m
// m = modr/m
// v = VEX "v" field
// i = immediate
// s = register field of is4/imz2 field
// - = implicit (unencoded) operand
// x = indeX register of mib. 014..017 bytecodes are used.
//
// For an operand that should be filled into more than one field,
// enter it as e.g. "r+v".
var byte_code_compile = function (str, relax) {
    // 函数改编自nasm-2.16 insns.pl
    var lc = /^(?:([^\s:]*)\:*([^\s:]*)\:|)\s*(.*\S)\s*$/.exec(str);
    if (!lc) throw new Error(`数据无法解析：${str}`);
    var [, opr = '', tuple = '', opc = ''] = lc;
    var op = 0;
    var oppos = {};
    for (var c of opr) {
        if (c === "+") op--;
        else {
            if (relax & 1) op--;
            relax >>= 1;
            oppos[c] = op++;
        }
    }
    var tup = tupletype(tuple);
    var codes = [];
    var litix;
    var last_imm = 'h', prefix_ok = 1;
    var opex;
    var tmp;
    for (op of opc.split(/\s*(?:\s|(?=[\/\\]))/)) {
        var pc = plain_codes[op];
        if (isFinite(pc)) {
            codes.push(pc);
        }
        else if (prefix_ok && /^(66|f2|f3)$/i.test(pc)) {
            switch (op) {
                case '66':
                    codes.push(0361);
                    break;
                case 'f2':
                    codes.push(0332);
                    break;
                default:
                    codes.push(0333);
            }
        }
        else if (/^[0-9a-f]{2}$/i.test(op)) {
            if (isFinite(litix) && litix + codes[litix] + 1 === codes.length && codes[litix] < 4) {
                codes[litix]++;
                codes.push(parseInt(op, 16));
            }
            else {
                litix = codes.length;
                codes.push(01, parseInt(op, 16));
            }
            prefix_ok = 0;
        }
        else if (op === '/r') {
            if (!isFinite(oppos.r) || !isFinite(oppos.m)) {
                throw op + "缺少r和m操作数！";
            }
            opex = (oppos.m & 4 ? 06 : 0) | (oppos.r & 4 ? 05 : 0);
            if (opex) codes.push(opex);
            if (oppos.x) codes.push(014 + (oppos.x & 3));
            codes.push(0100 + ((oppos.m & 3) << 3) + (oppos.r & 3));
            prefix_ok = 0;
        }
        else if (tmp = /^\/([0-7])$/.exec(op)) {
            if (!isFinite(oppos.m)) {
                throw op + "缺少m操作数";
            }
            if (oppos.m & 4) codes.push(06);
            codes.push(0200 + ((oppos.m & 3) << 3) + parseInt(tmp[1], 8));
            prefix_ok = 0;
        }
        else if (tmp = /^\/([0-3]?)r([0-7])$/.exec(op)) {
            if (!isFinite(oppos.r)) {
                throw op + "缺少r操作数";
            }
            if (oppos.r & 4) codes.push(05);
            codes.push(0171);
            codes.push((tmp[1] << 6) + ((oppos.r & 3) << 3) + +tmp[2]);
            prefix_ok = 0;
        }
        else if (tmp = /^(vex|xop)(|\..*)$/i.exec(op)) {
            var vexname = tmp[1];
            var c = vexmap[vexname];
            var [$m, $w, $l, $p] = [, 2, , 0];
            var has_nds = 0;
            var subops = op.split('.');
            subops.shift();
            for (var oq of subops) switch (oq) {
                case '128': case 'l0': case 'lz': $l = 0; break;
                case '256': case 'l1': $l = 1; break;
                case 'lig': $l = 2; break;
                case 'w0': $w = 0; break;
                case 'w1': $w = 1; break;
                case 'wig': $w = 2; break;
                case 'ww': $w = 3; break;
                case 'np': case 'p0': $p = 0; break;
                case '66': case 'p1': $p = 1; break;
                case 'f3': case 'p2': $p = 2; break;
                case 'f2': case 'p3': $p = 3; break;
                case '0f': $m = 1; break;
                case '0f38': $m = 2; break;
                case '0f3a': $m = 3; break;
                case 'nds': case 'ndd': case 'dds':
                    if (!isFinite(oppos.v)) {
                        throw ` ${vexname}.${oq} 缺失v操作数`;
                    }
                    has_nds = 1;
                    break;
                default:
                    if (tmp = /^m([0-9]+)$/.exec(oq)) {
                        $m = +tmp[1];
                    } else {
                        throw `${vexname}未定义子码${oq}\n`;
                    }

            }
            if (!isFinite($m) || !isFinite($w) || !isFinite($l) || !isFinite($p)) {
                throw `定义${vexname}时缺少数据！`;
            }
            var minmap = c === 1 ? 8 : 0;
            if ($m < minmap || $m > 31) {
                throw new `${vexname}只接收${minmap}到31之间的数字`;
            }
            codes.push(oppos.v ? 0260 + (oppos.v & 3) : 0270, (c << 6) + $m, ($w << 4) + ($l << 2) + $p);
            prefix_ok = 0;
        }
        else if (tmp = /^(evex)(|\..*)$/i.exec(op)) {
            var c = vexmap[tmp[1]];
            var [$m, $w, $l, $p] = [, 2, , 0];
            var has_nds = 0;
            var subops = op.split(/\./);
            subops.shift();
            for (var oq of subops) switch (oq) {
                case '128': case 'l0': case 'lz': case 'lig': $l = 0; break;
                case '256': case 'l1': $l = 1; break;
                case '512': case 'l2': $l = 2; break;
                case 'w0': $w = 0; break;
                case 'w1': $w = 1; break;
                case 'wig': $w = 2; break;
                case 'ww': $w = 3; break;
                case 'np': case 'p0': $p = 0; break;
                case '66': case 'p1': $p = 1; break;
                case 'f3': case 'p2': $p = 2; break;
                case 'f2': case 'p3': $p = 3; break;
                case '0f': $m = 1; break;
                case '0f38': $m = 2; break;
                case '0f3a': $m = 3; break;
                case 'nds': case 'ndd': case 'dds':
                    if (!isFinite(oppos.v)) {
                        throw `evex.${oq} 缺少v操作数`;
                    }
                    has_nds = 1;
                    break;
                default:
                    if (tmp = /^m([0-9]+)$/.exec(oq)) {
                        $m = +tmp[1];
                    }
                    else {
                        throw `EVEX缺少子码: ${oq}`;
                    }
            }
            if (!isFinite($m) || !isFinite($w) || !isFinite($l) || !isFinite($p)) {
                throw `定义EVEX时缺少数据！`;
            }
            if ($m > 15) {
                throw "EVEX只接收 0到15之间的数";
            }
            codes.push(isFinite(oppos.v) ? 0240 + (oppos.v & 3) : 0250, (c << 6) + $m, ($w << 4) + ($l << 2) + $p, tup);
            prefix_ok = 0;
        }
        else if (isFinite(imm_codes[op])) {
            if (op == 'seg') {
                if (last_imm < 'i') {
                    throw `seg 缺少立即数`;
                }
            }
            else {
                last_imm = String.fromCharCode(last_imm.charCodeAt(0) + 1);
                if (last_imm > 'j') {
                    throw `立即数过多`;
                }
            }
            if (!isFinite(oppos[last_imm])) {
                throw `${op}缺少${last_imm}操作数`;
            }
            if (oppos[last_imm] & 4) codes.push(05);
            codes.push(imm_codes[op] + (oppos[last_imm] & 3));
            prefix_ok = 0;
        }
        else if (op === '/is4') {
            if (!isFinite(oppos.s)) {
                throw `${op}缺少s操作数`;
            }
            if (isFinite(oppos.i)) {
                codes.push(0172, (oppos.s << 3) + oppos.i);
            }
            else {
                if (oppos.s & 4) codes.push(05);
                codes.push(0174 + (oppos.s & 3));
            }
            prefix_ok = 0;
        }
        else if (tmp = /^\/is4\=([0-9]+)$/.exec(op)) {
            var imm = +tmp[1];
            if (!isFinite(oppos.s)) {
                throw `${op}缺少s操作数`;
            }
            if (imm < 0 || imm > 15) {
                throw `imm4值错了：${op}:${imm}`;
            }
            codes.push(0173, (oppos.s << 4) + imm);
            prefix_ok = 0;
        }
        else if (tmp = /^([0-9a-f]{2})\+c$/.exec(op)) {
            codes.push(0330, parseInt(tmp[1], 16));
            prefix_ok = 0;
        }
        else if (tmp = /^([0-9a-f]{2})\+r$/.exec(op)) {
            if (!isFinite(oppos.r)) {
                throw `${op}缺少r操作数`;
            }
            if (oppos.r & 4) codes.push(05);
            codes.push(010 + (oppos.r & 3), parseInt(tmp[1], 16));
            prefix_ok = 0;
        }
        else if (tmp = /^\\([0-7]+|x[0-9a-f]{2})$/.exec(op)) {
            codes.push(parseInt(tmp[1], 8));
        }
        else {
            throw `未知操作符：${op}`;
        }
    }
    return codes;
};
var tuple_codes = {
    '': 000,
    'fv': 001,
    'hv': 002,
    'fvm': 003,
    't1s8': 004,
    't1s16': 005,
    't1s': 006,
    't1f32': 007,
    't1f64': 010,
    't2': 011,
    't4': 012,
    't8': 013,
    'hvm': 014,
    'qvm': 015,
    'ovm': 016,
    'm128': 017,
    'dup': 020,
};
var tupletype = function (tuplestr) {
    if (!(tuplestr in tuple_codes)) throw new Error(`类型没有找到：${tuplestr}`)
    return 0300 + tuple_codes[tuplestr];
};
//** 参考 decodify */
var getcode = function (c, relax) {
    var m = /^\s*\[([^\]]*)\]\s*$/.exec(c);
    if (m) return byte_code_compile(m[1], relax);
    var codes = [];
    c = c.replace(/\\([^\\]+)/g, function (n, m) {
        if (!/^[a-z]/.test(m)) {
            codes.push(parseInt(m, 8));
        }
        switch (m.charAt(0).toLowerCase()) {
            case "x":
                codes.push(parseInt(m.slice(1), 16));
                break;
            default:
                throw "未知格式"
        }
        return n;
    });
    return codes;
};
var bytecode_list = [];
var format_insn = function (opcode, operands, codes, flags, relax) {
    // 本段代码参考 nasm16 x86/insns.pl;
    var nd = 0;
    var num, flagsindex;
    var bytecode;
    var op, ops, opsize, opp, opx, oppx, decos, opevex;
    if (operands === 'ignore') return [];
    operands = operands.replace(/\*/g, '').replace(/\:/g, "|colon,");
    ops = [];
    opsize = [];
    decos = [];
    var tmp;
    if (operands !== 'void') {
        for (op of operands.split(',')) {
            var opsz = 0;
            opx = [];
            opevex = [];
            for (opp of op.split('|')) {
                oppx = [];
                opp = opp.replace(/^(b(32|64)|mask|z|er|sae)$/, function (_, a) {
                    opevex.push(a);
                    return ''
                }).replace(/^(b(32|64)|mask|z|er|sae)$/, function (_, a) {
                    opevex.push(a);
                    return '';
                }).replace(/(?<!\d)(8|16|32|64|80|128|256|512)$/, function (_, a) {
                    oppx.push(`bits${a}`);
                    opsz = +a;
                    return '';
                }).replace(/^mem$/, 'memory')
                    .replace(/^memory_offs$/, 'mem_offs')
                    .replace(/^imm$/, 'immediate')
                    .replace(/^([a-z]+)rm$/, 'rm_$1')
                    .replace(/^rm$/, 'rm_gpr')
                    .replace(/^reg$/, 'reg_gpr');
                if (!/(^|\s)evex\./.test(codes)) {
                    opp = opp.replace(/^(rm_[xyz]mm)$/, '$1_l16')
                        .replace(/^([xyz]mm)reg$/, '$1_l16');
                }
                if (opp) opx.push(opp), opx.push.apply(opx, oppx);
            }
            op = opx.join('|');
            ops.push(op);
            opsize.push(opsz);
            decos.push(opevex.length ? opevex.join("|") : '0');
        }
    }
    num = ops.length;
    while (ops.length < MAX_OPERANDS) {
        ops.push('0');
        opsize.push(0);
        decos.push('0');
    }
    operands = ops.join(',').toUpperCase();
    var decorators = `{${decos.join(',')}}`;
    if (/^\{(0,)+0\}$/.test(decorators)) {
        decorators = "NO_DECORATOR";
    }
    decorators = decorators.toUpperCase();
    var arx;
    var _flags = {};
    for (var flag of flags.split(',')) {
        if (!flag) continue;
        if (flag == 'ND') {
            nd = 1;
        }
        else {
            _flags[flag] = true;
        }
        if (flag == 'NEVER' || flag === "NOP") {
            _flags['OBSOLETE'] = true;
        }
        if (tmp = /^AR([0-9]+)$/.exec(flag)) {
            arx = +tmp[1];
        }
    }
    if (/evex\./.test(codes)) {
        _flags["EVEX"] = true;
    } else if (/(vex|xop)\./.test(codes)) {
        _flags["VEX"] = true;
    }
    if (_flags["SM"] || _flags["SM2"]) {
        var ssize = 0;
        var e = _flags["SM2"] ? 2 : MAX_OPERANDS;
        for (var i = 0; i < e; i++) {
            if (!opsize[i]) continue;
            if (!ssize) {
                ssize = opsize[i];
            }
            else if (opsize[i] !== ssize) {
                throw `SM标记与参数${i}矛盾`;
            }
        }
    }
    var s = isFinite(arx) ? arx : 0;
    var e = isFinite(arx) ? arx : MAX_OPERANDS - 1;
    for (var sf in sflags) {
        if (!_flags[sf]) continue;
        for (var i = s; i <= e; i++) {
            if (opsize[i] && !/\breg_(gpr|[cdts]reg)\b/.test(ops[i])) {
                if (opsize[i] !== sflags[sf]) throw `${sf}标记与参数${i}(${ops[i]})不一致`;
            }
        }
    }
    var flagsindex = insns_flag_index(Object.keys(_flags));
    if (!isFinite(flagsindex)) throw "标记有误：" + sflags;
    var bytecode = getcode(codes, relax).concat(0);
    bytecode_list.push(bytecode);
    codes = hexstr(bytecode);
    count_bytecods(bytecode);
    return [{ opcode, num, operands, decorators, codes, bytecode, flags: _flags, flagsindex }, nd];
};
var count_bytecods = function () {
    var skip = 0;
    for (var $bc of arguments) {
        if (skip) {
            skip--;
            continue;
        }
        bytecode_count[$bc]++;
        if ($bc >= 01 && $bc <= 04) {
            skip = $bc;
        } else if (($bc & ~03) == 010) {
            skip = 1;
        } else if (($bc & ~013) == 0144) {
            skip = 1;
        } else if ($bc == 0172 || $bc == 0173) {
            skip = 1;
        } else if (($bc & ~3) == 0260 || $bc == 0270) {   // VEX
            skip = 2;
        } else if (($bc & ~3) == 0240 || $bc == 0250) {   // EVEX
            skip = 3;
        } else if ($bc == 0330) {
            skip = 1;
        }
    }

};
var hexstr = function (c) {
    return c.map(c => {
        c = c.toString(16);
        if (c.length < 2) c = "0" + c;
        return c;
    }).join('');
};
var sflags = {
    'SB': 8, 'SW': 16, 'SD': 32, 'SQ': 64,
    'SO': 128, 'SY': 256, 'SZ': 512
};
var line = 0;
var max = 0;
var codeTree = {};
var big = [];
var n_opcodes = 0, n_opcodes_cc = 0;
var k_opcodes_cc = Object.create(null);
var k_opcodes = Object.create(null);
var dinstables = Object.create(null);
insns.replace(/[^\r\n]+/g, function (row) {
    line++;
    if (/^\s*;/.test(row)) return;
    row = row.replace(/;[\s\S]*?$/, '');
    if (!row) return;
    var match = /^\s*(\S+)\s+(\S+)\s+(\S+|\[.*\])\s+(\S+)\s*$/.exec(row);
    if (!match) {
        console.warn(`第 ${line} 行不是四个字段，已跳过！`);
        return;
    }
    var [, a, b, c, d] = match;
    var fields = [a, b, c, d, 0];
    var field_list = [fields];
    var relax = /\*/.test(b);
    if (relax) {
        if (!/^\[/.test(c)) {
            throw "有*号但是使用了字节码。";
        }
        var ops = b.split(',');
        var opmask = 0;
        if (/\*/.test(ops[0])) throw "首个操作数带*号";
        for (var cx = 1, dx = ops.length; cx < dx; cx++) {
            if (/\*/.test(ops[cx])) opmask |= 1 << cx;
        }
        for (var cx = 1, dx = 1 << ops.length; cx < dx; cx++) {
            if ((cx & ~opmask) === 0) {
                var xops = [];
                var omask = ~cx;
                for (var cy = 0, dy = ops.length; cy < dy; cy++) {
                    if (omask & 1) {
                        xops.push(ops[cy]);
                    }
                    omask >>= 1;
                }
                field_list.push([fields[0], xops.join(','), fields[2], fields[3], cx]);
            }
        }
    }
    for (var fields of field_list) {
        var [formatted, nd] = format_insn(...fields);
        if (formatted) {
            var aname = fields[0];
            if (!codeTree[aname]) codeTree[aname] = [];
            codeTree[aname].push(formatted);
        }
        if (/cc$/.test(fields[0])) {
            if (!isFinite(k_opcodes_cc[fields[0]])) {
                k_opcodes_cc[fields[0]] = n_opcodes_cc++;
            }
            else if (!isFinite(k_opcodes[fields[0]])) {
                k_opcodes[fields[0]] = n_opcodes++;
            }
        }
        if (!formatted && !nd) {
            big.push(formatted);
            var sseq = startseq(fields[2], fields[4]);
            for (var i of sseq) {
                if (!dinstables[i]) {
                    dinstables[i] = [];
                }
                dinstables[i].push(big.length);
            }
        }

    }
    c = getcode(c, relax);
    var id = `${a} ${b}`;
    var data = { name: a, 操作数: b, code: c, 硬件: d };
});
function range(start, end) {
    var res = new Array(end - start);
    for (var cx = 0, dx = res.length; cx < dx; cx++) {
        res[cx] = start + cx;
    }
    return res;
}
function addprefix(a, ...b) {
    return a + b.map(hexstr).join('');
}
function startseq($codestr, $relax) {
    var $word;
    var codes = [];
    var $c = $codestr;
    var $c0, $c1, $i;
    var $prefix = '';

    codes = getcode($codestr, $relax);

    while (isFinite($c0 = codes.shift())) {
        $c1 = codes[0];
        if ($c0 >= 01 && $c0 <= 04) {
            // Fixed byte string
            var $fbs = $prefix;
            while (isFinite($c0)) {
                if ($c0 >= 01 && $c0 <= 04) {
                    while ($c0--) {
                        $fbs += hexstr(codes.shift());
                    }
                } else {
                    break;
                }
                $c0 = codes.shift();
            }

            for (var $pfx of disasm_prefixes) {
                if ($fbs.slice(0, $pfx.length) == $pfx) {
                    $prefix = $pfx;
                    $fbs = $fbs.slice($pfx.length);
                    break;
                }
            }

            if ($fbs !== '') {
                return $prefix.concat($fbs.slice(0, 2));
            }
            codes.unshift($c0);
        } else if ($c0 >= 010 && $c0 <= 013) {
            return addprefix($prefix, ...range($c1, $c1 + 7));
        } else if (($c0 & ~013) == 0144) {
            return addprefix($prefix, $c1, $c1 | 2);
        } else if ($c0 == 0330) {
            return addprefix($prefix, ...range($c1, $c1 + 15));
        } else if ($c0 == 0 || $c0 == 0340) {
            return $prefix;
        } else if (($c0 & ~3) == 0260 || $c0 == 0270 ||
            ($c0 & ~3) == 0240 || $c0 == 0250) {
            var $c, $m, $wlp;
            $m = codes.shift();
            $wlp = codes.shift();
            $c = ($m >> 6);
            $m = $m & 31;
            $prefix += vex_class[$c] + hexstr($m) + ($wlp & 3).toString(16);
            if ($c0 < 0260) {
                var $tuple = codes.shift();
            }
        } else if ($c0 >= 0172 && $c0 <= 173) {
            codes.shift();      // Skip is4 control byte
        } else {
            // We really need to be able to distinguish "forbidden"
            // and "ignorable" codes here
        }
    }
    return $prefix;

}
return codeTree;
import { flag_byname, insns_flag_values } from "./insns-iflags.mjs";
var 初始化指令集 = function (archtype = "386", call) {
    archtype = archtype.toUpperCase();
    var flag = flag_byname[archtype];
    if (!flag) throw `核心类型不支持${archtype}`;
    var n = flag[0];
    var i = n >> 5;
    var f = 1 << (n & 31);
    for (var k in insns) {
        let op = insns[k];
        op = op.filter(o => {
            var flags = insns_flag_values[o.flagsindex];
            if (flags[i] !== f) return false;
            return true;
        })
        if (!op.length) continue;
        k = k.toLowerCase();
        call(k, op);
    }
};

class x86 {
    #初始化寄存器() {
        var create64 = function () {
            var r64 = new BigInt64Array(1);
            var r32 = new Uint32Array(r64.buffer, 0, 1);
            var r16 = new Uint16Array(r32.buffer, 0, 1);
            var r8l = new Uint8Array(r16.buffer, 0, 1);
            var r8h = new Uint8Array(r16.buffer, 1, 1);
            return [r8h, r8l, r16, r32, r64];
        }
        var reg = this;
        var init = function (names) {
            var rs = create64();
            while (names.length) {
                reg[names.pop().toUpperCase()] = rs.pop();
            }
        }
        "ABCD".split('').forEach(a => {
            var names = `AH,AL,AX,EAX,RAX`.replace(/A/g, a).split(',');
            init(names);
        })
        "BP,SI,DI".split(',').forEach(a => {
            var names = `SL,S,ES,RS`.replace(/S/g, a).split(',');
            init(names);
        });
        "8,9,10,11,12,13,14,15".split(",").forEach(k => {
            var names = `r8b,r8w,r8d,r8`.replace(/8/g, k).split(',');
            init(names);
        });
    }
    #执行指令码(code, arg1, arg2) {
    }
    #执行机器码() {
    }
    constructor(archtype) {
        this.#初始化寄存器();
        初始化指令集(archtype, function (k, op) {
            Object.defineProperty(this, k, {
                get: function () {
                    return op;
                }
            })
        });
    }
}
class 狸猫 {
    static flag_byname = flag_byname;
    static getInsns(archtype) {
        var t = {};
        初始化指令集(archtype, (k, op) => t[k] = op);
        return t;
    }

    constructor(cpu = new x86("386")) {
        this.cpu = cpu;
        this.mem = [];
    }
}

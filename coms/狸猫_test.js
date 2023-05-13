var basepath = path.join(__dirname, "../mbasm/");
var includepath = [path.join(basepath, "coms"), path.join(basepath, 'masm32/include')];
var data = fs.readFileSync(path.join(basepath, "apps/blink.asm")).toString().replace(/^\s*\..*$/mg, '');
var asm2ia32 = 狸猫.asm2ia32;
data = data.replace(/^\s*include\s+([\s\S]*?)\s*$/mg, function (_, inc) {
    inc = strings.decode(inc);
    var found = null;
    for (var p of includepath) {
        var temp = path.join(p, inc);
        if (fs.existsSync(temp)) {
            found = temp;
            break;
        }
    }
    if (!found) throw `未发现文件${inc}`;
    return fs.readFileSync(found);
});
var lm = new 狸猫;
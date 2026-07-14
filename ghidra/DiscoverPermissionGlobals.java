import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DiscoverPermissionGlobals extends GhidraScript {
    DecompInterface decomp;

    String decompile(Function f) throws Exception {
        DecompileResults res = decomp.decompileFunction(f, 60, new ConsoleTaskMonitor());
        return res.decompileCompleted() ? res.getDecompiledFunction().getC() : null;
    }

    LinkedHashSet<Long> gateGlobals(Function f) {
        LinkedHashSet<Long> addrs = new LinkedHashSet<>();
        boolean hasAnd = false;
        InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext()) {
            Instruction insn = it.next();
            String mnem = insn.getMnemonicString();
            if (mnem.equals("ldrb")) {
                for (Reference r : insn.getReferencesFrom()) {
                    addrs.add(r.getToAddress().getOffset());
                }
            }
            if (mnem.equals("and"))
                hasAnd = true;
        }
        return (hasAnd && !addrs.isEmpty()) ? addrs : new LinkedHashSet<>();
    }

    @Override
    public void run() throws Exception {
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        Address strAddr = null;
        DataIterator it = currentProgram.getListing().getDefinedData(true);
        while (it.hasNext()) {
            Data d = it.next();
            if ("HasInternalPermission".equals(d.getValue())) {
                strAddr = d.getAddress();
                break;
            }
        }
        if (strAddr == null) {
            println("RESULT: STRING_NOT_FOUND");
            return;
        }
        println("found string at 0x" + strAddr);

        Function bestGate = null;
        LinkedHashSet<Long> bestGlobals = null;
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(strAddr);
        while (refs.hasNext()) {
            Function registrar = getFunctionContaining(refs.next().getFromAddress());
            if (registrar == null)
                continue;
            String regText = decompile(registrar);
            if (regText == null)
                continue;

            for (String line : regText.split("\n")) {
                if (!line.contains("HasInternalPermission"))
                    continue;
                Matcher tok = Pattern.compile("(thunk_)?FUN_[0-9a-fA-F]+").matcher(line);
                while (tok.find()) {
                    String name = tok.group();
                    List<Function> cands = getGlobalFunctions(name);
                    if (cands.isEmpty() && name.startsWith("thunk_")) {
                        cands = getGlobalFunctions(name.substring("thunk_".length()));
                    }
                    for (Function cand : cands) {
                        Function real = cand;
                        if (real.isThunk()) {
                            Function target = real.getThunkedFunction(true);
                            if (target != null)
                                real = target;
                        }
                        LinkedHashSet<Long> globals = gateGlobals(real);
                        if (!globals.isEmpty()) {
                            println("candidate gate: " + name + " -> " + real.getName() + " @ " + real.getEntryPoint());
                            bestGate = real;
                            bestGlobals = globals;
                        }
                    }
                }
            }
        }

        if (bestGate == null) {
            println("RESULT: GATE_NOT_FOUND");
            return;
        }

        StringBuilder sb = new StringBuilder();
        for (Long a : bestGlobals) {
            if (sb.length() > 0)
                sb.append(",");
            sb.append(Long.toHexString(a));
        }
        println("RESULT: GLOBALS=" + sb);
    }
}

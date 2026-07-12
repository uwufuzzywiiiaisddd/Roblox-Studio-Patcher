import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
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

    boolean looksLikeGate(String c) {
        if (c == null) return false;
        Matcher m = Pattern.compile("DAT_[0-9a-fA-F]+").matcher(c);
        int hits = 0;
        while (m.find()) hits++;
        return hits >= 1 && c.contains("&");
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
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(strAddr);
        while (refs.hasNext()) {
            Function registrar = getFunctionContaining(refs.next().getFromAddress());
            if (registrar == null) continue;
            String regText = decompile(registrar);
            if (regText == null) continue;

            for (String line : regText.split("\n")) {
                if (!line.contains("HasInternalPermission")) continue;
                Matcher tok = Pattern.compile("(thunk_)?FUN_[0-9a-fA-F]+").matcher(line);
                while (tok.find()) {
                    String name = tok.group();
                    List<Function> cands = getGlobalFunctions(name);
                    if (cands.isEmpty() && name.startsWith("thunk_")) {
                        cands = getGlobalFunctions(name.substring("thunk_".length()));
                    }
                    for (Function cand : cands) {
                        String candText = decompile(cand);
                        if (looksLikeGate(candText)) {
                            println("candidate gate: " + name + " @ " + cand.getEntryPoint());
                            println(candText);
                            bestGate = cand;
                        }
                    }
                }
            }
        }

        if (bestGate == null) {
            println("RESULT: GATE_NOT_FOUND");
            return;
        }

        LinkedHashSet<String> addrs = new LinkedHashSet<>();
        Matcher m = Pattern.compile("DAT_([0-9a-fA-F]+)").matcher(decompile(bestGate));
        while (m.find()) addrs.add(m.group(1));
        println("RESULT: GLOBALS=" + String.join(",", addrs));
    }
}

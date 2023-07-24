/*
 * Copyright 2021 Astra Security
 */
package org.zaproxy.addon.astrascripts;

import java.io.File;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;

/** Astra Scripts Extension */
public class ExtensionAstraScripts extends ExtensionAdaptor {

    public static final String NAME = "ExtensionAstraScripts";

    protected static final String PREFIX = "astraScripts";

    private File scriptDir = new File(Constant.getZapHome(), "astra-scripts");
    private static final Logger LOG = LogManager.getLogger(ExtensionAstraScripts.class);
    private ExtensionScript extScript;

    @Override
    public void postInit() {
        addScriptsFromDir(scriptDir);
    }

    public ExtensionAstraScripts() {
        super(NAME);
        setI18nPrefix(PREFIX);
    }

    private void addScriptsFromDir(File dir) {
        LOG.debug("Adding scripts from dir: " + dir.getAbsolutePath());
        int addedScripts = 0;
        for (ScriptType type : getExtScript().getScriptTypes()) {
            File typeDir = new File(dir, type.getName());
            if (typeDir.exists()) {
                for (File f : typeDir.listFiles()) {
                    // Assuming all script are written in JS and for GraalVM
                    String engineName = "Graal.js";

                    try {
                        if (f.canWrite()) {
                            // NOTE: An existing script with the same name will be overwritten
                            String scriptName = f.getName();
                            LOG.debug("Loading script " + scriptName);
                            ScriptWrapper sw =
                                    new ScriptWrapper(
                                            scriptName,
                                            "",
                                            getExtScript().getEngineWrapper(engineName),
                                            type,
                                            true,
                                            f);
                            getExtScript().loadScript(sw);
                            getExtScript().addScript(sw, false);
                        }
                        addedScripts++;
                    } catch (Exception e) {
                        LOG.error(e.getMessage(), e);
                    }
                }
            }
        }
        LOG.debug("Added {} scripts.", addedScripts);
    }

    private ExtensionScript getExtScript() {
        if (extScript == null) {
            extScript =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        }
        return extScript;
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();
        getExtScript().removeScriptsFromDir(scriptDir);
    }
}

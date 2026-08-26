package probe

import (
	"encoding/json"
	"fmt"
	"strings"
)

// DefaultTimeoutSec is the default timeout for runtime probes.
const DefaultTimeoutSec = 15

// GenerateNodeProbeScript generates a bash snippet that creates and runs
// a Node.js probe script. The probe require()s/import()s each package
// to trigger runtime behavior under strace monitoring, then optionally
// invokes package CLI bin entries with --help.
func GenerateNodeProbeScript(packages []string, timeoutSec int) string {
	if len(packages) == 0 {
		return ""
	}
	if timeoutSec <= 0 {
		timeoutSec = DefaultTimeoutSec
	}

	pkgJSON, _ := json.Marshal(packages)

	js := fmt.Sprintf(
		`var _timer=setTimeout(function(){console.error("GOAUDIT_PROBE_TIMEOUT");process.exit(124)},%d);`+
			`var _fs=require("fs");`+
			`var _path=require("path");`+
			`var _cp=require("child_process");`+
			`var _pkgs=%s;`+
			`async function _tryWorkspace(pkg){try{var p=JSON.parse(_fs.readFileSync("/workspace/package.json","utf8"));`+
			`if(p&&p.name===pkg){require("/workspace");console.error("GOAUDIT_PROBE_IMPORT_OK:"+pkg);await _probeBins("/workspace");return true;}}catch(e){}return false;}`+
			`function _resolvePkgRoot(pkg){try{return _path.dirname(require.resolve(pkg+"/package.json"));}catch(e){`+
			`try{var d=_path.dirname(require.resolve(pkg));for(var g=0;g<20;g++){if(_fs.existsSync(_path.join(d,"package.json")))return d;`+
			`var up=_path.dirname(d);if(up===d)break;d=up;}return null;}catch(e2){return null;}}}`+
			`function _binEntries(pkgRoot){try{var pj=JSON.parse(_fs.readFileSync(_path.join(pkgRoot,"package.json"),"utf8"));`+
			`if(!pj||!pj.bin)return[];if(typeof pj.bin==="string")return[pj.bin];return Object.keys(pj.bin).map(function(k){return pj.bin[k];});}catch(e){return[];}}`+
			`var _deadline=Date.now()+%d;`+
			`function _remaining(){var r=_deadline-Date.now();if(r<=0){clearTimeout(_timer);console.error("GOAUDIT_PROBE_TIMEOUT");process.exit(124);}return r;}`+
			`function _runBin(bin,args){return new Promise(function(resolve){var settled=false;var child;`+
			`try{child=_cp.spawn(bin,args,{env:process.env,stdio:"ignore"});}catch(e){resolve(false);return;}`+
			`var t=setTimeout(function(){if(!settled){settled=true;try{child.kill("SIGKILL");}catch(e){}resolve(false);}},_remaining());`+
			`child.on("error",function(){if(!settled){settled=true;clearTimeout(t);resolve(false);}});`+
			`child.on("exit",function(code,signal){if(!settled){settled=true;clearTimeout(t);resolve(signal===null&&code===0);}});});}`+
			`async function _probeBins(pkg){var root=_resolvePkgRoot(pkg);if(!root)return;`+
			`var entries=_binEntries(root);for(var i=0;i<entries.length;i++){var rel=entries[i];var bin=_path.join(root,rel);`+
			`try{if(!_fs.existsSync(bin))continue;`+
			`if(await _runBin(bin,["--help"])){console.error("GOAUDIT_PROBE_BIN_OK:"+pkg+":"+rel);}`+
			`else{console.error("GOAUDIT_PROBE_BIN_FAIL:"+pkg+":"+rel);}}catch(e){console.error("GOAUDIT_PROBE_BIN_FAIL:"+pkg+":"+rel);}}}`+
			`(async function(){for(var i=0;i<_pkgs.length;i++){`+
			`try{require(_pkgs[i]);console.error("GOAUDIT_PROBE_IMPORT_OK:"+_pkgs[i]);await _probeBins(_pkgs[i]);}catch(e){`+
			`try{await import(_pkgs[i]);console.error("GOAUDIT_PROBE_IMPORT_OK:"+_pkgs[i]);await _probeBins(_pkgs[i]);}`+
			`catch(e2){if(!(await _tryWorkspace(_pkgs[i]))){console.error("GOAUDIT_PROBE_IMPORT_FAILED:"+_pkgs[i]+":"+((e2&&e2.code)||"ERR"));}}}}`+
			`console.error("GOAUDIT_PROBE_LIMITATION:import_and_bin_help_only");`+
			`clearTimeout(_timer);process.exit(0);})().catch(function(e){console.error("GOAUDIT_PROBE_IMPORT_FAILED:probe:"+((e&&e.code)||"ERR"));process.exit(1)});`,
		timeoutSec*1000, string(pkgJSON), timeoutSec*1000)

	var b strings.Builder
	b.WriteString("\ncat << 'GOAUDIT_PROBE_EOF' > /workspace/.goaudit_probe.js\n")
	b.WriteString(js + "\n")
	b.WriteString("GOAUDIT_PROBE_EOF\n")
	b.WriteString(fmt.Sprintf("NODE_PATH=/workspace/node_modules timeout %d node /workspace/.goaudit_probe.js || true\n", timeoutSec+2))
	return b.String()
}

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
		`var _timer=setTimeout(function(){_killChildren();console.error("GOAUDIT_PROBE_TIMEOUT");process.exit(124)},%d);`+
			`var _fs=require("fs");`+
			`var _path=require("path");`+
			`var _url=require("url");`+
			`var _cp=require("child_process");`+
			`var _pkgs=%s;`+
			`var _children=[];`+
			`function _killChildren(){for(var i=0;i<_children.length;i++){try{_children[i].kill("SIGKILL");}catch(e){}}_children=[];}`+
			`async function _tryWorkspace(pkg){var p;try{p=JSON.parse(_fs.readFileSync("/workspace/package.json","utf8"));}catch(e){return false;}`+
			`if(!p||p.name!==pkg)return false;var loaded=false;try{require("/workspace");loaded=true;}catch(e1){`+
			// Fallback entries are only valid when the manifest declares no main;
			// a present-but-broken main must not be masked by index.js.
			`var cands=[];if(typeof p.main==="string"){cands.push(p.main);}else{cands.push("index.js","index.mjs");}`+
			`for(var i=0;i<cands.length&&!loaded;i++){try{await import(_url.pathToFileURL(_path.resolve("/workspace",cands[i])).href);loaded=true;}catch(e2){}}}`+
			`if(loaded){console.error("GOAUDIT_PROBE_IMPORT_OK:"+pkg);}else{console.error("GOAUDIT_PROBE_IMPORT_FAILED:"+pkg+":ERR_LOAD");}`+
			`try{await _probeBins("/workspace",pkg);}catch(e){}return true;}`+
			`function _resolvePkgRoot(pkg){`+
			// Installed packages live under NODE_PATH; check there first so root
			// resolution does not depend on the package exporting ./package.json.
			`var direct=_path.join("/workspace/node_modules",pkg);`+
			`if(_fs.existsSync(_path.join(direct,"package.json")))return direct;`+
			`try{return _path.dirname(require.resolve(pkg+"/package.json"));}catch(e){`+
			`try{var d=_path.dirname(require.resolve(pkg));var first=null;`+
			`for(var g=0;g<20;g++){`+
			`if(_fs.existsSync(_path.join(d,"package.json"))){`+
			`try{var pj=JSON.parse(_fs.readFileSync(_path.join(d,"package.json"),"utf8"));`+
			`if(pj&&pj.name===pkg)return d;if(first===null)first=d;}catch(pe){}}`+
			`var up=_path.dirname(d);if(up===d)break;d=up;}`+
			`return first;}catch(e2){return null;}}}`+
			`function _binEntries(pkgRoot){try{var pj=JSON.parse(_fs.readFileSync(_path.join(pkgRoot,"package.json"),"utf8"));`+
			`if(!pj||!pj.bin)return[];if(typeof pj.bin==="string")return[pj.bin];return Object.keys(pj.bin).map(function(k){return pj.bin[k];});}catch(e){return[];}}`+
			`var _deadline=Date.now()+%d;`+
			`function _remaining(){var r=_deadline-Date.now();if(r<=0){clearTimeout(_timer);_killChildren();console.error("GOAUDIT_PROBE_TIMEOUT");process.exit(124);}return r;}`+
			`function _runBin(bin,args){return new Promise(function(resolve){var settled=false;var child;var r=_remaining();`+
			`try{child=_cp.spawn(bin,args,{env:process.env,stdio:"ignore"});}catch(e){resolve(false);return;}`+
			`_children.push(child);`+
			`var t=setTimeout(function(){if(!settled){settled=true;try{child.kill("SIGKILL");}catch(e){}resolve(false);}},r);`+
			`child.on("error",function(){var i=_children.indexOf(child);if(i>=0)_children.splice(i,1);if(!settled){settled=true;clearTimeout(t);resolve(false);}});`+
			`child.on("exit",function(code,signal){var i=_children.indexOf(child);if(i>=0)_children.splice(i,1);if(!settled){settled=true;clearTimeout(t);resolve(signal===null&&code===0);}});});}`+
			`async function _probeBins(root,label){label=label||root;`+
			`var entries=_binEntries(root);for(var i=0;i<entries.length;i++){var rel=entries[i];var bin=_path.join(root,rel);`+
			`try{if(!_fs.existsSync(bin)){console.error("GOAUDIT_PROBE_BIN_FAIL:"+label+":"+rel+":missing");continue;}`+
			`if(await _runBin(bin,["--help"])){console.error("GOAUDIT_PROBE_BIN_OK:"+label+":"+rel);}`+
			`else{console.error("GOAUDIT_PROBE_BIN_FAIL:"+label+":"+rel);}}catch(e){console.error("GOAUDIT_PROBE_BIN_FAIL:"+label+":"+rel);}}}`+
			`(async function(){for(var i=0;i<_pkgs.length;i++){`+
			// Bin probing runs from the resolved installed root regardless of
			// whether the entry point imports, so packages that fail to load
			// still get their declared CLI bins exercised.
			`var _ok=false,_err=null,_root=null;`+
			`try{require(_pkgs[i]);_ok=true;}catch(e){_err=e;}`+
			`if(!_ok){try{await import(_pkgs[i]);_ok=true;}catch(e2){_err=e2;}}`+
			`if(_ok){console.error("GOAUDIT_PROBE_IMPORT_OK:"+_pkgs[i]);_root=_resolvePkgRoot(_pkgs[i]);if(_root){try{await _probeBins(_root,_pkgs[i]);}catch(e3){}}}`+
			`else if(!(await _tryWorkspace(_pkgs[i]))){console.error("GOAUDIT_PROBE_IMPORT_FAILED:"+_pkgs[i]+":"+((_err&&_err.code)||"ERR"));`+
			`_root=_resolvePkgRoot(_pkgs[i]);if(_root){try{await _probeBins(_root,_pkgs[i]);}catch(e3){}}}}`+
			`console.error("GOAUDIT_PROBE_LIMITATION:import_and_bin_help_only");`+
			`clearTimeout(_timer);process.exit(0);})().catch(function(e){_killChildren();console.error("GOAUDIT_PROBE_IMPORT_FAILED:probe:"+((e&&e.code)||"ERR"));process.exit(1)});`,
		timeoutSec*1000, string(pkgJSON), timeoutSec*1000)

	var b strings.Builder
	// .cjs extension: the probe uses require(), and for workspaces with
	// "type": "module" a .js file would be loaded as ESM and crash.
	b.WriteString("\ncat << 'GOAUDIT_PROBE_EOF' > /workspace/.goaudit_probe.cjs\n")
	b.WriteString(js + "\n")
	b.WriteString("GOAUDIT_PROBE_EOF\n")
	fmt.Fprintf(&b, "NODE_PATH=/workspace/node_modules timeout %d node /workspace/.goaudit_probe.cjs || true\n", timeoutSec+2)
	return b.String()
}

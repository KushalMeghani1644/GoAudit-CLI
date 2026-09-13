## Changelog
* b0b4f30bb3495e2f6034ddb355cf057d400ff5d5 Add CI to validate whether sandbox installs prequisites, and fix warnings
* 12750050206b265a59069633bcd1a6b12c14a872 Add better error messages when sandbox fails, and hints to resolve them
* ca1870e52ab0471faed17b640ca326f47c6ec007 Add demo video
* 147ce4781ef64240aac9244ac69a8e0d010b413d Add formatting
* b1f6b198fe3ea143a0b42dd9ec57e8fb5fe3d22e Add pnpm and bun to the sandbox
* b9864aba223a5f3a58528e9598ec670020144353 Add pnpm, bun, support. Refine the checking mechanism for curl | sh
* c0418fa791c6719ff08269f61f946ad9a0d48dc4 Add readme
* 8ae845adf77a092229131d3f6bf03b472f2b151a Add robust project-level deps scanning
* 3a8fd91869d23fbaae8e07be653e33cf677ef569 Create LICENSE
* b89ceb576c7ecf178ff089c1781e9e49217f4815 Fix CI failing
* 59e04396b5a8e1a45d916ed5d8c18b7884147a00 Fix CI failing
* b17e3415c8cc444f02a6ec9d4ca684c89aa223ad Fix bugs and addres review
* e2cc240789a7d17368bb3020a69eb2f5ca10a92e Fix commands failing
* 6a4548b6f357299a7ad693dac676159be19f2bb0 Fix demo GIF
* ca3030b057a91d4ce77cebafc32964717a6f2377 Fix dynamic scanning bugs
* f021920bf561b799cc4f244fd7201ff0d7b75f59 Fix false positives
* f18e649dd2afd61dbba3a52a11c848171e52981d Fix favicon
* 6bfbfbfce4634ff81d8e1935d000322505f75f3d Fix formatting
* f3e13c41218c626681bf8ad768ce4553cb682f2b Fix networking issues and harden security testing
* fcc3f818f7c83685944f5fdab2dc868078fe9146 Fix runsc
* 722f7edcec21d44c4b2b790179fda7cb68e24709 Fix runsc image pulling, and add caching to improve performance
* 6ecb7f40ef35222880ae0a7eeb312ce081a28d45 Fix runsc warnings
* 5a54d51501e9d7c612b488d20fa7fa3d664145d8 GoAudit 0.1.0 sandbox and audit npm install or curl | sh and catch credential theft
* a4e2ac1429759f63688b458102be2570962265b9 Implement better output formatting with colored output
* 9712add86c86b3a2a6b73cbb813ad6ed06fd0645 Implement features for catching privelege escalation
* 5b9cb4e6abadc38bddd8c82c6c40b728bf9c4260 Implemented the dynamic scanning fixes across parser, probe, sandbox wrapper, reporting, and pipeline health.
* c1815ce076367376dc79ee7121accecdbee1899d Improve README
* aa2dd0610cebc6dcd17012c18dcb668f79e2b36c Improve README
* 72471f9d2941ed3f6d7b74993a72ccc288040d83 Improve dynamic scanning and IPv6 detection
* 1194380d277b474ef20d91ad67286420cc973ea1 KUS-49: flatten Go module path to github.com/goaudit/cli
* 4e120d20261bf3d8979c83fb3218816309eb5840 KUS-49: gofmt import alignment after module rename
* 7ac9d86a10fdc2117528a7ef6f43bbeb4cf4732d KUS-49: keep module path, add Homebrew tap and mise install via GoReleaser
* 8590ab906a956c4c68617bb4bc151b99eb4e7661 KUS-50: Require gVisor for sandbox scans (#19)
* d21714a35bd8a57cf392397d4621614564cf7bb0 KUS-51 Keep E2E npm config install-only
* 06b99b5350e67adc2c762a84fea2457044695de6 KUS-51 Scope scans to JavaScript installs
* fe1dcec3d52b24e716b461450c10a1190f6b9b7e KUS-51 Update install-only E2E command
* 663c963f12eaf9b5c9b15c6c3dc5d5be6adef5e8 Merge branch 'main' into fix/audit-04-sandbox-cache
* a7f7178c9fc62ffb98ba104e8579f7ebd989ca94 Merge branch 'main' into fix/audit-04-sandbox-cache
* c852eab4bcfa8f761788d19a537c725ae5e2d2d5 Merge branch 'main' into fix/audit-06-project-deps
* 4586b2410544c9ba13e67486250ac887dbe61cea Merge branch 'main' into fix/audit-06-project-deps
* d6382cc09a452b6bd8f5050e85a1403b1db42176 Merge branch 'main' into fix/audit-08-pipeline-policy
* 9f0ee0e671be1fe0cdc2d9429ee16c9c4b8e0829 Merge branch 'main' into fix/audit-10-sandbox-errors
* 2fb360dacd03325fa0bb3437ff37805786e3aded Merge branch 'main' of github.com:KushalMeghani1644/GoAudit
* a3fefb46730fdf75476bdfee493efb9208fe7640 Merge pull request #1 from KushalMeghani1644/cache
* d4664a2f7273b47ae33dca7c2a4fd54770049e99 Merge pull request #10 from KushalMeghani1644/fix/audit-08-pipeline-policy
* 8493d5c934630ac9addac472e523cf4253567c58 Merge pull request #11 from KushalMeghani1644/fix/audit-09-docs
* 21f081186f2a9b35ce4a639ae02edc4816922f2d Merge pull request #12 from KushalMeghani1644/fix/audit-10-sandbox-errors
* f09c4da0be6eec94a0427bc03bdb6dbeb689bc49 Merge pull request #13 from KushalMeghani1644/fix/readme-package-managers
* 656db86712d2a35cbbdc1f858e9542cdcaa6c84a Merge pull request #14 from KushalMeghani1644/fix/kus-67-honeypot-credentials
* 8ee9782c3ec5598f4d33145ed72704ec76919683 Merge pull request #15 from KushalMeghani1644/fix/kus-7-privilege-escalation-tests
* 9db969b8954e2d7a7f8f7cfe1ae3aace07acdb42 Merge pull request #16 from KushalMeghani1644/kushalmeghani108/kus-52-remove-run-as-root-flag
* 86a086cf1a3ba0bd43ab62a44e8679fd1014dc45 Merge pull request #17 from KushalMeghani1644/kushalmeghani108/kus-70-scan-project-flags-clean-installs-as-malicious-package
* 4eb568a7ef7d5616e8a2d8cdfe99b2db5e9f3d70 Merge pull request #18 from KushalMeghani1644/kus-51-scope-javascript-ecosystem
* 942780d1da007733a27035311414c174903cbf51 Merge pull request #2 from KushalMeghani1644/dynamic-fix
* a62c9c7c6c54ea27edcdf6a323610a8ee3c68270 Merge pull request #4 from KushalMeghani1644/fix/audit-02-ssrf-remote-scripts
* a8caa7cefff9d577b25072ee7d5dc6e6334e1551 Merge pull request #5 from KushalMeghani1644/fix/audit-03-parser-verdict
* 9d08c4c6648f6b2a18b2843bcb032d774f3cf0be Merge pull request #6 from KushalMeghani1644/fix/audit-04-sandbox-cache
* c774ef3cb39c202ef436b1dfea5e4d8eb36b3ae9 Merge pull request #7 from KushalMeghani1644/fix/audit-05-npm-static
* 9528ecfd9bcd68c56884ddc9f51ac425932315d6 Merge pull request #8 from KushalMeghani1644/fix/audit-06-project-deps
* 5d9236e4daca940d4b6712bf832060328e464f01 Merge pull request #9 from KushalMeghani1644/fix/audit-07-probe
* 95ca33e3fb1576952ccdf223770a658d128841ca Merge remote-tracking branch 'origin/main' into HEAD
* c82b82a9622324833e2d261a093cca9bc9876033 Merge remote-tracking branch 'origin/main' into HEAD
* ce64b2b44f212be2fd1ac98ee0c50353c4aada1d Merge remote-tracking branch 'origin/main' into fix/audit-04-sandbox-cache
* b0e6222d077048531f0b695a4b325cfc665c41b5 Merge remote-tracking branch 'origin/main' into fix/audit-06-project-deps
* 52d427ff266361895d36d14ca23a1047f085eae4 Merge remote-tracking branch 'origin/main' into kushalmeghani108/kus-70-scan-project-flags-clean-installs-as-malicious-package
* f88016fa8cdd1bf855eee08a0764b1b28349f632 Remove problems.md
* 599138566ae08533ceb385c3f15cd7bc387a91bd Replace ImageInspectWithRaw with ImageInspect
* b141c8295044190e0886a9f707de385d9a28d36d Resolve conflict
* de7e223d1677d55b642fa9b64e8fcffc83271977 Revert "KUS-49: flatten Go module path to github.com/goaudit/cli"
* 8238b30074f7ad02830f62bd0dccd57170c5368b Revert "KUS-49: gofmt import alignment after module rename"
* 72547c1d99399584404945caae05783956911753 Update GoAudit fix registry host clarification, add --verbose flag, add prettier formatting
* bdabc82e7eb08efca32e40977d130394da480814 Update GoAudit, fix gVisor runsc sandboxing, add proper fallback to runc, and add CI workflows
* 7090a6a401fe95ba1cbb7ff868cff318f625360c Update README.md
* eae020e9686aee0c7c3a7322406d5b911503cf8c Update download link
* 1b6b54f6c5755f9322bb5b650e26a4daf3842c52 Update readme
* 6839eafc7f4f9befbc1ab2c3385ab8991e863301 Update readme
* ae7fda5706a4a99fa16ebef4b82337a6b202a4f0 chore: remove committed build artifacts and ignore local binaries
* d7b3b13354040cdc09904d39125e324f3fa0e92a fix dynamic sandbox detection, and package analysis
* 0028fa75d4cf024299a13e11b37108fa13823e31 fix formatting
* c5ee23d4ea4874b3fdeb62509011c2044e741073 fix minor issues
* 53ed82215cc4036975d3ef004369d847dd06f458 fix(analyzer): resolve npm aliases and preserve wrappers
* cb340b3a525ac8b7525b0471c2cb2cc4495bfc5d fix(analyzer): resolve npm aliases in ExtractPackageNamesFromCommand
* 66def880a56e4c85d5edcd967733afed9ea91553 fix(analyzer): stop at ||, report partial parse coverage, resolve v-prefixed versions
* e0e4788659e0eb98bfc4766e522b4b102102f81b fix(analyzer): tokenize unspaced shell separators, consume long sudo option values
* ea2d1d9010f189ebe45c6484633d13bf12b74ee3 fix(analyzer): treat escaped newlines as shell line continuations
* e3c2b71405569a6e930d4ab75edda71648d80be7 fix(analyzer): unquote words while tokenizing, before separator splitting
* a90b5953857fb1b49d766d7a3b35d1b6fb9838fc fix(analyzer): version-aware registry checks and safer command parsing
* 9c3771a527a3df394f64fbd9a1518e50ae9943b1 fix(ci): isolate privilege escalation fixtures
* 4a8c6cb02f299bdef362d8a5836d2745ab6d2040 fix(cli): enforce pinned pnpm version
* 9b1a43051232dc385259a435238027e39d2b25a9 fix(cli): guard typed diagnostic errors
* f46e357b2c8ad4c655499b71c191dc37fa3d1789 fix(cli): honor network/offline for host static analysis and fail-on
* bd9f238471e68e5bf1b67cd2864311a2c260c21c fix(detection): cover privilege escalation attempts
* 78b956ab7ee28f2474ccab070375ae0c14477997 fix(detection): refine privilege attempt classification
* a52aab1d47967fdd1ef99d54b7a9a706684f0274 fix(parser): handle failed mounts and fd reuse
* 0c0ed9734e9c7c6efa60c513f5211ca786fbf268 fix(parser): remove passwd false positives and require send for DATA_EXFIL
* bca94d2bd17d34630cc6896363855a9a27907db9 fix(parser): tighten capability and exfil verdicts
* 8800a35ad9f4fa0cdd0cfaa3d778a5a95befebfe fix(probe): exercise package bins and document probe limits
* 3278d473a40184916c526374abe15b0881e2b940 fix(probe): load ESM workspaces via dynamic import and kill bin children on timeout
* 586c5c6e71bd0f7a0021761fdfca360d814c42df fix(probe): prefer manifest matching the package name during root fallback walk
* d50208fb63cebea32cd179ca6ecd6ef86eded443 fix(probe): probe bins on workspace import and resolve package root via upward walk
* 755d504cd7641312b0c3ffc4c8abb4b55e2bb514 fix(probe): report missing declared bins as failures
* e67f70924a380e227ac4022b289016d414078ee4 fix(probe): resolve package root before bin probing and honor broken main
* bb881ab30960964e70fc6ca5d21f036209b8cfdc fix(probe): use async bin probes with shared deadline and check exit status
* a995fc9720a23651c6613ee0946b16474a761628 fix(project): address lockfile parser review
* d5c5cee8164b67ba2ad680cfb75d3dc571e66f3c fix(project): honor selected lockfile manager
* a89e0b5db8f5e48d5c4a04d1df8026fd67bc056e fix(project): transitive deps from npm/pnpm/bun lockfiles and workspaces
* 9e44e5a2d2968eb0136e011eaa19f20af27b429a fix(sandbox): address honeypot review feedback
* 292384aca05e28ca07c0f288dfda39d973820283 fix(sandbox): isolate package manager config from npmrc honeypot
* 04a31f60060f5eaacf80d5f3b73bab5b4114f82e fix(sandbox): isolate package manager setup config
* 1737299a418b8b9c5bbc83b2c93c8a52631e1b36 fix(sandbox): make honeypot credentials realistic
* 30d3698761e428e98520f7cb82afff51d6f033a4 fix(sandbox): parse registry-qualified floating tags
* ff50837ced997de1747c68a0569628dce4a2e08c fix(sandbox): reject /root as sandbox home and bound guard test timeout
* cb5e2e66d4b2c5e662627db7efe9ab74b7da4b05 fix(sandbox): reset warm containers and fix cache network isolation
* ebf691f6d0969753f0202a66189509a02e0ca151 fix(sandbox): treat untagged image refs as floating and guard home wipe
* 2e6ef6fef0752b650c2b069a23a772d08f0a2678 fix(security): block host-side SSRF in remote script analysis
* f32bc6c4167d523e956eb219919d5e6b243508ad fix(security): resolve remote script SSRF review
* 34f250a32048f1487178a29f98189628e344473a fix(security): stage project trees before sandbox mount (#3)
* a8219fdc7b9128831a397f443232f1c9536d7450 fix: add diagnostic package and gofmt cache tests
* 56dec8da1fd4a5fa96a11913cedcb2363978b6bf fix: drop unused Fatal/diagnostic dependency from report
* b2e0dd2974123195f60ebc3eab54d5b18f7b32a0 fix: remove root sandbox execution mode (KUS-52)
* 7e3797cf970b375b041175c757160e2eda4a620f fix: vendor diagnostic package for lockfile error messages
* b2ddf9223baa59db2083b610b0a30db8984ca8a9 style: gofmt npm analyzer tests for CI
* 6b95dfdf35ad85eb87041f468c7abfee7c993430 style: gofmt parser and explain for CI
* 0e8686102e461b5293fdc7914eced43ea127135c test(sandbox): reject live npmrc config references
* 6a7d5ef1faa6d331b89de1e6c3620739e57364ab test(sandbox): require ssh-keygen for honeypot validation
* 805dcb087e781d5192759a25af4a79bfa0754892 test(sandbox): validate all honeypot credentials

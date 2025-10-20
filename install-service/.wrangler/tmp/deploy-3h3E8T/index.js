var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// node_modules/unenv/dist/runtime/_internal/utils.mjs
// @__NO_SIDE_EFFECTS__
function createNotImplementedError(name) {
  return new Error(`[unenv] ${name} is not implemented yet!`);
}
__name(createNotImplementedError, "createNotImplementedError");
// @__NO_SIDE_EFFECTS__
function notImplemented(name) {
  const fn = /* @__PURE__ */ __name(() => {
    throw /* @__PURE__ */ createNotImplementedError(name);
  }, "fn");
  return Object.assign(fn, { __unenv__: true });
}
__name(notImplemented, "notImplemented");
// @__NO_SIDE_EFFECTS__
function notImplementedClass(name) {
  return class {
    __unenv__ = true;
    constructor() {
      throw new Error(`[unenv] ${name} is not implemented yet!`);
    }
  };
}
__name(notImplementedClass, "notImplementedClass");

// node_modules/unenv/dist/runtime/node/internal/perf_hooks/performance.mjs
var _timeOrigin = globalThis.performance?.timeOrigin ?? Date.now();
var _performanceNow = globalThis.performance?.now ? globalThis.performance.now.bind(globalThis.performance) : () => Date.now() - _timeOrigin;
var nodeTiming = {
  name: "node",
  entryType: "node",
  startTime: 0,
  duration: 0,
  nodeStart: 0,
  v8Start: 0,
  bootstrapComplete: 0,
  environment: 0,
  loopStart: 0,
  loopExit: 0,
  idleTime: 0,
  uvMetricsInfo: {
    loopCount: 0,
    events: 0,
    eventsWaiting: 0
  },
  detail: void 0,
  toJSON() {
    return this;
  }
};
var PerformanceEntry = class {
  static {
    __name(this, "PerformanceEntry");
  }
  __unenv__ = true;
  detail;
  entryType = "event";
  name;
  startTime;
  constructor(name, options) {
    this.name = name;
    this.startTime = options?.startTime || _performanceNow();
    this.detail = options?.detail;
  }
  get duration() {
    return _performanceNow() - this.startTime;
  }
  toJSON() {
    return {
      name: this.name,
      entryType: this.entryType,
      startTime: this.startTime,
      duration: this.duration,
      detail: this.detail
    };
  }
};
var PerformanceMark = class PerformanceMark2 extends PerformanceEntry {
  static {
    __name(this, "PerformanceMark");
  }
  entryType = "mark";
  constructor() {
    super(...arguments);
  }
  get duration() {
    return 0;
  }
};
var PerformanceMeasure = class extends PerformanceEntry {
  static {
    __name(this, "PerformanceMeasure");
  }
  entryType = "measure";
};
var PerformanceResourceTiming = class extends PerformanceEntry {
  static {
    __name(this, "PerformanceResourceTiming");
  }
  entryType = "resource";
  serverTiming = [];
  connectEnd = 0;
  connectStart = 0;
  decodedBodySize = 0;
  domainLookupEnd = 0;
  domainLookupStart = 0;
  encodedBodySize = 0;
  fetchStart = 0;
  initiatorType = "";
  name = "";
  nextHopProtocol = "";
  redirectEnd = 0;
  redirectStart = 0;
  requestStart = 0;
  responseEnd = 0;
  responseStart = 0;
  secureConnectionStart = 0;
  startTime = 0;
  transferSize = 0;
  workerStart = 0;
  responseStatus = 0;
};
var PerformanceObserverEntryList = class {
  static {
    __name(this, "PerformanceObserverEntryList");
  }
  __unenv__ = true;
  getEntries() {
    return [];
  }
  getEntriesByName(_name, _type) {
    return [];
  }
  getEntriesByType(type) {
    return [];
  }
};
var Performance = class {
  static {
    __name(this, "Performance");
  }
  __unenv__ = true;
  timeOrigin = _timeOrigin;
  eventCounts = /* @__PURE__ */ new Map();
  _entries = [];
  _resourceTimingBufferSize = 0;
  navigation = void 0;
  timing = void 0;
  timerify(_fn, _options) {
    throw createNotImplementedError("Performance.timerify");
  }
  get nodeTiming() {
    return nodeTiming;
  }
  eventLoopUtilization() {
    return {};
  }
  markResourceTiming() {
    return new PerformanceResourceTiming("");
  }
  onresourcetimingbufferfull = null;
  now() {
    if (this.timeOrigin === _timeOrigin) {
      return _performanceNow();
    }
    return Date.now() - this.timeOrigin;
  }
  clearMarks(markName) {
    this._entries = markName ? this._entries.filter((e2) => e2.name !== markName) : this._entries.filter((e2) => e2.entryType !== "mark");
  }
  clearMeasures(measureName) {
    this._entries = measureName ? this._entries.filter((e2) => e2.name !== measureName) : this._entries.filter((e2) => e2.entryType !== "measure");
  }
  clearResourceTimings() {
    this._entries = this._entries.filter((e2) => e2.entryType !== "resource" || e2.entryType !== "navigation");
  }
  getEntries() {
    return this._entries;
  }
  getEntriesByName(name, type) {
    return this._entries.filter((e2) => e2.name === name && (!type || e2.entryType === type));
  }
  getEntriesByType(type) {
    return this._entries.filter((e2) => e2.entryType === type);
  }
  mark(name, options) {
    const entry = new PerformanceMark(name, options);
    this._entries.push(entry);
    return entry;
  }
  measure(measureName, startOrMeasureOptions, endMark) {
    let start;
    let end;
    if (typeof startOrMeasureOptions === "string") {
      start = this.getEntriesByName(startOrMeasureOptions, "mark")[0]?.startTime;
      end = this.getEntriesByName(endMark, "mark")[0]?.startTime;
    } else {
      start = Number.parseFloat(startOrMeasureOptions?.start) || this.now();
      end = Number.parseFloat(startOrMeasureOptions?.end) || this.now();
    }
    const entry = new PerformanceMeasure(measureName, {
      startTime: start,
      detail: {
        start,
        end
      }
    });
    this._entries.push(entry);
    return entry;
  }
  setResourceTimingBufferSize(maxSize) {
    this._resourceTimingBufferSize = maxSize;
  }
  addEventListener(type, listener, options) {
    throw createNotImplementedError("Performance.addEventListener");
  }
  removeEventListener(type, listener, options) {
    throw createNotImplementedError("Performance.removeEventListener");
  }
  dispatchEvent(event) {
    throw createNotImplementedError("Performance.dispatchEvent");
  }
  toJSON() {
    return this;
  }
};
var PerformanceObserver = class {
  static {
    __name(this, "PerformanceObserver");
  }
  __unenv__ = true;
  static supportedEntryTypes = [];
  _callback = null;
  constructor(callback) {
    this._callback = callback;
  }
  takeRecords() {
    return [];
  }
  disconnect() {
    throw createNotImplementedError("PerformanceObserver.disconnect");
  }
  observe(options) {
    throw createNotImplementedError("PerformanceObserver.observe");
  }
  bind(fn) {
    return fn;
  }
  runInAsyncScope(fn, thisArg, ...args) {
    return fn.call(thisArg, ...args);
  }
  asyncId() {
    return 0;
  }
  triggerAsyncId() {
    return 0;
  }
  emitDestroy() {
    return this;
  }
};
var performance = globalThis.performance && "addEventListener" in globalThis.performance ? globalThis.performance : new Performance();

// node_modules/@cloudflare/unenv-preset/dist/runtime/polyfill/performance.mjs
globalThis.performance = performance;
globalThis.Performance = Performance;
globalThis.PerformanceEntry = PerformanceEntry;
globalThis.PerformanceMark = PerformanceMark;
globalThis.PerformanceMeasure = PerformanceMeasure;
globalThis.PerformanceObserver = PerformanceObserver;
globalThis.PerformanceObserverEntryList = PerformanceObserverEntryList;
globalThis.PerformanceResourceTiming = PerformanceResourceTiming;

// node_modules/unenv/dist/runtime/node/console.mjs
import { Writable } from "node:stream";

// node_modules/unenv/dist/runtime/mock/noop.mjs
var noop_default = Object.assign(() => {
}, { __unenv__: true });

// node_modules/unenv/dist/runtime/node/console.mjs
var _console = globalThis.console;
var _ignoreErrors = true;
var _stderr = new Writable();
var _stdout = new Writable();
var log = _console?.log ?? noop_default;
var info = _console?.info ?? log;
var trace = _console?.trace ?? info;
var debug = _console?.debug ?? log;
var table = _console?.table ?? log;
var error = _console?.error ?? log;
var warn = _console?.warn ?? error;
var createTask = _console?.createTask ?? /* @__PURE__ */ notImplemented("console.createTask");
var clear = _console?.clear ?? noop_default;
var count = _console?.count ?? noop_default;
var countReset = _console?.countReset ?? noop_default;
var dir = _console?.dir ?? noop_default;
var dirxml = _console?.dirxml ?? noop_default;
var group = _console?.group ?? noop_default;
var groupEnd = _console?.groupEnd ?? noop_default;
var groupCollapsed = _console?.groupCollapsed ?? noop_default;
var profile = _console?.profile ?? noop_default;
var profileEnd = _console?.profileEnd ?? noop_default;
var time = _console?.time ?? noop_default;
var timeEnd = _console?.timeEnd ?? noop_default;
var timeLog = _console?.timeLog ?? noop_default;
var timeStamp = _console?.timeStamp ?? noop_default;
var Console = _console?.Console ?? /* @__PURE__ */ notImplementedClass("console.Console");
var _times = /* @__PURE__ */ new Map();
var _stdoutErrorHandler = noop_default;
var _stderrErrorHandler = noop_default;

// node_modules/@cloudflare/unenv-preset/dist/runtime/node/console.mjs
var workerdConsole = globalThis["console"];
var {
  assert,
  clear: clear2,
  // @ts-expect-error undocumented public API
  context,
  count: count2,
  countReset: countReset2,
  // @ts-expect-error undocumented public API
  createTask: createTask2,
  debug: debug2,
  dir: dir2,
  dirxml: dirxml2,
  error: error2,
  group: group2,
  groupCollapsed: groupCollapsed2,
  groupEnd: groupEnd2,
  info: info2,
  log: log2,
  profile: profile2,
  profileEnd: profileEnd2,
  table: table2,
  time: time2,
  timeEnd: timeEnd2,
  timeLog: timeLog2,
  timeStamp: timeStamp2,
  trace: trace2,
  warn: warn2
} = workerdConsole;
Object.assign(workerdConsole, {
  Console,
  _ignoreErrors,
  _stderr,
  _stderrErrorHandler,
  _stdout,
  _stdoutErrorHandler,
  _times
});
var console_default = workerdConsole;

// node_modules/wrangler/_virtual_unenv_global_polyfill-@cloudflare-unenv-preset-node-console
globalThis.console = console_default;

// node_modules/unenv/dist/runtime/node/internal/process/hrtime.mjs
var hrtime = /* @__PURE__ */ Object.assign(/* @__PURE__ */ __name(function hrtime2(startTime) {
  const now = Date.now();
  const seconds = Math.trunc(now / 1e3);
  const nanos = now % 1e3 * 1e6;
  if (startTime) {
    let diffSeconds = seconds - startTime[0];
    let diffNanos = nanos - startTime[0];
    if (diffNanos < 0) {
      diffSeconds = diffSeconds - 1;
      diffNanos = 1e9 + diffNanos;
    }
    return [diffSeconds, diffNanos];
  }
  return [seconds, nanos];
}, "hrtime"), { bigint: /* @__PURE__ */ __name(function bigint() {
  return BigInt(Date.now() * 1e6);
}, "bigint") });

// node_modules/unenv/dist/runtime/node/internal/process/process.mjs
import { EventEmitter } from "node:events";

// node_modules/unenv/dist/runtime/node/internal/tty/read-stream.mjs
var ReadStream = class {
  static {
    __name(this, "ReadStream");
  }
  fd;
  isRaw = false;
  isTTY = false;
  constructor(fd) {
    this.fd = fd;
  }
  setRawMode(mode) {
    this.isRaw = mode;
    return this;
  }
};

// node_modules/unenv/dist/runtime/node/internal/tty/write-stream.mjs
var WriteStream = class {
  static {
    __name(this, "WriteStream");
  }
  fd;
  columns = 80;
  rows = 24;
  isTTY = false;
  constructor(fd) {
    this.fd = fd;
  }
  clearLine(dir3, callback) {
    callback && callback();
    return false;
  }
  clearScreenDown(callback) {
    callback && callback();
    return false;
  }
  cursorTo(x, y, callback) {
    callback && typeof callback === "function" && callback();
    return false;
  }
  moveCursor(dx, dy, callback) {
    callback && callback();
    return false;
  }
  getColorDepth(env2) {
    return 1;
  }
  hasColors(count3, env2) {
    return false;
  }
  getWindowSize() {
    return [this.columns, this.rows];
  }
  write(str, encoding, cb) {
    if (str instanceof Uint8Array) {
      str = new TextDecoder().decode(str);
    }
    try {
      console.log(str);
    } catch {
    }
    cb && typeof cb === "function" && cb();
    return false;
  }
};

// node_modules/unenv/dist/runtime/node/internal/process/node-version.mjs
var NODE_VERSION = "22.14.0";

// node_modules/unenv/dist/runtime/node/internal/process/process.mjs
var Process = class _Process extends EventEmitter {
  static {
    __name(this, "Process");
  }
  env;
  hrtime;
  nextTick;
  constructor(impl) {
    super();
    this.env = impl.env;
    this.hrtime = impl.hrtime;
    this.nextTick = impl.nextTick;
    for (const prop of [...Object.getOwnPropertyNames(_Process.prototype), ...Object.getOwnPropertyNames(EventEmitter.prototype)]) {
      const value = this[prop];
      if (typeof value === "function") {
        this[prop] = value.bind(this);
      }
    }
  }
  // --- event emitter ---
  emitWarning(warning, type, code) {
    console.warn(`${code ? `[${code}] ` : ""}${type ? `${type}: ` : ""}${warning}`);
  }
  emit(...args) {
    return super.emit(...args);
  }
  listeners(eventName) {
    return super.listeners(eventName);
  }
  // --- stdio (lazy initializers) ---
  #stdin;
  #stdout;
  #stderr;
  get stdin() {
    return this.#stdin ??= new ReadStream(0);
  }
  get stdout() {
    return this.#stdout ??= new WriteStream(1);
  }
  get stderr() {
    return this.#stderr ??= new WriteStream(2);
  }
  // --- cwd ---
  #cwd = "/";
  chdir(cwd2) {
    this.#cwd = cwd2;
  }
  cwd() {
    return this.#cwd;
  }
  // --- dummy props and getters ---
  arch = "";
  platform = "";
  argv = [];
  argv0 = "";
  execArgv = [];
  execPath = "";
  title = "";
  pid = 200;
  ppid = 100;
  get version() {
    return `v${NODE_VERSION}`;
  }
  get versions() {
    return { node: NODE_VERSION };
  }
  get allowedNodeEnvironmentFlags() {
    return /* @__PURE__ */ new Set();
  }
  get sourceMapsEnabled() {
    return false;
  }
  get debugPort() {
    return 0;
  }
  get throwDeprecation() {
    return false;
  }
  get traceDeprecation() {
    return false;
  }
  get features() {
    return {};
  }
  get release() {
    return {};
  }
  get connected() {
    return false;
  }
  get config() {
    return {};
  }
  get moduleLoadList() {
    return [];
  }
  constrainedMemory() {
    return 0;
  }
  availableMemory() {
    return 0;
  }
  uptime() {
    return 0;
  }
  resourceUsage() {
    return {};
  }
  // --- noop methods ---
  ref() {
  }
  unref() {
  }
  // --- unimplemented methods ---
  umask() {
    throw createNotImplementedError("process.umask");
  }
  getBuiltinModule() {
    return void 0;
  }
  getActiveResourcesInfo() {
    throw createNotImplementedError("process.getActiveResourcesInfo");
  }
  exit() {
    throw createNotImplementedError("process.exit");
  }
  reallyExit() {
    throw createNotImplementedError("process.reallyExit");
  }
  kill() {
    throw createNotImplementedError("process.kill");
  }
  abort() {
    throw createNotImplementedError("process.abort");
  }
  dlopen() {
    throw createNotImplementedError("process.dlopen");
  }
  setSourceMapsEnabled() {
    throw createNotImplementedError("process.setSourceMapsEnabled");
  }
  loadEnvFile() {
    throw createNotImplementedError("process.loadEnvFile");
  }
  disconnect() {
    throw createNotImplementedError("process.disconnect");
  }
  cpuUsage() {
    throw createNotImplementedError("process.cpuUsage");
  }
  setUncaughtExceptionCaptureCallback() {
    throw createNotImplementedError("process.setUncaughtExceptionCaptureCallback");
  }
  hasUncaughtExceptionCaptureCallback() {
    throw createNotImplementedError("process.hasUncaughtExceptionCaptureCallback");
  }
  initgroups() {
    throw createNotImplementedError("process.initgroups");
  }
  openStdin() {
    throw createNotImplementedError("process.openStdin");
  }
  assert() {
    throw createNotImplementedError("process.assert");
  }
  binding() {
    throw createNotImplementedError("process.binding");
  }
  // --- attached interfaces ---
  permission = { has: /* @__PURE__ */ notImplemented("process.permission.has") };
  report = {
    directory: "",
    filename: "",
    signal: "SIGUSR2",
    compact: false,
    reportOnFatalError: false,
    reportOnSignal: false,
    reportOnUncaughtException: false,
    getReport: /* @__PURE__ */ notImplemented("process.report.getReport"),
    writeReport: /* @__PURE__ */ notImplemented("process.report.writeReport")
  };
  finalization = {
    register: /* @__PURE__ */ notImplemented("process.finalization.register"),
    unregister: /* @__PURE__ */ notImplemented("process.finalization.unregister"),
    registerBeforeExit: /* @__PURE__ */ notImplemented("process.finalization.registerBeforeExit")
  };
  memoryUsage = Object.assign(() => ({
    arrayBuffers: 0,
    rss: 0,
    external: 0,
    heapTotal: 0,
    heapUsed: 0
  }), { rss: /* @__PURE__ */ __name(() => 0, "rss") });
  // --- undefined props ---
  mainModule = void 0;
  domain = void 0;
  // optional
  send = void 0;
  exitCode = void 0;
  channel = void 0;
  getegid = void 0;
  geteuid = void 0;
  getgid = void 0;
  getgroups = void 0;
  getuid = void 0;
  setegid = void 0;
  seteuid = void 0;
  setgid = void 0;
  setgroups = void 0;
  setuid = void 0;
  // internals
  _events = void 0;
  _eventsCount = void 0;
  _exiting = void 0;
  _maxListeners = void 0;
  _debugEnd = void 0;
  _debugProcess = void 0;
  _fatalException = void 0;
  _getActiveHandles = void 0;
  _getActiveRequests = void 0;
  _kill = void 0;
  _preload_modules = void 0;
  _rawDebug = void 0;
  _startProfilerIdleNotifier = void 0;
  _stopProfilerIdleNotifier = void 0;
  _tickCallback = void 0;
  _disconnect = void 0;
  _handleQueue = void 0;
  _pendingMessage = void 0;
  _channel = void 0;
  _send = void 0;
  _linkedBinding = void 0;
};

// node_modules/@cloudflare/unenv-preset/dist/runtime/node/process.mjs
var globalProcess = globalThis["process"];
var getBuiltinModule = globalProcess.getBuiltinModule;
var workerdProcess = getBuiltinModule("node:process");
var isWorkerdProcessV2 = globalThis.Cloudflare.compatibilityFlags.enable_nodejs_process_v2;
var unenvProcess = new Process({
  env: globalProcess.env,
  // `hrtime` is only available from workerd process v2
  hrtime: isWorkerdProcessV2 ? workerdProcess.hrtime : hrtime,
  // `nextTick` is available from workerd process v1
  nextTick: workerdProcess.nextTick
});
var { exit, features, platform } = workerdProcess;
var {
  // Always implemented by workerd
  env,
  // Only implemented in workerd v2
  hrtime: hrtime3,
  // Always implemented by workerd
  nextTick
} = unenvProcess;
var {
  _channel,
  _disconnect,
  _events,
  _eventsCount,
  _handleQueue,
  _maxListeners,
  _pendingMessage,
  _send,
  assert: assert2,
  disconnect,
  mainModule
} = unenvProcess;
var {
  // @ts-expect-error `_debugEnd` is missing typings
  _debugEnd,
  // @ts-expect-error `_debugProcess` is missing typings
  _debugProcess,
  // @ts-expect-error `_exiting` is missing typings
  _exiting,
  // @ts-expect-error `_fatalException` is missing typings
  _fatalException,
  // @ts-expect-error `_getActiveHandles` is missing typings
  _getActiveHandles,
  // @ts-expect-error `_getActiveRequests` is missing typings
  _getActiveRequests,
  // @ts-expect-error `_kill` is missing typings
  _kill,
  // @ts-expect-error `_linkedBinding` is missing typings
  _linkedBinding,
  // @ts-expect-error `_preload_modules` is missing typings
  _preload_modules,
  // @ts-expect-error `_rawDebug` is missing typings
  _rawDebug,
  // @ts-expect-error `_startProfilerIdleNotifier` is missing typings
  _startProfilerIdleNotifier,
  // @ts-expect-error `_stopProfilerIdleNotifier` is missing typings
  _stopProfilerIdleNotifier,
  // @ts-expect-error `_tickCallback` is missing typings
  _tickCallback,
  abort,
  addListener,
  allowedNodeEnvironmentFlags,
  arch,
  argv,
  argv0,
  availableMemory,
  // @ts-expect-error `binding` is missing typings
  binding,
  channel,
  chdir,
  config,
  connected,
  constrainedMemory,
  cpuUsage,
  cwd,
  debugPort,
  dlopen,
  // @ts-expect-error `domain` is missing typings
  domain,
  emit,
  emitWarning,
  eventNames,
  execArgv,
  execPath,
  exitCode,
  finalization,
  getActiveResourcesInfo,
  getegid,
  geteuid,
  getgid,
  getgroups,
  getMaxListeners,
  getuid,
  hasUncaughtExceptionCaptureCallback,
  // @ts-expect-error `initgroups` is missing typings
  initgroups,
  kill,
  listenerCount,
  listeners,
  loadEnvFile,
  memoryUsage,
  // @ts-expect-error `moduleLoadList` is missing typings
  moduleLoadList,
  off,
  on,
  once,
  // @ts-expect-error `openStdin` is missing typings
  openStdin,
  permission,
  pid,
  ppid,
  prependListener,
  prependOnceListener,
  rawListeners,
  // @ts-expect-error `reallyExit` is missing typings
  reallyExit,
  ref,
  release,
  removeAllListeners,
  removeListener,
  report,
  resourceUsage,
  send,
  setegid,
  seteuid,
  setgid,
  setgroups,
  setMaxListeners,
  setSourceMapsEnabled,
  setuid,
  setUncaughtExceptionCaptureCallback,
  sourceMapsEnabled,
  stderr,
  stdin,
  stdout,
  throwDeprecation,
  title,
  traceDeprecation,
  umask,
  unref,
  uptime,
  version,
  versions
} = isWorkerdProcessV2 ? workerdProcess : unenvProcess;
var _process = {
  abort,
  addListener,
  allowedNodeEnvironmentFlags,
  hasUncaughtExceptionCaptureCallback,
  setUncaughtExceptionCaptureCallback,
  loadEnvFile,
  sourceMapsEnabled,
  arch,
  argv,
  argv0,
  chdir,
  config,
  connected,
  constrainedMemory,
  availableMemory,
  cpuUsage,
  cwd,
  debugPort,
  dlopen,
  disconnect,
  emit,
  emitWarning,
  env,
  eventNames,
  execArgv,
  execPath,
  exit,
  finalization,
  features,
  getBuiltinModule,
  getActiveResourcesInfo,
  getMaxListeners,
  hrtime: hrtime3,
  kill,
  listeners,
  listenerCount,
  memoryUsage,
  nextTick,
  on,
  off,
  once,
  pid,
  platform,
  ppid,
  prependListener,
  prependOnceListener,
  rawListeners,
  release,
  removeAllListeners,
  removeListener,
  report,
  resourceUsage,
  setMaxListeners,
  setSourceMapsEnabled,
  stderr,
  stdin,
  stdout,
  title,
  throwDeprecation,
  traceDeprecation,
  umask,
  uptime,
  version,
  versions,
  // @ts-expect-error old API
  domain,
  initgroups,
  moduleLoadList,
  reallyExit,
  openStdin,
  assert: assert2,
  binding,
  send,
  exitCode,
  channel,
  getegid,
  geteuid,
  getgid,
  getgroups,
  getuid,
  setegid,
  seteuid,
  setgid,
  setgroups,
  setuid,
  permission,
  mainModule,
  _events,
  _eventsCount,
  _exiting,
  _maxListeners,
  _debugEnd,
  _debugProcess,
  _fatalException,
  _getActiveHandles,
  _getActiveRequests,
  _kill,
  _preload_modules,
  _rawDebug,
  _startProfilerIdleNotifier,
  _stopProfilerIdleNotifier,
  _tickCallback,
  _disconnect,
  _handleQueue,
  _pendingMessage,
  _channel,
  _send,
  _linkedBinding
};
var process_default = _process;

// node_modules/wrangler/_virtual_unenv_global_polyfill-@cloudflare-unenv-preset-node-process
globalThis.process = process_default;

// node_modules/itty-router/index.mjs
var e = /* @__PURE__ */ __name(({ base: e2 = "", routes: t = [], ...o2 } = {}) => ({ __proto__: new Proxy({}, { get: /* @__PURE__ */ __name((o3, s2, r, n) => "handle" == s2 ? r.fetch : (o4, ...a) => t.push([s2.toUpperCase?.(), RegExp(`^${(n = (e2 + o4).replace(/\/+(\/|$)/g, "$1")).replace(/(\/?\.?):(\w+)\+/g, "($1(?<$2>*))").replace(/(\/?\.?):(\w+)/g, "($1(?<$2>[^$1/]+?))").replace(/\./g, "\\.").replace(/(\/?)\*/g, "($1.*)?")}/*$`), a, n]) && r, "get") }), routes: t, ...o2, async fetch(e3, ...o3) {
  let s2, r, n = new URL(e3.url), a = e3.query = { __proto__: null };
  for (let [e4, t2] of n.searchParams) a[e4] = a[e4] ? [].concat(a[e4], t2) : t2;
  for (let [a2, c2, i2, l2] of t) if ((a2 == e3.method || "ALL" == a2) && (r = n.pathname.match(c2))) {
    e3.params = r.groups || {}, e3.route = l2;
    for (let t2 of i2) if (null != (s2 = await t2(e3.proxy ?? e3, ...o3))) return s2;
  }
} }), "e");
var o = /* @__PURE__ */ __name((e2 = "text/plain; charset=utf-8", t) => (o2, { headers: s2 = {}, ...r } = {}) => void 0 === o2 || "Response" === o2?.constructor.name ? o2 : new Response(t ? t(o2) : o2, { headers: { "content-type": e2, ...s2.entries ? Object.fromEntries(s2) : s2 }, ...r }), "o");
var s = o("application/json; charset=utf-8", JSON.stringify);
var c = o("text/plain; charset=utf-8", String);
var i = o("text/html");
var l = o("image/jpeg");
var p = o("image/png");
var d = o("image/webp");

// src/utils/platform.js
function detectPlatform(userAgent, scriptType) {
  const ua = userAgent.toLowerCase();
  if (scriptType === "powershell") {
    return "windows";
  }
  if (ua.includes("windows") || ua.includes("win32") || ua.includes("win64")) {
    return "windows";
  }
  if (ua.includes("macintosh") || ua.includes("darwin") || ua.includes("mac os")) {
    return "macos";
  }
  if (ua.includes("linux")) {
    return "linux";
  }
  return scriptType === "powershell" ? "windows" : "linux";
}
__name(detectPlatform, "detectPlatform");
function detectArchitecture(userAgent) {
  const ua = userAgent.toLowerCase();
  if (ua.includes("arm64") || ua.includes("aarch64")) {
    return "arm64";
  }
  if (ua.includes("armv7") || ua.includes("armhf")) {
    return "arm";
  }
  if (ua.includes("x86_64") || ua.includes("amd64") || ua.includes("win64")) {
    return "x64";
  }
  if (ua.includes("i386") || ua.includes("i686") || ua.includes("x86")) {
    return "x86";
  }
  return "x64";
}
__name(detectArchitecture, "detectArchitecture");

// templates/install.sh.js
var bashTemplate = `#!/bin/bash
# cert-ctrl installation script
# Generated by: {{BASE_URL}}
# Platform: {{PLATFORM}}-{{ARCHITECTURE}}
# Mirror: {{MIRROR_NAME}}
# Country: {{COUNTRY}}

set -euo pipefail

# Configuration from service
PLATFORM="{{PLATFORM}}"
ARCHITECTURE="{{ARCHITECTURE}}"
MIRROR_URL="{{MIRROR_URL}}"
BASE_URL="{{BASE_URL}}"
VERSION="{{VERSION}}"
# System installation only - user installation removed
# USER_INSTALL is always false
VERBOSE="\${VERBOSE:-{{VERBOSE}}}"
FORCE="\${FORCE:-{{FORCE}}}"
DRY_RUN="\${DRY_RUN:-{{DRY_RUN}}}"

# Advanced configuration (overridable via environment or flags)
CONFIG_DIR="\${CONFIG_DIR:-}"
INSTALL_SERVICE="\${INSTALL_SERVICE:-}"
ENABLE_SERVICE="\${ENABLE_SERVICE:-}"
SERVICE_NAME="\${SERVICE_NAME:-certctrl.service}"
SERVICE_ACCOUNT="\${SERVICE_ACCOUNT:-root}"
SERVICE_DESCRIPTION="cert-ctrl certificate management agent"
NONINTERACTIVE="\${NONINTERACTIVE:-false}"
CHANNEL="\${CHANNEL:-stable}"

LAST_DOWNLOAD_URL=""
LAST_CHECKSUM_URL=""
CONFIG_DIR_PLACEHOLDER="{{CONFIG_DIR}}"
if [ -z "$CONFIG_DIR" ] && [ -n "$CONFIG_DIR_PLACEHOLDER" ]; then
    CONFIG_DIR="$CONFIG_DIR_PLACEHOLDER"
fi

STATE_DIR="\${STATE_DIR:-/var/lib/certctrl}"
STATE_DIR_PLACEHOLDER="{{STATE_DIR}}"
if [ -z "$STATE_DIR" ] && [ -n "$STATE_DIR_PLACEHOLDER" ]; then
    STATE_DIR="$STATE_DIR_PLACEHOLDER"
fi
STATE_DIR_NAME="$(basename "$STATE_DIR")"
RESTART_SERVICE_AFTER_INSTALL="false"
SHA256_CMD=()

# Override with environment or parameters
INSTALL_DIR="\${INSTALL_DIR:-{{INSTALL_DIR}}}"
if [ -z "$INSTALL_DIR" ]; then
    INSTALL_DIR="/usr/local/bin"
fi

# Colors
RED='\x1B[0;31m'
GREEN='\x1B[0;32m'
YELLOW='\x1B[1;33m'
BLUE='\x1B[0;34m'
NC='\x1B[0m'

# Logging functions
log_info() { echo -e "\${BLUE}[INFO]\${NC} $1" >&2; }
log_success() { echo -e "\${GREEN}[SUCCESS]\${NC} $1" >&2; }
log_warning() { echo -e "\${YELLOW}[WARNING]\${NC} $1" >&2; }
log_error() { echo -e "\${RED}[ERROR]\${NC} $1" >&2; }
log_verbose() {
    if [ "$VERBOSE" = "true" ]; then
        echo -e "\${BLUE}[VERBOSE]\${NC} $1" >&2
    fi
}

# Detect platform if not provided
detect_platform() {
    if [ -n "$PLATFORM" ] && [ "$PLATFORM" != "unknown" ]; then
        echo "$PLATFORM-$ARCHITECTURE"
        return
    fi
    
    local platform=""
    local arch=""
    
    case "$(uname -s)" in
        Linux*)     platform="linux" ;;
        Darwin*)    platform="macos" ;;
        *)          log_error "Unsupported platform: $(uname -s)"; exit 1 ;;
    esac
    
    case "$(uname -m)" in
        x86_64|amd64)   arch="x64" ;;
        aarch64|arm64)  arch="arm64" ;;
        armv7l)         arch="arm" ;;
        *)              arch="x64" ;; # Default
    esac
    
    echo "\${platform}-\${arch}"
}

# Check dependencies
set_checksum_tool() {
    if command -v sha256sum >/dev/null 2>&1; then
        SHA256_CMD=(sha256sum)
        return 0
    fi

    if command -v shasum >/dev/null 2>&1; then
        SHA256_CMD=(shasum -a 256)
        return 0
    fi

    log_error "Required dependency 'sha256sum' (or 'shasum') is not installed."
    log_info "macOS: brew install coreutils"
    exit 1
}

check_dependencies() {
    local deps=("curl" "tar" "gzip")
    if [ "$INSTALL_SERVICE" = "true" ]; then
        deps+=("systemctl")
    fi

    for dep in "\${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            log_error "Required dependency '$dep' is not installed."
            exit 1
        fi
    done
    
    set_checksum_tool

    log_verbose "All dependencies are available"
}

# Resolve version
resolve_version() {
    if [ "$VERSION" = "latest" ]; then
        log_info "Resolving latest version..."
        local latest_url="$BASE_URL/api/version/latest"
        
        if command -v jq &> /dev/null; then
            VERSION=$(curl -fsSL "$latest_url" | jq -r '.version')
        else
            VERSION=$(curl -fsSL "$latest_url" | grep '"version":' | sed -E 's/.*"version": "([^"]+)".*/\\1/')
        fi
        
        if [ -z "$VERSION" ] || [ "$VERSION" = "null" ]; then
            log_error "Failed to resolve latest version"
            exit 1
        fi
        
        log_verbose "Resolved latest version: $VERSION"
    fi
}

# Download binary
download_binary() {
    local platform_arch="$1"
    
    # Use proxy if available, otherwise direct GitHub
    local download_url
    if [ "$MIRROR_URL" = "$BASE_URL/releases/proxy" ]; then
        download_url="$MIRROR_URL/$VERSION/cert-ctrl-$platform_arch.tar.gz"
    else
        download_url="$MIRROR_URL/{{GITHUB_REPO_OWNER}}/{{GITHUB_REPO_NAME}}/releases/download/$VERSION/cert-ctrl-$platform_arch.tar.gz"
    fi

    LAST_DOWNLOAD_URL="$download_url"
    
    if [ "$DRY_RUN" = "true" ]; then
        log_info "DRY RUN: Would download cert-ctrl from $download_url"
        echo ""
        return 0
    fi

    local temp_file=$(mktemp)
    
    log_info "Downloading cert-ctrl $VERSION for $platform_arch..."
    log_verbose "Download URL: $download_url"
    
    if ! curl -fsSL "$download_url" -o "$temp_file"; then
        log_error "Failed to download cert-ctrl"
        rm -f "$temp_file"
        exit 1
    fi
    
    echo "$temp_file"
}

download_checksum() {
    local platform_arch="$1"

    if [ "$DRY_RUN" = "true" ]; then
        LAST_CHECKSUM_URL=""
        return 0
    fi

    local checksum_url
    if [ "$MIRROR_URL" = "$BASE_URL/releases/proxy" ]; then
        checksum_url="$MIRROR_URL/$VERSION/cert-ctrl-$platform_arch.tar.gz.sha256"
    else
        checksum_url="$MIRROR_URL/{{GITHUB_REPO_OWNER}}/{{GITHUB_REPO_NAME}}/releases/download/$VERSION/cert-ctrl-$platform_arch.tar.gz.sha256"
    fi

    LAST_CHECKSUM_URL="$checksum_url"

    local checksum_file=$(mktemp)
    log_verbose "Fetching checksum from $checksum_url"

    if curl -fsSL "$checksum_url" -o "$checksum_file"; then
        echo "$checksum_file"
        return 0
    fi

    log_warning "Checksum file not available; skipping verification"
    rm -f "$checksum_file"
    echo ""
}

verify_checksum() {
    local archive_file="$1"
    local checksum_file="$2"

    if [ -z "$checksum_file" ]; then
        return 0
    fi

    if [ ! -f "$checksum_file" ]; then
        log_warning "Checksum file missing; skipping verification"
        return 0
    fi

    log_info "Verifying archive integrity..."

    local expected=$(awk 'NF>=1 {print $1; exit}' "$checksum_file")
    local actual_output=$("\${SHA256_CMD[@]}" "$archive_file")
    local actual=\${actual_output%% *}

    if [ -z "$expected" ]; then
        log_warning "Checksum file empty; skipping verification"
        return 0
    fi

    if [ "$expected" != "$actual" ]; then
        log_error "Checksum verification failed"
        log_verbose "Expected: $expected"
        log_verbose "Actual:   $actual"
        exit 1
    fi

    log_success "Checksum verified"
}

prompt_yes_no() {
    local message="$1"

    if [ "$NONINTERACTIVE" = "true" ]; then
        return 0
    fi

    read -p "$message [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        return 0
    fi
    return 1
}

install_config_files() {
    local extract_dir="$1"

    if [ "$DRY_RUN" = "true" ]; then
        log_info "DRY RUN: Would place configuration into $CONFIG_DIR"
        return 0
    fi

    local config_source=""
    if [ -d "$extract_dir/config" ]; then
        config_source="$extract_dir/config"
    elif [ -d "$extract_dir/etc/certctrl" ]; then
        config_source="$extract_dir/etc/certctrl"
    fi

    if [ -z "$config_source" ]; then
        log_verbose "No configuration directory found in archive"
        return 0
    fi

    log_info "Installing configuration to $CONFIG_DIR"
    if [ -d "$CONFIG_DIR" ] && [ -n "$(ls -A "$CONFIG_DIR" 2>/dev/null)" ] && [ "$FORCE" = "false" ]; then
        if [ "$NONINTERACTIVE" = "true" ]; then
            log_info "Configuration directory exists but continuing (non-interactive mode)"
        else
            log_warning "Configuration directory $CONFIG_DIR already exists and contains files"
            log_info "To overwrite: Use ?force in URL or FORCE=true with sudo -E"
            log_info "Skipping configuration install"
            return 0
        fi
    fi
    mkdir -p "$CONFIG_DIR"
    cp -R "$config_source/." "$CONFIG_DIR/"
    log_success "Configuration installed"
}

ensure_service_account() {
    local account="$SERVICE_ACCOUNT"

    if [ "$account" = "" ] || [ "$account" = "root" ]; then
        return 0
    fi

    if id "$account" &> /dev/null; then
        return 0
    fi

    if command -v useradd &> /dev/null; then
        log_info "Creating service account $account"
        useradd --system --no-create-home --shell /usr/sbin/nologin "$account"
    else
        log_warning "useradd not available; please ensure account $account exists"
    fi
}

stop_service_if_running() {
    # Avoid ETXTBUSY when overwriting the binary while the service is running
    if [ "$EUID" -ne 0 ]; then
        return 0
    fi
    if ! command -v systemctl >/dev/null 2>&1; then
        return 0
    fi
    if ! systemctl list-unit-files "$SERVICE_NAME" >/dev/null 2>&1; then
        return 0
    fi
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        log_info "Stopping $SERVICE_NAME before upgrading binary"
        if systemctl stop "$SERVICE_NAME"; then
            RESTART_SERVICE_AFTER_INSTALL="true"
        else
            log_warning "Failed to stop $SERVICE_NAME; continuing with installation"
        fi
    fi
}

create_systemd_unit() {
    cat > "/etc/systemd/system/$SERVICE_NAME" << 'EOF'
[Unit]
Description=@@DESCRIPTION@@
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=5
User=@@SERVICE_USER@@
Group=@@SERVICE_USER@@
WorkingDirectory=@@CONFIG_DIR@@
StateDirectory=@@STATE_DIR_NAME@@
ExecStart=@@BINARY_PATH@@ --config-dirs @@CONFIG_DIR@@ --keep-running
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cert-ctrl

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=@@CONFIG_DIR@@
ReadWritePaths=@@STATE_DIR@@

[Install]
WantedBy=multi-user.target
EOF
}

install_service_unit() {

    if [ "$INSTALL_SERVICE" != "true" ]; then
        log_verbose "Service installation disabled"
        return 0
    fi

    if [ "$DRY_RUN" = "true" ]; then
        log_info "DRY RUN: Would install systemd unit $SERVICE_NAME"
        return 0
    fi

    if [ "$EUID" -ne 0 ]; then
        log_warning "Service installation requires root privileges (skipping service setup)"
        log_info "To install service manually after installation:"
        log_info "  sudo systemctl enable --now $SERVICE_NAME"
        return 0
    fi

    if ! command -v systemctl &> /dev/null; then
        log_warning "systemctl not available; skipping service installation"
        return 0
    fi

    ensure_service_account

    log_info "Installing systemd unit at /etc/systemd/system/$SERVICE_NAME"
    if [ -f "/etc/systemd/system/$SERVICE_NAME" ] && [ "$FORCE" = "false" ]; then
        if [ "$NONINTERACTIVE" = "true" ]; then
            log_info "Overwriting existing service unit (non-interactive mode)"
        else
            log_warning "Service $SERVICE_NAME already exists."
            log_info "To overwrite: Use ?force in URL or FORCE=true with sudo -E"
            log_info "Skipping service installation"
            return 0
        fi
    fi

    create_systemd_unit

    # Substitute placeholders in the service file
    sed -i "s|@@BINARY_PATH@@|$INSTALL_DIR/cert-ctrl|g" "/etc/systemd/system/$SERVICE_NAME"
    sed -i "s|@@CONFIG_DIR@@|$CONFIG_DIR|g" "/etc/systemd/system/$SERVICE_NAME"
    sed -i "s|@@SERVICE_USER@@|$SERVICE_ACCOUNT|g" "/etc/systemd/system/$SERVICE_NAME"
    sed -i "s|@@DESCRIPTION@@|$SERVICE_DESCRIPTION|g" "/etc/systemd/system/$SERVICE_NAME"
    sed -i "s|@@STATE_DIR_NAME@@|$STATE_DIR_NAME|g" "/etc/systemd/system/$SERVICE_NAME"
    sed -i "s|@@STATE_DIR@@|$STATE_DIR|g" "/etc/systemd/system/$SERVICE_NAME"

    # Ensure config directory exists and has proper permissions
    if [ ! -d "$CONFIG_DIR" ]; then
        log_info "Creating config directory $CONFIG_DIR"
        mkdir -p "$CONFIG_DIR"
    fi
    if [ ! -d "$STATE_DIR" ]; then
        log_info "Creating state directory $STATE_DIR"
        mkdir -p "$STATE_DIR"
    fi
    chown -R "$SERVICE_ACCOUNT:$SERVICE_ACCOUNT" "$CONFIG_DIR" 2>/dev/null || true
    chmod 755 "$CONFIG_DIR"
    chown -R "$SERVICE_ACCOUNT:$SERVICE_ACCOUNT" "$STATE_DIR" 2>/dev/null || true
    chmod 755 "$STATE_DIR"

    systemctl daemon-reload
    log_success "Systemd unit installed successfully"

    if [ "$ENABLE_SERVICE" = "true" ]; then
        log_info "Enabling and starting $SERVICE_NAME"
        if systemctl enable --now "$SERVICE_NAME"; then
            log_success "Service $SERVICE_NAME started successfully"
        else
            log_warning "Service installation completed but failed to start"
            log_info "Check logs with: journalctl -u $SERVICE_NAME"
            log_info "Start manually with: systemctl start $SERVICE_NAME"
        fi
    else
        log_info "Service installed. Enable manually with: systemctl enable --now $SERVICE_NAME"
    fi
}

# Install binary
install_binary() {
    local temp_file="$1"
    local platform_arch="$2"
    
    if [ "$DRY_RUN" = "true" ]; then
        log_info "DRY RUN: Would install to $INSTALL_DIR"
        if [ "$INSTALL_SERVICE" = "true" ]; then
            log_info "DRY RUN: Would install systemd unit $SERVICE_NAME"
        fi
        return 0
    fi
    
    mkdir -p "$INSTALL_DIR"
    
    log_info "Installing to $INSTALL_DIR..."
    
    # Extract
    local extract_dir=$(mktemp -d)
    if ! tar -xzf "$temp_file" -C "$extract_dir"; then
        log_error "Failed to extract downloaded file"
        rm -rf "$extract_dir"
        exit 1
    fi
    
    # Find binary
    local binary_path=""
    if [ -f "$extract_dir/cert-ctrl" ]; then
        binary_path="$extract_dir/cert-ctrl"
    elif [ -f "$extract_dir/bin/cert-ctrl" ]; then
        binary_path="$extract_dir/bin/cert-ctrl"
    else
        log_error "cert-ctrl binary not found in archive"
        rm -rf "$extract_dir"
        exit 1
    fi
    
    # Check existing installation
    if [ -f "$INSTALL_DIR/cert-ctrl" ] && [ "$FORCE" = "false" ]; then
        local current_version=""
        if [ -x "$INSTALL_DIR/cert-ctrl" ]; then
            current_version=$("$INSTALL_DIR/cert-ctrl" --version 2>/dev/null || echo "unknown")
        fi
        
        log_warning "cert-ctrl is already installed at $INSTALL_DIR/cert-ctrl"
        if [ -n "$current_version" ]; then
            log_info "Current version: $current_version"
            log_info "New version: $VERSION"
        fi
        log_info ""
        log_info "To proceed with installation, choose one of:"
        log_info "  1. URL parameter:   curl -fsSL "https://install.lets-script.com/install.sh?force" | sudo bash"
        log_info "  2. Environment var: FORCE=true curl -fsSL https://install.lets-script.com/install.sh | sudo -E bash"
        log_info "  3. Remove existing: sudo rm $INSTALL_DIR/cert-ctrl && curl -fsSL https://install.lets-script.com/install.sh | sudo bash"
        log_info ""
        log_error "Installation stopped. Use one of the options above to continue."
        rm -rf "$extract_dir"
        exit 1
    fi
    
    # Install
    stop_service_if_running
    chmod +x "$binary_path"
    cp "$binary_path" "$INSTALL_DIR/cert-ctrl"
    log_success "Binary installed"

    install_config_files "$extract_dir"
    install_service_unit

    if [ "$RESTART_SERVICE_AFTER_INSTALL" = "true" ]; then
        if [ "$EUID" -ne 0 ] || ! command -v systemctl >/dev/null 2>&1; then
            log_warning "Service $SERVICE_NAME was stopped but could not be restarted automatically"
        else
            log_info "Restarting $SERVICE_NAME after upgrade"
            if systemctl start "$SERVICE_NAME"; then
                log_success "Service $SERVICE_NAME restarted"
            else
                log_warning "Failed to restart $SERVICE_NAME; start manually with: systemctl start $SERVICE_NAME"
            fi
        fi
    fi

    rm -rf "$extract_dir"

    log_success "cert-ctrl installed successfully!"
}

# Setup PATH
setup_path() {
    # System installation - /usr/local/bin should already be in PATH
    return 0
}

# Verify installation
verify_installation() {
    local binary_path="$INSTALL_DIR/cert-ctrl"
    
    if [ ! -f "$binary_path" ]; then
        log_error "Installation failed: binary not found"
        exit 1
    fi
    
    if "$binary_path" --version &>/dev/null; then
        local version=$("$binary_path" --version 2>/dev/null | head -n1)
        log_success "Installation verified! Version: $version"
        return 0
    else
        log_warning "Binary installed but version check failed"
        
        # Try to run the binary and show error output
        echo ""
        log_info "Trying to diagnose the issue..."
        local error_output
        error_output=$("$binary_path" 2>&1 || true)
        
        # Check if it's a glibc version issue
        if echo "$error_output" | grep -q "GLIBC_"; then
            log_error "Your system is missing required glibc versions!"
            echo ""
            
            # Show current glibc version
            local current_glibc=""
            if [ -f /lib/x86_64-linux-gnu/libc.so.6 ]; then
                current_glibc=$(/lib/x86_64-linux-gnu/libc.so.6 2>&1 | grep -o "release version [0-9]*.[0-9]*" | awk '{print $NF}')
            fi
            
            if [ -z "$current_glibc" ] && command -v ldd &>/dev/null; then
                current_glibc=$(ldd --version 2>&1 | head -1 | grep -oE '[0-9]+.[0-9]+' | head -1)
            fi
            
            if [ -n "$current_glibc" ]; then
                log_warning "Your system has: glibc $current_glibc"
            else
                log_warning "Unable to detect your current glibc version"
            fi
            
            # Extract and show required versions
            local required_versions
            required_versions=$(echo "$error_output" | grep -o "GLIBC_[0-9.]*" | sort -u | tr '
' ' ')
            log_warning "Required versions: $required_versions"
            
            echo ""
            
            # Detect OS and provide specific advice
            if [ -f /etc/os-release ]; then
                local os_id=$(grep "^ID=" /etc/os-release | cut -d'=' -f2 | tr -d '"')
                local version_id=$(grep "^VERSION_ID=" /etc/os-release | cut -d'=' -f2 | tr -d '"')
                
                log_info "Your system: $os_id $version_id"
                echo ""
                
                case "$os_id" in
                    ubuntu)
                        case "$version_id" in
                            "24.04"|"23.10"|"23.04")
                                log_success "Ubuntu $version_id has compatible glibc - update your packages:"
                                echo "  sudo apt update && sudo apt full-upgrade -y"
                                ;;
                            "22.04"|"20.04")
                                log_error "Ubuntu $version_id is not supported - glibc is too old."
                                echo ""
                                log_warning "cert-ctrl requires glibc 2.36+ but Ubuntu $version_id only has glibc 2.35."
                                echo ""
                                log_info "ONLY SOLUTION: Upgrade to Ubuntu 24.04 LTS"
                                echo "  sudo do-release-upgrade"
                                echo ""
                                log_info "Alternative: Use Docker instead"
                                echo "  docker run -it cert-ctrl --version"
                                ;;
                            *)
                                log_info "Try updating your Ubuntu packages:"
                                echo "  sudo apt update && sudo apt full-upgrade -y"
                                ;;
                        esac
                        ;;
                    debian)
                        log_info "For Debian $version_id, try:"
                        echo "  sudo apt update && sudo apt full-upgrade -y"
                        ;;
                    rhel|centos|rocky|almalinux|fedora)
                        log_info "For RHEL/CentOS/Rocky/Fedora, update packages:"
                        echo "  sudo dnf update -y"
                        ;;
                    *)
                        log_info "Try updating your system packages:"
                        echo "  sudo apt update && sudo apt upgrade -y  # Debian-based"
                        echo "  sudo dnf update -y                    # RHEL-based"
                        ;;
                esac
            fi
            
            echo ""
            log_info "Alternative options:"
            echo "  1. Use Docker: docker run cert-ctrl --version"
            echo "  2. Build from source on your system"
            echo "  3. Use a container with compatible glibc"
        else
            log_error "Binary failed to run:"
            echo "$error_output"
        fi
        
        echo ""
        log_error "Installation incomplete due to runtime dependencies."
        return 1
    fi
}

# Main function
main() {
    log_info "Starting cert-ctrl installation..."
    log_verbose "Service URL: $BASE_URL"
    log_verbose "Mirror: $MIRROR_URL"
    log_verbose "Install directory: $INSTALL_DIR"
    log_verbose "Config directory: $CONFIG_DIR"
    log_verbose "Service install: $INSTALL_SERVICE (enable=$ENABLE_SERVICE)"
    
    check_dependencies
    
    local platform_arch=$(detect_platform)
    log_verbose "Platform: $platform_arch"
    
    resolve_version
    
    if [ ! -w "$(dirname "$INSTALL_DIR")" ] && [ "$EUID" -ne 0 ]; then
        log_error "Installation requires root privileges"
        exit 1
    fi
    
    local temp_file=$(download_binary "$platform_arch")

    if [ "$DRY_RUN" = "true" ]; then
        log_info "DRY RUN: No changes were made"
        return 0
    fi

    if [ -z "$temp_file" ]; then
        log_error "Download failed"
        exit 1
    fi

    local checksum_file=$(download_checksum "$platform_arch")
    verify_checksum "$temp_file" "$checksum_file"
    
    install_binary "$temp_file" "$platform_arch"
    
    rm -f "$temp_file"
    if [ -n "$checksum_file" ]; then
        rm -f "$checksum_file"
    fi
    
    setup_path
    verify_installation
    
    echo
    log_success "cert-ctrl installation completed!"
    echo
    echo "Next steps:"
    echo "  - Run: cert-ctrl --help"
    if [ "$INSTALL_SERVICE" = "true" ]; then
        if [ "$ENABLE_SERVICE" = "true" ]; then
            echo "  - Check service status: systemctl status $SERVICE_NAME"
        else
            echo "  - Enable service when ready: sudo systemctl enable --now $SERVICE_NAME"
        fi
    fi
    echo
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --install-dir|--dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --config-dir)
            CONFIG_DIR="$2"
            shift 2
            ;;
        --service)
            INSTALL_SERVICE="true"
            ENABLE_SERVICE="true"
            shift
            ;;
        --no-service)
            INSTALL_SERVICE="false"
            ENABLE_SERVICE="false"
            shift
            ;;
        --enable-service)
            ENABLE_SERVICE="true"
            shift
            ;;
        --no-enable)
            ENABLE_SERVICE="false"
            shift
            ;;
        --non-interactive|--yes|-y)
            NONINTERACTIVE="true"
            FORCE=true
            shift
            ;;
        --channel)
            CHANNEL="$2"
            shift 2
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            echo "cert-ctrl installation script"
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --user-install    Install to user directory"
            echo "  --version VER     Install specific version"
            echo "  --install-dir DIR Custom install directory"
            echo "  --config-dir DIR  Override configuration directory"
            echo "  --force           Overwrite existing installation"
            echo "  --service         Install and enable systemd service"
            echo "  --no-service      Skip systemd service installation"
            echo "  --enable-service  Enable service after install"
            echo "  --no-enable       Install service but do not enable"
            echo "  --non-interactive Run without prompts (assumes yes)"
            echo "  --verbose         Enable verbose output"
            echo "  --dry-run         Show what would be done"
            echo "  --help            Show this help"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [ -z "$CONFIG_DIR" ]; then
    CONFIG_DIR="/etc/certctrl"
fi

if [ -z "$INSTALL_SERVICE" ]; then
    INSTALL_SERVICE="true"
fi

if [ -z "$ENABLE_SERVICE" ]; then
    ENABLE_SERVICE="$INSTALL_SERVICE"
fi

if [ -z "$FORCE" ]; then
    FORCE="false"
fi

if [ -z "$DRY_RUN" ]; then
    DRY_RUN="false"
fi

if [ -z "$VERBOSE" ]; then
    VERBOSE="false"
fi

# Run installation
main
`;

// templates/install.ps1.js
var powershellTemplate = `# cert-ctrl installation script (PowerShell)
# Generated by: {{BASE_URL}}
# Mirror: {{MIRROR_NAME}}
# Version: {{VERSION}}
# Platform: windows-{{ARCHITECTURE}}

param(
    [switch]$UserInstall,
    [string]$Version = "{{VERSION}}",
    [string]$InstallDir,
    [switch]$Verbose,
    [switch]$Force,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-SystemArchitecture {
    try {
        $runtimeType = [System.Runtime.InteropServices.RuntimeInformation]
        $property = $runtimeType.GetProperty('OSArchitecture')
        if ($property) {
            $value = $property.GetValue($null)
            if ($value) {
                return $value.ToString()
            }
        }
    }
    catch {
        # Ignore and try alternate mechanisms
    }

    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        if ($os.OSArchitecture) {
            return $os.OSArchitecture
        }
    }
    catch {
        try {
            $os = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
            if ($os.OSArchitecture) {
                return $os.OSArchitecture
            }
        }
        catch {
            # Fall through
        }
    }

    if ([Environment]::Is64BitOperatingSystem) {
        return 'x64'
    }

    return 'x86'
}

function Write-Info($Message) {
    Write-Host "[INFO] $Message"
}

function Write-Success($Message) {
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-WarningMessage($Message) {
    Write-Warning $Message
}

function Write-ErrorMessage($Message) {
    Write-Error $Message
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$serviceName = "CertCtrlAgent"
$serviceDisplayName = "Cert Ctrl Agent"
$serviceDescription = "Maintains device certificates and polls the cert-ctrl control plane."
$serviceArgs = "--keep-running"

function Register-CertCtrlService {
    param(
        [string]$BinaryPath,
        [bool]$IsUserInstall,
        [bool]$ForceInstall
    )

    if ($IsUserInstall) {
        Write-Info "User install selected; skipping Windows service registration."
        return $false
    }

    if (-not (Test-Administrator)) {
        Write-WarningMessage "Administrator privileges are required to register the Windows service. Skipping."
        return $false
    }

    $imagePath = '"' + $BinaryPath + '" ' + $serviceArgs

    try {
        $existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($existing) {
            if (-not $ForceInstall) {
                Write-Info "Windows service '$serviceName' already exists. Use -Force to recreate it."
                if ($existing.Status -ne 'Running') {
                    Start-Service -Name $serviceName -ErrorAction SilentlyContinue
                }
                return $true
            }

            if ($existing.Status -eq 'Running') {
                Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            }
            sc.exe delete $serviceName | Out-Null
            Start-Sleep -Seconds 2
            while (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
                Start-Sleep -Milliseconds 200
            }
        }

        New-Service -Name $serviceName -BinaryPathName $imagePath -DisplayName $serviceDisplayName -Description $serviceDescription -StartupType Automatic -ErrorAction Stop
        Start-Service -Name $serviceName -ErrorAction SilentlyContinue
        Write-Success "Windows service '$serviceName' registered."
        return $true
    }
    catch {
        Write-WarningMessage "Failed to configure Windows service '$serviceName': $($_.Exception.Message)"
        return $false
    }
}

$archSlug = "{{ARCHITECTURE}}"
if ([string]::IsNullOrWhiteSpace($archSlug)) {
    $archSlug = "x64"
}

$systemArchitecture = Get-SystemArchitecture
switch -regex ($systemArchitecture) {
    'arm64|aarch64' { $archSlug = 'arm64'; break }
    'arm' { $archSlug = 'arm'; break }
    'x86|x64|amd64|86|64' { $archSlug = 'x64'; break }
    default { $archSlug = 'x64' }
}

$paramUserInstall = $false
if ($PSBoundParameters.ContainsKey('UserInstall') -and $UserInstall.IsPresent) {
    $paramUserInstall = $true
}

$paramForceInstall = ([bool]$Force) -or ("{{FORCE}}" -eq "true")


$installPath = if ($InstallDir) {
    $InstallDir
} else {
    if ($paramUserInstall) {
        Join-Path $env:LOCALAPPDATA "Programs\\cert-ctrl"
    } else {
        "C:\\Program Files\\cert-ctrl"
    }
}

if ($paramUserInstall -and -not (Test-Administrator)) {
    Write-Info "User-mode installation selected; administrator rights are not required."
}

$mirrorUrl = "{{MIRROR_URL}}"
if ($mirrorUrl -eq "{{BASE_URL}}/releases/proxy") {
    $packageUrl = "$mirrorUrl/$Version/cert-ctrl-windows-$archSlug.zip"
} else {
    $packageUrl = "$mirrorUrl/{{GITHUB_REPO_OWNER}}/{{GITHUB_REPO_NAME}}/releases/download/$Version/cert-ctrl-windows-$archSlug.zip"
}

$tempDir = New-Item -ItemType Directory -Path ([System.IO.Path]::GetTempPath()) -Name ("cert-ctrl-" + [System.Guid]::NewGuid().ToString())
$zipPath = Join-Path $tempDir "cert-ctrl.zip"

Write-Info "Downloading cert-ctrl $Version..."
Invoke-WebRequest -Uri $packageUrl -OutFile $zipPath -UseBasicParsing

if ($DryRun -or ("{{DRY_RUN}}" -eq "true")) {
    Write-Info "DRY RUN: Installation files prepared at $tempDir"
    exit 0
}

Expand-Archive -Path $zipPath -DestinationPath $tempDir -Force

New-Item -ItemType Directory -Force -Path $installPath | Out-Null

$binaryPath = Join-Path $tempDir 'cert-ctrl.exe'
if (-not (Test-Path $binaryPath)) {
    $binaryPath = Join-Path $tempDir 'bin\\cert-ctrl.exe'
}

if (-not (Test-Path $binaryPath)) {
    Write-ErrorMessage "cert-ctrl executable not found in downloaded archive"
    exit 1
}

$destinationBinary = Join-Path $installPath 'cert-ctrl.exe'
Copy-Item -Path $binaryPath -Destination $destinationBinary -Force
$serviceInstalled = Register-CertCtrlService -BinaryPath $destinationBinary -IsUserInstall:$paramUserInstall -ForceInstall:$paramForceInstall

Write-Success "cert-ctrl installed at $destinationBinary"
Write-Info "Binary directory: $installPath"
$normalizedInstallPath = $installPath.TrimEnd('\\')
$pathEntries = $env:PATH -split ';'
$pathPresent = $pathEntries | Where-Object { $_.TrimEnd('\\') -ieq $normalizedInstallPath }
if (-not $pathPresent) {
    $originalPath = $env:PATH
    if (-not ($env:PATH -like "*$normalizedInstallPath*")) {
        $env:PATH = ($originalPath.TrimEnd(';')) + ';' + $installPath
        Write-Info "Added $installPath to PATH for this PowerShell session."
        Write-Info "Verify now with: where.exe cert-ctrl"
    }

    $userPath = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::User)
    if ([string]::IsNullOrWhiteSpace($userPath)) {
        $userPath = $originalPath
    }
    $userEntries = $userPath -split ';'
    $userHasPath = $userEntries | Where-Object { $_.TrimEnd('\\') -ieq $normalizedInstallPath }
    if (-not $userHasPath) {
        $newUserPath = if ([string]::IsNullOrWhiteSpace($userPath)) {
            $installPath
        } else {
            ($userPath.TrimEnd(';')) + ';' + $installPath
        }
        [Environment]::SetEnvironmentVariable("PATH", $newUserPath, [EnvironmentVariableTarget]::User)
        Write-Info "Persisted install directory to current user's PATH."
    }

    if (Test-Administrator) {
        $machinePath = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::Machine)
        if ([string]::IsNullOrWhiteSpace($machinePath)) {
            $machinePath = $originalPath
        }
        $machineEntries = $machinePath -split ';'
        $machineHasPath = $machineEntries | Where-Object { $_.TrimEnd('\\') -ieq $normalizedInstallPath }
        if (-not $machineHasPath) {
            $newMachinePath = if ([string]::IsNullOrWhiteSpace($machinePath)) {
                $installPath
            } else {
                ($machinePath.TrimEnd(';')) + ';' + $installPath
            }
            [Environment]::SetEnvironmentVariable("PATH", $newMachinePath, [EnvironmentVariableTarget]::Machine)
            Write-Info "Persisted install directory to machine PATH."
        }
    } else {
        Write-Info "Re-open PowerShell to use cert-ctrl without specifying the full path."
    }
}
if ($serviceInstalled) {
    Write-Info "Windows service '$serviceName' is running."
} elseif (-not $paramUserInstall) {
    $manualCommand = "sc create $serviceName binPath="" + $destinationBinary + "" " + $serviceArgs
    Write-Info "Register later as a service with: $manualCommand"
}
$statusCommand = 'Get-Service ' + $serviceName
Write-Info "Service status: $statusCommand"
`;

// templates/install-macos.sh.js
var macosTemplate = `#!/bin/bash
# cert-ctrl macOS installation script for system-wide launchd service

set -euo pipefail

if [[ \${EUID:-$(id -u)} -ne 0 ]]; then
    echo "[ERROR] Run this installer with sudo or as root." >&2
    exit 1
fi

REPO_OWNER="{{GITHUB_REPO_OWNER}}"
REPO_NAME="{{GITHUB_REPO_NAME}}"
VERSION="{{VERSION}}"
BASE_URL="{{BASE_URL}}"
MIRROR_URL="{{MIRROR_URL}}"
INSTALL_DIR="\${INSTALL_DIR:-{{INSTALL_DIR}}}"
if [ -z "$INSTALL_DIR" ]; then
    INSTALL_DIR="/usr/local/bin"
fi
CONFIG_DIR="\${CONFIG_DIR:-{{CONFIG_DIR}}}"
STATE_DIR="\${STATE_DIR:-{{STATE_DIR}}}"
LOG_DIR="\${LOG_DIR:-/var/log}"
SERVICE_LABEL="\${SERVICE_LABEL:-{{SERVICE_LABEL}}}"
PLIST_PATH="/Library/LaunchDaemons/\${SERVICE_LABEL}.plist"
DOWNLOAD_OS="macos"
RED='\x1B[0;31m'
GREEN='\x1B[0;32m'
BLUE='\x1B[0;34m'
YELLOW='\x1B[1;33m'
NC='\x1B[0m'
SHA256_CMD=()
ARCHIVE_TMPDIR=""

die() {
    echo -e "\${RED}[ERROR]\${NC} $1" >&2
    exit 1
}

log_info() {
    echo -e "\${BLUE}[INFO]\${NC} $1" >&2
}

log_success() {
    echo -e "\${GREEN}[SUCCESS]\${NC} $1" >&2
}

log_warn() {
    echo -e "\${YELLOW}[WARNING]\${NC} $1" >&2
}

check_dependencies() {
    local deps=("curl" "tar" "gzip")
    for dep in "\${deps[@]}"; do
        command -v "$dep" >/dev/null 2>&1 || die "Required dependency '$dep' is not installed."
    done

    if command -v sha256sum >/dev/null 2>&1; then
        SHA256_CMD=(sha256sum)
    elif command -v shasum >/dev/null 2>&1; then
        SHA256_CMD=(shasum -a 256)
    else
        die "Install coreutils (brew install coreutils) to obtain sha256sum or shasum."
    fi
}

detect_arch() {
    case "$(uname -m)" in
        arm64) echo "arm64" ;;
        x86_64) echo "x64" ;;
        *) die "Unsupported architecture $(uname -m)" ;;
    esac
}

resolve_version() {
    if [[ "$VERSION" != "latest" ]]; then
        echo "$VERSION"
        return
    fi

    local api="https://api.github.com/repos/\${REPO_OWNER}/\${REPO_NAME}/releases/latest"
    if command -v jq >/dev/null 2>&1; then
        curl -fsSL "$api" | jq -r '.tag_name' || die "Failed to resolve latest version via GitHub API."
    else
        curl -fsSL "$api" | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name": "([^"]+)".*/\\1/' || die "Failed to parse latest version."
    fi
}

download_archive() {
    local version="$1"
    local arch="$2"
    local temp_dir
    temp_dir=$(mktemp -d)
    ARCHIVE_TMPDIR="$temp_dir"
    local archive="\${temp_dir}/cert-ctrl.tar.gz"
    local checksum="\${archive}.sha256"
    local tarball="cert-ctrl-\${DOWNLOAD_OS}-\${arch}.tar.gz"
    local base_url=""

    if [ "$MIRROR_URL" = "$BASE_URL/releases/proxy" ]; then
        base_url="$MIRROR_URL/$version"
    else
        base_url="$MIRROR_URL/\${REPO_OWNER}/\${REPO_NAME}/releases/download/$version"
    fi

    log_info "Downloading \${tarball} ($version)"
    curl -fsSL "\${base_url}/\${tarball}" -o "$archive" || die "Failed to download archive."

    log_info "Downloading checksum"
    if curl -fsSL "\${base_url}/\${tarball}.sha256" -o "$checksum"; then
        local expected
        expected=$(awk 'NF>=1 {print $1; exit}' "$checksum")
        local actual_output
        actual_output=$("\${SHA256_CMD[@]}" "$archive")
        local actual=\${actual_output%% *}
        [[ -z "$expected" ]] && die "Checksum file is empty."
        if [[ "$expected" != "$actual" ]]; then
            die "Checksum mismatch (expected $expected, got $actual)."
        fi
        log_success "Checksum verified."
    else
        log_warn "Checksum file unavailable; skipping verification."
    fi

    echo "$archive"
}

install_binary() {
    local archive="$1"
    local temp_extract
    temp_extract=$(mktemp -d)
    tar -xzf "$archive" -C "$temp_extract" || die "Failed to extract archive."

    local binary_path
    if [[ -f "\${temp_extract}/cert-ctrl" ]]; then
        binary_path="\${temp_extract}/cert-ctrl"
    elif [[ -f "\${temp_extract}/bin/cert-ctrl" ]]; then
        binary_path="\${temp_extract}/bin/cert-ctrl"
    else
        die "cert-ctrl binary not found inside archive."
    fi

    mkdir -p "$INSTALL_DIR"
    install -m 755 "$binary_path" "\${INSTALL_DIR}/cert-ctrl"
    log_success "Installed cert-ctrl to \${INSTALL_DIR}."
}

prepare_directories() {
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$STATE_DIR"
    chmod 755 "$CONFIG_DIR" "$STATE_DIR"
    log_info "Configuration directory: $CONFIG_DIR"
    log_info "State directory: $STATE_DIR"

    mkdir -p "$LOG_DIR"
    : > "\${LOG_DIR}/certctrl.log"
    : > "\${LOG_DIR}/certctrl.err.log"
    chmod 644 "\${LOG_DIR}/certctrl.log" "\${LOG_DIR}/certctrl.err.log"
}

write_launchd_plist() {
    cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>\${SERVICE_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>\${INSTALL_DIR}/cert-ctrl</string>
        <string>--config-dirs</string>
        <string>\${CONFIG_DIR}</string>
        <string>--keep-running</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>CERTCTRL_STATE_DIR</key>
        <string>\${STATE_DIR}</string>
    </dict>
    <key>WorkingDirectory</key>
    <string>\${CONFIG_DIR}</string>
    <key>StandardOutPath</key>
    <string>\${LOG_DIR}/certctrl.log</string>
    <key>StandardErrorPath</key>
    <string>\${LOG_DIR}/certctrl.err.log</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF
    chown root:wheel "$PLIST_PATH"
    chmod 644 "$PLIST_PATH"
    log_success "LaunchDaemon written to \${PLIST_PATH}."
}

reload_service() {
    if launchctl list | grep -q "\${SERVICE_LABEL}"; then
        log_info "Unloading existing service \${SERVICE_LABEL}."
        launchctl bootout system "$PLIST_PATH" >/dev/null 2>&1 || launchctl unload "$PLIST_PATH" >/dev/null 2>&1 || true
    fi

    log_info "Loading service \${SERVICE_LABEL}."
    if launchctl bootstrap system "$PLIST_PATH" >/dev/null 2>&1; then
        launchctl enable system/\${SERVICE_LABEL} >/dev/null 2>&1 || true
        launchctl kickstart -k system/\${SERVICE_LABEL} >/dev/null 2>&1 || true
    log_success "Service \${SERVICE_LABEL} started."
    else
        launchctl load "$PLIST_PATH" >/dev/null 2>&1 || die "Failed to load LaunchDaemon."
        log_warn "Service loaded via legacy launchctl load; verify status manually."
    fi
}

print_next_steps() {
    echo
    log_success "cert-ctrl installation complete."
    echo "Next steps:" >&2
    echo "  - Check status: sudo launchctl print system/\${SERVICE_LABEL}" >&2
    echo "  - View logs: tail -f \${LOG_DIR}/certctrl.log" >&2
    echo "  - Stop service: sudo launchctl bootout system \${PLIST_PATH}" >&2
    echo "  - Start service: sudo launchctl bootstrap system \${PLIST_PATH}" >&2
}

main() {
    log_info "Starting cert-ctrl macOS installation..."
    check_dependencies
    local arch
    arch=$(detect_arch)
    local version
    version=$(resolve_version)
    local archive
    archive=$(download_archive "$version" "$arch")
    install_binary "$archive"
    prepare_directories
    write_launchd_plist
    reload_service
    rm -f "$archive" "$archive.sha256" 2>/dev/null || true
    if [[ -n "$ARCHIVE_TMPDIR" ]]; then
        rm -rf "$ARCHIVE_TMPDIR"
    fi
    print_next_steps
}

main "$@"
`;

// src/utils/templates.js
async function getInstallTemplate(scriptType, options) {
  const {
    platform: platform2,
    architecture,
    country,
    mirror,
    params,
    baseUrl
  } = options;
  const defaults = {
    configDir: "/etc/certctrl",
    stateDir: "/var/lib/certctrl",
    installDir: params.installDir || "",
    serviceLabel: "",
    logDir: "/var/log"
  };
  if (scriptType === "macos") {
    defaults.configDir = "/Library/Application Support/certctrl";
    defaults.stateDir = "/Library/Application Support/certctrl/state";
    defaults.installDir = params.installDir || "/usr/local/bin";
    defaults.serviceLabel = "com.coderealm.certctrl";
    defaults.logDir = "/var/log";
  }
  const templateVars = {
    PLATFORM: platform2,
    ARCHITECTURE: architecture,
    COUNTRY: country,
    MIRROR_URL: mirror.url,
    MIRROR_NAME: mirror.name,
    BASE_URL: baseUrl,
    VERSION: params.version,
    VERBOSE: params.verbose ? "true" : "false",
    FORCE: params.force ? "true" : "false",
    INSTALL_DIR: defaults.installDir,
    CONFIG_DIR: defaults.configDir,
    STATE_DIR: defaults.stateDir,
    SERVICE_LABEL: defaults.serviceLabel,
    LOG_DIR: defaults.logDir,
    DRY_RUN: params.dryRun ? "true" : "false",
    GITHUB_REPO_OWNER: "coderealm-atlas",
    GITHUB_REPO_NAME: "cert-ctrl"
  };
  if (scriptType === "powershell") {
    return interpolateTemplate(powershellTemplate, templateVars);
  } else if (scriptType === "macos") {
    return interpolateTemplate(macosTemplate, templateVars);
  } else {
    return interpolateTemplate(bashTemplate, templateVars);
  }
}
__name(getInstallTemplate, "getInstallTemplate");
function interpolateTemplate(template, vars) {
  let result = template;
  for (const [key, value] of Object.entries(vars)) {
    const placeholder = new RegExp(`\\{\\{${key}\\}\\}`, "g");
    result = result.replace(placeholder, value);
  }
  return result;
}
__name(interpolateTemplate, "interpolateTemplate");

// src/utils/cors.js
var corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, HEAD, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
  "Access-Control-Max-Age": "86400"
  // 24 hours
};
function handleCORS(request) {
  return new Response(null, {
    status: 204,
    headers: corsHeaders
  });
}
__name(handleCORS, "handleCORS");

// src/handlers/install.js
async function installHandler(request, env2) {
  try {
    const url = new URL(request.url);
    const userAgent = request.headers.get("User-Agent") || "";
    const country = request.cf?.country || "US";
    const pathname = url.pathname;
    let scriptType;
    if (pathname.endsWith(".ps1")) {
      scriptType = "powershell";
    } else if (pathname.endsWith("install-macos.sh")) {
      scriptType = "macos";
    } else {
      scriptType = "bash";
    }
    const platform2 = scriptType === "macos" ? "macos" : detectPlatform(userAgent, scriptType);
    const architecture = detectArchitecture(userAgent);
    const params = {
      version: url.searchParams.get("version") || "latest",
      verbose: url.searchParams.has("verbose") || url.searchParams.has("v"),
      force: url.searchParams.has("force"),
      installDir: url.searchParams.get("install-dir") || url.searchParams.get("dir"),
      dryRun: url.searchParams.has("dry-run")
    };
    const mirror = await selectBestMirror(country, env2);
    const script = await getInstallTemplate(scriptType, {
      platform: platform2,
      architecture,
      country,
      mirror,
      params,
      baseUrl: `https://${url.host}`
    });
    const contentType = scriptType === "powershell" ? "application/x-powershell; charset=utf-8" : "application/x-sh; charset=utf-8";
    return new Response(script, {
      headers: {
        "Content-Type": contentType,
        "Cache-Control": "public, max-age=300",
        // 5 minutes
        "X-Platform": platform2,
        "X-Architecture": architecture,
        "X-Mirror": mirror.name,
        ...corsHeaders
      }
    });
  } catch (error3) {
    console.error("Install handler error:", error3);
    return new Response("Error generating installation script", {
      status: 500,
      headers: {
        "Content-Type": "text/plain",
        ...corsHeaders
      }
    });
  }
}
__name(installHandler, "installHandler");
async function selectBestMirror(country, env2) {
  const mirrors = {
    proxy: {
      name: "cloudflare-proxy",
      url: `https://${env2.CURRENT_HOST || "install.lets-script.com"}/releases/proxy`,
      regions: ["all"]
    },
    github: {
      name: "github-direct",
      url: "https://github.com",
      regions: ["fallback"]
    }
  };
  return mirrors.proxy;
}
__name(selectBestMirror, "selectBestMirror");

// src/utils/github.js
var DEFAULT_USER_AGENT = "cert-ctrl-install-service/1.0.0";
function buildGithubHeaders(env2, extraHeaders = {}) {
  const headers = {
    "User-Agent": DEFAULT_USER_AGENT,
    ...extraHeaders
  };
  const token = env2?.GITHUB_TOKEN;
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  return headers;
}
__name(buildGithubHeaders, "buildGithubHeaders");
function describeGithubFailure(response, bodyText, env2) {
  let parsed;
  let message = bodyText || "";
  let documentationUrl;
  try {
    parsed = JSON.parse(bodyText);
    if (parsed && typeof parsed === "object") {
      message = parsed.message || message;
      documentationUrl = parsed.documentation_url || parsed.documentationUrl;
    }
  } catch (error3) {
  }
  const rateLimitRemaining = response.headers.get("X-RateLimit-Remaining");
  const status = response.status;
  const lowerMessage = (message || "").toLowerCase();
  let reason = "unknown";
  let hint = "Unexpected response returned by GitHub.";
  if (status === 401) {
    reason = "unauthorized";
    hint = "GitHub rejected the token. Double-check that it is valid and not expired.";
  } else if (status === 403) {
    if (rateLimitRemaining === "0" || lowerMessage.includes("rate limit")) {
      reason = "rate_limit";
      hint = "GitHub API rate limit exceeded. Wait for the limit to reset or use a token with higher limits.";
    } else {
      reason = "forbidden";
      hint = env2?.GITHUB_TOKEN ? "The GitHub token lacks sufficient permissions for this repository." : "This repository requires authentication. Provide a GitHub token with repo read access.";
    }
  } else if (status === 404) {
    reason = "not_found";
    hint = env2?.GITHUB_TOKEN ? "Release not found or the token cannot see it. Ensure a release exists and the token has repo scope." : "Release not found. Supply a GitHub token for private repositories or publish a release.";
  }
  return {
    status,
    message,
    documentationUrl,
    rateLimitRemaining,
    reason,
    hint
  };
}
__name(describeGithubFailure, "describeGithubFailure");

// src/handlers/version.js
async function versionHandler(request, env2) {
  try {
    const url = new URL(request.url);
    const pathname = url.pathname;
    if (pathname.includes("/latest")) {
      return await handleLatestVersion(request, env2);
    } else if (pathname.includes("/check")) {
      return await handleVersionCheck(request, env2);
    }
    return new Response("Invalid version endpoint", {
      status: 400,
      headers: corsHeaders
    });
  } catch (error3) {
    console.error("Version handler error:", error3);
    return new Response("Error processing version request", {
      status: 500,
      headers: {
        "Content-Type": "application/json",
        ...corsHeaders
      }
    });
  }
}
__name(versionHandler, "versionHandler");
async function handleLatestVersion(request, env2) {
  try {
    const cacheKey = "latest_release";
    let releaseData = await env2.RELEASE_CACHE.get(cacheKey, "json");
    if (!releaseData) {
      const apiUrl = `https://api.github.com/repos/${env2.GITHUB_REPO_OWNER}/${env2.GITHUB_REPO_NAME}/releases/latest`;
      const headers = buildGithubHeaders(env2, {
        Accept: "application/vnd.github.v3+json"
      });
      const response = await fetch(apiUrl, { headers });
      if (!response.ok) {
        const bodyText = await response.text();
        const details = describeGithubFailure(response, bodyText, env2);
        console.error("GitHub latest release error:", details);
        const error3 = new Error(`GitHub API error: ${response.status}`);
        error3.details = details;
        throw error3;
      }
      releaseData = await response.json();
      await env2.RELEASE_CACHE.put(cacheKey, JSON.stringify(releaseData), {
        expirationTtl: 600
      });
    }
    const result = {
      version: releaseData.tag_name,
      published_at: releaseData.published_at,
      prerelease: releaseData.prerelease,
      draft: releaseData.draft,
      download_urls: extractDownloadUrls(releaseData.assets),
      changelog_url: releaseData.html_url,
      body: releaseData.body
    };
    return new Response(JSON.stringify(result, null, 2), {
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "public, max-age=600",
        // 10 minutes
        ...corsHeaders
      }
    });
  } catch (error3) {
    console.error("Latest version error:", error3);
    return new Response(JSON.stringify({
      error: "Failed to fetch latest version",
      message: error3.message,
      details: error3.details || null
    }), {
      status: 500,
      headers: {
        "Content-Type": "application/json",
        ...corsHeaders
      }
    });
  }
}
__name(handleLatestVersion, "handleLatestVersion");
async function handleVersionCheck(request, env2) {
  try {
    const url = new URL(request.url);
    const currentVersion = url.searchParams.get("current") || url.searchParams.get("version");
    const platform2 = url.searchParams.get("platform") || "unknown";
    const arch2 = url.searchParams.get("arch") || "unknown";
    if (!currentVersion) {
      return new Response(JSON.stringify({
        error: "Missing current version parameter"
      }), {
        status: 400,
        headers: {
          "Content-Type": "application/json",
          ...corsHeaders
        }
      });
    }
    const latestResponse = await handleLatestVersion(request, env2);
    const latestData = await latestResponse.json();
    if (latestResponse.status !== 200) {
      return latestResponse;
    }
    const latestVersion = latestData.version;
    const newerVersionAvailable = compareVersions(latestVersion, currentVersion) > 0;
    const result = {
      current_version: currentVersion,
      latest_version: latestVersion,
      newer_version_available: newerVersionAvailable,
      platform: platform2,
      architecture: arch2,
      download_urls: latestData.download_urls,
      changelog_url: latestData.changelog_url,
      security_update: await isSecurityUpdate(latestData.body),
      minimum_supported_version: await getMinimumSupportedVersion(env2),
      deprecation_warnings: await getDeprecationWarnings(currentVersion, env2),
      update_urgency: await getUpdateUrgency(currentVersion, latestVersion, latestData.body)
    };
    return new Response(JSON.stringify(result, null, 2), {
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "public, max-age=300",
        // 5 minutes
        ...corsHeaders
      }
    });
  } catch (error3) {
    console.error("Version check error:", error3);
    return new Response(JSON.stringify({
      error: "Failed to check version",
      message: error3.message
    }), {
      status: 500,
      headers: {
        "Content-Type": "application/json",
        ...corsHeaders
      }
    });
  }
}
__name(handleVersionCheck, "handleVersionCheck");
function extractDownloadUrls(assets) {
  const urls = {};
  assets.forEach((asset) => {
    const name = asset.name.toLowerCase();
    if (name.includes("linux") && name.includes("x64")) {
      urls["linux-x64"] = asset.browser_download_url;
    } else if (name.includes("linux") && name.includes("arm64")) {
      urls["linux-arm64"] = asset.browser_download_url;
    } else if (name.includes("windows") && name.includes("x64")) {
      urls["windows-x64"] = asset.browser_download_url;
    } else if (name.includes("macos") && name.includes("x64")) {
      urls["macos-x64"] = asset.browser_download_url;
    } else if (name.includes("macos") && name.includes("arm64")) {
      urls["macos-arm64"] = asset.browser_download_url;
    }
  });
  return urls;
}
__name(extractDownloadUrls, "extractDownloadUrls");
function compareVersions(version1, version2) {
  const v1 = version1.replace(/^v/, "").split(".").map(Number);
  const v2 = version2.replace(/^v/, "").split(".").map(Number);
  for (let i2 = 0; i2 < Math.max(v1.length, v2.length); i2++) {
    const a = v1[i2] || 0;
    const b = v2[i2] || 0;
    if (a > b) return 1;
    if (a < b) return -1;
  }
  return 0;
}
__name(compareVersions, "compareVersions");
async function isSecurityUpdate(releaseBody) {
  if (!releaseBody) return false;
  const securityKeywords = [
    "security",
    "vulnerability",
    "cve",
    "exploit",
    "patch",
    "hotfix",
    "critical",
    "urgent"
  ];
  const bodyLower = releaseBody.toLowerCase();
  return securityKeywords.some((keyword) => bodyLower.includes(keyword));
}
__name(isSecurityUpdate, "isSecurityUpdate");
async function getMinimumSupportedVersion(env2) {
  const config2 = await env2.CONFIG?.get("minimum_supported_version");
  return config2 || "v1.0.0";
}
__name(getMinimumSupportedVersion, "getMinimumSupportedVersion");
async function getDeprecationWarnings(currentVersion, env2) {
  const warnings = await env2.CONFIG?.get("deprecation_warnings", "json") || {};
  return warnings[currentVersion] || [];
}
__name(getDeprecationWarnings, "getDeprecationWarnings");
async function getUpdateUrgency(currentVersion, latestVersion, releaseBody) {
  const versionGap = compareVersions(latestVersion, currentVersion);
  if (await isSecurityUpdate(releaseBody)) {
    return "critical";
  }
  if (versionGap >= 2) {
    return "high";
  } else if (versionGap >= 1) {
    return "medium";
  }
  return "low";
}
__name(getUpdateUrgency, "getUpdateUrgency");

// src/handlers/proxy.js
async function proxyHandler(request, env2) {
  try {
    const url = new URL(request.url);
    const pathParts = url.pathname.split("/").filter(Boolean);
    const version2 = pathParts[2];
    const rawFilename = pathParts.slice(3).join("/");
    const filename = rawFilename ? decodeURIComponent(rawFilename) : void 0;
    console.log("Proxy request received", {
      url: request.url,
      version: version2,
      rawFilename,
      filename
    });
    console.log("GitHub token presence", {
      hasToken: Boolean(env2.GITHUB_TOKEN)
    });
    if (!version2 || !filename) {
      return new Response("Invalid proxy URL format", {
        status: 400,
        headers: corsHeaders
      });
    }
    let actualVersion = version2;
    if (version2 === "latest") {
      actualVersion = await getLatestVersion(env2);
      if (!actualVersion) {
        return new Response("Could not resolve latest version", {
          status: 500,
          headers: corsHeaders
        });
      }
    }
    const resolution = await resolveDownloadSource(env2, actualVersion, filename);
    console.log("Resolution result", {
      requestedVersion: version2,
      actualVersion,
      filename,
      resolution
    });
    if (!resolution?.downloadUrl) {
      return new Response(JSON.stringify({
        error: `Release file not found: ${filename}`,
        details: resolution?.details || "Asset missing from GitHub release"
      }, null, 2), {
        status: 404,
        headers: {
          "Content-Type": "application/json",
          ...corsHeaders
        }
      });
    }
    const githubUrl = resolution.downloadUrl;
    const cacheKey = `release:${actualVersion}:${filename}`;
    let cachedResponse = await env2.RELEASE_CACHE.get(cacheKey, "arrayBuffer");
    if (cachedResponse) {
      return new Response(cachedResponse, {
        headers: {
          "Content-Type": getContentType(filename),
          "Cache-Control": "public, max-age=86400",
          // 24 hours
          "X-Cache": "HIT",
          "X-Version": actualVersion,
          ...corsHeaders
        }
      });
    }
    if (request.method === "HEAD") {
      console.log("Handling HEAD request", {
        version: actualVersion,
        filename,
        source: resolution?.source,
        hasAssetMeta: Boolean(resolution?.asset)
      });
      const responseHeaders = new Headers(corsHeaders);
      const assetMeta = resolution?.asset;
      if (assetMeta) {
        console.log("Using metadata for HEAD response", {
          version: actualVersion,
          filename,
          size: assetMeta.size,
          contentType: assetMeta.content_type
        });
        if (assetMeta.content_type) {
          responseHeaders.set("Content-Type", assetMeta.content_type);
        } else {
          responseHeaders.set("Content-Type", getContentType(filename));
        }
        if (typeof assetMeta.size === "number") {
          responseHeaders.set("Content-Length", assetMeta.size.toString());
        }
        if (assetMeta.updated_at) {
          responseHeaders.set("Last-Modified", new Date(assetMeta.updated_at).toUTCString());
        }
      } else {
        const headResponse = await fetch(githubUrl, {
          method: "HEAD",
          headers: buildGithubHeaders(env2)
        });
        console.log("GitHub HEAD response", {
          url: githubUrl,
          status: headResponse.status,
          ok: headResponse.ok
        });
        if (!headResponse.ok) {
          const bodyText = await headResponse.text();
          const details = describeGithubFailure(headResponse, bodyText, env2);
          return new Response(JSON.stringify({
            error: `HEAD failed for ${filename}`,
            details
          }, null, 2), {
            status: headResponse.status,
            headers: {
              "Content-Type": "application/json",
              ...corsHeaders
            }
          });
        }
        headResponse.headers.forEach((value, key) => {
          responseHeaders.set(key, value);
        });
      }
      responseHeaders.set("X-Cache", "MISS");
      responseHeaders.set("X-Version", actualVersion);
      if (resolution?.source) {
        responseHeaders.set("X-Source", resolution.source);
      }
      return new Response(null, {
        status: 200,
        headers: responseHeaders
      });
    }
    const githubResponse = await fetch(githubUrl, {
      headers: buildGithubHeaders(env2)
    });
    console.log("GitHub fetch response", {
      url: githubUrl,
      status: githubResponse.status,
      ok: githubResponse.ok
    });
    if (!githubResponse.ok) {
      const bodyText = await githubResponse.text();
      const details = describeGithubFailure(githubResponse, bodyText, env2);
      console.error("GitHub proxy asset error:", {
        url: githubUrl,
        details
      });
      return new Response(JSON.stringify({
        error: `Release file not found: ${filename}`,
        details
      }, null, 2), {
        status: githubResponse.status,
        headers: {
          "Content-Type": "application/json",
          ...corsHeaders
        }
      });
    }
    const content = await githubResponse.arrayBuffer();
    const contentType = githubResponse.headers.get("Content-Type") || getContentType(filename);
    if (content.byteLength < 10 * 1024 * 1024) {
      await env2.RELEASE_CACHE.put(cacheKey, content, {
        expirationTtl: 86400
        // 24 hours
      });
    }
    if (env2.ANALYTICS_ENABLED) {
      recordDownload(request, env2, actualVersion, filename, content.byteLength);
    }
    return new Response(content, {
      headers: {
        "Content-Type": contentType,
        "Content-Length": content.byteLength.toString(),
        "Cache-Control": "public, max-age=86400",
        // 24 hours
        "X-Cache": "MISS",
        "X-Version": actualVersion,
        "X-Content-Length": content.byteLength.toString(),
        ...resolution?.source ? { "X-Source": resolution.source } : {},
        ...corsHeaders
      }
    });
  } catch (error3) {
    console.error("Proxy handler error:", error3);
    return new Response("Proxy error", {
      status: 500,
      headers: {
        "Content-Type": "text/plain",
        ...corsHeaders
      }
    });
  }
}
__name(proxyHandler, "proxyHandler");
async function getLatestVersion(env2) {
  try {
    const cacheKey = "latest_release";
    let releaseData = await env2.RELEASE_CACHE.get(cacheKey, "json");
    if (!releaseData) {
      const apiUrl = `https://api.github.com/repos/${env2.GITHUB_REPO_OWNER}/${env2.GITHUB_REPO_NAME}/releases/latest`;
      const headers = buildGithubHeaders(env2, {
        Accept: "application/vnd.github.v3+json"
      });
      const response = await fetch(apiUrl, { headers });
      if (response.ok) {
        releaseData = await response.json();
        await env2.RELEASE_CACHE.put(cacheKey, JSON.stringify(releaseData), {
          expirationTtl: 600
          // 10 minutes
        });
      } else {
        const bodyText = await response.text();
        const details = describeGithubFailure(response, bodyText, env2);
        console.error("GitHub latest version lookup failed in proxy handler:", details);
      }
    }
    return releaseData?.tag_name;
  } catch (error3) {
    console.error("Error getting latest version:", error3);
    return null;
  }
}
__name(getLatestVersion, "getLatestVersion");
async function resolveDownloadSource(env2, version2, filename) {
  const owner = env2.GITHUB_REPO_OWNER;
  const repo = env2.GITHUB_REPO_NAME;
  const directUrl = `https://github.com/${owner}/${repo}/releases/download/${version2}/${encodeURIComponent(filename)}`;
  console.log("Resolving download source", {
    version: version2,
    filename,
    directUrl
  });
  const metadata = await getReleaseMetadata(env2, version2);
  console.log("Metadata lookup result", {
    version: version2,
    hasMetadata: Boolean(metadata),
    assetCount: metadata?.assets?.length || 0
  });
  const assetFromMeta = metadata?.assets?.find((asset) => asset?.name === filename);
  if (assetFromMeta?.browser_download_url) {
    console.log("Found asset in metadata", {
      version: version2,
      filename,
      source: "metadata"
    });
    return {
      downloadUrl: assetFromMeta.browser_download_url,
      source: "metadata",
      asset: assetFromMeta
    };
  }
  const directTest = await fetch(directUrl, {
    method: "HEAD",
    headers: buildGithubHeaders(env2)
  });
  console.log("Direct HEAD check", {
    url: directUrl,
    status: directTest.status,
    ok: directTest.ok
  });
  if (directTest.ok || directTest.status === 302) {
    return {
      downloadUrl: directUrl,
      source: "direct-head"
    };
  }
  const refreshedMetadata = await getReleaseMetadata(env2, version2, { forceRefresh: true });
  console.log("Metadata refresh result", {
    version: version2,
    hasMetadata: Boolean(refreshedMetadata),
    assetCount: refreshedMetadata?.assets?.length || 0
  });
  const refreshedAsset = refreshedMetadata?.assets?.find((asset) => asset?.name === filename);
  if (refreshedAsset?.browser_download_url) {
    return {
      downloadUrl: refreshedAsset.browser_download_url,
      source: "metadata-refresh",
      asset: refreshedAsset
    };
  }
  const altVersion = version2.startsWith("v") ? version2.substring(1) : `v${version2}`;
  console.log("Trying alternate version", {
    version: version2,
    altVersion
  });
  if (altVersion !== version2) {
    const altMetadata = await getReleaseMetadata(env2, altVersion);
    console.log("Alternate metadata lookup", {
      altVersion,
      hasMetadata: Boolean(altMetadata),
      assetCount: altMetadata?.assets?.length || 0
    });
    const altAsset = altMetadata?.assets?.find((asset) => asset?.name === filename);
    if (altAsset?.browser_download_url) {
      return {
        downloadUrl: altAsset.browser_download_url,
        source: "metadata-alt",
        asset: altAsset
      };
    }
    const altDirectUrl = `https://github.com/${owner}/${repo}/releases/download/${altVersion}/${encodeURIComponent(filename)}`;
    const altHead = await fetch(altDirectUrl, {
      method: "HEAD",
      headers: buildGithubHeaders(env2)
    });
    console.log("Alternate direct HEAD check", {
      url: altDirectUrl,
      status: altHead.status,
      ok: altHead.ok
    });
    if (altHead.ok || altHead.status === 302) {
      return {
        downloadUrl: altDirectUrl,
        source: "direct-alt-head"
      };
    }
  }
  return {
    downloadUrl: null,
    source: "unresolved",
    details: {
      reason: "not_found",
      version: version2,
      filename
    }
  };
}
__name(resolveDownloadSource, "resolveDownloadSource");
async function getReleaseMetadata(env2, version2, options = {}) {
  if (!version2) {
    return null;
  }
  const { forceRefresh = false } = options;
  const cacheKey = `release_meta:${version2}`;
  if (!forceRefresh) {
    const cached = await env2.RELEASE_CACHE.get(cacheKey, "json");
    console.log("KV metadata cache lookup", {
      version: version2,
      cacheHit: Boolean(cached)
    });
    if (cached) {
      return cached;
    }
  }
  const apiUrl = `https://api.github.com/repos/${env2.GITHUB_REPO_OWNER}/${env2.GITHUB_REPO_NAME}/releases/tags/${version2}`;
  const headers = buildGithubHeaders(env2, {
    Accept: "application/vnd.github.v3+json"
  });
  try {
    const response = await fetch(apiUrl, { headers });
    if (!response.ok) {
      const logContext = {
        version: version2,
        status: response.status
      };
      if (response.status === 401 || response.status === 403) {
        console.warn("Release metadata fetch unauthorized", {
          ...logContext,
          hasToken: Boolean(env2.GITHUB_TOKEN)
        });
      } else {
        console.error("Release metadata fetch failed", logContext);
      }
      if (response.status !== 404) {
        const bodyText = await response.text();
        const details = describeGithubFailure(response, bodyText, env2);
        console.error("GitHub release metadata fetch failed:", {
          version: version2,
          details
        });
      }
      return null;
    }
    const metadata = await response.json();
    console.log("Fetched metadata from GitHub", {
      version: version2,
      assetCount: metadata?.assets?.length || 0
    });
    await env2.RELEASE_CACHE.put(cacheKey, JSON.stringify(metadata), {
      expirationTtl: 600
      // 10 minutes
    });
    return metadata;
  } catch (error3) {
    console.error("Error fetching release metadata", {
      version: version2,
      error: error3?.message || error3
    });
    return null;
  }
}
__name(getReleaseMetadata, "getReleaseMetadata");
function getContentType(filename) {
  const ext = filename.toLowerCase().split(".").pop();
  const mimeTypes = {
    "tar.gz": "application/gzip",
    "tgz": "application/gzip",
    "zip": "application/zip",
    "exe": "application/octet-stream",
    "deb": "application/vnd.debian.binary-package",
    "rpm": "application/x-rpm",
    "dmg": "application/x-apple-diskimage",
    "pkg": "application/x-newton-compatible-pkg",
    "msi": "application/x-msi",
    "sig": "application/pgp-signature",
    "asc": "text/plain",
    "sha256": "text/plain",
    "md5": "text/plain"
  };
  if (filename.endsWith(".tar.gz")) {
    return mimeTypes["tar.gz"];
  }
  return mimeTypes[ext] || "application/octet-stream";
}
__name(getContentType, "getContentType");
async function recordDownload(request, env2, version2, filename, size) {
  try {
    const timestamp = Date.now();
    const country = request.cf?.country || "unknown";
    const userAgent = request.headers.get("User-Agent") || "unknown";
    const downloadData = {
      timestamp,
      version: version2,
      filename,
      size,
      country,
      userAgent: hashUserAgent(userAgent),
      // Hash for privacy
      ip_hash: await hashIP(request.headers.get("CF-Connecting-IP"))
    };
    const analyticsKey = `download:${timestamp}:${Math.random().toString(36).substr(2, 9)}`;
    await env2.ANALYTICS.put(analyticsKey, JSON.stringify(downloadData), {
      expirationTtl: 2592e3
      // 30 days
    });
    const dailyKey = `daily_downloads:${(/* @__PURE__ */ new Date()).toISOString().split("T")[0]}`;
    const currentCount = await env2.ANALYTICS.get(dailyKey) || "0";
    await env2.ANALYTICS.put(dailyKey, (parseInt(currentCount) + 1).toString(), {
      expirationTtl: 2592e3
      // 30 days
    });
  } catch (error3) {
    console.error("Error recording download:", error3);
  }
}
__name(recordDownload, "recordDownload");
function hashUserAgent(userAgent) {
  const platform2 = userAgent.toLowerCase();
  if (platform2.includes("windows")) return "windows";
  if (platform2.includes("mac")) return "macos";
  if (platform2.includes("linux")) return "linux";
  if (platform2.includes("curl")) return "curl";
  if (platform2.includes("wget")) return "wget";
  if (platform2.includes("powershell")) return "powershell";
  return "other";
}
__name(hashUserAgent, "hashUserAgent");
async function hashIP(ip) {
  if (!ip) return "unknown";
  const encoder = new TextEncoder();
  const data = encoder.encode(ip + "salt_string_here");
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("").substr(0, 16);
}
__name(hashIP, "hashIP");

// src/utils/analytics.js
function detectPlatform2(userAgent = "") {
  const ua = userAgent.toLowerCase();
  if (ua.includes("windows")) return "windows";
  if (ua.includes("mac os") || ua.includes("macintosh")) return "mac";
  if (ua.includes("linux")) return "linux";
  if (ua.includes("android")) return "android";
  if (ua.includes("iphone") || ua.includes("ipad") || ua.includes("ios")) return "ios";
  return "other";
}
__name(detectPlatform2, "detectPlatform");
async function trackRequest(request, env2) {
  if (!env2 || String(env2.ANALYTICS_ENABLED).toLowerCase() !== "true") {
    return;
  }
  if (!env2.ANALYTICS) {
    console.warn("ANALYTICS binding missing; skipping analytics tracking");
    return;
  }
  try {
    const now = /* @__PURE__ */ new Date();
    const dateKey = now.toISOString().slice(0, 10);
    const url = new URL(request.url);
    const userAgent = request.headers.get("User-Agent") || "";
    const platform2 = detectPlatform2(userAgent);
    const storageKey = `stats:${dateKey}`;
    const existing = await env2.ANALYTICS.get(storageKey);
    let record;
    if (existing) {
      try {
        record = JSON.parse(existing);
      } catch (error3) {
        console.error("Failed to parse analytics record", error3);
        record = { total: 0, paths: {}, platforms: {} };
      }
    } else {
      record = { total: 0, paths: {}, platforms: {} };
    }
    record.total += 1;
    record.paths[url.pathname] = (record.paths[url.pathname] || 0) + 1;
    record.platforms[platform2] = (record.platforms[platform2] || 0) + 1;
    record.updatedAt = now.toISOString();
    await env2.ANALYTICS.put(storageKey, JSON.stringify(record), {
      expirationTtl: Number(env2.ANALYTICS_RETENTION_DAYS || 45) * 24 * 60 * 60
    });
  } catch (error3) {
    console.error("Analytics tracking failed:", error3);
  }
}
__name(trackRequest, "trackRequest");
async function fetchAnalytics(env2, type) {
  if (!env2 || !env2.ANALYTICS) {
    return { error: "Analytics storage not configured" };
  }
  const prefix = "stats:";
  const allKeys = await env2.ANALYTICS.list({ prefix, limit: 1e3 });
  const records = [];
  for (const { name } of allKeys.keys) {
    const value = await env2.ANALYTICS.get(name);
    if (!value) continue;
    try {
      const parsed = JSON.parse(value);
      records.push({
        date: name.substring(prefix.length),
        ...parsed
      });
    } catch (error3) {
      console.error("Failed to parse analytics entry", name, error3);
    }
  }
  if (type === "platforms") {
    const aggregation = {};
    for (const record of records) {
      for (const [platform2, count3] of Object.entries(record.platforms || {})) {
        aggregation[platform2] = (aggregation[platform2] || 0) + count3;
      }
    }
    return { platforms: aggregation };
  }
  return {
    days: records.sort((a, b) => a.date < b.date ? 1 : -1).map((record) => ({
      date: record.date,
      total: record.total || 0,
      paths: record.paths || {},
      platforms: record.platforms || {}
    }))
  };
}
__name(fetchAnalytics, "fetchAnalytics");

// src/handlers/analytics.js
async function analyticsHandler(request, env2) {
  if (!env2 || String(env2.ANALYTICS_ENABLED).toLowerCase() !== "true") {
    return new Response(JSON.stringify({ error: "Analytics disabled" }), {
      status: 404,
      headers: {
        "Content-Type": "application/json",
        ...corsHeaders
      }
    });
  }
  try {
    const url = new URL(request.url);
    const type = url.pathname.split("/").pop();
    const payload = await fetchAnalytics(env2, type);
    return new Response(JSON.stringify(payload, null, 2), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        ...corsHeaders
      }
    });
  } catch (error3) {
    console.error("Analytics handler failed:", error3);
    return new Response(JSON.stringify({ error: "Failed to load analytics" }), {
      status: 500,
      headers: {
        "Content-Type": "application/json",
        ...corsHeaders
      }
    });
  }
}
__name(analyticsHandler, "analyticsHandler");

// src/handlers/health.js
async function healthHandler(request, env2) {
  const analyticsEnabled = env2 && typeof env2.ANALYTICS_ENABLED !== "undefined" ? String(env2.ANALYTICS_ENABLED).toLowerCase() === "true" : false;
  const rateLimitEnabled = env2 && typeof env2.RATE_LIMIT_ENABLED !== "undefined" ? String(env2.RATE_LIMIT_ENABLED).toLowerCase() === "true" : false;
  const status = {
    status: "healthy",
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    environment: env2 && env2.ENVIRONMENT ? env2.ENVIRONMENT : "production",
    checks: {
      releaseCache: "unconfigured",
      analytics: analyticsEnabled ? "enabled" : "disabled",
      rateLimiting: rateLimitEnabled ? "enabled" : "disabled"
    }
  };
  if (env2 && env2.RELEASE_CACHE) {
    try {
      const cached = await env2.RELEASE_CACHE.get("latest_release");
      status.checks.releaseCache = cached ? "hit" : "miss";
    } catch (error3) {
      status.checks.releaseCache = "error";
      status.status = "degraded";
      status.error = `Cache check failed: ${error3.message}`;
    }
  }
  return new Response(JSON.stringify(status, null, 2), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      ...corsHeaders
    }
  });
}
__name(healthHandler, "healthHandler");

// src/utils/rateLimit.js
var DEFAULT_LIMIT = 120;
var DEFAULT_WINDOW_SECONDS = 60;
var buckets = /* @__PURE__ */ new Map();
async function rateLimiter(request, env2) {
  if (!env2 || String(env2.RATE_LIMIT_ENABLED).toLowerCase() !== "true") {
    return;
  }
  const limit = Number(env2.RATE_LIMIT_MAX_REQUESTS || DEFAULT_LIMIT);
  const windowSeconds = Number(env2.RATE_LIMIT_WINDOW_SECONDS || DEFAULT_WINDOW_SECONDS);
  const now = Date.now();
  const clientKey = request.headers.get("CF-Connecting-IP") || "anonymous";
  let bucket = buckets.get(clientKey);
  if (!bucket || bucket.expiresAt <= now) {
    bucket = {
      count: 0,
      expiresAt: now + windowSeconds * 1e3
    };
    buckets.set(clientKey, bucket);
  }
  bucket.count += 1;
  if (bucket.count > limit) {
    const retryAfter = Math.max(1, Math.ceil((bucket.expiresAt - now) / 1e3));
    return new Response("Too Many Requests", {
      status: 429,
      headers: {
        "Retry-After": String(retryAfter),
        "Content-Type": "text/plain"
      }
    });
  }
}
__name(rateLimiter, "rateLimiter");

// src/index.js
var router = e();
router.options("*", handleCORS);
router.get("/health", healthHandler);
router.get("/install.sh", rateLimiter, installHandler);
router.get("/install.ps1", rateLimiter, installHandler);
router.get("/install-macos.sh", rateLimiter, installHandler);
router.get("/api/version/check", rateLimiter, versionHandler);
router.get("/api/version/latest", rateLimiter, versionHandler);
router.get("/releases/proxy/:version/:filename", rateLimiter, proxyHandler);
router.get("/releases/proxy/latest/:filename", rateLimiter, proxyHandler);
router.head("/releases/proxy/:version/:filename", rateLimiter, proxyHandler);
router.head("/releases/proxy/latest/:filename", rateLimiter, proxyHandler);
router.get("/api/stats/:type", analyticsHandler);
router.get("/", async (request, env2) => {
  const response = {
    service: "cert-ctrl-install-service",
    version: "1.0.0",
    endpoints: {
      "Unix/Linux Install": "/install.sh",
      "macOS Install": "/install-macos.sh",
      "Windows Install": "/install.ps1",
      "Version Check": "/api/version/check",
      "Latest Version": "/api/version/latest",
      "Proxy Releases": "/releases/proxy/{version}/{filename}",
      "Health Check": "/health"
    },
    usage: {
      "Quick Install (Unix)": "curl -fsSL https://install.lets-script.com/install.sh | bash",
      "Quick Install (macOS)": "curl -fsSL https://install.lets-script.com/install-macos.sh | sudo bash",
      "Quick Install (Windows)": "iwr -useb https://install.lets-script.com/install.ps1 | iex",
      "Version Check": "curl https://install.lets-script.com/api/version/latest"
    }
  };
  return new Response(JSON.stringify(response, null, 2), {
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders
    }
  });
});
router.all("*", () => {
  return new Response("Not Found", {
    status: 404,
    headers: corsHeaders
  });
});
var index_default = {
  async fetch(request, env2, ctx) {
    try {
      if (env2.ANALYTICS_ENABLED) {
        ctx.waitUntil(trackRequest(request, env2));
      }
      const response = await router.handle(request, env2, ctx);
      response.headers.set("X-Content-Type-Options", "nosniff");
      response.headers.set("X-Frame-Options", "DENY");
      response.headers.set("X-XSS-Protection", "1; mode=block");
      response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
      return response;
    } catch (error3) {
      console.error("Worker error:", error3);
      return new Response("Internal Server Error", {
        status: 500,
        headers: {
          "Content-Type": "text/plain",
          ...corsHeaders
        }
      });
    }
  },
  // Scheduled handler for maintenance tasks
  async scheduled(event, env2, ctx) {
    switch (event.cron) {
      case "0 */6 * * *":
        ctx.waitUntil(warmCache(env2));
        ctx.waitUntil(cleanupAnalytics(env2));
        break;
    }
  }
};
async function warmCache(env2) {
  try {
    const latestUrl = `https://api.github.com/repos/${env2.GITHUB_REPO_OWNER}/${env2.GITHUB_REPO_NAME}/releases/latest`;
    const headers = buildGithubHeaders(env2, {
      Accept: "application/vnd.github.v3+json"
    });
    const response = await fetch(latestUrl, { headers });
    if (response.ok) {
      const data = await response.json();
      const cacheKey = "latest_release";
      await env2.RELEASE_CACHE.put(cacheKey, JSON.stringify(data), {
        expirationTtl: 3600
        // 1 hour
      });
      console.log("Cache warmed for latest release");
    } else {
      const bodyText = await response.text();
      const details = describeGithubFailure(response, bodyText, env2);
      console.warn("Cache warm GitHub lookup failed:", details);
    }
  } catch (error3) {
    console.error("Cache warming failed:", error3);
  }
}
__name(warmCache, "warmCache");
async function cleanupAnalytics(env2) {
  try {
    const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1e3;
    const cutoffKey = `analytics:${thirtyDaysAgo}`;
    console.log("Analytics cleanup triggered");
  } catch (error3) {
    console.error("Analytics cleanup failed:", error3);
  }
}
__name(cleanupAnalytics, "cleanupAnalytics");
export {
  index_default as default
};
//# sourceMappingURL=index.js.map

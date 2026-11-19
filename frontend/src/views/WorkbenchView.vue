<script setup>
/**
 * 工作台：单入口 + 瀑布式分析结果
 *
 * 设计思路：
 *   上传 → 自动分析 → 结果按"信令 → 媒体 → 编码 → 诊断 → 报文"逐层展开，
 *   每节可折叠、可跳转，滚动时自动高亮当前节（滚动叙事）。
 */
import { ref, computed, onMounted, onUnmounted, nextTick, watch } from 'vue'
import { useRouter } from 'vue-router'
import * as echarts from 'echarts'
import { api } from '../api/client'
import { useTaskStore } from '../stores/task'
import VideoPlayer from '../components/VideoPlayer.vue'
import AiSummarySection from '../components/AiSummarySection.vue'

const router = useRouter()
const store = useTaskStore()

const task = ref(null)
const overview = ref(null)
const sessions = ref([])
const diagnostics = ref([])
const streams = ref([])
const mediaStats = ref(null)
const metrics = {}
const packets = ref([])
const packetTotal = ref(0)

const uploading = ref(false)
const uploadPct = ref(0)
const dragging = ref(false)
const err = ref('')
const fileInput = ref(null)
const busyStage = ref('')
const busyPct = ref(0)

const openSections = ref({
  hero: true, kpi: true, signal: true, media: true,
  codec: true, diag: true, packet: true
})
const activeSection = ref('kpi')
// AI 设置抽屉走全局 store，避免两个实例
const aiPanelOpen = computed({
  get: () => store.aiPanelOpen,
  set: (v) => v ? store.openAiPanel() : store.closeAiPanel()
})

const charts = {}
const C = {
  brand: '#D70D19', ds: '#4D6BFE', ok: '#22c55e', warn: '#f0a020',
  crit: '#f0453a', info: '#3d9be9', dim: '#6f7d90'
}

/* ---------------- 主题色读取（图表跟随明暗） ---------------- */
function themeColors() {
  const dark = document.documentElement.getAttribute('data-theme') !== 'light'
  return {
    text: dark ? '#a5b3c4' : '#4c5a6b',
    dim: dark ? '#6f7d90' : '#74828f',
    line: dark ? '#1a2432' : '#e4eaf2',
    surface: dark ? '#111823' : '#ffffff',
    tipBg: dark ? '#161f2c' : '#ffffff',
    tipBorder: dark ? '#2c3a4d' : '#d3dde8',
    tipText: dark ? '#eaf0f7' : '#101822'
  }
}

function chart(id, opt) {
  const el = document.getElementById(id)
  if (!el) return
  if (!charts[id]) charts[id] = echarts.init(el)
  charts[id].setOption(opt, true)
}

function baseGrid(extra = {}) {
  const t = themeColors()
  return {
    backgroundColor: 'transparent',
    textStyle: { color: t.text, fontSize: 11 },
    tooltip: {
      backgroundColor: t.tipBg,
      borderColor: t.tipBorder,
      borderWidth: 1,
      textStyle: { color: t.tipText, fontSize: 11.5 },
      extraCssText: 'box-shadow:0 6px 24px rgba(0,0,0,.22);border-radius:8px;'
    },
    ...extra
  }
}

function axisCommon() {
  const t = themeColors()
  return {
    axisLine: { lineStyle: { color: t.line } },
    axisTick: { show: false },
    axisLabel: { color: t.dim, fontSize: 10 }
  }
}
function splitCommon() {
  const t = themeColors()
  return { splitLine: { lineStyle: { color: t.line, type: 'dashed' } } }
}

/* ---------------- 数据加载 ---------------- */
let loadSeq = 0
async function loadAll() {
  if (!store.currentTaskId) return
  const seq = ++loadSeq
  const tid = store.currentTaskId
  const stale = () => seq !== loadSeq || tid !== store.currentTaskId
  try {
    const t = await store.loadTask(tid)
    if (stale()) return          // 期间已切换任务：丢弃旧响应，避免覆盖新任务
    task.value = t
    if (task.value.status !== 'completed') return
    const [ov, ss, dg, pk] = await Promise.all([
      api.overview(store.currentTaskId),
      api.sessions(store.currentTaskId, { page_size: 30 }),
      api.diagnostics(store.currentTaskId, { page_size: 40 }),
      api.packets(store.currentTaskId, { page_size: 8 })
    ])
    overview.value = ov
    sessions.value = ss.items
    diagnostics.value = dg.items
    packets.value = pk.items
    packetTotal.value = pk.total

    // 拉媒体流
    // 关键：有信令时按会话取（能带设备归属）；无信令时按任务取
    // —— 纯 RTP 码流包没有 INVITE，session_id 全为空，
    //    如果只按会话取流就会一条都看不到
    let allStreams = []

    if (ss.items.length) {
      const pairs = await Promise.all(
        ss.items.map(async (s) => {
          const [media, mt] = await Promise.all([
            api.sessionMedia(s.id),
            api.sessionMetrics(s.id)
          ])
          return { s, media, mt }
        })
      )
      pairs.forEach(({ s, media, mt }) => {
        media.items.forEach(st => { st._sid = s.id; st._dev = s.device_id })
        allStreams.push(...media.items)
        mt.items.forEach(x => { metrics[x.stream_id] = x })
      })
      // 兜底：会话没覆盖到的流（session_id 为空）也要展示
      const covered = new Set(allStreams.map(x => x.id))
      const all = await api.taskMedia(store.currentTaskId)
      all.items.forEach(st => {
        if (!covered.has(st.id)) {
          st._sid = null
          st._orphan = true
          allStreams.push(st)
        }
      })
    } else {
      // 无信令：直接取任务下所有流
      const all = await api.taskMedia(store.currentTaskId)
      allStreams = all.items.map(st => ({ ...st, _sid: null, _orphan: true }))
    }

    streams.value = allStreams

    // 媒体统计（无信令时用于概览展示）
    try {
      mediaStats.value = await api.taskMediaStats(store.currentTaskId)
    } catch { mediaStats.value = null }

    await nextTick()
    renderCharts()
  } catch (e) { err.value = e.message }
}

function renderCharts() {
  const ov = overview.value
  if (!ov) return
  const s = ov.summary || {}
  const t = themeColors()

  /* --- 1. 业务分布环形 --- */
  const md = ov.method_distribution || {}
  const biz = Object.entries(md).map(([k, v]) => ({ name: k, value: v }))
    .sort((a, b) => b.value - a.value)
  const bizTotal = biz.reduce((a, b) => a + b.value, 0) || 1

  chart('c-biz', baseGrid({
    tooltip: { ...baseGrid().tooltip, trigger: 'item' },
    legend: {
      orient: 'vertical', right: 8, top: 'center',
      itemWidth: 8, itemHeight: 8, itemGap: 10,
      textStyle: { color: t.text, fontSize: 11 },
      formatter: (n) => {
        const it = biz.find(d => d.name === n)
        return it ? `${n}  ${(it.value / bizTotal * 100).toFixed(0)}%` : n
      }
    },
    series: [{
      type: 'pie', radius: ['52%', '76%'], center: ['27%', '50%'],
      itemStyle: { borderColor: t.surface, borderWidth: 3 },
      label: {
        show: true, position: 'center',
        formatter: () => `{n|${bizTotal}}\n{l|报文}`,
        rich: {
          n: { fontSize: 22, fontWeight: 700, color: t.tipText, lineHeight: 26 },
          l: { fontSize: 10.5, color: t.dim }
        }
      },
      data: biz,
      color: [C.brand, C.ds, C.ok, C.warn, C.info, '#9b59f0', C.dim]
    }]
  }))

  /* --- 2. 响应码 --- */
  const cd = ov.code_distribution || {}
  const codes = Object.entries(cd).sort((a, b) => b[1] - a[1]).slice(0, 7)
  chart('c-code', baseGrid({
    grid: { left: 66, right: 46, top: 10, bottom: 10 },
    tooltip: { ...baseGrid().tooltip, trigger: 'axis',
               axisPointer: { type: 'shadow' } },
    xAxis: { type: 'value', show: false },
    yAxis: {
      type: 'category',
      data: codes.map(c => c[0]).reverse(),
      ...axisCommon(),
      axisLabel: { color: t.text, fontSize: 10.5, fontFamily: 'monospace' }
    },
    series: [{
      type: 'bar',
      data: codes.map(c => ({
        value: c[1],
        itemStyle: {
          color: c[0].startsWith('2') ? C.ok
            : /^[456]/.test(c[0]) ? C.crit
            : c[0].startsWith('1') ? C.info : C.warn,
          borderRadius: [0, 4, 4, 0]
        }
      })).reverse(),
      barWidth: 13,
      label: { show: true, position: 'right', color: t.text, fontSize: 10.5 }
    }]
  }))

  /* --- 3. 会话状态 --- */
  const sigD = ov.signal_distribution || {}
  const medD = ov.media_distribution || {}
  const total = s.session_count || 0
  chart('c-state', baseGrid({
    tooltip: { ...baseGrid().tooltip, trigger: 'item' },
    legend: {
      bottom: 0, itemWidth: 8, itemHeight: 8, itemGap: 14,
      textStyle: { color: t.text, fontSize: 10.5 }
    },
    series: [{
      type: 'pie', radius: ['48%', '70%'], center: ['50%', '44%'],
      itemStyle: { borderColor: t.surface, borderWidth: 3 },
      label: {
        show: true, position: 'center',
        formatter: () => `{n|${total}}\n{l|点播会话}`,
        rich: {
          n: { fontSize: 24, fontWeight: 700, color: t.tipText, lineHeight: 28 },
          l: { fontSize: 10.5, color: t.dim }
        }
      },
      data: [
        { name: '信令成功', value: sigD.success || 0, itemStyle: { color: C.ok } },
        { name: '无媒体', value: medD.no_media || 0, itemStyle: { color: C.crit } },
        { name: '信令失败', value: sigD.failed || 0, itemStyle: { color: C.warn } },
        { name: '其他', value: (sigD.incomplete || 0) + (medD.undecodable || 0),
          itemStyle: { color: C.dim } }
      ].filter(d => d.value > 0)
    }]
  }))

  /* --- 4. 码率趋势（所有流） --- */
  const PALETTE = [C.ds, C.ok, C.warn, C.info, '#9b59f0', C.brand]
  const brSeries = streams.value.map((st, i) => {
    const m = metrics[st.id]
    if (!m?.bitrate_series?.length) return null
    return {
      name: '0x' + (st.ssrc ? st.ssrc.toString(16) : i),
      type: 'line', smooth: true, showSymbol: false,
      lineStyle: { width: 1.8, color: PALETTE[i % PALETTE.length] },
      areaStyle: {
        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: PALETTE[i % PALETTE.length] + '38' },
          { offset: 1, color: PALETTE[i % PALETTE.length] + '00' }
        ])
      },
      data: m.bitrate_series.map(p => [p.t, p.v])
    }
  }).filter(Boolean)

  chart('c-bitrate', baseGrid({
    grid: { left: 56, right: 20, top: 34, bottom: 30 },
    legend: {
      top: 0, right: 0, itemWidth: 8, itemHeight: 8, itemGap: 12,
      textStyle: { color: t.dim, fontSize: 10 },
      data: brSeries.map(x => x.name)
    },
    tooltip: { ...baseGrid().tooltip, trigger: 'axis' },
    xAxis: {
      type: 'value', name: '秒', nameTextStyle: { color: t.dim, fontSize: 9.5 },
      ...axisCommon(), ...splitCommon()
    },
    yAxis: {
      type: 'value', name: 'kbps', nameTextStyle: { color: t.dim, fontSize: 9.5 },
      ...axisCommon(), ...splitCommon(), axisLine: { show: false }
    },
    series: brSeries
  }))

  /* --- 5. 抖动趋势 --- */
  const jSeries = streams.value.map((st, i) => {
    const m = metrics[st.id]
    if (!m?.jitter_series?.length) return null
    return {
      name: '0x' + (st.ssrc ? st.ssrc.toString(16) : i),
      type: 'line', smooth: true, showSymbol: false,
      lineStyle: { width: 1.8, color: PALETTE[i % PALETTE.length] },
      data: m.jitter_series.map(p => [p.t, p.v])
    }
  }).filter(Boolean)

  chart('c-jitter', baseGrid({
    grid: { left: 56, right: 20, top: 34, bottom: 30 },
    legend: {
      top: 0, right: 0, itemWidth: 8, itemHeight: 8, itemGap: 12,
      textStyle: { color: t.dim, fontSize: 10 },
      data: jSeries.map(x => x.name)
    },
    tooltip: { ...baseGrid().tooltip, trigger: 'axis' },
    xAxis: {
      type: 'value', name: '秒', nameTextStyle: { color: t.dim, fontSize: 9.5 },
      ...axisCommon(), ...splitCommon()
    },
    yAxis: {
      type: 'value', name: 'ms', nameTextStyle: { color: t.dim, fontSize: 9.5 },
      ...axisCommon(), ...splitCommon(), axisLine: { show: false }
    },
    series: jSeries
  }))
}

/* ---------------- 上传 ---------------- */
async function handleFile(f) {
  if (!f) return
  err.value = ''
  uploading.value = true
  uploadPct.value = 0
  try {
    const res = await api.upload(f, p => { uploadPct.value = p })
    store.setCurrent(res.task_id)
    task.value = await store.loadTask(res.task_id)
    await api.analyze(res.task_id)
    startPoll()
  } catch (e) {
    err.value = e.message
  } finally {
    uploading.value = false
  }
}

let pollTimer = null
function startPoll() {
  stopPoll()
  pollTimer = setInterval(async () => {
    try {
      task.value = await store.loadTask()
      busyStage.value = task.value.stage || ''
      busyPct.value = task.value.progress || 0
      if (!['pending', 'analyzing'].includes(task.value.status)) {
        stopPoll()
        if (task.value.status === 'completed') await loadAll()
      }
    } catch { /* 忽略 */ }
  }, 1000)
}
function stopPoll() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null } }

function onDrop(e) {
  dragging.value = false
  const f = e.dataTransfer?.files?.[0]
  if (f) handleFile(f)
}
function onPick(e) {
  handleFile(e.target.files?.[0])
  e.target.value = ''
}

const reanalyzing = ref(false)
async function reanalyze() {
  if (!store.currentTaskId || reanalyzing.value) return
  reanalyzing.value = true
  err.value = ''
  try {
    await api.analyze(store.currentTaskId)
    task.value = await store.loadTask()
    startPoll()
  } catch (e) {
    err.value = e.message
  } finally {
    reanalyzing.value = false
  }
}

function reset() {
  stopPoll()
  store.setCurrent(null)
  loadSeq++                     // 作废在途的加载请求
  task.value = null
  overview.value = null
  sessions.value = []
  diagnostics.value = []
  streams.value = []
  packets.value = []
  // 若停留在 /tasks/:id，回到工作台首页，避免 URL 与页面状态不一致
  if (router.currentRoute.value.name === 'task') router.replace('/')
}

// 分析步骤（与后端 stage 百分比对齐）
const ANALYSIS_STEPS = [
  { label: '读取文件信息', pct: 5 },
  { label: '建立报文索引', pct: 15 },
  { label: '解析 SIP 信令', pct: 30 },
  { label: '重建点播会话', pct: 45 },
  { label: '分析 RTP 媒体', pct: 60 },
  { label: 'PS/ES 解封装', pct: 75 },
  { label: '执行诊断', pct: 85 },
  { label: '生成汇总', pct: 95 }
]

/* ---------------- 派生数据 ---------------- */
const summary = computed(() => overview.value?.summary || {})
const diagTotal = computed(() => {
  const d = summary.value.diagnostics || {}
  return (d.critical || 0) + (d.warning || 0) + (d.info || 0)
})

// 编码信息汇总（从流的 extra.ps 里取）
const codecList = computed(() =>
  streams.value.map(st => ({
    id: st.id,
    ssrc: st.ssrc,
    codec: st.codec,
    width: st.width,
    height: st.height,
    frameCount: st.frame_count,
    keyframeCount: st.keyframe_count,
    transport: st.transport,
    ps: st.extra?.ps || null
  })).filter(x => x.codec || x.ps)
)

const codecSummary = computed(() => {
  const set = new Set()
  let res = ''
  codecList.value.forEach(x => {
    if (x.codec) set.add(x.codec)
    if (x.width && x.height && !res) res = `${x.width}×${x.height}`
  })
  return {
    codecs: [...set],
    resolution: res || null,
    totalFrames: codecList.value.reduce((a, b) => a + (b.frameCount || 0), 0),
    totalKeyframes: codecList.value.reduce((a, b) => a + (b.keyframeCount || 0), 0)
  }
})

// 各板块是否有内容 —— 空板块自动隐藏（不再显示"挤在一起"的空框）
const hasSignal = computed(() => sessions.value.length > 0)
const hasMedia = computed(() => streams.value.length > 0)
const hasCodec = computed(() => codecList.value.length > 0)
const hasDiag = computed(() => diagnostics.value.length > 0)
const hasPacket = computed(() => packets.value.length > 0)

// 可播放的视频流（重建成功的），按包数降序，多的更有内容
const playableStreams = computed(() =>
  streams.value
    .filter(st => st.extra?.rebuild?.ok && st.rebuilt_path)
    .sort((a, b) => (b.packet_count || 0) - (a.packet_count || 0)))

// 视频展示数量（流太多时先显示前 N 个，可展开）
const videoLimit = ref(8)
const showAllVideos = ref(false)
const visibleVideos = computed(() =>
  showAllVideos.value ? playableStreams.value
                      : playableStreams.value.slice(0, videoLimit.value))

// 动态编号：只给可见板块编号
const secNums = computed(() => {
  const map = {}
  let n = 1
  map.kpi = n++
  map.ai = n++          // AI 概览固定第 2 位
  if (hasSignal.value) map.signal = n++
  if (hasMedia.value) map.media = n++
  if (hasCodec.value) map.codec = n++
  if (hasDiag.value) map.diag = n++
  if (hasPacket.value) map.packet = n++
  return map
})

const spyList = computed(() => {
  const out = [{ k: 'kpi', l: '总览' }, { k: 'ai', l: 'AI 分析' }]
  if (hasSignal.value) out.push({ k: 'signal', l: '信令' })
  if (hasMedia.value) out.push({ k: 'media', l: '媒体' })
  if (hasCodec.value) out.push({ k: 'codec', l: '编码' })
  if (hasDiag.value) out.push({ k: 'diag', l: '诊断' })
  if (hasPacket.value) out.push({ k: 'packet', l: '报文' })
  return out
})

const EV = { confirmed: '已确认', suspected: '疑似', insufficient: '证据不足' }
const EV_CLS = { confirmed: 'ok', suspected: 'warning', insufficient: 'unknown' }
const SEV_CLS = { critical: 'critical', warning: 'warning', info: 'info', unknown: 'unknown' }

const fmt = (v, d = 2) => v == null ? null : Number(v).toFixed(d)

function toggle(k) { openSections.value[k] = !openSections.value[k] }
function goSession(id) { router.push(`/sessions/${id}`) }
function goPacket(num) {
  router.push({ name: 'packets', query: { number: num } })
}

/* ---------------- 滚动叙事：高亮当前节 ---------------- */
const SECTION_IDS = ['sec-kpi', 'sec-ai', 'sec-signal', 'sec-media', 'sec-codec', 'sec-diag', 'sec-packet']
let scrollObs = null

function setupScrollSpy() {
  if (scrollObs) scrollObs.disconnect()
  const opts = { rootMargin: '-30% 0px -55% 0px', threshold: 0 }
  scrollObs = new IntersectionObserver((entries) => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        activeSection.value = e.target.id.replace('sec-', '')
      }
    })
  }, opts)
  nextTick(() => {
    SECTION_IDS.forEach(id => {
      const el = document.getElementById(id)
      if (el) scrollObs.observe(el)
    })
  })
}

function scrollTo(sec) {
  const el = document.getElementById('sec-' + sec)
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
}

// 主题切换后重绘图表
function onThemeChange() {
  Object.keys(charts).forEach(k => {
    charts[k]?.dispose()
    delete charts[k]
  })
  nextTick(renderCharts)
}

onMounted(async () => {
  await loadAll()
  if (store.isAnalyzing) startPoll()
  setupScrollSpy()
  window.addEventListener('alma-theme-changed', onThemeChange)
})
onUnmounted(() => {
  stopPoll()
  scrollObs?.disconnect()
  window.removeEventListener('alma-theme-changed', onThemeChange)
})
watch(() => store.currentTaskId, async () => {
  await loadAll()
  setupScrollSpy()
})
watch(openSections, () => nextTick(renderCharts), { deep: true })
</script>

<template>
  <div class="page">
    <!-- ==================== 上传入口 ==================== -->
    <div v-if="!task" class="hero">
      <div class="hero-bg"></div>
      <div class="hero-in">
        <div class="hero-tag">
          <span class="ht-dot"></span>
          网络抓包分析 · 协议与流媒体诊断
        </div>
        <h1 class="hero-h1">
          上传抓包，<span class="hl">一次看清</span>整条链路
        </h1>
        <p class="hero-p">
          通用网络报文解析打底 —— SIP / RTP / RTCP / TCP 流重组，
          再针对视频联网场景下钻到 SDP 协商、PS 封装与视频编码还原
        </p>
        <div class="hero-tags">
          <span class="hsz">PCAP / PCAPNG</span>
          <span class="hsz">SIP · SDP</span>
          <span class="hsz">RTP / RTCP</span>
          <span class="hsz">PS / ES</span>
          <span class="hsz">H.264 / H.265</span>
        </div>

        <div class="up-zone"
             :class="{ dragging, busy: uploading }"
             @dragover.prevent="dragging = true"
             @dragleave.prevent="dragging = false"
             @drop.prevent="onDrop"
             @click="!uploading && $refs.fileInput.click()">
          <input ref="fileInput" type="file" accept=".pcap,.pcapng,.cap"
                 hidden @change="onPick" />

          <template v-if="!uploading">
            <div class="up-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6">
                <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
                <polyline points="17 8 12 3 7 8"/>
                <line x1="12" y1="3" x2="12" y2="15"/>
              </svg>
            </div>
            <div class="up-title">拖拽抓包文件到这里，或点击选择</div>
            <div class="up-hint">.pcap / .pcapng · 单文件最大 2GB</div>
            <div class="up-caps">
              <span><i class="c-sip"></i>信令解析</span>
              <span><i class="c-rtp"></i>媒体质量</span>
              <span><i class="c-ps"></i>码流还原</span>
              <span><i class="c-diag"></i>故障诊断</span>
            </div>
          </template>

          <div v-else class="up-progress">
            <div class="up-title">上传中 {{ uploadPct }}%</div>
            <div class="up-bar"><i :style="{ width: uploadPct + '%' }"></i></div>
          </div>
        </div>

        <div v-if="err" class="err-box mt-14" style="max-width:600px;margin-left:auto;margin-right:auto">
          {{ err }}
        </div>
      </div>
    </div>

    <!-- ==================== 分析中 ==================== -->
    <div v-else-if="store.isAnalyzing" class="analyzing-wrap">
      <div class="an-card">
        <div class="an-ring">
          <svg viewBox="0 0 100 100">
            <circle cx="50" cy="50" r="42" fill="none"
                    stroke="var(--line)" stroke-width="6"/>
            <circle cx="50" cy="50" r="42" fill="none"
                    stroke="var(--brand)" stroke-width="6"
                    stroke-linecap="round"
                    :stroke-dasharray="`${264 * (busyPct || task.progress) / 100} 264`"
                    transform="rotate(-90 50 50)"
                    style="transition:stroke-dasharray .5s var(--ease)"/>
          </svg>
          <div class="an-pct">{{ busyPct || task.progress }}<span>%</span></div>
        </div>
        <div class="an-stage">{{ busyStage || task.stage || '分析中' }}</div>
        <div class="an-steps">
          <div v-for="(s, i) in ANALYSIS_STEPS" :key="i" class="an-step"
               :class="{ done: (busyPct || task.progress) > s.pct,
                         now: (busyPct || task.progress) > (ANALYSIS_STEPS[i-1]?.pct ?? -1) &&
                              (busyPct || task.progress) <= s.pct }">
            <span class="as-dot"></span>
            <span class="as-txt">{{ s.label }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- ==================== 分析失败 ==================== -->
    <div v-else-if="task.status === 'failed'" class="fail-wrap">
      <div class="err-box">
        <strong>分析失败</strong>
        <div class="mt-10">{{ task.error_message || '未知错误' }}</div>
      </div>
      <button class="btn mt-14" @click="reset">重新上传</button>
    </div>

    <!-- ==================== 已取消 ==================== -->
    <div v-else-if="task.status === 'cancelled'" class="fail-wrap">
      <div class="info-box">
        <strong>分析已取消</strong>
        <div class="mt-10">已保留上传文件，可重新分析；如不需要，可新建分析。</div>
      </div>
      <button class="btn mt-14" :disabled="reanalyzing" @click="reanalyze">重新分析</button>
      <button class="btn mt-14" style="margin-left:8px" @click="reset">新建分析</button>
    </div>

    <!-- ==================== 结果瀑布 ==================== -->
    <template v-else-if="task.status === 'completed'">
      <!-- 进度导航 -->
      <nav class="spy">
        <div class="spy-in">
          <button v-for="s in spyList" :key="s.k" class="spy-btn"
            :class="{ on: activeSection === s.k }"
            @click="scrollTo(s.k)">{{ s.l }}</button>
          <span class="spacer"></span>
          <span class="spy-file mono-sm truncate">
            {{ task.file?.filename }}
          </span>
          <button class="btn-mini" @click="reset">新建分析</button>
        </div>
      </nav>

      <!-- ===== 1. 总览 ===== -->
      <section id="sec-kpi" class="sec rise mb-20">
        <div class="sec-head">
          <span class="sec-num">{{ secNums.kpi }}</span>
          <span class="sec-title">分析总览</span>
          <span class="sec-sub">
            {{ task.file?.packet_count?.toLocaleString() }} 报文 ·
            {{ task.file?.duration?.toFixed(1) }}s ·
            {{ task.file?.link_type }}
          </span>
          <span class="spacer"></span>
          <span v-if="summary.capture_warnings" class="badge warning">
            {{ summary.capture_warnings }} 项抓包提示
          </span>
        </div>
        <div class="sec-body">
          <!-- 无信令时：用媒体视角展示（纯 RTP 码流包） -->
          <div v-if="!hasSignal && mediaStats" class="kpis mb-20">
            <div class="kpi brand">
              <div class="kpi-label">报文总数</div>
              <div class="kpi-value">{{ (summary.packet_count || 0).toLocaleString() }}</div>
              <div class="kpi-sub">{{ task.file?.duration?.toFixed(1) }}s 抓包时长</div>
            </div>
            <div class="kpi ok">
              <div class="kpi-label">RTP 流</div>
              <div class="kpi-value ok">{{ mediaStats.total }}</div>
              <div class="kpi-sub">{{ mediaStats.total_packets.toLocaleString() }} 个包</div>
            </div>
            <div class="kpi" :class="mediaStats.rebuilt ? 'ok' : 'warning'">
              <div class="kpi-label">成功解码</div>
              <div class="kpi-value" :class="mediaStats.rebuilt ? 'ok' : 'warning'">
                {{ mediaStats.rebuilt }}
                <span class="kpi-unit">/ {{ mediaStats.total }}</span>
              </div>
              <div class="kpi-sub">可播放视频</div>
            </div>
            <div class="kpi">
              <div class="kpi-label">合计码率</div>
              <div class="kpi-value">
                {{ (mediaStats.total_bitrate / 1000).toFixed(1) }}
                <span class="kpi-unit">Mbps</span>
              </div>
              <div class="kpi-sub">所有流总和</div>
            </div>
            <div class="kpi" :class="mediaStats.avg_jitter > 50 ? 'warning' : 'ok'">
              <div class="kpi-label">平均抖动</div>
              <div class="kpi-value" :class="mediaStats.avg_jitter == null ? 'na'
                : (mediaStats.avg_jitter > 50 ? 'warning' : 'ok')">
                {{ mediaStats.avg_jitter != null ? mediaStats.avg_jitter : '—' }}
                <span v-if="mediaStats.avg_jitter != null" class="kpi-unit">ms</span>
              </div>
              <div class="kpi-sub">RFC 3550</div>
            </div>
            <div class="kpi">
              <div class="kpi-label">编码 / 分辨率</div>
              <div class="kpi-value sm" style="font-size:15px">
                {{ Object.keys(mediaStats.codecs).join('/') || '—' }}
              </div>
              <div class="kpi-sub">
                {{ Object.entries(mediaStats.resolutions).map(([k,v]) => k + '×' + v).join(' · ') || '—' }}
              </div>
            </div>
            <div class="kpi">
              <div class="kpi-label">信令</div>
              <div class="kpi-value na" style="font-size:15px">未捕获</div>
              <div class="kpi-sub">该抓包不含 SIP</div>
            </div>
          </div>

          <!-- 提示：无信令 -->
          <div v-if="!hasSignal" class="info-box mb-20">
            <strong>这个抓包不含 SIP 信令</strong> —— 只能做媒体层分析。
            媒体流无法归属到具体设备或点播会话（没有 INVITE 上下文）。
            要还原完整点播链路，需要在信令与媒体都经过的节点重新抓包。
          </div>

          <div v-if="hasSignal" class="kpis">
            <div class="kpi brand">
              <div class="kpi-label">报文总数</div>
              <div class="kpi-value">{{ (summary.packet_count || 0).toLocaleString() }}</div>
              <div class="kpi-sub">{{ task.file?.duration?.toFixed(2) }}s 抓包时长</div>
            </div>
            <div class="kpi">
              <div class="kpi-label">点播会话</div>
              <div class="kpi-value">{{ summary.session_count ?? 0 }}</div>
              <div class="kpi-sub">SIP 业务会话</div>
            </div>
            <div class="kpi" :class="summary.signal_success_rate >= 90 ? 'ok' : 'warning'">
              <div class="kpi-label">信令建立成功率</div>
              <div class="kpi-value" :class="summary.signal_success_rate == null ? 'na'
                : (summary.signal_success_rate >= 90 ? 'ok' : 'warning')">
                {{ summary.signal_success_rate != null ? fmt(summary.signal_success_rate, 1) : '—' }}
                <span v-if="summary.signal_success_rate != null" class="kpi-unit">%</span>
              </div>
              <div class="kpi-sub">{{ summary.signal_success || 0 }}/{{ summary.session_count || 0 }} 成功</div>
            </div>
            <div class="kpi" :class="summary.sessions_with_media ? 'ok' : 'critical'">
              <div class="kpi-label">发现媒体</div>
              <div class="kpi-value" :class="summary.sessions_with_media ? 'ok' : 'critical'">
                {{ summary.sessions_with_media ?? 0 }}
                <span class="kpi-unit">/ {{ summary.session_count || 0 }}</span>
              </div>
              <div class="kpi-sub">{{ summary.total_streams || 0 }} 条 RTP 流</div>
            </div>
            <div class="kpi" :class="diagTotal ? 'critical' : 'ok'">
              <div class="kpi-label">异常事件</div>
              <div class="kpi-value" :class="diagTotal ? 'critical' : 'ok'">{{ diagTotal }}</div>
              <div class="kpi-sub">
                {{ summary.diagnostics?.critical || 0 }} 严重 ·
                {{ summary.diagnostics?.warning || 0 }} 警告
              </div>
            </div>
            <div class="kpi">
              <div class="kpi-label">首媒体包耗时</div>
              <div class="kpi-value sm" :class="summary.avg_first_media_latency == null ? 'na' : 'warning'">
                {{ summary.avg_first_media_latency != null
                    ? fmt(summary.avg_first_media_latency, 3) : '无法计算' }}
                <span v-if="summary.avg_first_media_latency != null" class="kpi-unit">s</span>
              </div>
              <div class="kpi-sub">INVITE → 首个 RTP</div>
            </div>
            <div class="kpi">
              <div class="kpi-label">RTP 抖动</div>
              <div class="kpi-value sm" :class="summary.avg_jitter_ms == null ? 'na'
                : (summary.avg_jitter_ms > 50 ? 'warning' : 'ok')">
                {{ summary.avg_jitter_ms != null ? fmt(summary.avg_jitter_ms, 2) : '无媒体' }}
                <span v-if="summary.avg_jitter_ms != null" class="kpi-unit">ms</span>
              </div>
              <div class="kpi-sub">RFC 3550 平均值</div>
            </div>
          </div>

          <div class="g3 mt-20">
            <div class="mini-card">
              <div class="mc-head">业务分布</div>
              <div class="mc-chart" id="c-biz"></div>
            </div>
            <div class="mini-card">
              <div class="mc-head">SIP 响应码</div>
              <div class="mc-chart" id="c-code"></div>
            </div>
            <div class="mini-card">
              <div class="mc-head">会话状态</div>
              <div class="mc-chart" id="c-state"></div>
            </div>
          </div>
        </div>
      </section>

      <!-- ===== AI 分析概览 ===== -->
      <section id="sec-ai" class="rise mb-20">
        <AiSummarySection :num="secNums.ai" />
      </section>

      <!-- ===== 信令 ===== -->
      <section v-if="hasSignal" id="sec-signal" class="sec rise mb-20">
        <div class="sec-head clickable" @click="toggle('signal')">
          <span class="sec-num">{{ secNums.signal }}</span>
          <span class="sec-title">SIP 信令分析</span>
          <span class="sec-sub">{{ sessions.length }} 个会话</span>
          <span class="spacer"></span>
          <router-link to="/sip" class="btn-mini" @click.stop>信令时序图 →</router-link>
          <span class="chev" :class="{ open: openSections.signal }">›</span>
        </div>
        <div v-show="openSections.signal" class="sec-body flush">
          <table class="tbl" v-if="sessions.length">
            <thead>
              <tr>
                <th>会话</th><th>设备 / 通道 ID</th><th>开始</th><th>时长</th>
                <th>信令</th><th>媒体</th><th>结束</th><th>诊断</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="s in sessions" :key="s.id" @click="goSession(s.id)">
                <td class="mono">#{{ s.id }}</td>
                <td class="mono truncate" style="max-width:220px">{{ s.device_id || '—' }}</td>
                <td class="mono-sm">{{ s.start_time?.toFixed(2) }}s</td>
                <td class="num">{{ s.total_duration != null ? s.total_duration.toFixed(2) + 's' : '—' }}</td>
                <td>
                  <span class="badge" :class="s.signal_status === 'success' ? 'ok'
                    : (s.signal_status === 'failed' ? 'critical' : 'warning')">
                    {{ { success:'成功', failed:'失败', incomplete:'不完整', unknown:'未知' }[s.signal_status] }}
                  </span>
                </td>
                <td>
                  <span class="badge" :class="s.media_status === 'received' ? 'ok'
                    : (s.media_status === 'no_media' ? 'critical' : 'warning')">
                    {{ { received:'已收到', no_media:'无媒体', undecodable:'不可解码', unknown:'未知' }[s.media_status] }}
                  </span>
                </td>
                <td>
                  <span class="badge" :class="s.end_reason === 'normal' ? 'ok' : 'warning'">
                    {{ { normal:'正常', abnormal:'异常', capture_ended:'抓包结束', unknown:'未知' }[s.end_reason] }}
                  </span>
                </td>
                <td>
                  <span v-if="s.critical_count" class="badge critical">{{ s.critical_count }}</span>
                  <span v-else-if="s.warning_count" class="badge warning">{{ s.warning_count }}</span>
                  <span v-else class="badge ok">—</span>
                </td>
              </tr>
            </tbody>
          </table>
          <div v-else class="empty">
            未识别到点播会话
            <div class="hint">抓包中可能不含 INVITE 信令，或抓包点位于信令路径之外</div>
          </div>
        </div>
      </section>

      <!-- ===== 3. 媒体 ===== -->
      <section v-if="hasMedia" id="sec-media" class="sec rise mb-20">
        <div class="sec-head clickable" @click="toggle('media')">
          <span class="sec-num">{{ secNums.media }}</span>
          <span class="sec-title">RTP 媒体质量</span>
          <span class="sec-sub">{{ streams.length }} 条流</span>
          <span class="spacer"></span>
          <span v-if="!streams.length" class="badge critical">未捕获媒体</span>
          <router-link to="/media" class="btn-mini" @click.stop>详细分析 →</router-link>
          <span class="chev" :class="{ open: openSections.media }">›</span>
        </div>
        <div v-show="openSections.media" class="sec-body">
          <template v-if="streams.length">
            <div class="g2">
              <div class="mini-card">
                <div class="mc-head">媒体码率趋势</div>
                <div class="mc-chart lg" id="c-bitrate"></div>
              </div>
              <div class="mini-card">
                <div class="mc-head">RTP 抖动趋势</div>
                <div class="mc-chart lg" id="c-jitter"></div>
              </div>
            </div>

            <!-- 重建视频 -->
            <div v-if="playableStreams.length" class="video-sec">
              <div class="vs-head">
                <span class="vs-title">视频画面还原</span>
                <span class="vs-sub">
                  {{ playableStreams.length }} 条流成功解码
                  · RTP → PS → ES → H.264
                  <template v-if="!hasSignal"> · 无信令，按 SSRC 编号</template>
                </span>
              </div>
              <div class="video-grid">
                <VideoPlayer v-for="st in visibleVideos"
                             :key="st.id" :stream="st" />
              </div>
              <div v-if="playableStreams.length > videoLimit"
                   class="video-more">
                <button class="btn sm" @click="showAllVideos = !showAllVideos">
                  {{ showAllVideos
                      ? '收起'
                      : `展开剩余 ${playableStreams.length - videoLimit} 条` }}
                </button>
              </div>
            </div>

            <div v-else class="video-none">
              <div class="vn-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6">
                  <rect x="2" y="4" width="20" height="14" rx="2"/>
                  <line x1="2" y1="20" x2="22" y2="20"/>
                </svg>
              </div>
              <div>
                <div class="vn-t">未能还原出视频画面</div>
                <div class="vn-s">
                  抓到 RTP 但解码失败。常见原因：抓包起点缺少 SPS/PPS、
                  PS 封装不规范、或该流是纯音频
                </div>
              </div>
            </div>

            <div class="stream-grid mt-20">
              <div v-for="st in streams" :key="st.id" class="stream-card">
                <div class="sc-top">
                  <span class="mono sc-ssrc">0x{{ st.ssrc?.toString(16) }}</span>
                  <span class="badge unknown">{{ st.transport }}</span>
                </div>
                <div class="sc-metrics">
                  <div><i>包数</i><b>{{ st.packet_count }}</b></div>
                  <div><i>码率</i><b>{{ st.avg_bitrate != null ? fmt(st.avg_bitrate, 0) : '—' }}<span>kbps</span></b></div>
                  <div><i>抖动</i><b :class="st.jitter_avg > 50 ? 'text-warning' : ''">
                    {{ st.jitter_avg != null ? fmt(st.jitter_avg, 2) : '—' }}<span>ms</span></b></div>
                  <div><i>缺口</i><b :class="st.seq_gap_packets ? 'text-critical' : ''">
                    {{ st.seq_gap_packets }}</b></div>
                </div>
                <div class="sc-bar">
                  <div class="sb-track">
                    <div class="sb-fill"
                         :style="{ width: Math.min(100, (st.avg_bitrate || 0) / 250) + '%' }"></div>
                  </div>
                </div>
              </div>
            </div>
          </template>
          <div v-else class="empty">
            未捕获到媒体流
            <div class="hint">
              可能是媒体未经过抓包点，或媒体端口未建立连接。<br/>
              信号成功不等于媒体成功，更不等于画面可播放。
            </div>
          </div>
        </div>
      </section>

      <!-- ===== 4. 编码 ===== -->
      <section v-if="hasCodec" id="sec-codec" class="sec rise mb-20">
        <div class="sec-head clickable" @click="toggle('codec')">
          <span class="sec-num">{{ secNums.codec }}</span>
          <span class="sec-title">视频编码分析</span>
          <span class="sec-sub">
            PS / PES / ES 解封装
            <template v-if="codecSummary.codecs.length">
              · {{ codecSummary.codecs.join(' + ') }}
            </template>
          </span>
          <span class="spacer"></span>
          <span v-if="!codecList.length" class="badge unknown">无数据</span>
          <span class="chev" :class="{ open: openSections.codec }">›</span>
        </div>
        <div v-show="openSections.codec" class="sec-body">
          <template v-if="codecList.length">
            <div class="codec-kpis">
              <div class="ck">
                <i>编码格式</i>
                <b>{{ codecSummary.codecs.join(' / ') || '未识别' }}</b>
              </div>
              <div class="ck">
                <i>分辨率</i>
                <b>{{ codecSummary.resolution || '未解析' }}</b>
              </div>
              <div class="ck">
                <i>总帧数</i>
                <b>{{ codecSummary.totalFrames || '—' }}</b>
              </div>
              <div class="ck">
                <i>关键帧</i>
                <b>{{ codecSummary.totalKeyframes || '—' }}</b>
              </div>
            </div>

            <div class="codec-table mt-20">
              <table class="tbl">
                <thead>
                  <tr>
                    <th>SSRC</th><th>编码</th><th>Profile / Level</th>
                    <th>分辨率</th><th>帧数</th><th>关键帧</th>
                    <th>参数集</th><th>PS 包</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="x in codecList" :key="x.id">
                    <td class="mono">0x{{ x.ssrc?.toString(16) }}</td>
                    <td>
                      <span v-if="x.codec" class="badge brand">{{ x.codec }}</span>
                      <span v-else class="text-na">未识别</span>
                    </td>
                    <td class="mono-sm">
                      {{ x.ps?.video?.profile || '—' }}
                      <template v-if="x.ps?.video?.level"> / L{{ x.ps.video.level }}</template>
                    </td>
                    <td class="mono-sm">
                      {{ x.width && x.height ? `${x.width}×${x.height}` : '—' }}
                    </td>
                    <td class="num">{{ x.frameCount ?? '—' }}</td>
                    <td class="num" :class="x.keyframeCount ? 'text-ok' : ''">
                      {{ x.keyframeCount ?? '—' }}
                    </td>
                    <td>
                      <span v-if="x.ps?.video?.has_sps && x.ps?.video?.has_pps"
                            class="badge ok">SPS+PPS</span>
                      <span v-else-if="x.ps?.video?.has_sps" class="badge warning">仅 SPS</span>
                      <span v-else class="badge critical">缺失</span>
                    </td>
                    <td class="num">{{ x.ps?.pack_count ?? '—' }}</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div class="info-box mt-14">
              <strong>解析说明</strong>：分辨率与帧结构由 SPS 解析得出，不依赖 ffmpeg。
              若抓包起始于 GOP 中间，可能缺少参数集导致无法解析——
              此时显示「未识别」而非猜测值。
            </div>
          </template>
          <div v-else class="empty">
            没有可解析的视频 ES 数据
            <div class="hint">
              可能原因：未捕获媒体流、载荷非 PS 封装、或抓包不完整
            </div>
          </div>
        </div>
      </section>

      <!-- ===== 5. 诊断 ===== -->
      <section v-if="hasDiag" id="sec-diag" class="sec rise mb-20">
        <div class="sec-head clickable" @click="toggle('diag')">
          <span class="sec-num">{{ secNums.diag }}</span>
          <span class="sec-title">智能故障诊断</span>
          <span class="sec-sub">{{ diagTotal }} 条结论</span>
          <span class="spacer"></span>
          <span v-if="summary.diagnostics?.critical" class="badge critical">
            {{ summary.diagnostics.critical }} 严重
          </span>
          <router-link to="/diagnostics" class="btn-mini" @click.stop>全部 →</router-link>
          <span class="chev" :class="{ open: openSections.diag }">›</span>
        </div>
        <div v-show="openSections.diag" class="sec-body">
          <div v-if="diagnostics.length" class="diag-list">
            <div v-for="d in diagnostics.slice(0, 8)" :key="d.id"
                 class="diag-item" :class="d.severity">
              <div class="di-head">
                <span class="badge" :class="SEV_CLS[d.severity]">{{ d.severity }}</span>
                <span class="di-rule mono">{{ d.rule_id }}</span>
                <span class="di-title">{{ d.title }}</span>
                <span class="spacer"></span>
                <span class="badge" :class="EV_CLS[d.evidence_level]">
                  {{ EV[d.evidence_level] }}
                </span>
              </div>
              <div class="di-desc">{{ d.description }}</div>
              <div class="di-foot">
                <span v-if="d.device_id" class="mono-sm">设备 {{ d.device_id }}</span>
                <span v-if="d.timestamp != null" class="mono-sm">{{ d.timestamp.toFixed(2) }}s</span>
                <span v-if="d.session_id" class="di-link" @click="goSession(d.session_id)">
                  会话 #{{ d.session_id }} →
                </span>
              </div>
            </div>
          </div>
          <div v-else class="empty">
            未发现异常
            <div class="hint">规则引擎未在该任务中检测到问题</div>
          </div>
        </div>
      </section>

      <!-- ===== 6. 报文 ===== -->
      <section v-if="hasPacket" id="sec-packet" class="sec rise">
        <div class="sec-head clickable" @click="toggle('packet')">
          <span class="sec-num">{{ secNums.packet }}</span>
          <span class="sec-title">原始报文</span>
          <span class="sec-sub">{{ packetTotal.toLocaleString() }} 条</span>
          <span class="spacer"></span>
          <router-link to="/packets" class="btn-mini" @click.stop>查看全部 →</router-link>
          <span class="chev" :class="{ open: openSections.packet }">›</span>
        </div>
        <div v-show="openSections.packet" class="sec-body flush">
          <table class="tbl">
            <thead>
              <tr><th>#</th><th>时间</th><th>协议</th><th>源 → 目的</th><th>长度</th></tr>
            </thead>
            <tbody>
              <tr v-for="p in packets" :key="p.id" @click="goPacket(p.packet_number)">
                <td class="mono">{{ p.packet_number }}</td>
                <td class="mono-sm">{{ p.timestamp?.toFixed(3) }}</td>
                <td><span class="badge unknown">{{ p.protocol }}</span></td>
                <td class="mono-sm truncate" style="max-width:340px">
                  {{ p.source_ip }}:{{ p.source_port ?? '-' }} →
                  {{ p.destination_ip }}:{{ p.destination_port ?? '-' }}
                </td>
                <td class="num">{{ p.length }}</td>
              </tr>
            </tbody>
          </table>
          <div v-if="!packets.length" class="empty">暂无报文</div>
        </div>
      </section>

      <!-- 底部局限声明 -->
      <div class="foot-note">
        <strong>分析局限</strong>：所有结论仅反映抓包点观察到的流量，
        不代表端到端网络状况或客户端实际播放结果。
        SIP 成功 ≠ 媒体成功 ≠ 画面可播放。
        无法计算的指标显示为「无法计算」而非 0。
      </div>
    </template>
  </div>
</template>

<style scoped>
/* ============ 上传 Hero ============ */
.hero {
  position: relative;
  min-height: calc(100vh - 62px);
  display: flex; align-items: center; justify-content: center;
  overflow: hidden;
  padding: 40px 20px;
}
.hero-bg {
  position: absolute; inset: 0;
  background: var(--hero-grad);
  pointer-events: none;
}
.hero-bg::after {
  content: ''; position: absolute; inset: 0;
  background-image:
    linear-gradient(var(--grid-line) 1px, transparent 1px),
    linear-gradient(90deg, var(--grid-line) 1px, transparent 1px);
  background-size: 56px 56px;
  mask-image: radial-gradient(ellipse 70% 60% at 50% 40%, #000 30%, transparent 75%);
}
.hero-in {
  position: relative; z-index: 1;
  max-width: 720px; width: 100%;
  text-align: center;
}
.hero-tag {
  display: inline-flex; align-items: center; gap: 7px;
  padding: 5px 14px;
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 99px;
  font-size: 11.5px; color: var(--text-3);
  font-family: var(--font-mono);
  margin-bottom: 22px;
}
.ht-dot {
  width: 6px; height: 6px; border-radius: 50%;
  background: var(--brand);
  box-shadow: 0 0 8px var(--brand);
  animation: pulse 2s ease-in-out infinite;
}
@keyframes pulse { 50% { opacity: .4 } }

.hero-h1 {
  font-size: 40px; font-weight: 720;
  letter-spacing: -1.6px;
  line-height: 1.18;
  margin-bottom: 16px;
}
.hl {
  background: linear-gradient(120deg, var(--brand), var(--brand-lt));
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
}
.hero-p {
  font-size: 15px; color: var(--text-3);
  line-height: 1.75; margin-bottom: 20px;
  max-width: 640px; margin-left: auto; margin-right: auto;
}

.hero-tags {
  display: flex; gap: 7px; justify-content: center;
  flex-wrap: wrap; margin-bottom: 30px;
}
.hsz {
  font-size: 11.5px; color: var(--text-3);
  padding: 3px 10px;
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 99px;
  font-family: var(--font-mono);
  letter-spacing: .02em;
}

.up-zone {
  border: 2px dashed var(--line-strong);
  border-radius: var(--radius-xl);
  background: var(--surface);
  padding: 52px 36px;
  cursor: pointer;
  transition: all var(--dur) var(--ease);
}
.up-zone:hover, .up-zone.dragging {
  border-color: var(--brand);
  background: var(--brand-soft);
  transform: translateY(-2px);
  box-shadow: var(--glow-brand);
}
.up-zone.busy { cursor: default; transform: none; }
.up-icon {
  width: 62px; height: 62px; margin: 0 auto 18px;
  border-radius: 16px;
  background: var(--brand-soft);
  border: 1px solid var(--brand-line);
  display: flex; align-items: center; justify-content: center;
  color: var(--brand-lt);
}
.up-icon svg { width: 28px; height: 28px; }
.up-title { font-size: 16px; font-weight: 550; margin-bottom: 8px; }
.up-hint { font-size: 12.5px; color: var(--text-3); }
.up-caps {
  display: flex; gap: 18px; justify-content: center;
  margin-top: 22px; flex-wrap: wrap;
}
.up-caps span {
  display: inline-flex; align-items: center; gap: 6px;
  font-size: 11.5px; color: var(--text-4);
}
.up-caps i {
  width: 6px; height: 6px; border-radius: 2px; display: inline-block;
}
.c-sip { background: var(--ds); }
.c-rtp { background: var(--ok); }
.c-ps { background: var(--warning); }
.c-diag { background: var(--brand); }

.up-progress { max-width: 380px; margin: 0 auto; }
.up-bar {
  height: 6px; background: var(--surface-3);
  border-radius: 99px; overflow: hidden; margin-top: 16px;
}
.up-bar i {
  display: block; height: 100%;
  background: linear-gradient(90deg, var(--brand), var(--brand-lt));
  border-radius: 99px;
  transition: width .3s var(--ease);
}

/* ============ 分析中 ============ */
.analyzing-wrap {
  min-height: calc(100vh - 62px);
  display: flex; align-items: center; justify-content: center;
  padding: 40px 20px;
}
.an-card {
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: var(--radius-lg);
  padding: 44px 56px;
  text-align: center;
  min-width: 420px;
  box-shadow: var(--shadow);
}
.an-ring { position: relative; width: 128px; height: 128px; margin: 0 auto 24px; }
.an-ring svg { width: 100%; height: 100%; }
.an-pct {
  position: absolute; inset: 0;
  display: flex; align-items: center; justify-content: center;
  font-size: 30px; font-weight: 700;
  letter-spacing: -1px;
  color: var(--text);
}
.an-pct span { font-size: 15px; color: var(--text-3); margin-left: 1px; }
.an-stage {
  font-size: 15px; font-weight: 600;
  margin-bottom: 22px;
}
.an-steps {
  display: grid; grid-template-columns: 1fr 1fr;
  gap: 8px 22px; text-align: left;
}
.an-step {
  display: flex; align-items: center; gap: 8px;
  font-size: 12px; color: var(--text-4);
  transition: color var(--dur) var(--ease);
  padding: 3px 0;
}
.an-step .as-txt { transition: all var(--dur) var(--ease); }
.an-step.done .as-txt { opacity: .8; }
.an-step.now .as-txt {
  font-weight: 600;
  transform: translateX(2px);
}
.as-dot {
  width: 6px; height: 6px; border-radius: 50%;
  background: var(--line-strong); flex: none;
  transition: all .3s;
}
.an-step.done { color: var(--text-2); }
.an-step.done .as-dot { background: var(--ok); }
.an-step.now { color: var(--brand-lt); font-weight: 600; }
.an-step.now .as-dot {
  background: var(--brand);
  box-shadow: 0 0 10px var(--brand);
  animation: pulse 1.2s ease-in-out infinite;
}

.fail-wrap { max-width: 600px; margin: 60px auto; }

/* ============ 滚动导航 ============ */
.spy {
  position: sticky; top: 62px; z-index: 50;
  background: color-mix(in srgb, var(--bg) 88%, transparent);
  backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--line);
  margin: -26px -28px 22px;
  padding: 0 28px;
}
.spy-in {
  max-width: 1720px; margin: 0 auto;
  height: 48px; display: flex; align-items: center; gap: 4px;
}
.spy-btn {
  padding: 6px 14px;
  background: transparent;
  border: none;
  border-radius: var(--radius-xs);
  color: var(--text-3);
  font-size: 12.5px;
  font-family: inherit;
  cursor: pointer;
  transition: all var(--dur) var(--ease);
  position: relative;
}
.spy-btn:hover { color: var(--text); background: var(--surface); }
.spy-btn.on {
  color: var(--brand-lt);
  font-weight: 600;
}
.spy-btn.on::after {
  content: ''; position: absolute;
  left: 14px; right: 14px; bottom: -1px; height: 2px;
  background: var(--brand);
  border-radius: 2px;
}
.spy-file { color: var(--text-4); max-width: 280px; margin-right: 10px; }

/* ============ 区块 ============ */
.clickable { cursor: pointer; user-select: none; }
.clickable:hover { background: var(--surface-3); }
.chev {
  color: var(--text-4); font-size: 16px;
  transition: transform var(--dur) var(--ease);
  margin-left: 4px;
}
.chev.open { transform: rotate(90deg); }

.mini-card {
  background: var(--surface-2);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  overflow: hidden;
}
.mc-head {
  padding: 11px 15px;
  font-size: 12px; font-weight: 600;
  color: var(--text-2);
  border-bottom: 1px solid var(--line);
}
.mc-chart { height: 190px; }
.mc-chart.lg { height: 230px; }


/* 视频区 */
.video-sec { margin-bottom: 20px; }
.vs-head {
  display: flex; align-items: baseline; gap: 10px;
  margin-bottom: 12px;
}
.vs-title { font-size: 13px; font-weight: 600; color: var(--text); }
.vs-sub { font-size: 11px; color: var(--text-4); }
.video-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 14px;
}

.video-more {
  display: flex; justify-content: center;
  margin-top: 14px;
}

.video-none {
  display: flex; align-items: center; gap: 14px;
  padding: 18px 20px;
  background: var(--surface-2);
  border: 1px dashed var(--line-strong);
  border-radius: var(--radius);
}
.vn-icon {
  width: 40px; height: 40px; flex: none;
  border-radius: 11px;
  background: var(--surface-3);
  border: 1px solid var(--line-2);
  display: flex; align-items: center; justify-content: center;
  color: var(--text-4);
}
.vn-icon svg { width: 18px; height: 18px; }
.vn-t { font-size: 12.5px; color: var(--text-2); font-weight: 550; margin-bottom: 4px; }
.vn-s { font-size: 11.5px; color: var(--text-4); line-height: 1.7; }

/* 媒体流卡 */
.stream-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
  gap: 12px;
}
.stream-card {
  background: var(--surface-2);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  padding: 14px 16px;
  transition: all var(--dur) var(--ease);
}
.stream-card:hover {
  border-color: var(--line-strong);
  transform: translateY(-2px);
  box-shadow: var(--shadow-sm);
}
.sc-top {
  display: flex; align-items: center; justify-content: space-between;
  margin-bottom: 12px;
}
.sc-ssrc { font-size: 12px; color: var(--brand-lt); font-weight: 600; }
.sc-metrics {
  display: grid; grid-template-columns: repeat(4, 1fr);
  gap: 8px;
}
.sc-metrics > div { display: flex; flex-direction: column; gap: 2px; }
.sc-metrics i { font-size: 10px; color: var(--text-4); font-style: normal; }
.sc-metrics b {
  font-size: 14px; font-weight: 650;
  color: var(--text); font-variant-numeric: tabular-nums;
}
.sc-metrics b span { font-size: 9.5px; color: var(--text-4); font-weight: 400; margin-left: 1px; }
.sc-bar { margin-top: 12px; }
.sb-track {
  height: 3px; background: var(--surface-4);
  border-radius: 99px; overflow: hidden;
}
.sb-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--ds), var(--brand));
  border-radius: 99px;
  transition: width .5s var(--ease);
}

/* 编码 */
.codec-kpis {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
}
.ck {
  background: var(--surface-2);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  padding: 13px 16px;
}
.ck i {
  display: block; font-size: 10.5px;
  color: var(--text-4); font-style: normal; margin-bottom: 5px;
}
.ck b {
  font-size: 16px; font-weight: 650;
  color: var(--text); letter-spacing: -.3px;
}
.codec-table {
  border: 1px solid var(--line);
  border-radius: var(--radius);
  overflow: hidden;
}

/* 诊断 */
.diag-list { display: flex; flex-direction: column; gap: 10px; }
.diag-item {
  background: var(--surface-2);
  border: 1px solid var(--line);
  border-left: 3px solid var(--text-4);
  border-radius: var(--radius-sm);
  padding: 13px 16px;
  transition: all var(--dur) var(--ease);
}
.diag-item:hover { border-color: var(--line-strong); }
.diag-item.critical { border-left-color: var(--critical); }
.diag-item.warning { border-left-color: var(--warning); }
.diag-item.info { border-left-color: var(--info); }

.di-head {
  display: flex; align-items: center; gap: 9px;
  flex-wrap: wrap; margin-bottom: 6px;
}
.di-rule { font-size: 11px; color: var(--text-4); }
.di-title { font-size: 13px; font-weight: 600; color: var(--text); }
.di-desc {
  font-size: 12.5px; color: var(--text-2);
  line-height: 1.72;
}
.di-foot {
  display: flex; gap: 16px; flex-wrap: wrap;
  margin-top: 8px; align-items: center;
}
.di-link {
  font-size: 11.5px; color: var(--brand-lt);
  cursor: pointer; font-weight: 500;
}
.di-link:hover { text-decoration: underline; }

/* 底部 */
.foot-note {
  margin-top: 26px; padding: 18px 22px;
  background: var(--surface-2);
  border: 1px solid var(--line);
  border-left: 3px solid var(--line-strong);
  border-radius: var(--radius);
  font-size: 12px; color: var(--text-3);
  line-height: 1.8;
}
.foot-note strong { color: var(--text-2); }
</style>

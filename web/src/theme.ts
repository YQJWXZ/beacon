import * as echarts from 'echarts'

// Stripe-style light theme: violet first, cyan second, navy text.
export const PALETTE = ['#635bff', '#00d4ff', '#7a73ff', '#0a2540', '#30c48d']

echarts.registerTheme('stripe', {
  color: PALETTE,
  backgroundColor: 'transparent',
  textStyle: {
    color: '#425466',
    fontFamily:
      "Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', sans-serif",
    fontWeight: 400,
  },
  title: { textStyle: { color: '#0a2540', fontWeight: 600 } },
  legend: {
    textStyle: { color: '#425466', fontSize: 12 },
    icon: 'roundRect',
    itemWidth: 12,
    itemHeight: 4,
    inactiveColor: '#cbd5e1',
  },
  tooltip: {
    backgroundColor: '#ffffff',
    borderColor: '#e6ebf1',
    borderWidth: 1,
    textStyle: { color: '#0a2540', fontSize: 12 },
    extraCssText: 'box-shadow: 0 4px 20px rgba(0,0,0,0.08); border-radius: 8px;',
    axisPointer: { lineStyle: { color: 'rgba(99,91,255,0.35)', width: 1 } },
  },
  grid: { left: 48, right: 16, top: 36, bottom: 32, containLabel: false },
  xAxis: {
    axisLine: { lineStyle: { color: '#e6ebf1' } },
    axisTick: { show: false },
    axisLabel: { color: '#697386', fontSize: 11 },
    splitLine: { show: false },
  },
  yAxis: {
    axisLine: { show: false },
    axisTick: { show: false },
    axisLabel: { color: '#697386', fontSize: 11 },
    splitLine: { lineStyle: { color: '#eef2f7' } },
  },
})

export function areaGradient(color: string): echarts.graphic.LinearGradient {
  return new echarts.graphic.LinearGradient(0, 0, 0, 1, [
    { offset: 0, color: withAlpha(color, 0.20) },
    { offset: 1, color: withAlpha(color, 0.01) },
  ])
}

function withAlpha(hex: string, alpha: number): string {
  const h = hex.replace('#', '')
  const r = parseInt(h.slice(0, 2), 16)
  const g = parseInt(h.slice(2, 4), 16)
  const b = parseInt(h.slice(4, 6), 16)
  return `rgba(${r},${g},${b},${alpha})`
}

export { echarts }

import { useEffect, useRef } from 'react'
import type { EChartsOption } from 'echarts'
import { echarts } from '../theme'

interface Props {
  option: EChartsOption
  height?: number
}

// Thin wrapper: ECharts owns rendering, React only feeds options and resizes.
export function Chart({ option, height = 260 }: Props) {
  const ref = useRef<HTMLDivElement>(null)
  const chart = useRef<echarts.ECharts | null>(null)

  useEffect(() => {
    if (!ref.current) return
    const instance = echarts.init(ref.current, 'stripe', { renderer: 'canvas' })
    chart.current = instance
    const ro = new ResizeObserver(() => instance.resize())
    ro.observe(ref.current)
    return () => {
      ro.disconnect()
      instance.dispose()
      chart.current = null
    }
  }, [])

  useEffect(() => {
    chart.current?.setOption(option, true)
  }, [option])

  return <div ref={ref} className="chart" style={{ height }} role="img" aria-label="指标图表" />
}

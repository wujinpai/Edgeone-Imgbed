// 体积/数量格式化：统计卡与存储卡共用

/** 字节数 → 紧凑可读（B / KB / MB / GB，保留两位小数） */
export function formatCompactSize(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '0 B'
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`
  return `${Math.round(bytes)} B`
}

/** 大数字 → 紧凑（123456 → 123.5K），统计卡用 */
export function formatCompactCount(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '0'
  if (n >= 10000) return `${(n / 1000).toFixed(1)}K`
  return String(Math.round(n))
}

/** 图片扩展名（MIME 缺失时的兜底判定） */
const IMAGE_EXT_RE = /\.(jpe?g|png|gif|webp|bmp|avif)$/i

/**
 * 图片类型判定：MIME 优先，缺失时按文件名扩展名兜底。
 * 非图片（文档/压缩包）在展示层走文件图标 + 下载，不做 <img> 预览。
 */
export function isImageType(type?: string, name?: string): boolean {
  if (type) return type.startsWith('image/')
  return !!name && IMAGE_EXT_RE.test(name)
}

/** 时间戳 → HH:MM（今日）或 MM-DD（更早），最近上传卡片用 */
export function formatRecentTime(ts: number): string {
  const d = new Date(ts)
  const pad = (v: number) => String(v).padStart(2, '0')
  const now = new Date()
  const sameDay =
    d.getFullYear() === now.getFullYear() &&
    d.getMonth() === now.getMonth() &&
    d.getDate() === now.getDate()
  if (sameDay) return `${pad(d.getHours())}:${pad(d.getMinutes())}`
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
}

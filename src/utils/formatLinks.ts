// 上传结果共享类型 + 四格式链接构建函数（唯一负责转义/URL 编码的地方）
// 被 ResultCard.vue 与 HomeView.vue 共享导入。

import { isImageType } from './format'

export interface UploadResult {
  url: string
  urlOriginal?: string
  thumbnailUrl?: string
  thumbnailOriginalUrl?: string
  name?: string
  size?: number
  type?: string
  compressionRatio?: number
  width?: number
  height?: number
  hasThumbnail?: boolean
  thumbnailWidth?: number
  thumbnailHeight?: number
  thumbnailSize?: number
  /** KV 记录 id：FileUploader.uploadSingle 生成，首页据此做最近上传乐观插入（仅上传结果有，列表记录无） */
  recordId?: string
}

export type LinkFormatKey = 'url' | 'html' | 'markdown' | 'bbcode'

export interface LinkFormat {
  key: LinkFormatKey
  label: string
  hint: string
  value: string
}

// HTML 属性转义：& " < >
function escapeAttr(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
}

// Markdown 链接的括号转义：把 ) 编码，避免 () 打断链接语法
function escapeLink(s: string): string {
  return s.replace(/\)/g, '%29')
}

// buildFormats 在缺少 type/name 时按 URL 扩展名判断是否图片
const IMAGE_URL_RE = /\.(jpe?g|png|gif|webp|bmp|avif)(?:[?#]|$)/i

// Markdown 链接文字转义：[] 会打断链接语法
function escapeLinkText(s: string): string {
  return s.replace(/[[\]]/g, (m) => (m === '[' ? '\\[' : '\\]'))
}

/**
 * 为一图构建 4 种复制格式。
 * @param baseUrl 嵌入的 CDN URL；默认 info.url，可传 info.thumbnailUrl 以嵌入缩略图。
 */
export function buildFormats(info: UploadResult, baseUrl: string = info.url): LinkFormat[] {
  const name = info.name || ''
  // 缺少 type/name 时按 URL 扩展名兜底（兼容仅传 url 的旧调用）
  const isImg = info.type || name ? isImageType(info.type, name) : IMAGE_URL_RE.test(baseUrl)
  // 非图片（文档/压缩包）：生成文字链接而非 <img> 嵌入，否则 Markdown/HTML 会渲染成裂图
  if (!isImg) {
    const label = name || '文件'
    return [
      { key: 'url', label: '链接', hint: 'CDN 访问链接', value: baseUrl },
      {
        key: 'html',
        label: 'HTML',
        hint: '博客 / 富文本',
        value: `<a href="${escapeAttr(baseUrl)}" target="_blank" rel="noopener">${escapeAttr(label)}</a>`,
      },
      {
        key: 'markdown',
        label: 'Markdown',
        hint: 'README / 论坛',
        value: `[${escapeLinkText(label)}](${escapeLink(baseUrl)})`,
      },
      { key: 'bbcode', label: 'BBCode', hint: 'Discuz / 传统论坛', value: `[url=${baseUrl}]${label}[/url]` },
    ]
  }
  const alt = (info.name || 'img').replace(/\.\w+$/, '')
  return [
    { key: 'url', label: '链接', hint: 'CDN 访问链接', value: baseUrl },
    {
      key: 'html',
      label: 'HTML',
      hint: '博客 / 富文本',
      value: `<img src="${escapeAttr(baseUrl)}" alt="${escapeAttr(alt)}" />`,
    },
    {
      key: 'markdown',
      label: 'Markdown',
      hint: 'README / 论坛',
      value: `![${alt}](${escapeLink(baseUrl)})`,
    },
    {
      key: 'bbcode',
      label: 'BBCode',
      hint: 'Discuz / 传统论坛',
      value: `[img]${baseUrl}[/img]`,
    },
  ]
}

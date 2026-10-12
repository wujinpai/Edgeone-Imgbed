import { createRouter, createWebHistory } from 'vue-router'
import { isTokenLive } from '@/utils/authToken'
import { isPasswordEnabled, loadAuthStatus } from './authStatus'

// 各页面的懒加载器独立命名：既供路由使用，也供 prefetchRouteChunks 预取
const HomeView = () => import('../views/HomeView.vue')
const AdminView = () => import('../views/AdminView.vue')
const LoginView = () => import('../views/LoginView.vue')
const SettingsView = () => import('../views/SettingsView.vue')
const OrphanCleanupView = () => import('../views/OrphanCleanupView.vue')

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'home',
      component: HomeView,
    },
    {
      path: '/admin',
      name: 'admin',
      component: AdminView,
    },
    // [新增] 登录页路由
    {
      path: '/login',
      name: 'login',
      component: LoginView,
    },
    // [新增] 侧边栏占位页路由
    {
      path: '/settings',
      name: 'settings',
      component: SettingsView,
    },
    // 孤儿文件扫描与清理
    {
      path: '/orphan',
      name: 'orphan',
      component: OrphanCleanupView,
    },
  ],
})

// 首屏渲染完成后，在浏览器空闲时预加载各页面 chunk：
// 懒加载路由首次点击才现下载解析（AdminView/HomeView 各 ~17KB gzip），
// 预取后首次点导航栏即为秒开。登录页不预取（仅退出流程用，体积小）。
export function prefetchRouteChunks(): void {
  if (typeof window === 'undefined') return
  const load = () => {
    void HomeView()
    void AdminView()
    void SettingsView()
    void OrphanCleanupView()
  }
  const ric = (
    window as unknown as {
      requestIdleCallback?: (cb: () => void, opts?: { timeout: number }) => number
    }
  ).requestIdleCallback
  if (typeof ric === 'function') ric(load, { timeout: 2000 })
  else window.setTimeout(load, 1200)
}

// [新增] 全局前置守卫
router.beforeEach(async (to, from, next) => {
  // 同步双存储：localStorage（"记住我"）的 token 也镜像一份到 sessionStorage，
  // axios 拦截器只读 sessionStorage，避免两边不一致
  const remembered = localStorage.getItem('site_access_token')
  if (remembered && !sessionStorage.getItem('site_access_token')) {
    sessionStorage.setItem('site_access_token', remembered)
  }

  // 0. 未设置 SITE_PASSWORD（开放访问）时直接放行，不再强制走登录页
  // 探测未完成（null）时先等探测结果：否则开放部署的每次首访/刷新都会被误拦到登录页
  if (isPasswordEnabled() === null) {
    try {
      await loadAuthStatus()
    } catch {
      // 探测失败按有密码处理，走常规登录流程
    }
  }
  if (isPasswordEnabled() === false) {
    next()
    return
  }

  // 1. 检查是否有 token，并预判是否过期（过期 token 视为未登录，直接拦去登录页）
  const token = sessionStorage.getItem('site_access_token') || remembered
  const isAuthenticated = !!token && isTokenLive(token)

  // 2. 如果要去的是登录页，且已经登录，直接去首页
  if (to.name === 'login' && isAuthenticated) {
    next({ name: 'home' })
    return
  }

  // 3. 如果没有登录，且去的不是登录页，拦截跳转到登录页
  if (to.name !== 'login' && !isAuthenticated) {
    // 将用户原本想去的地址作为参数传过去，登录成功后跳回来
    next({ name: 'login', query: { redirect: to.fullPath } })
    return
  }

  // 4. 放行
  next()
})

export default router

<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { RouterView, useRoute } from 'vue-router'
import { Toaster } from 'vue-sonner'
import AppShell from '@/components/layout/AppShell.vue'
import { prefetchRouteChunks } from '@/router'

const route = useRoute()
// 侧栏 / 顶栏壳常驻在 App 层：路由切换只替换壳内主内容，
// 避免每个视图各自包裹 AppShell 导致整块导航被反复重建（导航点按因此更顺滑）
const useShell = computed(() => route.name !== 'login')

// 空闲预取各页面 chunk，消除首次点击导航的下载延迟
onMounted(() => prefetchRouteChunks())
</script>

<template>
  <AppShell v-if="useShell">
    <RouterView />
  </AppShell>
  <!-- 登录页为独立全屏布局，不套壳 -->
  <RouterView v-else />

  <!-- 全站统一 toast：顶部居中胶囊（日间深底白字 / 夜间浅底深字），配色与关闭钮样式统一在 main.css 覆盖。
       offset/mobileOffset：桌面 24px、移动端 16px；最终定位由 main.css 的视口钉扎规则兜底强制 -->
  <Toaster
    position="top-center"
    closeButton
    :offset="24"
    :mobileOffset="{ top: 16 }"
    :toastOptions="{ duration: 2500 }"
  />
</template>

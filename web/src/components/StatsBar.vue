<script setup>
import { severityLabel, severityOrder } from '../lib/format.js'

defineProps({
  stats: { type: Object, required: true }
})
</script>

<template>
  <section class="stats">
    <div class="stat total">
      <span class="value">{{ stats.total }}</span>
      <span class="label">Schwachstellen</span>
    </div>
    <div v-for="s in severityOrder" :key="s" class="stat" :class="`sev-${s.toLowerCase()}`">
      <span class="value">{{ stats.bySeverity?.[s] ?? 0 }}</span>
      <span class="label">{{ severityLabel(s) }}</span>
    </div>
    <div class="stat watch">
      <span class="value">{{ stats.watchlistHits }}</span>
      <span class="label">Betreffen eigene Systeme</span>
    </div>
  </section>
</template>

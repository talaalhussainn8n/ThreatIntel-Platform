<script setup>
import { onMounted, reactive, ref, watch } from 'vue'
import { api } from './lib/api.js'
import { severityLabel, severityOrder } from './lib/format.js'
import StatsBar from './components/StatsBar.vue'
import VulnerabilityTable from './components/VulnerabilityTable.vue'
import Watchlist from './components/Watchlist.vue'

const stats = ref({ total: 0, bySeverity: {}, topProducts: [], watchlistHits: 0 })
const result = ref({ items: [], total: 0, page: 1, pageSize: 20 })
const watchlist = ref([])
const error = ref('')
const loading = ref(false)
const filters = reactive({ search: '', severity: '', product: '', watchlistOnly: false, page: 1 })


async function load() {
  loading.value = true
  error.value = ''
  try {
    const [s, r, w] = await Promise.all([api.stats(), api.vulnerabilities(filters), api.watchlist()])
    stats.value = s
    result.value = r
    watchlist.value = w
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

let debounce
watch(() => [filters.search, filters.severity, filters.product, filters.watchlistOnly], () => {
  filters.page = 1
  clearTimeout(debounce)
  debounce = setTimeout(load, 300)
})

async function addProduct(product) {
  await api.addToWatchlist(product)
  await load()
}

async function removeProduct(product) {
  await api.removeFromWatchlist(product)
  await load()
}

function goTo(page) {
  filters.page = page
  load()
}

onMounted(load)
</script>

<template>
  <header>
    <h1>Threat Intelligence Lagebild</h1>
    <span class="hint">Öffentliche Schwachstellenmeldungen, automatisch bewertet und priorisiert</span>
  </header>

  <main>
    <p v-if="error" class="error">{{ error }}</p>
    <StatsBar :stats="stats" />

    <div class="layout">
      <section class="card">
        <form class="filters" @submit.prevent>
          <input v-model="filters.search" placeholder="CVE oder Stichwort suchen" />
          <select v-model="filters.severity">
            <option value="">Alle Schweregrade</option>
            <option v-for="s in severityOrder" :key="s" :value="s">{{ severityLabel(s) }}</option>
          </select>
          <input v-model="filters.product" placeholder="Produkt" />
          <label><input type="checkbox" v-model="filters.watchlistOnly" /> Nur eigene Systeme</label>
        </form>

        <p v-if="loading" class="hint">Lade ...</p>
        <VulnerabilityTable :items="result.items" />

        <nav class="pager" v-if="result.total > result.pageSize">
          <button :disabled="result.page <= 1" @click="goTo(result.page - 1)">Zurück</button>
          <span>Seite {{ result.page }} von {{ Math.ceil(result.total / result.pageSize) }}</span>
          <button :disabled="result.page * result.pageSize >= result.total" @click="goTo(result.page + 1)">Weiter</button>
        </nav>
      </section>

      <aside>
        <Watchlist :products="watchlist" @add="addProduct" @remove="removeProduct" />
        <section class="card">
          <h2>Am häufigsten betroffen</h2>
          <ol>
            <li v-for="p in stats.topProducts" :key="p.product">{{ p.product }} ({{ p.count }})</li>
          </ol>
        </section>
      </aside>
    </div>
  </main>
</template>

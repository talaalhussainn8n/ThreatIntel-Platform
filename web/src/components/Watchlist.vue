<script setup>
import { ref } from 'vue'

const props = defineProps({
  products: { type: Array, required: true }
})
const emit = defineEmits(['add', 'remove'])
const newProduct = ref('')

function add() {
  const value = newProduct.value.trim()
  if (!value || props.products.includes(value)) return
  emit('add', value)
  newProduct.value = ''
}
</script>

<template>
  <section class="card">
    <h2>Beobachtungsliste</h2>
    <p class="hint">Eigene Produkte erhalten höhere Priorität.</p>
    <form @submit.prevent="add" class="row">
      <input v-model="newProduct" placeholder="z. B. Apache Http Server" maxlength="128" />
      <button type="submit">Hinzufügen</button>
    </form>
    <ul class="chips">
      <li v-for="p in products" :key="p">
        {{ p }}
        <button class="link" :aria-label="`${p} entfernen`" @click="emit('remove', p)">entfernen</button>
      </li>
      <li v-if="products.length === 0" class="hint">Noch keine Produkte.</li>
    </ul>
  </section>
</template>

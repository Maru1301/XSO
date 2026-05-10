<script setup lang="ts">
import { reactive, ref } from 'vue'

const form = reactive({
  identifier: '',
  password: '',
})

const isSubmitting = ref(false)
const errorMessage = ref('')

async function submitLogin() {
  errorMessage.value = ''

  if (!form.identifier.trim() || !form.password) {
    errorMessage.value = 'Enter your account and password.'
    return
  }

  isSubmitting.value = true

  try {
    const response = await fetch('/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      credentials: 'include',
      body: JSON.stringify({
        identifier: form.identifier.trim(),
        password: form.password,
      }),
    })

    if (!response.ok) {
      form.password = ''
      errorMessage.value = 'Invalid account or password.'
      return
    }

    window.location.assign('/')
  } catch {
    errorMessage.value = 'Unable to sign in right now.'
  } finally {
    isSubmitting.value = false
  }
}
</script>

<template>
  <main class="shell">
    <section class="login-panel" aria-labelledby="login-title">
      <p class="brand">XSO</p>
      <h1 id="login-title">Sign in</h1>

      <form @submit.prevent="submitLogin">
        <label>
          Email or employee ID
          <input
            v-model="form.identifier"
            name="identifier"
            autocomplete="username"
            required
          >
        </label>

        <label>
          Password
          <input
            v-model="form.password"
            name="password"
            type="password"
            autocomplete="current-password"
            required
          >
        </label>

        <p v-if="errorMessage" class="error" role="alert">{{ errorMessage }}</p>

        <button type="submit" :disabled="isSubmitting">
          {{ isSubmitting ? 'Signing in...' : 'Continue' }}
        </button>
      </form>
    </section>
  </main>
</template>

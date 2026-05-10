import { createApp } from 'vue'
import App from './App.vue'
import './styles.css'

const root = document.querySelector<HTMLElement>('#app')

createApp(App, {
  challengeId: root?.dataset.challengeId ?? '',
}).mount('#app')

import { createRoot } from 'react-dom/client'
import CustomConfigUi from './CustomConfigUi'
import '@homebridge/plugin-ui-utils/ui.interface'

window.homebridge.addEventListener('ready', () => {
  createRoot(document.getElementById('root')!).render(<CustomConfigUi />)
})

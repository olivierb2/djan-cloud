import { createApp } from 'vue';
import BrowseApp from '../components/BrowseApp.vue';
import '../css/main.css';

const el = document.getElementById('browse-app');
if (el) {
  const pageData = JSON.parse(document.getElementById('page-data').textContent);
  const app = createApp(BrowseApp, {
    initialPath: pageData.currentPath || '',
    isAdmin: pageData.isAdmin || false,
    csrfToken: pageData.csrfToken || '',
  });
  app.mount(el);
}

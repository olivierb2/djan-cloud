import {
  ApplicationConfig,
  provideBrowserGlobalErrorListeners,
  provideZoneChangeDetection,
} from '@angular/core';
import { provideRouter } from '@angular/router';
import {
  provideHttpClient,
  withFetch,
  withInterceptors,
} from '@angular/common/http';

import { routes } from './app.routes';
import { provideIcons } from '@ng-icons/core';
import {
  heroUser,
  heroUsers,
  heroEye,
  heroEyeSlash,
  heroCheck,
  heroXMark,
  heroPlus,
  heroMagnifyingGlass,
  heroPencil,
  heroTrash,
  heroChevronDown,
  heroChevronLeft,
  heroChevronRight,
  heroArrowLeft,
  heroArrowRightOnRectangle,
  heroDocumentText,
  heroCheckCircle,
  heroXCircle,
  heroExclamationTriangle,
  heroUserCircle,
  heroBars3,
  heroFolder,
  heroFolderOpen,
  heroArrowUpTray,
  heroArrowDownTray,
  heroShare,
  heroCog6Tooth,
} from '@ng-icons/heroicons/outline';
import {
  lucideSettings,
} from '@ng-icons/lucide';
import { authInterceptor } from './core/interceptors/auth.interceptor';

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideZoneChangeDetection({ eventCoalescing: true }),
    provideRouter(routes),
    provideIcons({
      heroUser,
      heroUsers,
      heroEye,
      heroEyeSlash,
      heroCheck,
      heroXMark,
      heroPlus,
      heroMagnifyingGlass,
      heroPencil,
      heroTrash,
      heroChevronDown,
      heroChevronLeft,
      heroChevronRight,
      heroArrowLeft,
      heroArrowRightOnRectangle,
      heroDocumentText,
      heroCheckCircle,
      heroXCircle,
      heroExclamationTriangle,
      heroUserCircle,
      heroBars3,
      heroFolder,
      heroFolderOpen,
      heroArrowUpTray,
      heroArrowDownTray,
      heroShare,
      heroCog6Tooth,
      lucideSettings,
    }),
    provideHttpClient(withFetch(), withInterceptors([authInterceptor])),
  ],
};

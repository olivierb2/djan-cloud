import { NgModule } from '@angular/core';
import { RouterModule, Routes, UrlMatchResult, UrlSegment } from '@angular/router';
import { User } from './pages/user/user';
import { RoutePaths } from '../../core/constants/routes';

// Custom matcher to capture the full path after "browse/"
function browseMatcher(segments: UrlSegment[]): UrlMatchResult | null {
  if (segments.length === 0) return null;
  if (segments[0].path !== RoutePaths.BROWSE) return null;
  if (segments.length === 1) {
    return { consumed: segments, posParams: { path: new UrlSegment('', {}) } };
  }
  // Capture everything after "browse/" as a single "path" parameter
  const fullPath = segments.slice(1).map(s => s.path).join('/');
  return {
    consumed: segments,
    posParams: { path: new UrlSegment(fullPath, {}) },
  };
}

const routes: Routes = [
  {
    path: '',
    component: User,
    children: [
      {
        path: '',
        pathMatch: 'full',
        redirectTo: RoutePaths.BROWSE,
      },
      {
        matcher: browseMatcher,
        loadComponent: () =>
          import('../../pages/browse/browse').then(c => c.BrowsePage),
      },
      {
        path: RoutePaths.USERS,
        loadComponent: () =>
          import('../../pages/users/users').then(c => c.UsersPage),
      },
    ],
  },
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule],
})
export class UserRoutingModule {}

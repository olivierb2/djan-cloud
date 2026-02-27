import { Sidebar } from '../models/sidebar';
import { RoutePaths } from './routes';

export const MenuItems: Sidebar[] = [
  {
    name: 'My Files',
    subtitle: '',
    path: `/${RoutePaths.BROWSE}`,
    icon: 'folder.svg',
  },
];

import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, Subject } from 'rxjs';
import { environment } from '../../../environments/environment';

export interface BrowseResponse {
  current_folder: { id: number; name: string } | null;
  current_path: string;
  subfolders: { id: number; name: string; url_path: string }[];
  files: {
    id: number;
    display_name: string;
    content_type: string;
    size: number;
    created_at: string;
    updated_at: string;
  }[];
  parent_path: string | null;
  breadcrumb_parts: { name: string; path: string }[];
  is_shared: boolean;
  can_write: boolean;
  is_shared_root?: boolean;
  shared_folders?: { id: number; name: string; url_path: string; permission: string }[];
}

export interface TreeResponse {
  tree: TreeNode | null;
  shared: TreeNode[];
  is_admin: boolean;
}

export interface TreeNode {
  id: number;
  name: string;
  url_path: string;
  children: TreeNode[];
  sf_id?: number;
}

export interface FolderSelectorResponse {
  folder: { id: number; name: string; path: string };
  breadcrumbs: { name: string; id: number; path: string }[];
  subfolders: { id: number; name: string; path: string }[];
  shared_folders?: { id: number; name: string; path: string }[];
}

export interface PreviewResponse {
  type: 'text' | 'download';
  display_name: string;
  content?: string;
  content_type: string;
}

@Injectable({ providedIn: 'root' })
export class FileService {
  private http = inject(HttpClient);
  private apiUrl = environment.apiUrl;

  private treeChanged$ = new Subject<void>();
  readonly treeChanged = this.treeChanged$.asObservable();

  notifyTreeChanged(): void {
    this.treeChanged$.next();
  }

  browse(path: string = ''): Observable<BrowseResponse> {
    const url = path ? `${this.apiUrl}/browse/${path}` : `${this.apiUrl}/browse/`;
    return this.http.get<BrowseResponse>(url);
  }

  getTree(): Observable<TreeResponse> {
    return this.http.get<TreeResponse>(`${this.apiUrl}/tree/`);
  }

  createFolder(path: string, name: string): Observable<any> {
    const url = path ? `${this.apiUrl}/browse/${path}` : `${this.apiUrl}/browse/`;
    return this.http.post(url, { action: 'create_folder', name });
  }

  createFile(path: string, name: string): Observable<any> {
    const url = path ? `${this.apiUrl}/browse/${path}` : `${this.apiUrl}/browse/`;
    return this.http.post(url, { action: 'create_file', name });
  }

  uploadFile(path: string, file: File): Observable<any> {
    const url = path ? `${this.apiUrl}/browse/${path}` : `${this.apiUrl}/browse/`;
    const formData = new FormData();
    formData.append('file', file);
    formData.append('action', 'upload');
    return this.http.post(url, formData);
  }

  deleteFile(id: number): Observable<any> {
    return this.http.delete(`${this.apiUrl}/files/${id}/`);
  }

  deleteFolder(id: number): Observable<any> {
    return this.http.delete(`${this.apiUrl}/folders/${id}/delete/`);
  }

  moveItem(type: string, id: number, destinationFolderId: number): Observable<any> {
    return this.http.post(`${this.apiUrl}/move/${type}/${id}/`, { destination_folder_id: destinationFolderId });
  }

  renameItem(type: string, id: number, newName: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/rename/${type}/${id}/`, { new_name: newName });
  }

  downloadFile(id: number): Observable<Blob> {
    return this.http.get(`${this.apiUrl}/download/${id}/`, { responseType: 'blob' });
  }

  getPreview(id: number): Observable<PreviewResponse> {
    return this.http.get<PreviewResponse>(`${this.apiUrl}/preview/${id}/`);
  }

  getFolderContents(folderId?: number): Observable<FolderSelectorResponse> {
    const url = folderId ? `${this.apiUrl}/folders/${folderId}/` : `${this.apiUrl}/folders/`;
    return this.http.get<FolderSelectorResponse>(url);
  }
}

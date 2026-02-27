import { Component, OnInit, OnDestroy } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { Subject, takeUntil } from 'rxjs';
import { ToasterContainerComponent } from './core/components/toaster-container/toaster-container.component';
import { Confirmation } from './shared/components/confirmation/confirmation';
import { Auth } from './core/services/auth';
import { WebSocketService } from './core/services/websocket.service';
import { environment } from '../environments/environment';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, ToasterContainerComponent, Confirmation],
  templateUrl: './app.html',
  styleUrl: './app.scss'
})
export class App implements OnInit, OnDestroy {
  protected title = 'Djancloud';
  private destroy$ = new Subject<void>();

  constructor(
    private authService: Auth,
    private wsService: WebSocketService,
  ) {}

  ngOnInit(): void {
    this.authService.isAuthenticated$
      .pipe(takeUntil(this.destroy$))
      .subscribe((isAuthenticated: boolean) => {
        if (isAuthenticated) {
          this.wsService.connect({
            url: `${environment.wsUrl}/user/?token=${this.authService.getToken()}`,
            pingInterval: 30000,
          });
        } else {
          this.wsService.disconnect();
        }
      });
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
    this.wsService.disconnect();
  }
}

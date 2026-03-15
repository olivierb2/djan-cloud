import { Calendar } from '@fullcalendar/core';
import dayGridPlugin from '@fullcalendar/daygrid';
import timeGridPlugin from '@fullcalendar/timegrid';
import listPlugin from '@fullcalendar/list';
import interactionPlugin from '@fullcalendar/interaction';

import '../css/calendar.css';

document.addEventListener('DOMContentLoaded', function () {
  const calendarEl = document.getElementById('fullcalendar');
  if (!calendarEl) return;

  const eventsUrl = calendarEl.dataset.eventsUrl;
  const canWrite = calendarEl.dataset.canWrite === 'true';
  const calendarColor = calendarEl.dataset.calendarColor || '#3498db';

  const calendar = new Calendar(calendarEl, {
    plugins: [dayGridPlugin, timeGridPlugin, listPlugin, interactionPlugin],
    initialView: 'dayGridMonth',
    headerToolbar: {
      left: 'prev,today,next',
      center: 'title',
      right: 'dayGridMonth,timeGridWeek,timeGridDay,listWeek',
    },
    locale: document.documentElement.lang || 'en',
    height: 'auto',
    navLinks: true,
    editable: false,
    selectable: canWrite,
    nowIndicator: true,
    eventColor: calendarColor,

    events: function (info, successCallback, failureCallback) {
      const params = new URLSearchParams({
        start: info.startStr,
        end: info.endStr,
      });
      fetch(eventsUrl + '?' + params.toString(), {
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
      })
        .then((res) => res.json())
        .then((data) => successCallback(data))
        .catch((err) => failureCallback(err));
    },

    select: function (info) {
      if (!canWrite) return;
      const modal = document.getElementById('event-modal');
      if (!modal) return;

      const startInput = document.getElementById('dtstart-input');
      const endInput = document.getElementById('dtend-input');
      const allDayCheck = document.getElementById('all-day-check');

      if (info.allDay) {
        allDayCheck.checked = true;
        startInput.type = 'date';
        endInput.type = 'date';
        startInput.value = info.startStr;
        // FullCalendar exclusive end: subtract one day for display
        const endDate = new Date(info.end);
        endDate.setDate(endDate.getDate() - 1);
        endInput.value = endDate.toISOString().split('T')[0];
      } else {
        allDayCheck.checked = false;
        startInput.type = 'datetime-local';
        endInput.type = 'datetime-local';
        startInput.value = info.startStr.slice(0, 16);
        endInput.value = info.endStr.slice(0, 16);
      }

      modal.classList.remove('hidden');
      modal.classList.add('flex');
      calendar.unselect();
    },

    eventClick: function (info) {
      const event = info.event;
      const detailEl = document.getElementById('event-detail');
      if (!detailEl) return;

      document.getElementById('detail-title').textContent =
        event.title || '(No title)';
      document.getElementById('detail-start').textContent = event.allDay
        ? event.start.toLocaleDateString()
        : event.start.toLocaleString();
      document.getElementById('detail-end').textContent = event.end
        ? event.allDay
          ? event.end.toLocaleDateString()
          : event.end.toLocaleString()
        : '';
      document.getElementById('detail-location').textContent =
        event.extendedProps.location || '';
      document.getElementById('detail-description').textContent =
        event.extendedProps.description || '';

      const deleteForm = document.getElementById('detail-delete-form');
      if (deleteForm && event.extendedProps.deleteUrl) {
        deleteForm.action = event.extendedProps.deleteUrl;
        deleteForm.style.display = '';
      } else if (deleteForm) {
        deleteForm.style.display = 'none';
      }

      detailEl.classList.remove('hidden');
      detailEl.classList.add('flex');
    },
  });

  calendar.render();

  // Intercept event creation form to submit via AJAX
  const eventForm = document.querySelector('#event-modal form');
  if (eventForm) {
    eventForm.addEventListener('submit', function (e) {
      e.preventDefault();
      const formData = new FormData(eventForm);
      fetch(eventForm.action, {
        method: 'POST',
        body: formData,
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
      }).then(() => {
        eventForm.reset();
        const modal = document.getElementById('event-modal');
        modal.classList.remove('flex');
        modal.classList.add('hidden');
        // Reset inputs to datetime-local
        document.getElementById('dtstart-input').type = 'datetime-local';
        document.getElementById('dtend-input').type = 'datetime-local';
        calendar.refetchEvents();
      });
    });
  }

  // Intercept event delete form in detail modal
  const detailDeleteForm = document.getElementById('detail-delete-form');
  if (detailDeleteForm) {
    detailDeleteForm.addEventListener('submit', function (e) {
      e.preventDefault();
      if (!confirm('Delete this event?')) return;
      const formData = new FormData(detailDeleteForm);
      fetch(detailDeleteForm.action, {
        method: 'POST',
        body: formData,
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
      }).then(() => {
        const modal = document.getElementById('event-detail');
        modal.classList.remove('flex');
        modal.classList.add('hidden');
        calendar.refetchEvents();
      });
    });
  }
});

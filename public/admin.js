const themeToggle = document.querySelector('[data-theme-toggle]');
if (themeToggle) {
  const applyTheme = theme => {
    document.documentElement.classList.toggle('dark', theme === 'dark');
  };
  const savedTheme = localStorage.getItem('admin-theme');
  applyTheme(savedTheme === 'dark' ? 'dark' : 'light');
  themeToggle.addEventListener('click', () => {
    const nextTheme = document.documentElement.classList.contains('dark') ? 'light' : 'dark';
    localStorage.setItem('admin-theme', nextTheme);
    applyTheme(nextTheme);
  });
}

document.querySelector('[data-back]')?.addEventListener('click', () => {
  if (window.history.length > 1) window.history.back();
  else window.location.assign('/');
});

const sidebarToggle = document.querySelector('[data-sidebar-toggle]');
const sidebarCloseButtons = document.querySelectorAll('[data-sidebar-close]');
const mobileSidebarQuery = window.matchMedia('(max-width: 767px)');

function closeMobileSidebar() {
  document.body.classList.remove('sidebar-mobile-open');
}

sidebarToggle?.addEventListener('click', () => {
  if (mobileSidebarQuery.matches) {
    document.body.classList.toggle('sidebar-mobile-open');
    return;
  }
  const collapsed = document.body.classList.toggle('sidebar-collapsed');
  localStorage.setItem('admin-sidebar-collapsed', collapsed ? 'true' : 'false');
});

if (!mobileSidebarQuery.matches && localStorage.getItem('admin-sidebar-collapsed') === 'true') {
  document.body.classList.add('sidebar-collapsed');
}

sidebarCloseButtons.forEach(button => button.addEventListener('click', closeMobileSidebar));
const navigationItems = document.querySelectorAll('[data-nav-item]');

function updateActiveNavigation() {
  const target = window.location.hash || '#users';
  navigationItems.forEach(item => item.classList.toggle('active', item.getAttribute('href') === target));
}

navigationItems.forEach(link => {
  link.addEventListener('click', () => {
    closeMobileSidebar();
    window.setTimeout(updateActiveNavigation, 0);
  });
});
updateActiveNavigation();
window.addEventListener('hashchange', updateActiveNavigation);

document.querySelectorAll('[data-refresh]').forEach(button => {
  button.addEventListener('click', event => {
    event.currentTarget.classList.add('is-refreshing');
    window.location.reload();
  });
});

const profileToggle = document.querySelector('[data-profile-toggle]');
const profilePopover = document.querySelector('[data-profile-popover]');

function closeProfileMenu() {
  if (!profileToggle || !profilePopover) return;
  profilePopover.hidden = true;
  profileToggle.setAttribute('aria-expanded', 'false');
}

profileToggle?.addEventListener('click', event => {
  event.stopPropagation();
  const willOpen = profilePopover?.hidden;
  if (profilePopover) profilePopover.hidden = !willOpen;
  profileToggle.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
});

profilePopover?.addEventListener('click', event => event.stopPropagation());
document.addEventListener('click', closeProfileMenu);
document.addEventListener('keydown', event => {
  if (event.key === 'Escape') {
    if (deleteModal && !deleteModal.hidden) closeDeleteModal();
    else if (accountEditPanel && !accountEditPanel.hidden) closeAccountEdit();
    else closeAssignmentModal();
    closeProfileMenu();
    closeMobileSidebar();
  }
});

const userSearch = document.querySelector('[data-user-search]');
const userRows = [...document.querySelectorAll('[data-user-row]')];
const userSearchEmpty = document.querySelector('[data-user-search-empty]');

userSearch?.addEventListener('input', () => {
  const query = userSearch.value.trim().toLowerCase();
  let visible = 0;
  userRows.forEach(row => {
    const matches = !query || String(row.dataset.searchValue || '').includes(query);
    row.hidden = !matches;
    if (matches) visible++;
  });
  if (userSearchEmpty) userSearchEmpty.hidden = visible > 0 || userRows.length === 0;
});

const assignmentModal = document.querySelector('[data-assignment-modal]');
const assignmentForm = document.querySelector('[data-assignment-form]');
const modalUserName = document.querySelector('[data-modal-user-name]');
const modalUserEmail = document.querySelector('[data-modal-user-email]');
const modalUserInitial = document.querySelector('[data-modal-user-initial]');
const assignmentCount = document.querySelector('[data-assignment-count]');
const assignmentLimitMessage = document.querySelector('[data-assignment-limit-message]');
const maxAssignments = Number(assignmentForm?.dataset.assignmentLimit || 25);
const accountSearch = document.querySelector('[data-account-search]');
const accountSearchEmpty = document.querySelector('[data-account-search-empty]');
const accountOptionItems = [...document.querySelectorAll('[data-account-option]')];
const addAccountToggle = document.querySelector('[data-add-account-toggle]');
const newAccountPanel = document.querySelector('[data-new-account-panel]');
const accountEditPanel = document.querySelector('[data-account-edit-panel]');
const accountEditInput = document.querySelector('[data-account-edit-input]');
const accountEditSave = document.querySelector('[data-account-edit-save]');
const deleteModal = document.querySelector('[data-delete-modal]');
const deleteModalSurface = deleteModal?.querySelector('.delete-modal-surface');
const deleteModalTitle = deleteModal?.querySelector('[data-delete-modal-title]');
const deleteModalMessage = deleteModal?.querySelector('[data-delete-modal-message]');
const deleteModalTarget = deleteModal?.querySelector('[data-delete-modal-target]');
const deleteForm = deleteModal?.querySelector('[data-delete-form]');
let assignmentReturnFocus = null;
let deleteReturnFocus = null;

function syncModalOpenState() {
  const modalIsOpen = [assignmentModal, deleteModal].some(modal => modal && !modal.hidden);
  document.body.classList.toggle('modal-open', modalIsOpen);
}

function closeDeleteModal() {
  if (!deleteModal || deleteModal.hidden) return;
  deleteModal.hidden = true;
  if (deleteForm) deleteForm.removeAttribute('action');
  syncModalOpenState();
  deleteReturnFocus?.focus();
  deleteReturnFocus = null;
}

function openDeleteModal(button) {
  if (!deleteModal || !deleteForm || !button.dataset.deleteAction) return;
  deleteReturnFocus = button;
  deleteForm.action = button.dataset.deleteAction;
  if (deleteModalTitle) deleteModalTitle.textContent = button.dataset.deleteTitle || 'دڵنیابوونەوە لە سڕینەوە';
  if (deleteModalMessage) deleteModalMessage.textContent = button.dataset.deleteMessage || 'ئەم کردارە ناگەڕێتەوە.';
  if (deleteModalTarget) {
    deleteModalTarget.textContent = button.dataset.deleteTarget || '';
    deleteModalTarget.hidden = !button.dataset.deleteTarget;
  }
  deleteModal.hidden = false;
  syncModalOpenState();
  window.setTimeout(() => deleteModalSurface?.focus(), 0);
}

function closeAccountEdit() {
  if (!accountEditPanel) return;
  accountEditPanel.hidden = true;
  if (accountEditInput) {
    accountEditInput.value = '';
    accountEditInput.disabled = true;
  }
  if (accountEditSave) accountEditSave.removeAttribute('formaction');
}

function openAccountEdit(button) {
  if (!accountEditPanel || !accountEditInput || !accountEditSave) return;
  setNewAccountPanel(false);
  accountEditInput.disabled = false;
  accountEditInput.value = button.dataset.advertiserId || '';
  accountEditSave.formAction = `${accountEditPanel.dataset.actionBase}${button.dataset.accountId}/edit`;
  accountEditPanel.hidden = false;
  window.setTimeout(() => {
    accountEditInput.focus();
    accountEditInput.select();
  }, 0);
}

function filterAccountOptions() {
  const query = String(accountSearch?.value || '').trim().toLowerCase();
  let visible = 0;
  accountOptionItems.forEach(option => {
    const matches = !query || String(option.dataset.searchValue || '').toLowerCase().includes(query);
    option.hidden = !matches;
    if (matches) visible++;
  });
  if (accountSearchEmpty) accountSearchEmpty.hidden = visible > 0 || accountOptionItems.length === 0;
}

function setNewAccountPanel(open) {
  if (!addAccountToggle || !newAccountPanel || !assignmentForm) return;
  newAccountPanel.hidden = !open;
  addAccountToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
  const newIdInput = assignmentForm.querySelector('input[name="newAdvertiserId"]');
  if (!open && newIdInput) {
    newIdInput.value = '';
    newIdInput.setCustomValidity('');
    updateAssignmentLimit();
  }
  if (open) closeAccountEdit();
  if (open) window.setTimeout(() => newIdInput?.focus(), 0);
}

function updateAssignmentLimit() {
  if (!assignmentForm) return;
  const accountInputs = [...assignmentForm.querySelectorAll('input[name="advertiserIds"]')];
  const selectedIds = new Set(accountInputs.filter(input => input.checked).map(input => input.value));
  const newIdInput = assignmentForm.querySelector('input[name="newAdvertiserId"]');
  const newId = newIdInput?.value.trim() || '';
  const total = selectedIds.size + (newId && !selectedIds.has(newId) ? 1 : 0);
  const limitReached = total >= maxAssignments;
  const limitExceeded = total > maxAssignments;

  if (assignmentCount) assignmentCount.textContent = `${total} / ${maxAssignments}`;
  if (assignmentLimitMessage) assignmentLimitMessage.hidden = !limitReached;
  accountInputs.forEach(input => {
    const unavailable = input.dataset.accountAvailable !== 'true';
    input.disabled = unavailable || (!input.checked && limitReached);
  });
  newIdInput?.setCustomValidity(limitExceeded ? `هەر ئیمەیڵێک تەنها دەتوانێت تا ${maxAssignments} هەژماری ڕیکلامی هەبێت.` : '');
}

function closeAssignmentModal() {
  if (!assignmentModal || assignmentModal.hidden) return;
  assignmentModal.hidden = true;
  syncModalOpenState();
  assignmentReturnFocus?.focus();
  assignmentReturnFocus = null;
}

function openAssignmentModal(button) {
  if (!assignmentModal || !assignmentForm) return;
  let assignedAccounts = [];
  try { assignedAccounts = JSON.parse(button.dataset.assignedAccounts || '[]'); } catch {}
  const assignedSet = new Set(assignedAccounts.map(String));
  assignmentForm.action = `${assignmentForm.dataset.actionBase}${button.dataset.userId}/assignments`;
  assignmentForm.querySelectorAll('input[name="advertiserIds"]').forEach(input => {
    input.checked = assignedSet.has(input.value);
  });
  const newIdInput = assignmentForm.querySelector('input[name="newAdvertiserId"]');
  if (newIdInput) newIdInput.value = '';
  if (accountSearch) accountSearch.value = '';
  filterAccountOptions();
  setNewAccountPanel(false);
  closeAccountEdit();
  if (modalUserName) modalUserName.textContent = button.dataset.userName || 'بەکارهێنەری Google';
  if (modalUserEmail) modalUserEmail.textContent = button.dataset.userEmail || '';
  if (modalUserInitial) modalUserInitial.textContent = (button.dataset.userName || button.dataset.userEmail || 'U').charAt(0).toUpperCase();
  updateAssignmentLimit();
  assignmentReturnFocus = button;
  assignmentModal.hidden = false;
  syncModalOpenState();
  window.setTimeout(() => assignmentForm.focus(), 0);
}

document.querySelectorAll('[data-assign-user]').forEach(button => {
  button.addEventListener('click', () => openAssignmentModal(button));
});
document.querySelectorAll('[data-modal-close]').forEach(button => button.addEventListener('click', closeAssignmentModal));
document.querySelectorAll('[data-confirm-delete]').forEach(button => button.addEventListener('click', () => openDeleteModal(button)));
document.querySelectorAll('[data-delete-close]').forEach(button => button.addEventListener('click', closeDeleteModal));
document.querySelectorAll('[data-edit-account]').forEach(button => button.addEventListener('click', () => openAccountEdit(button)));
document.querySelectorAll('[data-account-edit-close]').forEach(button => button.addEventListener('click', closeAccountEdit));
accountSearch?.addEventListener('input', filterAccountOptions);
addAccountToggle?.addEventListener('click', () => {
  setNewAccountPanel(addAccountToggle.getAttribute('aria-expanded') !== 'true');
});
assignmentForm?.addEventListener('change', event => {
  if (event.target.matches('input[name="advertiserIds"]')) updateAssignmentLimit();
});
assignmentForm?.querySelector('input[name="newAdvertiserId"]')?.addEventListener('input', updateAssignmentLimit);

assignmentForm?.addEventListener('keydown', event => {
  if (event.key !== 'Tab') return;
  const focusable = [...assignmentForm.querySelectorAll('button:not([disabled]), input:not([disabled])')]
    .filter(element => !element.closest('[hidden]'));
  if (focusable.length === 0) return;
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
});

deleteModalSurface?.addEventListener('keydown', event => {
  if (event.key !== 'Tab') return;
  const focusable = [...deleteModalSurface.querySelectorAll('button:not([disabled])')];
  if (focusable.length === 0) return;
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
});

deleteForm?.addEventListener('submit', event => {
  const button = event.submitter;
  if (button) {
    button.disabled = true;
    button.setAttribute('aria-busy', 'true');
  }
});

assignmentForm?.addEventListener('submit', event => {
  const button = event.submitter;
  if (button) {
    button.disabled = true;
    button.setAttribute('aria-busy', 'true');
  }
});

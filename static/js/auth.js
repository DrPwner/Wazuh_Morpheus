/**
 * auth.js — Login page behavior
 */
document.addEventListener('DOMContentLoaded', function () {
  // Toggle password visibility
  const toggle = document.querySelector('.toggle-password');
  const pwInput = document.getElementById('password');
  if (toggle && pwInput) {
    toggle.addEventListener('click', function () {
      const isText = pwInput.type === 'text';
      pwInput.type = isText ? 'password' : 'text';
      toggle.querySelector('.eye-open').style.display = isText ? 'block' : 'none';
      toggle.querySelector('.eye-closed').style.display = isText ? 'none' : 'block';
    });
  }

  // Autofocus username
  const usernameInput = document.getElementById('username');
  if (usernameInput) usernameInput.focus();
});

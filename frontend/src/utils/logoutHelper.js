export const safeLogout = () => {
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  localStorage.removeItem('username');
  localStorage.removeItem('login_time');
  
  const highestId = window.setTimeout(() => {}, 0);
  for (let i = 0; i < highestId; i++) {
    window.clearTimeout(i);
  }
  
  setTimeout(() => {
    const baseUrl = window.location.origin;
    window.location.href = `${baseUrl}/login`;
  }, 100);
  
  return true;
};

export const logoutWithConfirmation = (callback) => {
  if (window.confirm('Вы уверены, что хотите выйти?')) {
    if (callback && typeof callback === 'function') {
      callback();
    }
    return safeLogout();
  }
  return false;
};
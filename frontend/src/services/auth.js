import axios from 'axios';

const API_URL = 'http://localhost:8000';

// жизнь токена
const TOKEN_LIFETIME = 24 * 60 * 60 * 1000;

// ээкземпляр axios с базовым URL
const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// для добавления токена к запросам
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token');
    if (token) {
      let authToken = token;
      if (!authToken.startsWith('Bearer ')) {
        authToken = `Bearer ${token}`;
      }
      config.headers.Authorization = authToken;
      console.log('Request headers:', config.headers);
    }
    return config;
  },
  (error) => {
    console.error('Request error:', error);
    return Promise.reject(error);
  }
);

api.interceptors.response.use(
  (response) => {
    console.log('Response received:', response.status, response.config.url);
    return response;
  },
  async (error) => {
    console.error('Response error:', {
      url: error.config?.url,
      status: error.response?.status,
      data: error.response?.data
    });
    
    const originalRequest = error.config;
    
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      
      try {
        const refreshToken = localStorage.getItem('refresh_token');
        if (refreshToken) {
          console.log('Attempting token refresh...');
          const response = await axios.post(`${API_URL}/refresh`, {
            refresh_token: refreshToken
          }, {
            headers: {
              'Content-Type': 'application/json',
            },
          });
          
          if (response.data.access_token) {
            localStorage.setItem('access_token', response.data.access_token);
            localStorage.setItem('refresh_token', response.data.refresh_token || refreshToken);
            
            // обновление заголовка авторизации
            originalRequest.headers.Authorization = `Bearer ${response.data.access_token}`;
            console.log('Token refreshed, retrying request...');
            return api(originalRequest);
          }
        }
      } catch (refreshError) {
        console.error('Token refresh failed:', refreshError);
        authService.forceLogout();
        window.location.href = '/login';
      }
    }
    
    return Promise.reject(error);
  }
);

// сохраняем время входа
const saveLoginTime = () => {
  localStorage.setItem('login_time', Date.now().toString());
};

const getLoginTime = () => {
  const time = localStorage.getItem('login_time');
  return time ? parseInt(time) : null;
};

const isSessionExpired = () => {
  const loginTime = getLoginTime();
  if (!loginTime) return true;
  
  const currentTime = Date.now();
  const sessionDuration = currentTime - loginTime;
  
  return sessionDuration > TOKEN_LIFETIME;
};

export const authService = {
  register: async (username, password) => {
    try {
      const response = await api.post('/register/', {
        username,
        password,
      });
      console.log('Registration successful:', response.data);
      return response.data;
    } catch (error) {
      console.error('Registration error:', error.response?.data || error);
      throw error.response?.data || error;
    }
  },

  login: async (username, password) => {
    try {
      const formData = new FormData();
      formData.append('username', username);
      formData.append('password', password);
      
      console.log('Attempting login for:', username);
      
      const response = await axios.post(`${API_URL}/login`, formData, {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      });
      
      console.log('Login response:', response.data);
      
      if (response.data.access_token) {
        let token = response.data.access_token;
        if (token.startsWith('Bearer ')) {
          token = token.substring(7);
        }
        
        localStorage.setItem('access_token', token);
        localStorage.setItem('refresh_token', response.data.refresh_token || '');
        localStorage.setItem('username', username);
        saveLoginTime();
        
        // таймер для автоматического выхзода
        authService.setAutoLogoutTimer();
        
        console.log('Login successful, token saved');
      }
      
      return response.data;
    } catch (error) {
      console.error('Login error:', error.response?.data || error);
      throw error.response?.data || error;
    }
  },

logout: async () => {
  try {
    const token = authService.getToken();
    
    if (token) {
      try {
        api.post('/logout').catch(err => {
          console.log('Logout server request may have failed, continuing with local logout');
        });
      } catch (err) {
        console.log('Could not send logout request to server, continuing with local logout');
      }
    }
  } catch (error) {
    console.log('Logout preparation error:', error);
  } finally {
    authService.forceLogout();
  }
},

forceLogout: () => {
  console.log('Performing force logout');
  
  authService.clearAutoLogoutTimer();
  
  const redirectToLogin = () => {
    window.location.href = '/login';
  };
  
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  localStorage.removeItem('username');
  localStorage.removeItem('login_time');
  
  setTimeout(redirectToLogin, 100);
},

  forceLogout: () => {
    console.log('Force logout');
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('username');
    localStorage.removeItem('login_time');
    authService.clearAutoLogoutTimer();
  },

  getCurrentUser: async () => {
    try {
      console.log('Fetching current user...');
      const token = localStorage.getItem('access_token');
      console.log('Current token:', token ? `${token.substring(0, 20)}...` : 'No token');
      
      const response = await api.get('/users/me/');
      console.log('User data received:', response.data);
      return response.data;
    } catch (error) {
      console.error('Get current user error:', error.response?.data || error);
          
      throw error.response?.data || error;
    }
  },

  getProtectedData: async () => {
    try {
      const response = await api.get('/protected/');
      return response.data;
    } catch (error) {
      throw error.response?.data || error;
    }
  },

  // обновление токена
  refreshToken: async () => {
    try {
      const refreshToken = localStorage.getItem('refresh_token');
      if (!refreshToken) {
        throw new Error('No refresh token available');
      }

      const response = await api.post('/refresh', {
        refresh_token: refreshToken
      });
      
      if (response.data.access_token) {
        let token = response.data.access_token;
        if (token.startsWith('Bearer ')) {
          token = token.substring(7);
        }
        
        localStorage.setItem('access_token', token);
        localStorage.setItem('refresh_token', response.data.refresh_token || refreshToken);
        saveLoginTime();
        console.log('Token refreshed successfully');
      }
      
      return response.data;
    } catch (error) {
      console.error('Refresh token error:', error);
      throw error.response?.data || error;
    }
  },

  isAuthenticated: () => {
    const token = localStorage.getItem('access_token');
    
    if (!token) {
      console.log('No token found');
      return false;
    }
    
    if (isSessionExpired()) {
      console.log('Session expired');
      authService.forceLogout();
      return false;
    }
    
    console.log('User is authenticated');
    return true;
  },

  getUsername: () => {
    return localStorage.getItem('username');
  },

  getToken: () => {
    return localStorage.getItem('access_token');
  },

  getFormattedSessionTimeLeft: () => {
    const loginTime = getLoginTime();
    if (!loginTime) return 'Сессия не начата';
    
    const currentTime = Date.now();
    const elapsed = currentTime - loginTime;
    const timeLeft = TOKEN_LIFETIME - elapsed;
    
    if (timeLeft <= 0) return 'Сессия истекла';
    
    const hours = Math.floor(timeLeft / (60 * 60 * 1000));
    const minutes = Math.floor((timeLeft % (60 * 60 * 1000)) / (60 * 1000));
    
    return `${hours}ч ${minutes}м`;
  },

  autoLogoutTimer: null,
  
  setAutoLogoutTimer: () => {
    authService.clearAutoLogoutTimer();
    
    const timeLeft = TOKEN_LIFETIME - (Date.now() - (getLoginTime() || 0));
    if (timeLeft > 0) {
      authService.autoLogoutTimer = setTimeout(() => {
        console.log('Auto logout triggered');
        authService.forceLogout();
        window.location.href = '/login';
        alert('Ваша сессия истекла. Пожалуйста, войдите снова.');
      }, timeLeft);
      console.log(`Auto logout timer set for ${Math.floor(timeLeft / 1000)} seconds`);
    }
  },
  
  clearAutoLogoutTimer: () => {
    if (authService.autoLogoutTimer) {
      clearTimeout(authService.autoLogoutTimer);
      authService.autoLogoutTimer = null;
    }
  },

  // проверка сессии
  initSessionCheck: () => {
    if (authService.isAuthenticated()) {
      authService.setAutoLogoutTimer();
    }
    
    setInterval(() => {
      if (!authService.isAuthenticated()) {
        authService.forceLogout();
      }
    }, 60 * 1000);
  }
};

export default api;
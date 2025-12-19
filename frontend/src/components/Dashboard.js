import React, { useState, useEffect } from 'react';
import { authService } from '../services/auth';

const Dashboard = ({ onLogout }) => {
  const [userInfo, setUserInfo] = useState(null);
  const [protectedData, setProtectedData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [sessionTimeLeft, setSessionTimeLeft] = useState('');
  const [isLoggingOut, setIsLoggingOut] = useState(false);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const userData = await authService.getCurrentUser();
        setUserInfo(userData);
        
        const protectedResponse = await authService.getProtectedData();
        setProtectedData(protectedResponse);
      } catch (err) {
        setError('Failed to fetch user data');
        if (err.status === 401) {
          setTimeout(() => {
            authService.forceLogout();
          }, 1000);
        }
      } finally {
        setLoading(false);
      }
    };

    fetchData();

    // оставшееся время сессии
    const updateSessionTime = () => {
      setSessionTimeLeft(authService.getFormattedSessionTimeLeft());
    };

    updateSessionTime();
    const intervalId = setInterval(updateSessionTime, 60000);

    return () => clearInterval(intervalId);
  }, []);

  const handleLogout = async () => {
    if (isLoggingOut) return;
    
    setIsLoggingOut(true);
    setError('');
    
    try {
      if (onLogout && typeof onLogout === 'function') {
        onLogout();
      }
      
      await authService.logout();
      
      console.log('Logout completed successfully');
      
    } catch (err) {
      console.error('Logout error in component:', err);
      setError('Logout failed. Please try again.');
      setIsLoggingOut(false);
      
      setTimeout(() => {
        authService.forceLogout();
      }, 1000);
    }
  };

  const handleRefreshToken = async () => {
    try {
      await authService.refreshToken();
      alert('Токен успешно обновлен!');
      setSessionTimeLeft(authService.getFormattedSessionTimeLeft());
    } catch (err) {
      alert('Не удалось обновить токен. Пожалуйста, войдите снова.');
      authService.forceLogout();
    }
  };

  if (loading) {
    return (
      <div className="dashboard-container">
        <div className="loading">Загрузка...</div>
      </div>
    );
  }

  const formatDate = (dateString) => {
    if (!dateString) return 'Никогда';
    return new Date(dateString).toLocaleDateString('ru-RU', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <div>
          <h1>Панель управления</h1>
          <div className="session-info">
            <span className="session-timer">Сессия истекает через: {sessionTimeLeft}</span>
          </div>
        </div>
        <div className="header-actions">
          <button 
            onClick={handleLogout} 
            className="logout-btn"
            disabled={isLoggingOut}
          >
            {isLoggingOut ? 'Выход...' : 'Выйти'}
          </button>
        </div>
      </div>

      {error && <div className="error-message">{error}</div>}

      <div className="dashboard-content">
        <div className="user-info-card">
          <h2>Информация о пользователе</h2>
          {userInfo && (
            <div className="user-details">
              <p><strong>Имя пользователя:</strong> {userInfo.username}</p>
              <p><strong>ID пользователя:</strong> {userInfo.id}</p>
              <p><strong>Зарегистрирован:</strong> {formatDate(userInfo.created_at)}</p>
              <p><strong>Последний вход:</strong> {formatDate(userInfo.last_login)}</p>
              <p><strong>Статус:</strong> {userInfo.is_active ? 'Активен' : 'Неактивен'}</p>
            </div>
          )}
        </div>

        <div className="protected-data-card">
          <h2>Защищенные данные</h2>
          {protectedData && (
            <div className="protected-details">
              <p><strong>Сообщение:</strong> {protectedData.message}</p>
              <p><strong>Время сервера:</strong> {formatDate(new Date().toISOString())}</p>
            </div>
          )}
        </div>

        <div className="quick-actions">
          <h2>Быстрые действия</h2>
          <div className="action-buttons">
            <button 
              onClick={handleRefreshToken}
              className="action-btn secondary"
              disabled={isLoggingOut}
            >
              Обновить токен
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;

import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/Login';
import Register from './components/Register';
import Dashboard from './components/Dashboard';
import PrivateRoute from './components/PrivateRoute';
import { authService } from './services/auth';
import './App.css';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [logoutTriggered, setLogoutTriggered] = useState(false);

  useEffect(() => {
    authService.initSessionCheck();
    
    const checkAuth = () => {
      const authStatus = authService.isAuthenticated();
      setIsAuthenticated(authStatus);
      setLoading(false);
    };

    checkAuth();
    
    const handleStorageChange = () => {
      if (!logoutTriggered) {
        checkAuth();
      }
    };
    
    window.addEventListener('storage', handleStorageChange);
    
    const intervalId = setInterval(() => {
      if (!logoutTriggered) {
        const authStatus = authService.isAuthenticated();
        if (authStatus !== isAuthenticated) {
          setIsAuthenticated(authStatus);
        }
      }
    }, 1000);
    
    return () => {
      window.removeEventListener('storage', handleStorageChange);
      clearInterval(intervalId);
    };
  }, [isAuthenticated, logoutTriggered]);

  const handleLogout = () => {
    setLogoutTriggered(true);
    setIsAuthenticated(false);
    
    setTimeout(() => {
      setLogoutTriggered(false);
    }, 2000);
  };

  if (loading) {
    return <div className="app-loading">Загрузка приложения...</div>;
  }

  return (
    <Router>
      <div className="App">
        <Routes>
          <Route 
            path="/login" 
            element={
              isAuthenticated ? (
                <Navigate to="/dashboard" replace />
              ) : (
                <Login setIsAuthenticated={setIsAuthenticated} />
              )
            } 
          />
          <Route 
            path="/register" 
            element={
              isAuthenticated ? (
                <Navigate to="/dashboard" replace />
              ) : (
                <Register setIsAuthenticated={setIsAuthenticated} />
              )
            } 
          />
          <Route 
            path="/dashboard" 
            element={
              <PrivateRoute>
                <Dashboard onLogout={handleLogout} />
              </PrivateRoute>
            } 
          />
          <Route 
            path="/" 
            element={
              <Navigate to={isAuthenticated ? "/dashboard" : "/login"} replace />
            } 
          />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
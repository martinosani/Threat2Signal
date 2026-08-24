import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ToastProvider } from './components/Toast';
import { AuthProvider } from './lib/AuthContext';
import Login from './pages/Login';
import PrivateRoute from './components/PrivateRoute';
import App from './App';
import Feed from './pages/Feed';
import AdvisoryDetail from './pages/AdvisoryDetail';
import TechniqueMatrix from './pages/TechniqueMatrix';
import GraphExplorer from './pages/GraphExplorer';
import IocSearch from './pages/IocSearch';
import DetectionRules from './pages/DetectionRules';
import MsrcView from './pages/MsrcView';
import CveDetail from './pages/CveDetail';
import ActorsMalware from './pages/ActorsMalware';
import NotFound from './pages/NotFound';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000, // 5 minutes
      refetchOnWindowFocus: true,
      retry: 1,
    },
  },
});

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <ToastProvider>
          <BrowserRouter>
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route element={<PrivateRoute />}>
                <Route element={<App />}>
                  <Route index element={<Feed />} />
                  <Route path="advisory/:id" element={<AdvisoryDetail />} />
                  <Route path="techniques" element={<TechniqueMatrix />} />
                  <Route path="graph" element={<GraphExplorer />} />
                  <Route path="iocs" element={<IocSearch />} />
                  <Route path="rules" element={<DetectionRules />} />
                  <Route path="msrc" element={<MsrcView />} />
                  <Route path="msrc/:cveId" element={<CveDetail />} />
                  <Route path="actors" element={<ActorsMalware />} />
                  <Route path="*" element={<NotFound />} />
                </Route>
              </Route>
            </Routes>
          </BrowserRouter>
        </ToastProvider>
      </AuthProvider>
    </QueryClientProvider>
  </StrictMode>,
);

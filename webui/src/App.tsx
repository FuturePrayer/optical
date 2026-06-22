import { useEffect, useMemo, useState } from 'react';
import { Layout, Menu, theme, Badge, Space, Typography } from 'antd';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  DashboardOutlined,
  ClusterOutlined,
  ClockCircleOutlined,
  SettingOutlined,
} from '@ant-design/icons';
import { Routes, Route, useNavigate, useLocation, Navigate } from 'react-router-dom';
import { HashRouter, Link } from 'react-router-dom';
import { api, openEventStream, getToken, setToken } from './api/client';
import Overview from './pages/Overview';
import Nodes from './pages/Nodes';
import Pending from './pages/Pending';
import NodeDetail from './pages/NodeDetail';
import ConfigPush from './pages/ConfigPush';
import Settings from './pages/Settings';

const { Header, Sider, Content } = Layout;
const { Title } = Typography;

function useSseInvalidation() {
  const qc = useQueryClient();
  useEffect(() => {
    if (!getToken()) return;
    const es = openEventStream((data) => {
      try {
        const evt = JSON.parse(data);
        // Any node event invalidates the nodes/overview caches (auto refetch).
        if (evt.node_id) {
          qc.invalidateQueries({ queryKey: ['nodes'] });
          qc.invalidateQueries({ queryKey: ['overview'] });
        }
      } catch {
        /* ignore malformed */
      }
    });
    return () => es.close();
  }, [qc]);
}

function LoginGate() {
  const [token, setTokenState] = useState(() => getToken() || '');
  const saved = getToken();
  if (!saved) {
    return (
      <div style={{ maxWidth: 380, margin: '6rem auto' }}>
        <Title level={3}>optical-center 登录</Title>
        <p>输入管理 token（配置文件的 <code>center_admin_token</code>）</p>
        <Space.Compact style={{ width: '100%' }}>
          <input
            style={{ flex: 1, padding: '6px 10px' }}
            type="password"
            placeholder="admin token"
            value={token}
            onChange={(e) => setTokenState(e.target.value)}
          />
          <button
            style={{ padding: '6px 16px' }}
            onClick={() => {
              setToken(token);
              window.location.reload();
            }}
          >
            登录
          </button>
        </Space.Compact>
        <p style={{ marginTop: 12, color: '#888', fontSize: 12 }}>
          未配置 token 时留空也可（本地开发模式）。
        </p>
      </div>
    );
  }
  return <AppShell />;
}

function AppShell() {
  const navigate = useNavigate();
  const location = useLocation();
  const { token: themeToken } = theme.useToken();
  const [collapsed, setCollapsed] = useState(false);

  const { data: overview } = useQuery({ queryKey: ['overview'], queryFn: api.overview });
  useSseInvalidation();

  const pendingCount = overview?.pending ?? 0;
  const selectedKey = useMemo(() => {
    const p = location.pathname;
    if (p.startsWith('/nodes/')) return '/nodes';
    return p;
  }, [location.pathname]);

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider collapsible collapsed={collapsed} onCollapse={setCollapsed}>
        <div style={{ height: 48, margin: 12, color: '#fff', fontWeight: 600, fontSize: 16, textAlign: 'center', lineHeight: '48px' }}>
          {collapsed ? '◉' : 'optical-center'}
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[selectedKey]}
          items={[
            { key: '/', icon: <DashboardOutlined />, label: <Link to="/">总览</Link> },
            {
              key: '/nodes',
              icon: <ClusterOutlined />,
              label: <Link to="/nodes">节点</Link>,
            },
            {
              key: '/pending',
              icon: <ClockCircleOutlined />,
              label: (
                <span>
                  <Link to="/pending">待审批</Link>
                  {pendingCount > 0 && (
                    <Badge count={pendingCount} size="small" style={{ marginLeft: 8 }} />
                  )}
                </span>
              ),
            },
            { key: '/config', icon: <ClockCircleOutlined />, label: <Link to="/config">配置下发</Link> },
            { key: '/settings', icon: <SettingOutlined />, label: <Link to="/settings">设置</Link> },
          ]}
        />
      </Sider>
      <Layout>
        <Header style={{ background: themeToken.colorBgContainer, padding: '0 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ fontSize: 16, fontWeight: 500 }}>
            optical 配置中心
          </span>
          <Space>
            {overview && (
              <>
                <Badge status={overview.online > 0 ? 'success' : 'error'} text={`${overview.online} 在线`} />
                <span style={{ color: '#888' }}>·</span>
                <span>{overview.total} 节点</span>
              </>
            )}
            <a onClick={() => { setToken(null); window.location.reload(); }}>退出</a>
          </Space>
        </Header>
        <Content style={{ margin: 16, padding: 24, background: themeToken.colorBgContainer, borderRadius: 8 }}>
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/nodes" element={<Nodes />} />
            <Route path="/nodes/:id" element={<NodeDetail />} />
            <Route path="/pending" element={<Pending />} />
            <Route path="/config" element={<ConfigPush />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" />} />
          </Routes>
        </Content>
      </Layout>
    </Layout>
  );
}

export default function App() {
  return (
    <HashRouter>
      <LoginGate />
    </HashRouter>
  );
}

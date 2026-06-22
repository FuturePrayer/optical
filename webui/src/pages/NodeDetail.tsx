import { Card, Descriptions, Tag, Table, Typography, Button, Space } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { useParams, Link } from 'react-router-dom';
import { api } from '../api/client';
import type { ForwarderConfig, TunnelSnapshot } from '../api/types';

const { Title, Text } = Typography;

function formatBytes(n: number): string {
  if (n < 1024) return `${n}B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)}MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)}GB`;
}

export default function NodeDetail() {
  const { id = '' } = useParams();
  const { data: node } = useQuery({ queryKey: ['node', id], queryFn: () => api.node(id) });

  if (!node) return <div>加载中…</div>;

  const tunnels: TunnelSnapshot[] = node.last_status?.snapshot?.tunnels || [];

  return (
    <div>
      <Space style={{ marginBottom: 16 }}>
        <Title level={4} style={{ margin: 0 }}>节点详情</Title>
        <Button><Link to="/nodes">返回列表</Link></Button>
      </Space>

      <Card size="small" style={{ marginBottom: 16 }}>
        <Descriptions size="small" column={2}>
          <Descriptions.Item label="node_id">
            <Text code copyable>{node.node_id}</Text>
          </Descriptions.Item>
          <Descriptions.Item label="状态">
            {node.online ? <Tag color="green">在线</Tag> : <Tag>离线</Tag>}
          </Descriptions.Item>
          <Descriptions.Item label="审批">
            <Tag color={node.status === 'approved' ? 'green' : 'orange'}>{node.status}</Tag>
          </Descriptions.Item>
          <Descriptions.Item label="版本">{node.last_version || '—'}</Descriptions.Item>
          <Descriptions.Item label="配置版本">{node.config_version}</Descriptions.Item>
          <Descriptions.Item label="运行时长">
            {node.last_status ? `${node.last_status.uptime_secs}s` : '—'}
          </Descriptions.Item>
        </Descriptions>
      </Card>

      <Title level={5}>当前生效配置 (v{node.config_version})</Title>
      <Table
        size="small"
        rowKey="listen"
        dataSource={node.forwarders}
        pagination={false}
        style={{ marginBottom: 16 }}
        columns={[
          { title: '监听', dataIndex: 'listen' },
          { title: '协议', dataIndex: 'proto' },
          { title: '隧道对端', dataIndex: 'tunnel' },
          { title: '目标', dataIndex: 'target' },
          { title: '反向', dataIndex: 'reverse', render: (r: boolean) => (r ? '是' : '否') },
        ]}
      />

      <Title level={5}>隧道连接</Title>
      {tunnels.length === 0 ? (
        <Text type="secondary">（无隧道连接）</Text>
      ) : (
        <Table
          size="small"
          rowKey="addr"
          dataSource={tunnels}
          pagination={false}
          columns={[
            { title: '对端', dataIndex: 'addr' },
            { title: '角色', dataIndex: 'role' },
            { title: '状态', dataIndex: 'state', render: (s: string) => <Tag color={s === 'connected' ? 'green' : 'red'}>{s}</Tag> },
            { title: 'RTT', dataIndex: 'rtt_us', render: (u: number) => (u ? `${(u / 1000).toFixed(2)}ms` : '—') },
            { title: '↑', dataIndex: 'bytes_sent', render: formatBytes },
            { title: '↓', dataIndex: 'bytes_recv', render: formatBytes },
            { title: '重连', dataIndex: 'reconnect_count' },
          ]}
        />
      )}
    </div>
  );
}

// Keep ForwarderConfig import used (type-only ref for clarity).
export type { ForwarderConfig };

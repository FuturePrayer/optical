import { Card, Col, Row, Statistic, Table, Tag, Typography } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import type { NodeRecord } from '../api/types';

const { Title } = Typography;

export default function Overview() {
  const { data: counts } = useQuery({ queryKey: ['overview'], queryFn: api.overview });
  const { data: nodes } = useQuery({ queryKey: ['nodes'], queryFn: api.nodes });

  const offline = (nodes || []).filter((n) => !n.online);
  const recent = (nodes || []).filter((n) => n.online).slice(0, 8);

  return (
    <div>
      <Title level={4}>集群总览</Title>
      <Row gutter={16}>
        <Col span={4}>
          <Card><Statistic title="节点总数" value={counts?.total ?? 0} /></Card>
        </Col>
        <Col span={4}>
          <Card><Statistic title="在线" value={counts?.online ?? 0} valueStyle={{ color: '#3f8600' }} /></Card>
        </Col>
        <Col span={4}>
          <Card><Statistic title="离线" value={counts?.offline ?? 0} valueStyle={{ color: '#cf1322' }} /></Card>
        </Col>
        <Col span={4}>
          <Card><Statistic title="待审批" value={counts?.pending ?? 0} valueStyle={{ color: '#d48806' }} /></Card>
        </Col>
        <Col span={4}>
          <Card><Statistic title="已批准" value={counts?.approved ?? 0} /></Card>
        </Col>
        <Col span={4}>
          <Card><Statistic title="已拒绝" value={counts?.rejected ?? 0} /></Card>
        </Col>
      </Row>

      <Title level={5} style={{ marginTop: 24 }}>异常节点（离线）</Title>
      <Table
        size="small"
        rowKey="node_id"
        dataSource={offline}
        pagination={false}
        columns={[
          {
            title: '节点',
            dataIndex: 'node_id',
            render: (id: string, r: NodeRecord) => (
              <Link to={`/nodes/${id}`}>{r.name || `${id.slice(0, 12)}…${id.slice(-4)}`}</Link>
            ),
          },
          { title: 'IP', render: (_: any, r: NodeRecord) => r.remote_addr || '—' },
          { title: '状态', dataIndex: 'status', render: (s: string) => <Tag color="red">离线</Tag> },
          { title: '版本', dataIndex: 'last_version' },
          { title: '配置版本', dataIndex: 'config_version' },
        ]}
      />

      <Title level={5} style={{ marginTop: 24 }}>在线节点</Title>
      <Table
        size="small"
        rowKey="node_id"
        dataSource={recent}
        pagination={false}
        columns={[
          {
            title: '节点',
            dataIndex: 'node_id',
            render: (id: string, r: NodeRecord) => (
              <Link to={`/nodes/${id}`}>{r.name || `${id.slice(0, 12)}…${id.slice(-4)}`}</Link>
            ),
          },
          { title: 'IP', render: (_: any, r: NodeRecord) => r.remote_addr || '—' },
          { title: '状态', dataIndex: 'status', render: () => <Tag color="green">在线</Tag> },
          { title: '版本', dataIndex: 'last_version' },
          { title: '配置版本', dataIndex: 'config_version' },
          { title: '转发规则数', render: (_: any, r: NodeRecord) => r.forwarders.length },
        ]}
      />
    </div>
  );
}

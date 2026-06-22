import { Table, Tag, Input, Space, Button, Typography } from 'antd';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { useState } from 'react';
import { api } from '../api/client';
import type { NodeRecord } from '../api/types';

const { Title } = Typography;

export default function Nodes() {
  const { data: nodes, isLoading } = useQuery({ queryKey: ['nodes'], queryFn: api.nodes });
  const qc = useQueryClient();
  const [filter, setFilter] = useState('');
  const [selected, setSelected] = useState<string[]>([]);

  const filtered = (nodes || []).filter((n) =>
    n.node_id.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div>
      <Title level={4}>节点列表</Title>
      <Space style={{ marginBottom: 16 }}>
        <Input.Search
          placeholder="搜索 node_id"
          allowClear
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          style={{ width: 320 }}
        />
      </Space>
      <Table
        size="small"
        rowKey="node_id"
        loading={isLoading}
        dataSource={filtered}
        rowSelection={{
          selectedRowKeys: selected,
          onChange: (keys) => setSelected(keys as string[]),
        }}
        pagination={{ pageSize: 20 }}
        columns={[
          {
            title: 'node_id',
            dataIndex: 'node_id',
            render: (id: string) => <Link to={`/nodes/${id}`}>{id.slice(0, 12)}…{id.slice(-4)}</Link>,
          },
          {
            title: '状态',
            render: (_, r: NodeRecord) =>
              r.online ? <Tag color="green">在线</Tag> : <Tag>离线</Tag>,
          },
          {
            title: '审批',
            dataIndex: 'status',
            render: (s: string) => {
              const color = s === 'approved' ? 'green' : s === 'pending' ? 'orange' : 'red';
              return <Tag color={color}>{s}</Tag>;
            },
          },
          { title: '版本', dataIndex: 'last_version' },
          { title: '配置版本', dataIndex: 'config_version' },
          { title: '转发规则', render: (_: any, r: NodeRecord) => r.forwarders.length },
          {
            title: '操作',
            render: (_, r: NodeRecord) => (
              <Link to={`/nodes/${r.node_id}`}>详情</Link>
            ),
          },
        ]}
      />
    </div>
  );
}

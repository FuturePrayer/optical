import { Table, Tag, Input, Space, Typography, Modal, message } from 'antd';
import { EditOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { useState } from 'react';
import { api } from '../api/client';
import type { NodeRecord } from '../api/types';

const { Title } = Typography;

/** Display label for a node: name if set, else truncated node_id. */
function nodeLabel(n: NodeRecord): string {
  return n.name || `${n.node_id.slice(0, 12)}…${n.node_id.slice(-4)}`;
}

export default function Nodes() {
  const { data: nodes, isLoading } = useQuery({ queryKey: ['nodes'], queryFn: api.nodes });
  const qc = useQueryClient();
  const [filter, setFilter] = useState('');
  const [renameTarget, setRenameTarget] = useState<NodeRecord | null>(null);
  const [renameValue, setRenameValue] = useState('');
  const [renaming, setRenaming] = useState(false);

  const filtered = (nodes || []).filter(
    (n) =>
      n.node_id.toLowerCase().includes(filter.toLowerCase()) ||
      (n.name || '').toLowerCase().includes(filter.toLowerCase())
  );

  const openRename = (n: NodeRecord) => {
    setRenameTarget(n);
    setRenameValue(n.name || '');
  };

  const doRename = async () => {
    if (!renameTarget) return;
    setRenaming(true);
    try {
      const name = renameValue.trim() === '' ? null : renameValue.trim();
      await api.rename(renameTarget.node_id, name);
      message.success(name ? `已重命名为「${name}」` : '已清除名称');
      qc.invalidateQueries({ queryKey: ['nodes'] });
      setRenameTarget(null);
    } catch (e: any) {
      message.error(`重命名失败: ${e.message}`);
    } finally {
      setRenaming(false);
    }
  };

  return (
    <div>
      <Title level={4}>节点列表</Title>
      <Space style={{ marginBottom: 16 }}>
        <Input.Search
          placeholder="搜索名称或 node_id"
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
        pagination={{ pageSize: 20 }}
        columns={[
          {
            title: '节点',
            dataIndex: 'node_id',
            render: (id: string, r: NodeRecord) => (
              <Space size={4}>
                <Link to={`/nodes/${id}`}>{nodeLabel(r)}</Link>
                <a onClick={() => openRename(r)} title="重命名">
                  <EditOutlined style={{ color: '#888', fontSize: 12 }} />
                </a>
              </Space>
            ),
          },
          {
            title: 'IP',
            dataIndex: 'remote_addr',
            render: (addr?: string) => addr || <span style={{ color: '#ccc' }}>—</span>,
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

      <Modal
        title="重命名节点"
        open={!!renameTarget}
        onOk={doRename}
        onCancel={() => setRenameTarget(null)}
        confirmLoading={renaming}
        okText="保存"
        cancelText="取消"
      >
        <p style={{ color: '#888', fontSize: 12, marginBottom: 8 }}>
          node_id: <code>{renameTarget?.node_id}</code>
        </p>
        <Input
          value={renameValue}
          onChange={(e) => setRenameValue(e.target.value)}
          placeholder="输入节点名称(留空清除名称,回退显示 node_id)"
          onPressEnter={doRename}
          autoFocus
        />
      </Modal>
    </div>
  );
}

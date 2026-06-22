import { Card, Table, Tag, Typography, Input, Button, Space, message } from 'antd';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { api, getToken, setToken } from '../api/client';

const { Title, Text } = Typography;

export default function Settings() {
  const { data: whitelist } = useQuery({ queryKey: ['whitelist'], queryFn: api.whitelist });
  const qc = useQueryClient();
  const [bulkInput, setBulkInput] = useState('');
  const [tokenInput, setTokenInput] = useState(getToken() || '');

  // Note: whitelist add currently goes through "approve" with an empty config,
  // which pre-registers the node_id as approved. Real approval + config happens
  // in the Pending / ConfigPush pages.
  const addWhitelist = async (ids: string[]) => {
    for (const id of ids) {
      const trimmed = id.trim();
      if (!trimmed) continue;
      try {
        await api.approve(trimmed, []);
      } catch (e: any) {
        message.error(`${trimmed.slice(0, 12)}… 失败: ${e.message}`);
      }
    }
    qc.invalidateQueries({ queryKey: ['whitelist'] });
    qc.invalidateQueries({ queryKey: ['nodes'] });
    message.success('已加入白名单');
    setBulkInput('');
  };

  return (
    <div>
      <Title level={4}>设置</Title>

      <Card title="访问控制" size="small" style={{ marginBottom: 16 }}>
        <Space direction="vertical" style={{ width: '100%' }}>
          <Text>管理 Token（当前会话使用，修改后重新登录生效）</Text>
          <Space.Compact style={{ width: '100%' }}>
            <Input value={tokenInput} onChange={(e) => setTokenInput(e.target.value)} style={{ flex: 1 }} />
            <Button onClick={() => { setToken(tokenInput || null); window.location.reload(); }}>保存并重载</Button>
          </Space.Compact>
        </Space>
      </Card>

      <Card title="节点白名单" size="small">
        <Table
          size="small"
          rowKey="id"
          dataSource={(whitelist || []).map((id) => ({ id }))}
          pagination={false}
          columns={[
            {
              title: 'node_id',
              dataIndex: 'id',
              render: (id: string) => <Text code copyable>{id}</Text>,
            },
            { title: '状态', render: () => <Tag color="green">已批准</Tag> },
            {
              title: '操作',
              render: (_: any, r: { id: string }) => (
                <Button danger size="small" onClick={async () => {
                  await api.remove(r.id);
                  qc.invalidateQueries({ queryKey: ['whitelist'] });
                  qc.invalidateQueries({ queryKey: ['nodes'] });
                }}>移除</Button>
              ),
            },
          ]}
        />
        <div style={{ marginTop: 16 }}>
          <Text>批量导入（每行一个 node_id）</Text>
          <Input.TextArea
            rows={3}
            value={bulkInput}
            onChange={(e) => setBulkInput(e.target.value)}
            placeholder="a3f2c1...\nb1c24f..."
            style={{ marginTop: 8 }}
          />
          <Button style={{ marginTop: 8 }} onClick={() => addWhitelist(bulkInput.split('\n'))}>导入</Button>
        </div>
      </Card>
    </div>
  );
}

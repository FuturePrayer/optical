import { Card, Tag, Button, Typography, Empty, Space, message } from 'antd';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import type { ForwarderConfig } from '../api/types';

const { Title, Text } = Typography;

export default function Pending() {
  const { data: pending } = useQuery({ queryKey: ['pending'], queryFn: api.pending });
  const qc = useQueryClient();
  const navigate = useNavigate();

  const approve = async (id: string) => {
    // Approve with an empty forwarder set; the user can push a real config next.
    const forwarders: ForwarderConfig[] = [];
    try {
      await api.approve(id, forwarders);
      message.success('已批准，请前往配置下发分配转发规则');
      qc.invalidateQueries({ queryKey: ['pending'] });
      qc.invalidateQueries({ queryKey: ['nodes'] });
      navigate(`/config?node=${id}`);
    } catch (e: any) {
      message.error(`批准失败: ${e.message}`);
    }
  };

  const reject = async (id: string) => {
    try {
      await api.reject(id);
      message.success('已拒绝');
      qc.invalidateQueries({ queryKey: ['pending'] });
      qc.invalidateQueries({ queryKey: ['nodes'] });
    } catch (e: any) {
      message.error(`拒绝失败: ${e.message}`);
    }
  };

  return (
    <div>
      <Title level={4}>待审批节点</Title>
      <Text type="secondary">白名单内节点自动批准；此处仅列出白名单外的未知节点。</Text>
      {(!pending || pending.length === 0) && (
        <Empty description="无待审批节点" style={{ marginTop: 48 }} />
      )}
      <Space direction="vertical" style={{ width: '100%', marginTop: 16 }}>
        {(pending || []).map((n) => (
          <Card key={n.node_id} size="small">
            <Space style={{ width: '100%', justifyContent: 'space-between' }}>
              <div>
                <Tag color="orange">未知节点</Tag>
                <Text code copyable>{n.node_id}</Text>
                <br />
                <Text type="secondary">版本 {n.last_version || '—'} · 不在白名单中</Text>
              </div>
              <Space>
                <Button type="primary" onClick={() => approve(n.node_id)}>批准并配置</Button>
                <Button danger onClick={() => reject(n.node_id)}>拒绝</Button>
              </Space>
            </Space>
          </Card>
        ))}
      </Space>
    </div>
  );
}

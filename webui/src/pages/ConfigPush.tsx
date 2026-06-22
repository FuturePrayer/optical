import { useState } from 'react';
import { Form, Input, Button, Select, Switch, Space, Card, Typography, message, Divider, Alert } from 'antd';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import type { ForwarderConfig } from '../api/types';

const { Title, Text, Paragraph } = Typography;

interface RuleForm extends ForwarderConfig {
  key: string;
}

export default function ConfigPush() {
  const [searchParams] = useSearchParams();
  const qc = useQueryClient();
  const { data: nodes } = useQuery({ queryKey: ['nodes'], queryFn: api.nodes });
  const [targetNode, setTargetNode] = useState(searchParams.get('node') || '');
  const [rules, setRules] = useState<RuleForm[]>([]);
  const [yamlInput, setYamlInput] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const importYaml = () => {
    try {
      // Minimal YAML forwarders parser (avoids a js-yaml dep): expects
      //   forwarders:
      //     - listen: ...
      //       proto: tcp
      //       tunnel: ...
      //       target: ...
      //       reverse: false
      const lines = yamlInput.split('\n');
      const parsed: RuleForm[] = [];
      let cur: Partial<RuleForm> | null = null;
      for (const raw of lines) {
        const line = raw.trim();
        if (line === '' || line.startsWith('#')) continue;
        if (line.startsWith('- ')) {
          if (cur) parsed.push(cur as RuleForm);
          cur = { key: Math.random().toString(36).slice(2) };
          const rest = line.slice(2).trim();
          if (rest) applyKv(cur, rest);
        } else if (cur && line.includes(':')) {
          applyKv(cur, line);
        }
      }
      if (cur) parsed.push(cur as RuleForm);
      setRules((r) => [...r, ...parsed.filter((p) => p.listen)]);
      message.success(`导入 ${parsed.length} 条规则`);
    } catch (e: any) {
      message.error(`解析失败: ${e.message}`);
    }
  };

  const applyKv = (obj: any, kv: string) => {
    const [k, ...rest] = kv.split(':');
    const v = rest.join(':').trim();
    if (k.trim() === 'proto') obj.proto = v === 'udp' ? 'udp' : 'tcp';
    else if (k.trim() === 'reverse') obj.reverse = v === 'true';
    else (obj as any)[k.trim()] = v.replace(/^"|"$/g, '');
  };

  const addRule = () => setRules((r) => [...r, {
    key: Math.random().toString(36).slice(2),
    listen: '', proto: 'tcp', tunnel: '', target: '', reverse: false,
  }]);

  const removeRule = (key: string) => setRules((r) => r.filter((x) => x.key !== key));

  const submit = async () => {
    if (!targetNode) { message.warning('请选择目标节点'); return; }
    const forwarders: ForwarderConfig[] = rules.map(({ key, ...rest }) => rest);
    setSubmitting(true);
    try {
      const res = await api.pushConfig(targetNode, forwarders);
      message.success(res.delivered ? `已下发到节点 (${forwarders.length} 条规则)` : '已保存，节点离线时下次连上生效');
      qc.invalidateQueries({ queryKey: ['nodes'] });
    } catch (e: any) {
      message.error(`下发失败: ${e.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div>
      <Title level={4}>配置下发</Title>

      <Form layout="inline" style={{ marginBottom: 16 }}>
        <Form.Item label="目标节点">
          <Select
            showSearch
            style={{ width: 360 }}
            placeholder="选择节点"
            value={targetNode || undefined}
            onChange={setTargetNode}
            options={(nodes || []).map((n) => ({
              value: n.node_id,
              label: `${n.node_id.slice(0, 12)}…${n.node_id.slice(-4)} ${n.online ? '●' : '○'}`,
            }))}
          />
        </Form.Item>
      </Form>

      <Card size="small" title="YAML 快速导入（可选）" style={{ marginBottom: 16 }}>
        <Input.TextArea
          rows={5}
          placeholder={'forwarders:\n  - listen: 0.0.0.0:8080\n    proto: tcp\n    tunnel: tcp://peer:9000\n    target: nginx:80'}
          value={yamlInput}
          onChange={(e) => setYamlInput(e.target.value)}
        />
        <Button style={{ marginTop: 8 }} onClick={importYaml}>解析并填充表单</Button>
      </Card>

      <Title level={5}>转发规则</Title>
      <Space direction="vertical" style={{ width: '100%' }}>
        {rules.map((r) => (
          <Card key={r.key} size="small">
            <Space wrap>
              <Input addonBefore="监听" value={r.listen} onChange={(e) => updateRule(r.key, 'listen', e.target.value)} style={{ width: 220 }} />
              <span>协议</span>
              <Select value={r.proto} onChange={(v) => updateRule(r.key, 'proto', v)} style={{ width: 100 }}
                options={[{ value: 'tcp', label: 'tcp' }, { value: 'udp', label: 'udp' }]} />
              <Input addonBefore="隧道对端" value={r.tunnel} onChange={(e) => updateRule(r.key, 'tunnel', e.target.value)} style={{ width: 260 }} />
              <Input addonBefore="目标" value={r.target} onChange={(e) => updateRule(r.key, 'target', e.target.value)} style={{ width: 200 }} />
              <Space><Switch checked={r.reverse} onChange={(v) => updateRule(r.key, 'reverse', v)} /> 反向</Space>
              <Button danger size="small" onClick={() => removeRule(r.key)}>删除</Button>
            </Space>
          </Card>
        ))}
      </Space>
      <Button type="dashed" style={{ marginTop: 12 }} onClick={addRule}>+ 添加规则</Button>

      <Divider />
      <Alert
        type="info"
        showIcon
        message={`本次将向节点 ${targetNode ? targetNode.slice(0, 12) + '…' : '（未选）'} 下发 ${rules.length} 条规则`}
        style={{ marginBottom: 16 }}
      />
      <Button type="primary" loading={submitting} onClick={submit}>正式下发</Button>
    </div>
  );

  function updateRule(key: string, field: string, value: any) {
    setRules((r) => r.map((x) => (x.key === key ? { ...x, [field]: value } : x)));
  }
}

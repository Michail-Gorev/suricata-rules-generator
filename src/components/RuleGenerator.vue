<template>
  <div class="p-8">
    <h1 class="text-2xl font-bold mb-6">Генератор правил Suricata</h1>

    <!-- Секция определения переменных -->
    <div class="mb-8 p-4 border rounded-lg bg-gray-50">
      <h2 class="text-xl font-bold mb-4">Определение переменных</h2>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <!-- Адресные группы -->
        <div>
          <h3 class="text-lg font-semibold mb-3 flex justify-between items-center">
            <span>Адресные группы</span>
            <button @click="addAddressGroup" class="bg-green-500 text-white px-3 py-1 rounded text-sm">+ Добавить</button>
          </h3>
          <div v-for="(group, index) in addressGroups" :key="'addr-'+index" class="mb-3 p-3 border rounded bg-white">
            <div class="flex mb-2">
              <input v-model="group.name" placeholder="Имя группы" class="flex-1 p-2 border rounded mr-2" @input="validateGroupName($event, index, 'address')">
              <button @click="removeGroup(index, 'address')" class="bg-red-500 text-white px-3 rounded">×</button>
            </div>
            <textarea v-model="group.value" placeholder="IP-адреса или CIDR (через запятую)" class="w-full p-2 border rounded" rows="2"></textarea>
            <div class="mt-1 text-sm text-gray-600">Пример: 192.168.1.0/24, 10.0.0.0/8, !192.168.1.100</div>
          </div>
        </div>

        <!-- Портовые группы -->
        <div>
          <h3 class="text-lg font-semibold mb-3 flex justify-between items-center">
            <span>Портовые группы</span>
            <button @click="addPortGroup" class="bg-green-500 text-white px-3 py-1 rounded text-sm">+ Добавить</button>
          </h3>
          <div v-for="(group, index) in portGroups" :key="'port-'+index" class="mb-3 p-3 border rounded bg-white">
            <div class="flex mb-2">
              <input v-model="group.name" placeholder="Имя группы" class="flex-1 p-2 border rounded mr-2" @input="validateGroupName($event, index, 'port')">
              <button @click="removeGroup(index, 'port')" class="bg-red-500 text-white px-3 rounded">×</button>
            </div>
            <textarea v-model="group.value" placeholder="Номера портов (через запятую)" class="w-full p-2 border rounded" rows="2"></textarea>
            <div class="mt-1 text-sm text-gray-600">Пример: 80, 443, 8080, !8081, 9000-9999</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Секция определения правил -->
    <div class="mb-8 p-4 border rounded-lg bg-gray-50">
      <h2 class="text-xl font-bold mb-4">Определение правил</h2>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <!-- Основные параметры -->
        <div>
          <h3 class="text-lg font-semibold mb-3">Основные параметры</h3>
          <div class="space-y-4">
            <div>
              <label class="block text-sm font-medium mb-1">Действие</label>
              <select v-model="rule.action" class="w-full p-2 border rounded bg-white">
                <option value="alert">alert (предупреждение)</option>
                <option value="drop">drop (отбросить)</option>
                <option value="pass">pass (пропустить)</option>
                <option value="reject">reject (отклонить)</option>
              </select>
            </div>

            <div>
              <label class="block text-sm font-medium mb-1">Протокол</label>
              <select v-model="rule.proto" class="w-full p-2 border rounded bg-white">
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="icmp">ICMP</option>
                <option value="http">HTTP</option>
                <option value="dns">DNS</option>
              </select>
            </div>

            <div>
              <label class="block text-sm font-medium mb-1">ID правила (sid)</label>
              <input v-model="rule.sid" type="number" class="w-full p-2 border rounded bg-white" placeholder="Уникальный ID">
            </div>

            <div>
              <label class="block text-sm font-medium mb-1">Версия (rev)</label>
              <input v-model="rule.rev" type="number" class="w-full p-2 border rounded bg-white" placeholder="Номер версии">
            </div>

            <div>
              <label class="block text-sm font-medium mb-1">Сообщение</label>
              <input v-model="rule.msg" class="w-full p-2 border rounded bg-white" placeholder="Описание правила">
            </div>
          </div>
        </div>

        <!-- Источник и назначение -->
        <div>
          <h3 class="text-lg font-semibold mb-3">Источник и назначение</h3>
          <div class="space-y-4">
            <div>
              <label class="block text-sm font-medium mb-1">Источник (IP)</label>
              <select v-model="rule.src_ip" class="w-full p-2 border rounded bg-white">
                <option value="any">любой</option>
                <option v-for="group in addressGroups" :value="group.name">{{ group.name }}</option>
                <option value="custom">-- указать вручную --</option>
              </select>
              <input v-if="rule.src_ip === 'custom'" v-model="rule.custom_src_ip" class="w-full mt-2 p-2 border rounded bg-white" placeholder="IP/CIDR источника">
            </div>

            <div>
              <label class="block text-sm font-medium mb-1">Порт источника</label>
              <select v-model="rule.src_port" class="w-full p-2 border rounded bg-white">
                <option value="any">любой</option>
                <option v-for="group in portGroups" :value="group.name">{{ group.name }}</option>
                <option value="custom">-- указать вручную --</option>
              </select>
              <input v-if="rule.src_port === 'custom'" v-model="rule.custom_src_port" class="w-full mt-2 p-2 border rounded bg-white" placeholder="Порт источника">
            </div>

            <div>
              <label class="block text-sm font-medium mb-1">Назначение (IP)</label>
              <select v-model="rule.dest_ip" class="w-full p-2 border rounded bg-white">
                <option value="any">любой</option>
                <option v-for="group in addressGroups" :value="group.name">{{ group.name }}</option>
                <option value="custom">-- указать вручную --</option>
              </select>
              <input v-if="rule.dest_ip === 'custom'" v-model="rule.custom_dest_ip" class="w-full mt-2 p-2 border rounded bg-white" placeholder="IP/CIDR назначения">
            </div>

            <div>
              <label class="block text-sm font-medium mb-1">Порт назначения</label>
              <select v-model="rule.dest_port" class="w-full p-2 border rounded bg-white">
                <option value="any">любой</option>
                <option v-for="group in portGroups" :value="group.name">{{ group.name }}</option>
                <option value="custom">-- указать вручную --</option>
              </select>
              <input v-if="rule.dest_port === 'custom'" v-model="rule.custom_dest_port" class="w-full mt-2 p-2 border rounded bg-white" placeholder="Порт назначения">
            </div>
          </div>
        </div>
      </div>

      <!-- Параметры содержимого -->
      <div class="mt-6">
        <h3 class="text-lg font-semibold mb-3">Параметры содержимого</h3>

        <div class="mb-4">
          <div class="flex items-center mb-2">
            <input v-model="rule.content" class="flex-1 p-2 border rounded bg-white" placeholder="Содержимое для поиска">
            <button @click="addContent" class="ml-2 bg-blue-500 text-white px-4 py-2 rounded">Добавить</button>
          </div>
          <div v-for="(content, index) in rule.contents" :key="index" class="flex items-center mb-2 p-2 bg-white border rounded">
            <span class="flex-1">content:"{{ content.pattern }}";</span>
            <div class="flex space-x-2">
              <select v-model="content.modifiers" multiple class="p-1 border rounded text-sm" style="height: auto">
                <option value="nocase">nocase</option>
                <option value="http_uri">http_uri</option>
                <option value="http_header">http_header</option>
                <option value="fast_pattern">fast_pattern</option>
              </select>
              <button @click="removeContent(index)" class="bg-red-500 text-white px-2 rounded">×</button>
            </div>
          </div>
        </div>

        <!-- Дополнительные параметры -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <label class="block text-sm font-medium mb-1">Класс типа</label>
            <input v-model="rule.class_type" class="w-full p-2 border rounded bg-white" placeholder="например, trojan-activity">
          </div>
          <div>
            <label class="block text-sm font-medium mb-1">Приоритет</label>
            <input v-model="rule.priority" type="number" class="w-full p-2 border rounded bg-white" placeholder="1-255">
          </div>
          <div>
            <label class="block text-sm font-medium mb-1">Метанданные</label>
            <input v-model="rule.metadata" class="w-full p-2 border rounded bg-white" placeholder="ключ значение">
          </div>
          <div>
            <label class="block text-sm font-medium mb-1">Ссылка</label>
            <input v-model="rule.reference" class="w-full p-2 border rounded bg-white" placeholder="URL ссылки">
          </div>
        </div>
      </div>

      <button @click="generateRule" class="mt-6 w-full bg-green-600 hover:bg-green-700 text-white py-3 px-4 rounded-lg font-medium">
        Сгенерировать правило
      </button>
    </div>

    <!-- Результат -->
    <div class="p-4 border rounded-lg bg-gray-50">
      <h2 class="text-xl font-bold mb-4">Результат</h2>

      <div class="mb-6">
        <div class="flex justify-between items-center mb-2">
          <h3 class="text-lg font-semibold">YAML конфигурация</h3>
          <button @click="copyYaml" class="bg-blue-500 hover:bg-blue-600 text-white px-3 py-1 rounded text-sm">
            Копировать YAML
          </button>
        </div>
        <pre class="bg-white p-4 rounded border overflow-x-auto text-sm">{{ yamlOutput }}</pre>
      </div>

      <div>
        <div class="flex justify-between items-center mb-2">
          <h3 class="text-lg font-semibold">Правило Suricata</h3>
          <div class="space-x-2">
            <button @click="copyRule" class="bg-blue-500 hover:bg-blue-600 text-white px-3 py-1 rounded text-sm">
              Копировать правило
            </button>
            <button @click="exportAll" class="bg-green-600 hover:bg-green-700 text-white px-3 py-1 rounded text-sm">
              Экспортировать всё
            </button>
          </div>
        </div>
        <pre class="bg-white p-4 rounded border overflow-x-auto text-sm">{{ ruleOutput }}</pre>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  data() {
    return {
      addressGroups: [
        { name: 'HOME_NET', value: '192.168.0.0/16, 10.0.0.0/8' },
        { name: 'EXTERNAL_NET', value: 'any' }
      ],
      portGroups: [
        { name: 'HTTP_PORTS', value: '80, 443, 8080, 8443' },
        { name: 'SHELL_PORTS', value: '22, 23, 3389' }
      ],
      rule: {
        action: 'alert',
        proto: 'tcp',
        src_ip: '$HOME_NET',
        src_port: 'any',
        direction: '->',
        dest_ip: '$EXTERNAL_NET',
        dest_port: '$HTTP_PORTS',
        msg: '',
        sid: this.generateSid(),
        rev: 1,
        content: '',
        contents: [],
        class_type: '',
        priority: '',
        metadata: '',
        reference: '',
        custom_src_ip: '',
        custom_src_port: '',
        custom_dest_ip: '',
        custom_dest_port: ''
      },
      yamlOutput: '',
      ruleOutput: ''
    }
  },
  methods: {
    addAddressGroup() {
      this.addressGroups.push({ name: '', value: '' });
    },
    addPortGroup() {
      this.portGroups.push({ name: '', value: '' });
    },
    removeGroup(index, type) {
      if (type === 'address') {
        this.addressGroups.splice(index, 1);
      } else {
        this.portGroups.splice(index, 1);
      }
    },
    validateGroupName(event, index, type) {
      // Убрана проверка на $ в начале имени
      const value = event.target.value;
      if (type === 'address') {
        this.addressGroups[index].name = value;
      } else {
        this.portGroups[index].name = value;
      }
    },
    addContent() {
      if (this.rule.content) {
        this.rule.contents.push({
          pattern: this.rule.content,
          modifiers: ['nocase']
        });
        this.rule.content = '';
      }
    },
    removeContent(index) {
      this.rule.contents.splice(index, 1);
    },
    generateSid() {
      return Math.floor(1000000 + Math.random() * 9000000);
    },
    generateRule() {
      // Генерация YAML
      const yamlVars = {
        'address-groups': {},
        'port-groups': {}
      };

      this.addressGroups.forEach(group => {
        yamlVars['address-groups'][group.name] = group.value.split(',').map(item => item.trim());
      });

      this.portGroups.forEach(group => {
        yamlVars['port-groups'][group.name] = group.value.split(',').map(item => item.trim());
      });

      // Получаем значения IP и портов (добавляем $ при использовании)
      const srcIp = this.rule.src_ip === 'custom'
        ? this.rule.custom_src_ip
        : (this.rule.src_ip !== 'any' ? `${this.rule.src_ip}` : 'any');

      const srcPort = this.rule.src_port === 'custom'
        ? this.rule.custom_src_port
        : (this.rule.src_port !== 'any' ? `${this.rule.src_port}` : 'any');

      const destIp = this.rule.dest_ip === 'custom'
        ? this.rule.custom_dest_ip
        : (this.rule.dest_ip !== 'any' ? `${this.rule.dest_ip}` : 'any');

      const destPort = this.rule.dest_port === 'custom'
        ? this.rule.custom_dest_port
        : (this.rule.dest_port !== 'any' ? `${this.rule.dest_port}` : 'any');

      // Формируем YAML
      this.yamlOutput = `%YAML 1.1
---
vars:
  address-groups:
${Object.entries(yamlVars['address-groups']).map(([name, values]) => `    ${name}: [${values.join(', ')}]`).join('\n')}
  port-groups:
${Object.entries(yamlVars['port-groups']).map(([name, values]) => `    ${name}: [${values.join(', ')}]`).join('\n')}

rules:
  - rule:
      action: ${this.rule.action}
      protocol: ${this.rule.proto}
      src_ip: ${srcIp}
      src_port: ${srcPort}
      direction: "${this.rule.direction}"
      dest_ip: ${destIp}
      dest_port: ${destPort}
      msg: "${this.rule.msg || ''}"
      sid: ${this.rule.sid}
      rev: ${this.rule.rev}
      contents:
      ${this.rule.contents.map(c => `        - pattern: "${c.pattern}"\n          modifiers: [${c.modifiers.join(', ')}]`).join('\n')}
      metadata: "${this.rule.metadata || ''}"
      classtype: "${this.rule.class_type || ''}"
      priority: ${this.rule.priority || 'null'}
      reference: "${this.rule.reference || ''}"`;

      // Генерация правила в строковом формате (с $ для переменных)
      let ruleParts = [
        this.rule.action,
        this.rule.proto,
        srcIp,
        srcPort,
        this.rule.direction,
        destIp,
        destPort
      ];

      let ruleOptions = [];
      if (this.rule.msg) {
        ruleOptions.push(`msg:"${this.rule.msg}"`);
      }

      if (this.rule.class_type) {
        ruleOptions.push(`classtype:${this.rule.class_type}`);
      }

      if (this.rule.priority) {
        ruleOptions.push(`priority:${this.rule.priority}`);
      }

      if (this.rule.reference) {
        ruleOptions.push(`reference:${this.rule.reference}`);
      }

      if (this.rule.metadata) {
        ruleOptions.push(`metadata:${this.rule.metadata}`);
      }

      this.rule.contents.forEach(content => {
        let contentPart = `content:"${content.pattern}"`;
        if (content.modifiers && content.modifiers.length > 0) {
          contentPart += `; ${content.modifiers.join('; ')}`;
        }
        ruleOptions.push(contentPart);
      });

      ruleOptions.push(`sid:${this.rule.sid}; rev:${this.rule.rev}`);

      this.ruleOutput = `${ruleParts.join(' ')} (${ruleOptions.join('; ')})`;
    },
    copyYaml() {
      navigator.clipboard.writeText(this.yamlOutput);
      alert('YAML конфигурация скопирована в буфер обмена!');
    },
    copyRule() {
      navigator.clipboard.writeText(this.ruleOutput);
      alert('Правило скопировано в буфер обмена!');
    },
    exportAll() {
      const content = `${this.yamlOutput}\n\n# Правила\n${this.ruleOutput}`;
      const blob = new Blob([content], { type: 'text/yaml' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'suricata_rules.yaml';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    }
  },
  mounted() {
    this.generateRule();
  }
}
</script>

<style>
/* Стили для мультиселекта */
select[multiple] {
  min-height: 38px;
  background-image: none;
  padding-right: 8px;
}
select[multiple] option {
  padding: 4px 8px;
}
</style>
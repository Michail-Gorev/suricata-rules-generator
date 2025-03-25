<template>
  <div class="p-8">
    <h1 class="text-2xl font-bold mb-4">Advanced Suricata Rule Generator</h1>

    <!-- Network Devices Section -->
    <div class="mb-8">
      <h2 class="text-xl font-bold mb-4">Network Devices</h2>
      <div v-for="(device, index) in networkDevices" :key="index" class="mb-4">
        <input v-model="device.name" type="text" placeholder="Device Name" class="p-2 border border-gray-300 rounded-md mr-2">
        <input v-model="device.ip" type="text" placeholder="IP Address" class="p-2 border border-gray-300 rounded-md">
        <button @click="removeDevice(index)" class="ml-2 bg-red-500 text-white p-2 rounded-md">Remove</button>
      </div>
      <button @click="addDevice" class="bg-blue-500 text-white p-2 rounded-md">Add Device</button>
    </div>

    <!-- Address Groups Section -->
    <div class="mb-8">
      <h2 class="text-xl font-bold mb-4">Address Groups</h2>
      <div v-for="(group, index) in addressGroups" :key="index" class="mb-4">
        <input v-model="group.name" type="text" placeholder="Group Name" class="p-2 border border-gray-300 rounded-md mr-2">
        <input v-model="group.addresses" type="text" placeholder="Addresses (comma separated)" class="p-2 border border-gray-300 rounded-md">
        <button @click="removeAddressGroup(index)" class="ml-2 bg-red-500 text-white p-2 rounded-md">Remove</button>
      </div>
      <button @click="addAddressGroup" class="bg-blue-500 text-white p-2 rounded-md">Add Address Group</button>
    </div>

    <!-- Port Groups Section -->
    <div class="mb-8">
      <h2 class="text-xl font-bold mb-4">Port Groups</h2>
      <div v-for="(group, index) in portGroups" :key="index" class="mb-4">
        <input v-model="group.name" type="text" placeholder="Group Name" class="p-2 border border-gray-300 rounded-md mr-2">
        <input v-model="group.ports" type="text" placeholder="Ports (comma separated)" class="p-2 border border-gray-300 rounded-md">
        <button @click="removePortGroup(index)" class="ml-2 bg-red-500 text-white p-2 rounded-md">Remove</button>
      </div>
      <button @click="addPortGroup" class="bg-blue-500 text-white p-2 rounded-md">Add Port Group</button>
    </div>

    <!-- Rule Configuration Section -->
    <div class="mb-8">
      <h2 class="text-xl font-bold mb-4">Rule Configuration</h2>
      <div class="mb-4">
        <label class="block text-sm font-medium text-gray-700">Source</label>
        <select v-model="rule.source" class="mt-1 block w-full p-2 border border-gray-300 rounded-md">
          <option v-for="device in networkDevices" :value="device.ip">{{ device.name }} ({{ device.ip }})</option>
          <option v-for="group in addressGroups" :value="group.name">{{ group.name }} ({{ group.addresses }})</option>
        </select>
      </div>
      <div class="mb-4">
        <label class="block text-sm font-medium text-gray-700">Destination</label>
        <select v-model="rule.destination" class="mt-1 block w-full p-2 border border-gray-300 rounded-md">
          <option v-for="device in networkDevices" :value="device.ip">{{ device.name }} ({{ device.ip }})</option>
          <option v-for="group in addressGroups" :value="group.name">{{ group.name }} ({{ group.addresses }})</option>
        </select>
      </div>
      <div class="mb-4">
        <label class="block text-sm font-medium text-gray-700">Protocol</label>
        <select v-model="rule.protocol" class="mt-1 block w-full p-2 border border-gray-300 rounded-md">
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
          <option value="icmp">ICMP</option>
          <option value="http">HTTP</option>
          <option value="ftp">FTP</option>
        </select>
      </div>
      <div class="mb-4">
        <label class="block text-sm font-medium text-gray-700">Source Port</label>
        <select v-model="rule.srcPort" class="mt-1 block w-full p-2 border border-gray-300 rounded-md">
          <option v-for="group in portGroups" :value="group.name">{{ group.name }} ({{ group.ports }})</option>
        </select>
      </div>
      <div class="mb-4">
        <label class="block text-sm font-medium text-gray-700">Destination Port</label>
        <select v-model="rule.destPort" class="mt-1 block w-full p-2 border border-gray-300 rounded-md">
          <option v-for="group in portGroups" :value="group.name">{{ group.name }} ({{ group.ports }})</option>
        </select>
      </div>
      <div class="mb-4">
        <label class="block text-sm font-medium text-gray-700">Action</label>
        <select v-model="rule.action" class="mt-1 block w-full p-2 border border-gray-300 rounded-md">
          <option value="drop">Drop</option>
          <option value="pass">Pass</option>
          <option value="reject">Reject</option>
          <option value="alert">Alert</option>
        </select>
      </div>
      <div class="mb-4">
        <label class="block text-sm font-medium text-gray-700">Filter Condition</label>
        <input v-model="rule.filterCondition" type="text" class="mt-1 block w-full p-2 border border-gray-300 rounded-md" placeholder="e.g., 'password'">
      </div>
      <button @click="generateRule" class="bg-blue-500 text-white p-2 rounded-md">Generate Rule</button>
    </div>

    <!-- Generated Rules Section -->
    <div class="mt-8">
      <h2 class="text-xl font-bold mb-2">Generated Rules</h2>
      <div class="mb-4">
        <h3 class="text-lg font-bold mb-2">YAML Rule</h3>
        <pre class="bg-gray-100 p-4 rounded-md">{{ yamlRule }}</pre>
      </div>
      <div class="mb-4">
        <h3 class="text-lg font-bold mb-2">Text Rule</h3>
        <pre class="bg-gray-100 p-4 rounded-md">{{ textRule }}</pre>
      </div>
      <button @click="exportYaml" class="mt-4 bg-green-500 text-white p-2 rounded-md">Export YAML</button>
    </div>
  </div>
</template>

<script>
export default {
  data() {
    return {
      networkDevices: JSON.parse(localStorage.getItem('networkDevices')) || [
        { name: 'Switch1', ip: '192.168.1.1' },
        { name: 'Router1', ip: '192.168.1.254' }
      ],
      addressGroups: JSON.parse(localStorage.getItem('addressGroups')) || [
        { name: 'HOME_NET', addresses: '192.168.1.0/24' }
      ],
      portGroups: JSON.parse(localStorage.getItem('portGroups')) || [
        { name: 'HTTP_PORTS', ports: '80, 8080' }
      ],
      rule: {
        source: '',
        destination: '',
        protocol: 'tcp',
        srcPort: '',
        destPort: '',
        action: 'drop',
        filterCondition: ''
      },
      yamlRule: '',
      textRule: ''
    };
  },
  methods: {
    addDevice() {
      this.networkDevices.push({ name: '', ip: '' });
      this.saveData();
    },
    removeDevice(index) {
      this.networkDevices.splice(index, 1);
      this.saveData();
    },
    addAddressGroup() {
      this.addressGroups.push({ name: '', addresses: '' });
      this.saveData();
    },
    removeAddressGroup(index) {
      this.addressGroups.splice(index, 1);
      this.saveData();
    },
    addPortGroup() {
      this.portGroups.push({ name: '', ports: '' });
      this.saveData();
    },
    removePortGroup(index) {
      this.portGroups.splice(index, 1);
      this.saveData();
    },
    saveData() {
      localStorage.setItem('networkDevices', JSON.stringify(this.networkDevices));
      localStorage.setItem('addressGroups', JSON.stringify(this.addressGroups));
      localStorage.setItem('portGroups', JSON.stringify(this.portGroups));
    },
    generateRule() {
      // Генерация YAML-правила
      const yamlTemplate = `- action: ${this.rule.action}
  src_ip: ${this.rule.source}
  dest_ip: ${this.rule.destination}
  protocol: ${this.rule.protocol}
  src_port: ${this.rule.srcPort}
  dest_port: ${this.rule.destPort}
  content: "${this.rule.filterCondition}"
  nocase: true`;

      this.yamlRule = yamlTemplate;

      // Генерация текстового правила
      const textTemplate = `${this.rule.action} ${this.rule.protocol} ${this.rule.source}:${this.rule.srcPort} -> ${this.rule.destination}:${this.rule.destPort} (${this.rule.filterCondition})`;
      this.textRule = textTemplate;
    },
    exportYaml() {
      // Создание YAML-файла с сетевыми переменными
      const addressGroupsYaml = this.addressGroups.map(group => `  ${group.name}: [${group.addresses}]`).join('\n');
      const portGroupsYaml = this.portGroups.map(group => `  ${group.name}: [${group.ports}]`).join('\n');

      const yamlContent = `vars:
      address-groups:
      ${addressGroupsYaml}
      port-groups:
      ${portGroupsYaml}

${this.yamlRule}`;

      const blob = new Blob([yamlContent], { type: 'text/yaml' });
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = 'suricata_rules.yaml';
      link.click();
    }
  }
};
</script>

<style scoped>
/* Стили для компонента */
</style>
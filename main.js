/**
 * MONITOR DE TRÁFEGO DE REDE - TRABALHO FINAL
 * * Funcionalidades:
 * 1. Captura via Raw Sockets (lib 'cap').
 * 2. Parsing manual de cabeçalhos (Ethernet, IPv4/IPv6, TCP/UDP, App).
 * 3. Logs em CSV separados por camada.
 * 4. Dashboard em tempo real com estatísticas por cliente do túnel.
 */

const Cap = require('cap').Cap;
const Decoders = require('cap').Decoders;
const { createObjectCsvWriter } = require('csv-writer');
const ipUtils = require('ip');

// --- 1. CONFIGURAÇÕES GERAIS ---
const INTERFACE = 'tun0'; // Interface do túnel (conforme PDF)
const BUFFER_SIZE = 10 * 1024 * 1024;
const TUNNEL_SUBNET_PREFIX = '172.31.66.'; // Prefixo dos clientes no túnel

// --- 2. CONFIGURAÇÃO DOS ARQUIVOS DE LOG (CSV) ---

// Log Camada Internet (IPv4, IPv6, ICMP) [Fonte: 25]
const logInternet = createObjectCsvWriter({
    path: 'camada_internet.csv',
    header: [
        { id: 'data', title: 'Data_Hora' },
        { id: 'proto', title: 'Protocolo' },
        { id: 'src', title: 'IP_Origem' },
        { id: 'dst', title: 'IP_Destino' },
        { id: 'id_proto', title: 'ID_Proto_Carga' },
        { id: 'info', title: 'Info_Extra' },
        { id: 'len', title: 'Tamanho_Bytes' }
    ],
    append: true
});

// Log Camada Transporte (TCP, UDP) [Fonte: 32]
const logTransporte = createObjectCsvWriter({
    path: 'camada_transporte.csv',
    header: [
        { id: 'data', title: 'Data_Hora' },
        { id: 'proto', title: 'Protocolo' },
        { id: 'src_ip', title: 'IP_Origem' },
        { id: 'src_port', title: 'Porta_Origem' },
        { id: 'dst_ip', title: 'IP_Destino' },
        { id: 'dst_port', title: 'Porta_Destino' },
        { id: 'len', title: 'Tamanho_Bytes' }
    ],
    append: true
});

// Log Camada Aplicação (HTTP, DNS, DHCP, NTP) [Fonte: 42]
const logAplicacao = createObjectCsvWriter({
    path: 'camada_aplicacao.csv',
    header: [
        { id: 'data', title: 'Data_Hora' },
        { id: 'proto', title: 'Protocolo' },
        { id: 'info', title: 'Conteudo_Info' },
        { id: 'len', title: 'Tamanho_Bytes' }
    ],
    append: true
});

// --- 3. ESTRUTURAS DE DADOS PARA O DASHBOARD ---
const globalStats = {
    TotalPacotes: 0,
    IPv4: 0,
    IPv6: 0,
    TCP: 0,
    UDP: 0,
    ICMP: 0,
    BytesTotais: 0
};

// Armazena estatísticas por cliente (IP do túnel)
const clientStats = {};

// --- 4. INICIALIZAÇÃO DA CAPTURA ---
const cap = new Cap();
const device = Cap.findDevice(INTERFACE);
const filter = ''; // Captura tudo
const bufSize = 10 * 1024 * 1024;
const buffer = Buffer.alloc(65535);

if (!device) {
    console.error(`ERRO: Interface '${INTERFACE}' não encontrada.`);
    console.error(`Certifique-se de que o programa túnel está rodando e criou a interface.`);
    console.error(`Dica: Rode 'ip addr' para listar as interfaces.`);
    process.exit(1);
}

try {
    const linkType = cap.open(device, filter, bufSize, buffer);
    cap.setMinBytes && cap.setMinBytes(0);
    console.log(`MONITOR INICIADO NA INTERFACE: ${device}`);
    console.log(`Tipo de Link: ${linkType}`);
} catch (e) {
    console.error(`ERRO ao abrir raw socket: ${e.message}`);
    console.error(`Você rodou com 'sudo'?`);
    process.exit(1);
}

// --- 5. LOOP PRINCIPAL DE PROCESSAMENTO DE PACOTES ---
cap.on('packet', (nBytes, trunc) => {
    globalStats.TotalPacotes++;
    globalStats.BytesTotais += nBytes;
    const timestamp = new Date().toISOString();

    // Determina offset inicial (pular header Ethernet se existir)
    let offset = 0;
    if (cap.linkType === 'ETHERNET') {
        offset = 14;
    } else if (cap.linkType === 'NULL' || cap.linkType === 'LOOP') {
        offset = 4; // Interfaces tun por vezes tem header de 4 bytes
    }

    // Verifica se o offset não estourou o buffer
    if (offset >= nBytes) return;

    // Leitura do primeiro byte para determinar versão IP (IPv4 ou IPv6)
    const version = (buffer[offset] & 0xf0) >> 4;

    if (version === 4) {
        parseIPv4(buffer, offset, nBytes, timestamp);
    } else if (version === 6) {
        parseIPv6(buffer, offset, nBytes, timestamp);
    }

    // Atualiza a tela a cada 5 pacotes para não piscar demais
    if (globalStats.TotalPacotes % 5 === 0) {
        updateDashboard();
    }
});

// --- 6. FUNÇÕES DE PARSING (CAMADA DE REDE) ---

function parseIPv4(buf, offset, totalLen, timestamp) {
    globalStats.IPv4++;
    
    // Cabeçalho IPv4
    const ihl = (buf[offset] & 0x0f) * 4; // Internet Header Length
    const protocolId = buf[offset + 9];
    const srcIp = ipUtils.toString(buf.slice(offset + 12, offset + 16));
    const dstIp = ipUtils.toString(buf.slice(offset + 16, offset + 20));

    let protocolName = 'Outro';
    let infoExtra = '-';

    if (protocolId === 1) {
        protocolName = 'ICMP';
        globalStats.ICMP++;
        const type = buf[offset + ihl];
        const code = buf[offset + ihl + 1];
        infoExtra = `Type:${type} Code:${code}`;
    } else if (protocolId === 6) protocolName = 'TCP';
    else if (protocolId === 17) protocolName = 'UDP';

    // Log CSV Internet
    logInternet.writeRecords([{
        data: timestamp, proto: 'IPv4', src: srcIp, dst: dstIp,
        id_proto: protocolId, info: infoExtra, len: totalLen
    }]);

    // Passa para Camada de Transporte se for TCP ou UDP
    if (protocolName === 'TCP' || protocolName === 'UDP') {
        parseTransport(buf, offset + ihl, protocolName, srcIp, dstIp, totalLen, timestamp);
    }
}

function parseIPv6(buf, offset, totalLen, timestamp) {
    globalStats.IPv6++;

    // Cabeçalho IPv6 (fixo 40 bytes)
    const nextHeader = buf[offset + 6];
    const hopLimit = buf[offset + 7];
    const srcIp = ipUtils.toString(buf.slice(offset + 8, offset + 24));
    const dstIp = ipUtils.toString(buf.slice(offset + 24, offset + 40));

    let protocolName = 'Outro';
    let infoExtra = `HopLimit: ${hopLimit}`;

    if (nextHeader === 58) {
        protocolName = 'ICMPv6';
        globalStats.ICMP++;
        // ICMPv6 header começa logo após os 40 bytes do IPv6
        const type = buf[offset + 40];
        infoExtra += ` ICMP Type:${type}`;
    } else if (nextHeader === 6) protocolName = 'TCP';
    else if (nextHeader === 17) protocolName = 'UDP';

    // Log CSV Internet
    logInternet.writeRecords([{
        data: timestamp, proto: 'IPv6', src: srcIp, dst: dstIp,
        id_proto: nextHeader, info: infoExtra, len: totalLen
    }]);

    if (protocolName === 'TCP' || protocolName === 'UDP') {
        parseTransport(buf, offset + 40, protocolName, srcIp, dstIp, totalLen, timestamp);
    }
}

// --- 7. FUNÇÃO DE PARSING (CAMADA DE TRANSPORTE) ---

function parseTransport(buf, offset, protoName, srcIp, dstIp, totalLen, timestamp) {
    if (offset + 4 > buf.length) return; // Segurança

    const srcPort = buf.readUInt16BE(offset);
    const dstPort = buf.readUInt16BE(offset + 2);

    if (protoName === 'TCP') globalStats.TCP++;
    if (protoName === 'UDP') globalStats.UDP++;

    // Atualiza Estatísticas por Cliente (Requisito do Dashboard)
    updateClientStats(srcIp, dstIp, totalLen, dstPort);

    // Log CSV Transporte
    logTransporte.writeRecords([{
        data: timestamp, proto: protoName,
        src_ip: srcIp, src_port: srcPort,
        dst_ip: dstIp, dst_port: dstPort,
        len: totalLen
    }]);

    // Passa para Camada de Aplicação
    parseApplication(buf, offset, protoName, srcPort, dstPort, totalLen, timestamp);
}

// --- 8. FUNÇÃO DE PARSING (CAMADA DE APLICAÇÃO) ---

function parseApplication(buf, offset, protoTransporte, srcPort, dstPort, totalLen, timestamp) {
    // Determina onde começa o Payload
    let headerLen = 0;
    if (protoTransporte === 'UDP') {
        headerLen = 8; // Fixo
    } else if (protoTransporte === 'TCP') {
        // Data Offset: 4 bits superiores do byte 12 (offset + 12)
        // Indica quantas palavras de 32 bits tem o header
        if (offset + 12 < buf.length) {
            const dataOffset = (buf[offset + 12] & 0xf0) >> 4;
            headerLen = dataOffset * 4;
        } else {
            return;
        }
    }

    const payloadOffset = offset + headerLen;
    if (payloadOffset >= buf.length) return; // Sem payload

    const payload = buf.slice(payloadOffset); // Buffer cru dos dados
    let appProto = null;
    let appInfo = '-';

    // Heurística baseada em portas
    if (srcPort === 53 || dstPort === 53) {
        appProto = 'DNS';
        // Tenta extrair texto legível para achar domínio
        appInfo = cleanString(payload);
    } 
    else if ([80, 8080].includes(srcPort) || [80, 8080].includes(dstPort)) {
        appProto = 'HTTP';
        const text = payload.toString('utf8');
        // Pega a primeira linha do request/response
        const firstLine = text.split('\r\n')[0];
        if (firstLine && firstLine.length < 100) appInfo = firstLine;
    }
    else if ([67, 68].includes(srcPort) || [67, 68].includes(dstPort)) {
        appProto = 'DHCP';
        appInfo = 'Transação DHCP';
    }
    else if (srcPort === 123 || dstPort === 123) {
        appProto = 'NTP';
        appInfo = 'Sync Tempo';
    }

    if (appProto) {
        logAplicacao.writeRecords([{
            data: timestamp,
            proto: appProto,
            info: appInfo.substring(0, 100), // Limita tamanho para não quebrar CSV
            len: totalLen
        }]);
    }
}

// --- 9. LÓGICA DE DASHBOARD (STATS POR CLIENTE) ---

function updateClientStats(srcIp, dstIp, bytes, port) {
    let clientIp = null;
    let remoteIp = null;

    // Verifica quem é o cliente (quem tem o IP 172.31.66.x)
    if (srcIp.startsWith(TUNNEL_SUBNET_PREFIX)) {
        clientIp = srcIp;
        remoteIp = dstIp;
    } else if (dstIp.startsWith(TUNNEL_SUBNET_PREFIX)) {
        clientIp = dstIp;
        remoteIp = srcIp;
    }

    if (clientIp) {
        if (!clientStats[clientIp]) {
            clientStats[clientIp] = { 
                bytes: 0, 
                pacotes: 0, 
                remotos: new Set(),
                ultimaAtividade: new Date()
            };
        }
        clientStats[clientIp].bytes += bytes;
        clientStats[clientIp].pacotes++;
        clientStats[clientIp].remotos.add(`${remoteIp}:${port}`);
        clientStats[clientIp].ultimaAtividade = new Date();
    }
}

function updateDashboard() {
    console.clear();
    console.log("============================================================");
    console.log(`   MONITOR DE TRÁFEGO EM TEMPO REAL (Interface: ${INTERFACE})`);
    console.log("============================================================");
    
    console.log("\n[ RESUMO GERAL ]");
    console.table({
        'Pacotes Totais': globalStats.TotalPacotes,
        'Bytes Totais': globalStats.BytesTotais,
        'IPv4': globalStats.IPv4,
        'IPv6': globalStats.IPv6,
        'TCP': globalStats.TCP,
        'UDP': globalStats.UDP,
        'ICMP': globalStats.ICMP
    });

    console.log("\n[ CLIENTES DO TÚNEL ]");
    // Transforma o objeto stats em array para tabela
    const tabelaClientes = Object.keys(clientStats).map(ip => {
        const dados = clientStats[ip];
        return {
            'IP Cliente': ip,
            'Pacotes': dados.pacotes,
            'Volume (KB)': (dados.bytes / 1024).toFixed(2),
            'Destinos Únicos': dados.remotos.size,
            'Última Ativ.': dados.ultimaAtividade.toLocaleTimeString()
        };
    });

    if (tabelaClientes.length > 0) {
        console.table(tabelaClientes);
    } else {
        console.log(" >> Nenhum tráfego de cliente detectado (172.31.66.x) ainda.");
    }

    console.log("\n------------------------------------------------------------");
    console.log("Logs sendo gravados em CSV: camada_internet, _transporte, _aplicacao");
    console.log("Pressione Ctrl+C para encerrar.");
}

// Helper para limpar strings binárias (para log de DNS/App)
function cleanString(buf) {
    // Substitui caracteres não imprimíveis por ponto
    return buf.toString('ascii').replace(/[^\x20-\x7E]/g, '.');
}
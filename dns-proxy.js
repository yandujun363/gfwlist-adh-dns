const dgram = require('dgram');
const dnsPacket = require('dns-packet');
const tls = require('tls');
const https = require('https');
const { Socket } = require('net');
const socket = dgram.createSocket('udp4');

// 配置选项
const config = {
    udpPort: 53,
    tcpPort: 53,
    cacheEnabled: true,
    cacheMaxSize: 1000,
    cacheDefaultTTL: 300, // 默认TTL（秒），当上游没有提供TTL时使用
    calibrationInterval: 5 * 60 * 1000, // 校准间隔（毫秒）
    statsInterval: 60 * 1000, // 统计信息打印间隔（毫秒）
    timeoutMultiplier: 2
};

// 上游DNS服务器列表及其动态超时信息
const upstreams = [
    { host: '1.1.1.1', port: 53, currentTimeout: 100, trusted: false, rttHistory: [], type: 'udp' },
    { host: '8.8.8.8', port: 53, currentTimeout: 100, trusted: false, rttHistory: [], type: 'udp' },
    { host: '101.101.101.101', port: 53, currentTimeout: 100, trusted: false, rttHistory: [], type: 'udp' },
];

// DoT/DoH 服务器列表
const dotServers = [
    { host: '1.1.1.1', port: 853, sni: '1dot1dot1dot1.cloudflare-dns.com', name: 'Cloudflare DoT' }
];

const dohServers = [
    { url: 'https://doh.umbrella.com/dns-query', name: 'Cisco Umbrella DoH' },
    { url: 'https://77.88.8.8/dns-query', name: 'Yandex DoH-1' },
    { url: 'https://77.88.8.1/dns-query', name: 'Yandex DoH-2' }
];

// 用于校准上游RTT的随机域名前缀
const RANDOM_DOMAIN_PREFIX = 'rnd-';
// 存储发出的探测请求
const calibrationRequests = new Map();
// 存储正常的客户端请求
const pendingRequests = new Map();

// DNS缓存
const dnsCache = new Map();
// 缓存清理定时器
let cacheCleanupInterval;

// TCP服务器支持
const tcpServer = require('net').createServer();
const TCP_TIMEOUT = 10000; // 10秒TCP超时

// 性能统计
const stats = {
    totalQueries: 0,
    successfulResponses: 0,
    failedResponses: 0,
    hijackDetections: 0,
    tcpQueries: 0,
    dotQueries: 0,
    dohQueries: 0,
    truncatedResponses: 0,
    cacheHits: 0,
    cacheMisses: 0,
    upstreamStats: {}
};

// 初始化上游统计
upstreams.forEach(upstream => {
    stats.upstreamStats[upstream.host] = {
        queries: 0,
        timeouts: 0,
        avgRtt: 0,
        lastRtt: 0,
        truncated: 0
    };
});

/**
 * 记录日志并添加时间戳
 */
function log(message, level = 'info') {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] ${message}`;

    if (level === 'error') {
        console.error(logMessage);
    } else if (level === 'warn') {
        console.warn(logMessage);
    } else {
        console.log(logMessage);
    }
}

/**
 * 生成缓存键
 */
function getCacheKey(query) {
    if (!query.questions || query.questions.length === 0) {
        return null;
    }

    const question = query.questions[0];
    return `${question.type}:${question.name}`.toLowerCase();
}

/**
 * 检查缓存中是否有响应
 */
function getFromCache(query) {
    if (!config.cacheEnabled) {
        return null;
    }

    const cacheKey = getCacheKey(query);
    if (!cacheKey) {
        return null;
    }

    const cached = dnsCache.get(cacheKey);
    if (!cached) {
        return null;
    }

    // 检查是否过期
    if (cached.expiresAt < Date.now()) {
        dnsCache.delete(cacheKey);
        return null;
    }

    // 返回缓存的响应，但更新ID以匹配查询
    const response = {
        ...cached.response,
        id: query.id
    };

    return dnsPacket.encode(response);
}

/**
 * 存储响应到缓存
 */
function setToCache(query, responseMsg) {
    if (!config.cacheEnabled) {
        return;
    }

    try {
        const response = dnsPacket.decode(responseMsg);
        const cacheKey = getCacheKey(query);

        if (!cacheKey || !response.answers || response.answers.length === 0) {
            return;
        }

        // 计算最小TTL（使用响应中的最小TTL）
        let minTTL = config.cacheDefaultTTL;
        for (const answer of response.answers) {
            if (answer.ttl && answer.ttl > 0) {
                minTTL = Math.min(minTTL, answer.ttl);
            }
        }

        // 如果缓存已满，清理一些条目
        if (dnsCache.size >= config.cacheMaxSize) {
            const keys = Array.from(dnsCache.keys());
            for (let i = 0; i < Math.floor(config.cacheMaxSize * 0.1); i++) {
                dnsCache.delete(keys[i]);
            }
        }

        dnsCache.set(cacheKey, {
            response: response,
            expiresAt: Date.now() + (minTTL * 1000)
        });

        log(`Cached response for ${cacheKey}, TTL: ${minTTL}s`);
    } catch (err) {
        log(`Error caching response: ${err.message}`, 'error');
    }
}

/**
 * 定期清理过期缓存
 */
function setupCacheCleanup() {
    if (cacheCleanupInterval) {
        clearInterval(cacheCleanupInterval);
    }

    cacheCleanupInterval = setInterval(() => {
        const now = Date.now();
        let cleaned = 0;

        for (const [key, value] of dnsCache.entries()) {
            if (value.expiresAt < now) {
                dnsCache.delete(key);
                cleaned++;
            }
        }

        if (cleaned > 0) {
            log(`Cleaned ${cleaned} expired cache entries`);
        }
    }, 60 * 1000); // 每分钟清理一次
}

/**
 * 计算移动平均RTT
 */
function calculateSmoothedRtt(upstream, newRtt) {
    upstream.rttHistory.push(newRtt);
    if (upstream.rttHistory.length > 10) {
        upstream.rttHistory.shift();
    }

    const total = upstream.rttHistory.reduce((sum, rtt, index) => {
        const weight = (index + 1) / upstream.rttHistory.length;
        return sum + (rtt * weight);
    }, 0);

    const weightSum = upstream.rttHistory.reduce((sum, _, index) => {
        return sum + ((index + 1) / upstream.rttHistory.length);
    }, 0);

    return total / weightSum;
}

/**
 * 使用DoT (DNS over TLS) 查询
 */
function queryWithDoT(queryMsg, queryId, question, callback) {
    const dotServer = dotServers[0]; // 使用第一个DoT服务器
    log(`Using DoT: ${dotServer.name} for query ID ${queryId} (${question})`);
    stats.dotQueries++;

    const options = {
        host: dotServer.host,
        port: dotServer.port,
        servername: dotServer.sni,
        rejectUnauthorized: true
    };

    const startTime = process.hrtime();
    const socket = tls.connect(options, () => {
        log(`DoT connection established to ${dotServer.host} for query ID ${queryId}`);

        // 发送DNS查询
        const lengthBuffer = Buffer.alloc(2);
        lengthBuffer.writeUInt16BE(queryMsg.length);
        socket.write(Buffer.concat([lengthBuffer, queryMsg]));
    });

    socket.setTimeout(TCP_TIMEOUT);

    let responseData = Buffer.alloc(0);
    socket.on('data', (data) => {
        responseData = Buffer.concat([responseData, data]);

        // 检查是否收到完整响应
        if (responseData.length >= 2) {
            const expectedLength = responseData.readUInt16BE(0);
            if (responseData.length >= expectedLength + 2) {
                const dnsResponse = responseData.slice(2, 2 + expectedLength);
                const endTime = process.hrtime(startTime);
                const duration = (endTime[0] * 1000) + (endTime[1] / 1000000);

                log(`DoT response received for query ID ${queryId} in ${duration.toFixed(2)}ms`);
                socket.end();
                callback(null, dnsResponse);
            }
        }
    });

    socket.on('error', (err) => {
        log(`DoT error for query ID ${queryId}: ${err.message}`, 'error');
        callback(err);
    });

    socket.on('timeout', () => {
        log(`DoT timeout for query ID ${queryId}`, 'warn');
        socket.destroy();
        callback(new Error('DoT timeout'));
    });
}

/**
 * 使用DoH (DNS over HTTPS) 查询
 */
function queryWithDoH(queryMsg, queryId, question, callback) {
    const dohServer = dohServers[0]; // 使用第一个DoH服务器
    log(`Using DoH: ${dohServer.name} for query ID ${queryId} (${question})`);
    stats.dohQueries++;

    const base64Query = queryMsg.toString('base64').replace(/=/g, '');
    const url = `${dohServer.url}?dns=${base64Query}`;

    const startTime = process.hrtime();
    const req = https.get(url, {
        headers: {
            'Accept': 'application/dns-message',
            'Content-Type': 'application/dns-message'
        },
        timeout: TCP_TIMEOUT
    }, (res) => {
        if (res.statusCode !== 200) {
            log(`DoH HTTP error: ${res.statusCode} for query ID ${queryId}`, 'error');
            callback(new Error(`HTTP ${res.statusCode}`));
            return;
        }

        let responseData = Buffer.alloc(0);
        res.on('data', (chunk) => {
            responseData = Buffer.concat([responseData, chunk]);
        });

        res.on('end', () => {
            const endTime = process.hrtime(startTime);
            const duration = (endTime[0] * 1000) + (endTime[1] / 1000000);

            log(`DoH response received for query ID ${queryId} in ${duration.toFixed(2)}ms`);
            callback(null, responseData);
        });
    });

    req.on('error', (err) => {
        log(`DoH error for query ID ${queryId}: ${err.message}`, 'error');
        callback(err);
    });

    req.on('timeout', () => {
        log(`DoH timeout for query ID ${queryId}`, 'warn');
        req.destroy();
        callback(new Error('DoH timeout'));
    });

    req.end();
}

/**
 * 处理TCP DNS查询
 */
function handleTcpQuery(socket) {
    socket.setTimeout(TCP_TIMEOUT);

    socket.on('data', (data) => {
        stats.tcpQueries++;

        // TCP DNS消息前面有2字节的长度字段
        if (data.length < 2) return;

        const length = data.readUInt16BE(0);
        if (data.length < length + 2) return;

        const dnsData = data.slice(2, 2 + length);
        let query;
        try {
            query = dnsPacket.decode(dnsData);
        } catch (err) {
            log(`Failed to decode TCP DNS packet: ${err.message}`, 'error');
            socket.end();
            return;
        }

        const queryId = query.id;
        const question = query.questions && query.questions[0] ? query.questions[0].name : 'unknown';

        log(`TCP Query ID ${queryId} from ${socket.remoteAddress}:${socket.remotePort} for ${question}`);

        // 检查客户端是否包含OPT记录
        const clientHasOpt = query.additionals && query.additionals.some(r => r.type === 'OPT');
        log(`TCP client query ID ${queryId} ${clientHasOpt ? 'has' : 'does not have'} OPT record`);

        // 检查缓存
        const cachedResponse = getFromCache(query);
        if (cachedResponse) {
            stats.cacheHits++;
            log(`Cache hit for TCP query ID ${queryId} (${question})`);

            const lengthBuffer = Buffer.alloc(2);
            lengthBuffer.writeUInt16BE(cachedResponse.length);
            socket.write(Buffer.concat([lengthBuffer, cachedResponse]));
            socket.end();
            return;
        }

        stats.cacheMisses++;

        // 确保TCP查询也包含OPT记录
        const queryMsgToSend = addOptRecordIfMissing(dnsData);

        // 直接使用DoT处理TCP查询（更可靠）
        queryWithDoT(queryMsgToSend, queryId, question, (err, response) => {
            if (err) {
                log(`TCP/DoT query failed for ID ${queryId}: ${err.message}`, 'error');
                const errorResponse = dnsPacket.encode({
                    type: 'response',
                    id: queryId,
                    flags: dnsPacket.AUTHORITATIVE_ANSWER | dnsPacket.RA | dnsPacket.SERVFAIL,
                    questions: query.questions,
                    answers: []
                });

                const lengthBuffer = Buffer.alloc(2);
                lengthBuffer.writeUInt16BE(errorResponse.length);
                socket.write(Buffer.concat([lengthBuffer, errorResponse]));
                socket.end();
                return;
            }

            // 缓存响应
            setToCache(query, response);

            // 发送响应
            const lengthBuffer = Buffer.alloc(2);
            lengthBuffer.writeUInt16BE(response.length);
            socket.write(Buffer.concat([lengthBuffer, response]));
            socket.end();
            stats.successfulResponses++;
        });
    });

    socket.on('error', (err) => {
        log(`TCP socket error: ${err.message}`, 'error');
    });

    socket.on('timeout', () => {
        log('TCP socket timeout', 'warn');
        socket.end();
    });
}

/**
 * 定期向上游发送探测请求，校准其RTT和超时时间
 */
function calibrateUpstreamTimeout(upstream) {
    const randomDomain = `${RANDOM_DOMAIN_PREFIX}${Math.random().toString(36).substring(2, 15)}.com`;
    const queryId = Math.floor(Math.random() * 65535);

    const queryBuffer = dnsPacket.encode({
        type: 'query',
        id: queryId,
        questions: [{ type: 'A', name: randomDomain }],
        additionals: [{
            type: 'OPT',
            name: '.',
            udpPayloadSize: 4096
        }]
    });

    const client = dgram.createSocket('udp4');
    const startTime = process.hrtime();

    calibrationRequests.set(randomDomain, {
        upstream,
        startTime,
        client,
        queryId
    });

    log(`Starting calibration for ${upstream.host} with query ID ${queryId} (domain: ${randomDomain})`);

    client.send(queryBuffer, 0, queryBuffer.length, upstream.port, upstream.host, (err) => {
        if (err) {
            log(`Error sending calibration to ${upstream.host}: ${err.message}`, 'error');
            client.close();
            calibrationRequests.delete(randomDomain);
        } else {
            log(`Calibration probe sent to ${upstream.host} for ${randomDomain}`);
        }
    });

    setTimeout(() => {
        if (calibrationRequests.has(randomDomain)) {
            log(`Calibration probe to ${upstream.host} for ${randomDomain} timed out`, 'warn');
            stats.upstreamStats[upstream.host].timeouts++;
            client.close();
            calibrationRequests.delete(randomDomain);
        }
    }, 2000);

    client.on('message', (msg) => {
        const endTime = process.hrtime(startTime);
        const rtt = (endTime[0] * 1000) + (endTime[1] / 1000000);

        log(`Calibration response from ${upstream.host} for ${randomDomain} - RTT: ${rtt.toFixed(2)}ms`);

        const smoothedRtt = calculateSmoothedRtt(upstream, rtt);
        upstream.currentTimeout = Math.max(50, (smoothedRtt * config.timeoutMultiplier));

        stats.upstreamStats[upstream.host].lastRtt = rtt;
        stats.upstreamStats[upstream.host].avgRtt = smoothedRtt;

        log(`${upstream.host} timeout updated to: ${upstream.currentTimeout}ms (smoothed RTT: ${smoothedRtt.toFixed(2)}ms)`);

        client.close();
        calibrationRequests.delete(randomDomain);
    });

    client.on('error', (err) => {
        log(`Socket error during calibration with ${upstream.host}: ${err.message}`, 'error');
        client.close();
        calibrationRequests.delete(randomDomain);
    });
}

// 启动TCP服务器
tcpServer.on('connection', handleTcpQuery);
tcpServer.on('error', (err) => {
    log(`TCP server error: ${err.message}`, 'error');
});
tcpServer.listen(config.tcpPort, () => {
    log(`TCP DNS server started on port ${config.tcpPort}`);
});

// 设置缓存清理
if (config.cacheEnabled) {
    setupCacheCleanup();
    log(`DNS caching enabled with max ${config.cacheMaxSize} entries`);
}

// 启动时及定期校准所有上游
log('Starting initial upstream calibration...');
upstreams.forEach(upstream => calibrateUpstreamTimeout(upstream));

setInterval(() => {
    log('Performing periodic upstream calibration...');
    upstreams.forEach(upstream => calibrateUpstreamTimeout(upstream));
}, config.calibrationInterval);

// 定期打印统计信息
setInterval(() => {
    log('=== DNS Proxy Statistics ===');
    log(`Total queries processed: ${stats.totalQueries}`);
    log(`Successful responses: ${stats.successfulResponses}`);
    log(`Failed responses: ${stats.failedResponses}`);
    log(`Hijack detections: ${stats.hijackDetections}`);
    log(`TCP queries: ${stats.tcpQueries}`);
    log(`DoT queries: ${stats.dotQueries}`);
    log(`DoH queries: ${stats.dohQueries}`);
    log(`Truncated responses: ${stats.truncatedResponses}`);
    log(`Cache hits: ${stats.cacheHits}`);
    log(`Cache misses: ${stats.cacheMisses}`);
    log(`Cache size: ${dnsCache.size}`);
    log(`Cache hit rate: ${stats.cacheHits + stats.cacheMisses > 0 ?
        ((stats.cacheHits / (stats.cacheHits + stats.cacheMisses)) * 100).toFixed(2) + '%' : 'N/A'}`);

    log('Upstream statistics:');
    for (const [host, upstreamStat] of Object.entries(stats.upstreamStats)) {
        log(`  ${host}: queries=${upstreamStat.queries}, timeouts=${upstreamStat.timeouts}, truncated=${upstreamStat.truncated}, avgRTT=${upstreamStat.avgRtt.toFixed(2)}ms`);
    }
    log('============================');
}, config.statsInterval);

/**
 * 为DNS查询添加OPT记录（如果不存在）
 */
function addOptRecordIfMissing(dnsMsgBuffer) {
    try {
        const query = dnsPacket.decode(dnsMsgBuffer);

        // 检查是否已有OPT记录
        const hasOpt = query.additionals &&
            query.additionals.some(r => r.type === 'OPT');

        // 如果已有OPT记录，直接返回原消息
        if (hasOpt) {
            return dnsMsgBuffer;
        }

        // 添加OPT记录
        query.additionals = query.additionals || [];
        query.additionals.push({
            type: 'OPT',
            name: '.',
            udpPayloadSize: 4096,
            extendedRcode: 0,
            version: 0,
            flags: 0
        });

        const enhancedMsg = dnsPacket.encode(query);
        log(`Added OPT record to query ID ${query.id}, new size: ${enhancedMsg.length} bytes`);
        return enhancedMsg;
    } catch (err) {
        log(`Failed to add OPT record: ${err.message}, using original message`, 'warn');
        return dnsMsgBuffer; // 解码失败，返回原消息
    }
}


// 处理UDP客户端请求
socket.on('message', (msg, rinfo) => {
    stats.totalQueries++;

    let query;
    try {
        query = dnsPacket.decode(msg);
    } catch (err) {
        log(`Failed to decode DNS packet from ${rinfo.address}:${rinfo.port}: ${err.message}`, 'error');
        return;
    }

    const queryId = query.id;
    const question = query.questions && query.questions[0] ? query.questions[0].name : 'unknown';

    log(`UDP Query ID ${queryId} from ${rinfo.address}:${rinfo.port} for ${question}`);

    // 检查客户端是否包含OPT记录
    const clientHasOpt = query.additionals && query.additionals.some(r => r.type === 'OPT');
    log(`Client query ID ${queryId} ${clientHasOpt ? 'has' : 'does not have'} OPT record`);

    // 忽略校准请求
    if (question.includes(RANDOM_DOMAIN_PREFIX)) {
        log(`Ignoring calibration request for ${question}`);
        return;
    }

    // 检查缓存
    const cachedResponse = getFromCache(query);
    if (cachedResponse) {
        stats.cacheHits++;
        log(`Cache hit for UDP query ID ${queryId} (${question})`);

        socket.send(cachedResponse, rinfo.port, rinfo.address, (err) => {
            if (err) {
                log(`Error sending cached response to client: ${err.message}`, 'error');
            } else {
                log(`Cached response for ID ${queryId} sent to client`);
            }
        });
        return;
    }

    stats.cacheMisses++;

    const requestRecord = {
        original: { msg, rinfo, query },
        responses: new Map(),
        answered: false,
        clients: [],
        startTime: process.hrtime(),
        useTcpFallback: false,
        clientHasOpt: clientHasOpt
    };
    pendingRequests.set(queryId, requestRecord);

    let maxWaitTime = 0;

    upstreams.forEach(upstream => {
        stats.upstreamStats[upstream.host].queries++;

        const client = dgram.createSocket('udp4');
        requestRecord.clients.push(client);

        const upstreamStartTime = process.hrtime();

        // 处理查询消息，确保有OPT记录
        const queryMsgToSend = addOptRecordIfMissing(msg);

        client.send(queryMsgToSend, 0, queryMsgToSend.length, upstream.port, upstream.host, (err) => {
            if (err) {
                log(`Error sending to ${upstream.host}: ${err.message}`, 'error');
                client.close();
            } else {
                const sendTime = process.hrtime(upstreamStartTime);
                const sendDuration = (sendTime[0] * 1000) + (sendTime[1] / 1000000);
                const msgSize = queryMsgToSend.length;
                const hasOpt = msgSize !== msg.length;
                log(`Query ID ${queryId} sent to ${upstream.host} in ${sendDuration.toFixed(2)}ms, size: ${msgSize} bytes ${hasOpt ? '(with added OPT)' : '(with existing OPT)'}`);
            }
        });

        client.on('message', (responseMsg) => {
            const record = pendingRequests.get(queryId);
            if (!record || record.answered || record.useTcpFallback) {
                client.close();
                return;
            }

            const receiveTime = process.hrtime(upstreamStartTime);
            const receiveDuration = (receiveTime[0] * 1000) + (receiveTime[1] / 1000000);

            let response;
            try {
                response = dnsPacket.decode(responseMsg);
            } catch (err) {
                log(`Failed to decode response from ${upstream.host} for ID ${queryId}: ${err.message}`, 'error');
                return;
            }

            // 检查是否被截断（大响应）
            const isTruncated = response.flags && response.flags.truncated;
            const hasOPTRecord = response.additionals && response.additionals.some(r => r.type === 'OPT');

            log(`Response from ${upstream.host} for ID ${queryId} received in ${receiveDuration.toFixed(2)}ms, truncated: ${isTruncated}, has OPT: ${hasOPTRecord}`);

            if (isTruncated) {
                stats.truncatedResponses++;
                stats.upstreamStats[upstream.host].truncated++;
                log(`Truncated response from ${upstream.host} for ID ${queryId}, switching to TCP fallback`);

                // 标记使用TCP回退，关闭所有UDP客户端
                record.useTcpFallback = true;
                record.clients.forEach(client => client.close());

                // 使用DoT进行查询
                queryWithDoT(msg, queryId, question, (err, tcpResponse) => {
                    if (err) {
                        log(`DoT fallback failed for ID ${queryId}: ${err.message}`, 'error');
                        // 尝试DoH作为最后手段
                        queryWithDoH(msg, queryId, question, (err, dohResponse) => {
                            if (err) {
                                log(`DoH fallback also failed for ID ${queryId}: ${err.message}`, 'error');
                                const errorResponse = dnsPacket.encode({
                                    type: 'response',
                                    id: queryId,
                                    flags: dnsPacket.AUTHORITATIVE_ANSWER | dnsPacket.RA | dnsPacket.SERVFAIL,
                                    questions: query.questions,
                                    answers: []
                                });
                                socket.send(errorResponse, rinfo.port, rinfo.address);
                                stats.failedResponses++;
                                return;
                            }

                            // 缓存响应
                            setToCache(query, dohResponse);

                            // 发送DoH响应
                            socket.send(dohResponse, rinfo.port, rinfo.address, (err) => {
                                if (err) {
                                    log(`Error sending DoH response to client: ${err.message}`, 'error');
                                } else {
                                    log(`DoH response for ID ${queryId} sent to client`);
                                    stats.successfulResponses++;
                                }
                            });
                        });
                        return;
                    }

                    // 缓存响应
                    setToCache(query, tcpResponse);

                    // 发送DoT响应
                    socket.send(tcpResponse, rinfo.port, rinfo.address, (err) => {
                        if (err) {
                            log(`Error sending DoT response to client: ${err.message}`, 'error');
                        } else {
                            log(`DoT response for ID ${queryId} sent to client`);
                            stats.successfulResponses++;
                        }
                    });
                });

                return;
            }

            record.responses.set(upstream.host, {
                msg: responseMsg,
                receiveDuration,
                hasOPT: hasOPTRecord
            });

            if (hasOPTRecord) {
                const totalTime = process.hrtime(record.startTime);
                const totalDuration = (totalTime[0] * 1000) + (totalTime[1] / 1000000);

                log(`Authentic response from ${upstream.host} for ID ${queryId}, replying to client. Total time: ${totalDuration.toFixed(2)}ms`);

                // 缓存响应
                setToCache(query, responseMsg);

                socket.send(responseMsg, rinfo.port, rinfo.address, (err) => {
                    if (err) {
                        log(`Error sending response to client: ${err.message}`, 'error');
                    } else {
                        log(`Response for ID ${queryId} successfully sent to client`);
                        stats.successfulResponses++;
                    }
                });

                record.answered = true;
                pendingRequests.delete(queryId);
                record.clients.forEach(client => client.close());
                return;
            }
        });

        client.on('error', (err) => {
            log(`Socket error with ${upstream.host} for query ID ${queryId}: ${err.message}`, 'error');
            client.close();
        });

        maxWaitTime = Math.max(maxWaitTime, upstream.currentTimeout);
    });

    setTimeout(() => {
        const record = pendingRequests.get(queryId);
        if (!record || record.answered || record.useTcpFallback) {
            return;
        }

        const totalTime = process.hrtime(record.startTime);
        const totalDuration = (totalTime[0] * 1000) + (totalTime[1] / 1000000);

        log(`Query ID ${queryId} timed out after ${totalDuration.toFixed(2)}ms (max wait: ${maxWaitTime}ms).`);

        if (record.responses.size > 0) {
            stats.hijackDetections++;
            log(`Received ${record.responses.size} hijacked responses for ID ${queryId}. Sending SERVFAIL.`);

            const errorResponse = dnsPacket.encode({
                type: 'response',
                id: queryId,
                flags: dnsPacket.AUTHORITATIVE_ANSWER | dnsPacket.RA | dnsPacket.SERVFAIL,
                questions: query.questions,
                answers: []
            });

            socket.send(errorResponse, rinfo.port, rinfo.address, (err) => {
                if (err) {
                    log(`Error sending SERVFAIL to client: ${err.message}`, 'error');
                }
            });
        } else {
            stats.failedResponses++;
            log(`No response from any upstream for ID ${queryId}.`);

            const errorResponse = dnsPacket.encode({
                type: 'response',
                id: queryId,
                flags: dnsPacket.AUTHORITATIVE_ANSWER | dnsPacket.RA | dnsPacket.SERVFAIL,
                questions: query.questions,
                answers: []
            });

            socket.send(errorResponse, rinfo.port, rinfo.address, (err) => {
                if (err) {
                    log(`Error sending SERVFAIL to client: ${err.message}`, 'error');
                }
            });
        }

        record.answered = true;
        pendingRequests.delete(queryId);
        record.clients.forEach(client => client.close());
    }, maxWaitTime);
});

socket.on('error', (err) => {
    log(`UDP server socket error: ${err.message}`, 'error');
});

socket.on('listening', () => {
    const address = socket.address();
    log(`UDP DNS proxy server running on ${address.address}:${address.port}`);
});

socket.bind(config.udpPort, () => {
    log(`UDP DNS proxy server started successfully on port ${config.udpPort}`);
});

// 优雅关闭处理
process.on('SIGINT', () => {
    log('Shutting down DNS proxy server...');

    // 清理资源
    if (cacheCleanupInterval) {
        clearInterval(cacheCleanupInterval);
    }

    socket.close();
    tcpServer.close();

    process.exit(0);
});
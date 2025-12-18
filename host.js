const fs = require("fs").promises;
const yaml = require("js-yaml");
const { get } = require("https");
const { format } = require("date-fns");
const dns2 = require("dns2");
const net = require("net");

// 专门的配置管理类
class ConfigManager {
  constructor() {
    this.config = null;
  }

  async load(configPath = "conf.yaml") {
    try {
      const configFile = await fs.readFile(configPath, "utf8");
      this.config = yaml.load(configFile);
      this.normalize();
      return this.config;
    } catch (error) {
      throw new Error(`配置加载失败: ${error.message}`);
    }
  }

  normalize() {
    this.config.upstream_DNS = this.normalizeDNSList(this.config.upstream_DNS);
    this.config.Whitelist_DNS = this.normalizeDNSList(
      this.config.Whitelist_DNS
    );
    this.config.dns_servers = this.normalizeDNSList(
      this.config.dns_servers || ["8.8.8.8", "1.1.1.1"]
    );

    // 设置合理的默认值
    this.config.domain_output = this.config.domain_output || "data/all";
    this.config.output_file = this.config.output_file || "dnsmasq.conf";
    this.config.author = this.config.author || "System";
    this.config.distribution_url = this.config.distribution_url || "";
    this.config.debug = Boolean(this.config.debug);
    this.config.classify_domains = Boolean(this.config.classify_domains);
    this.config.classify_dns_timeout = this.config.classify_dns_timeout || 3000;
    this.config.tcp_ping_timeout = this.config.tcp_ping_timeout || 300;
    this.config.tcp_ping_retries = this.config.tcp_ping_retries || 3;
  }

  normalizeDNSList(dnsList) {
    if (Array.isArray(dnsList)) {
      return dnsList.map((item) => item.trim()).filter((item) => item);
    }

    return (dnsList || "")
      .split("\n")
      .map((item) => item.trim())
      .filter((item) => item);
  }
}

// 专门的数据获取类
class DataFetcher {
  static async fetchData(source) {
    if (source.local_gfw_file) {
      return await DataFetcher.fetchLocalFile(source.local_gfw_file);
    } else if (source.gfw_list_url) {
      return await DataFetcher.fetchRemoteFile(source.gfw_list_url);
    }
    throw new Error("未配置数据源");
  }

  static async fetchLocalFile(filePath) {
    try {
      return await fs.readFile(filePath, "utf8");
    } catch (error) {
      throw new Error(`本地文件读取失败: ${error.message}`);
    }
  }

  static async fetchRemoteFile(url, maxRedirects = 5) {
    return new Promise((resolve, reject) => {
      const fetchWithRedirect = (currentUrl, redirectCount = 0) => {
        const request = get(currentUrl, (response) => {
          // 处理重定向
          if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
            if (redirectCount >= maxRedirects) {
              reject(new Error(`重定向次数过多（超过${maxRedirects}次）`));
              return;
            }

            const newUrl = new URL(response.headers.location, currentUrl).href;
            console.log(`重定向: ${currentUrl} -> ${newUrl}`);
            fetchWithRedirect(newUrl, redirectCount + 1);
            return;
          }

          // 处理成功响应
          if (response.statusCode === 200) {
            const chunks = [];
            response.on("data", (chunk) => chunks.push(chunk));
            response.on("end", () => resolve(Buffer.concat(chunks).toString()));
            return;
          }

          // 处理其他错误状态码
          reject(new Error(`HTTP ${response.statusCode}`));
        });

        request.setTimeout(30000, () => {
          request.destroy();
          reject(new Error("请求超时"));
        });

        request.on("error", reject);
      };

      fetchWithRedirect(url);
    });
  }
}

// 域名处理器 - 分别处理两种输出
class DomainProcessor {
  constructor(whiteListDNS, upstreamDNS) {
    this.whiteListDNS = whiteListDNS.join(" ");
    this.upstreamDNS = upstreamDNS.join(" ");

    // 预编译正则表达式，提高性能
    this.patterns = {
      domain:
        /^(?=^.{3,255}$)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$/,
      prefixPattern: /^(\|\||\.)/,
      whiteListPattern: /^@@\|\|/,
      ipAddress: /^\d{1,3}(\.\d{1,3}){3}$/,
    };

    // 用于去重的Set
    this.domainSet = new Set();
    this.dnsConfigSet = new Set();
  }

  // 处理中间域名列表（忽略@@||）
  processForDomainList(line) {
    const trimmedLine = line.trim();
    if (!trimmedLine) return null;

    // 跳过白名单域名 (@@||domain)
    if (this.patterns.whiteListPattern.test(trimmedLine)) {
      return null;
    }

    let processedDomain = trimmedLine;

    // 处理前缀 (||domain or .domain)
    if (this.patterns.prefixPattern.test(trimmedLine)) {
      processedDomain = trimmedLine.replace(this.patterns.prefixPattern, "");
    }

    // 验证域名格式
    if (this.isValidDomain(processedDomain)) {
      const result = `domain:${processedDomain}`;
      // 去重检查
      if (!this.domainSet.has(processedDomain)) {
        this.domainSet.add(processedDomain);
        return result;
      }
    }

    return null;
  }

  // 处理DNS配置（正常处理所有格式）
  processForDNSConfig(line) {
    const trimmedLine = line.trim();
    if (!trimmedLine) return null;

    // 处理白名单域名 (@@||domain)
    if (this.patterns.whiteListPattern.test(trimmedLine)) {
      const domain = trimmedLine.replace(this.patterns.whiteListPattern, "");
      if (this.isValidDomain(domain)) {
        const result = `[/${domain}/]${this.upstreamDNS}`;
        // 去重检查
        if (!this.dnsConfigSet.has(result)) {
          this.dnsConfigSet.add(result);
          return result;
        }
      }
      return null;
    }

    let processedDomain = trimmedLine;
    let dnsServer = this.whiteListDNS;

    // 处理前缀 (||domain or .domain)
    if (this.patterns.prefixPattern.test(trimmedLine)) {
      processedDomain = trimmedLine.replace(this.patterns.prefixPattern, "");
    }

    // 验证域名格式
    if (this.isValidDomain(processedDomain)) {
      const result = `[/${processedDomain}/]${dnsServer}`;
      // 去重检查
      if (!this.dnsConfigSet.has(result)) {
        this.dnsConfigSet.add(result);
        return result;
      }
    }

    return null;
  }

  // 批量处理中间域名列表
  processBatchForDomainList(lines, debug = false) {
    const results = [];
    this.domainSet.clear(); // 清空Set

    for (const line of lines) {
      const result = this.processForDomainList(line);

      if (result) {
        results.push(result);
        if (debug) {
          console.log(`[域名列表] ${line.padEnd(40)} → ${result}`);
        }
      } else if (debug && line.trim()) {
        console.log(`[域名列表-跳过] ${line}`);
      }
    }

    if (debug) {
      console.log(
        `[去重统计] 域名列表去重前: ${lines.length} 行，去重后: ${results.length} 个域名`
      );
    }

    return results;
  }

  // 批量处理DNS配置
  processBatchForDNSConfig(lines, debug = false) {
    const results = [];
    this.dnsConfigSet.clear(); // 清空Set

    for (const line of lines) {
      const result = this.processForDNSConfig(line);

      if (result) {
        results.push(result);
        if (debug) {
          console.log(`[DNS配置] ${line.padEnd(40)} → ${result}`);
        }
      } else if (debug && line.trim()) {
        console.log(`[DNS配置-跳过] ${line}`);
      }
    }

    if (debug) {
      console.log(
        `[去重统计] DNS配置去重前: ${lines.length} 行，去重后: ${results.length} 个条目`
      );
    }

    return results;
  }

  isValidDomain(domain) {
    // 排除IP地址
    if (this.patterns.ipAddress.test(domain)) {
      return false;
    }
    return this.patterns.domain.test(domain);
  }
}

class DomainClassifier {
  constructor(config) {
    this.config = config;
    this.dnsClient = null;
    
    // 并发控制配置
    this.concurrencyLimit = config.concurrency?.dns_queries || 5; // DNS查询并发数
    this.tcpConcurrencyLimit = config.concurrency?.tcp_tests || 5; // TCP测试并发数
    this.activeQueries = 0;
    this.activeTCPTests = 0;
    this.dnsQueue = [];
    this.tcpQueue = [];
    
    // 缓存机制
    this.dnsCache = new Map();
    this.cacheTTL = (config.performance?.cache_ttl || 300) * 1000; // 缓存时间（毫秒）
    this.enableCache = config.performance?.enable_cache !== false; // 默认启用缓存
    
    // 超时配置
    this.queryTimeouts = {
      SOA: (config.classify_dns_timeout || 3000) * (config.performance?.timeout_multiplier || 1.5),
      NS: (config.classify_dns_timeout || 3000) * (config.performance?.timeout_multiplier || 1.5),
      A: 2000,
      TCP_PING: config.tcp_ping_timeout || 500
    };
    
    // 重试配置
    this.maxRetries = {
      DNS: config.retry?.dns || 1,
      TCP: config.retry?.tcp || 1
    };
    
    // 结果存储
    this.classificationResults = {
      cloudflare: [],
      pingable: [],
      other: []
    };
    
    // 统计信息
    this.stats = {
      total: 0,
      cloudflare: 0,
      pingable: 0,
      other: 0,
      errors: 0,
      cached: 0,
      timeouts: 0,
      performance: {
        dnsQueries: 0,
        tcpTests: 0,
        totalTime: 0,
        avgDNSResponse: 0,
        avgTCPResponse: 0
      }
    };
  }

  // 初始化DNS客户端
  initDNSClient() {
    if (!this.dnsClient) {
      this.dnsClient = new (require('dns2'))({
        nameServers: this.config.dns_servers,
        timeout: this.config.classify_dns_timeout || 3000,
        recursive: true
      });

      if (this.config.debug) {
        console.log(`DNS客户端已初始化，使用DNS服务器: ${this.config.dns_servers.join(', ')}`);
        console.log(`并发配置: DNS=${this.concurrencyLimit}, TCP=${this.tcpConcurrencyLimit}`);
      }
    }
  }

  // ==================== 并发控制机制 ====================

  // DNS查询并发控制
  async executeDNSQueryWithConcurrency(task, domain, type) {
    return new Promise((resolve, reject) => {
      const executeTask = async () => {
        this.activeQueries++;
        const startTime = Date.now();
        
        try {
          const result = await task(domain, type);
          const duration = Date.now() - startTime;
          this.stats.performance.dnsQueries++;
          this.stats.performance.avgDNSResponse = 
            (this.stats.performance.avgDNSResponse * (this.stats.performance.dnsQueries - 1) + duration) / 
            this.stats.performance.dnsQueries;
          
          resolve(result);
        } catch (error) {
          reject(error);
        } finally {
          this.activeQueries--;
          this.processDNSQueue();
        }
      };

      if (this.activeQueries < this.concurrencyLimit) {
        executeTask();
      } else {
        this.dnsQueue.push(() => executeTask());
      }
    });
  }

  // TCP测试并发控制
  async executeTCPTestWithConcurrency(task, domain) {
    return new Promise((resolve, reject) => {
      const executeTask = async () => {
        this.activeTCPTests++;
        const startTime = Date.now();
        
        try {
          const result = await task(domain);
          const duration = Date.now() - startTime;
          this.stats.performance.tcpTests++;
          this.stats.performance.avgTCPResponse = 
            (this.stats.performance.avgTCPResponse * (this.stats.performance.tcpTests - 1) + duration) / 
            this.stats.performance.tcpTests;
          
          resolve(result);
        } catch (error) {
          reject(error);
        } finally {
          this.activeTCPTests--;
          this.processTCPQueue();
        }
      };

      if (this.activeTCPTests < this.tcpConcurrencyLimit) {
        executeTask();
      } else {
        this.tcpQueue.push(() => executeTask());
      }
    });
  }

  // 处理DNS队列
  processDNSQueue() {
    while (this.dnsQueue.length > 0 && this.activeQueries < this.concurrencyLimit) {
      const task = this.dnsQueue.shift();
      task();
    }
  }

  // 处理TCP队列
  processTCPQueue() {
    while (this.tcpQueue.length > 0 && this.activeTCPTests < this.tcpConcurrencyLimit) {
      const task = this.tcpQueue.shift();
      task();
    }
  }

  // ==================== 带缓存的DNS查询 ====================

  // 带重试和超时的DNS查询
  async dnsQuery(domain, type = 'A') {
    const queryTask = async (domain, type) => {
      try {
        const response = await Promise.race([
          this.dnsClient.query(domain, type.toUpperCase()),
          new Promise((_, reject) => 
            setTimeout(() => reject(new Error('DNS查询超时')), this.queryTimeouts[type] || 2000)
          )
        ]);
        return response;
      } catch (error) {
        if (this.config.debug) {
          console.log(`DNS查询失败 ${domain} (${type}):`, error.message);
        }
        return null;
      }
    };

    return this.executeDNSQueryWithConcurrency(queryTask, domain, type);
  }

  // 带缓存的DNS查询
  async cachedDNSQuery(domain, type = 'A') {
    if (!this.enableCache) {
      return await this.dnsQuery(domain, type);
    }

    const cacheKey = `${domain}:${type}`;
    const now = Date.now();
    
    // 检查缓存
    if (this.dnsCache.has(cacheKey)) {
      const cached = this.dnsCache.get(cacheKey);
      if (now - cached.timestamp < this.cacheTTL) {
        this.stats.cached++;
        if (this.config.debug) {
          console.log(`[缓存命中] ${domain} (${type})`);
        }
        return cached.data;
      }
    }
    
    // 执行查询
    const result = await this.dnsQuery(domain, type);
    
    // 缓存结果
    if (result) {
      this.dnsCache.set(cacheKey, {
        data: result,
        timestamp: now
      });
    }
    
    return result;
  }

  // ==================== 域名分类核心逻辑 ====================

  // 判断是否为Cloudflare域名
  async isCloudflareDomain(domain) {
    try {
      if (typeof domain !== 'string' || !domain.trim()) {
        return false;
      }

      const cleanDomain = domain.trim();

      // 1. 查询SOA记录
      const soaResponse = await this.cachedDNSQuery(cleanDomain, 'SOA');
      if (soaResponse && soaResponse.answers && soaResponse.answers.length > 0) {
        for (const answer of soaResponse.answers) {
          // 检查SOA记录的各个字段
          let answerStr = JSON.stringify(answer).toLowerCase();

          if (answer.primary && answer.primary.toLowerCase().includes('cloudflare')) {
            if (this.config.debug) {
              console.log(`${cleanDomain} - SOA.primary包含cloudflare: ${answer.primary}`);
            }
            return true;
          }
          if (answer.admin && answer.admin.toLowerCase().includes('cloudflare')) {
            if (this.config.debug) {
              console.log(`${cleanDomain} - SOA.admin包含cloudflare: ${answer.admin}`);
            }
            return true;
          }
          if (answerStr.includes('cloudflare')) {
            if (this.config.debug) {
              console.log(`${cleanDomain} - SOA记录包含cloudflare:`, answerStr);
            }
            return true;
          }
        }
      }

      // 2. 查询NS记录
      const nsResponse = await this.cachedDNSQuery(cleanDomain, 'NS');
      if (nsResponse && nsResponse.answers && nsResponse.answers.length > 0) {
        for (const answer of nsResponse.answers) {
          if (answer.ns && answer.ns.toLowerCase().includes('cloudflare')) {
            if (this.config.debug) {
              console.log(`${cleanDomain} - NS记录包含cloudflare: ${answer.ns}`);
            }
            return true;
          }

          let answerStr = JSON.stringify(answer).toLowerCase();
          if (answerStr.includes('cloudflare')) {
            if (this.config.debug) {
              console.log(`${cleanDomain} - NS记录包含cloudflare:`, answerStr);
            }
            return true;
          }
        }
      }

      return false;
    } catch (error) {
      if (this.config.debug) {
        console.error(`检查Cloudflare域名失败 ${domain}:`, error.message);
      }
      return false;
    }
  }

  // TCP Ping测试（带并发控制）
  async tcpPing(domain) {
    const pingTask = async (domain) => {
      try {
        if (typeof domain !== 'string' || !domain.trim()) {
          return false;
        }

        const cleanDomain = domain.trim();
        const ports = [443];
        const timeout = this.queryTimeouts.TCP_PING;
        const retries = this.maxRetries.TCP;

        for (const port of ports) {
          for (let i = 0; i < retries; i++) {
            try {
              const result = await new Promise((resolve, reject) => {
                const socket = new net.Socket();
                let timedOut = false;

                const timer = setTimeout(() => {
                  timedOut = true;
                  socket.destroy();
                  reject(new Error('连接超时'));
                }, timeout);

                socket.connect(port, cleanDomain, () => {
                  clearTimeout(timer);
                  socket.end();
                  resolve(true);
                });

                socket.on('error', (err) => {
                  clearTimeout(timer);
                  if (!timedOut) {
                    reject(err);
                  }
                });

                socket.setTimeout(timeout, () => {
                  if (!timedOut) {
                    timedOut = true;
                    socket.destroy();
                    reject(new Error('socket超时'));
                  }
                });
              });

              if (result) {
                if (this.config.debug) {
                  console.log(`${cleanDomain}:${port} - TCP Ping成功`);
                }
                return true;
              }
            } catch (error) {
              if (this.config.debug && i < retries - 1) {
                console.log(`${cleanDomain}:${port} 第${i + 1}次尝试失败:`, error.message);
              }
            }
          }
        }
        return false;
      } catch (error) {
        if (this.config.debug) {
          console.error(`TCP Ping测试失败 ${domain}:`, error.message);
        }
        return false;
      }
    };

    return this.executeTCPTestWithConcurrency(pingTask, domain);
  }

  // 分类单个域名
  async classifyDomain(domainEntry) {
    let result = 'other';
    
    try {
      if (typeof domainEntry !== 'string' || !domainEntry.includes('domain:')) {
        throw new Error('无效的域名格式');
      }

      const domain = domainEntry.replace('domain:', '').trim();
      if (!domain) {
        throw new Error('空域名');
      }

      this.stats.total++;

      // 检查是否为Cloudflare域名
      const isCloudflare = await this.isCloudflareDomain(domain);
      if (isCloudflare) {
        result = 'cloudflare';
        this.classificationResults.cloudflare.push(domainEntry);
        this.stats.cloudflare++;
      } else {
        // 只有在不是Cloudflare时才进行TCP Ping测试
        const isPingable = await this.tcpPing(domain);
        if (isPingable) {
          result = 'pingable';
          this.classificationResults.pingable.push(domainEntry);
          this.stats.pingable++;
        } else {
          result = 'other';
          this.classificationResults.other.push(domainEntry);
          this.stats.other++;
        }
      }

    } catch (error) {
      if (error.message === 'DNS查询超时') {
        this.stats.timeouts++;
      }
      
      this.classificationResults.other.push(domainEntry);
      this.stats.other++;
      this.stats.errors++;
      
      if (this.config.debug) {
        console.log(`域名分类失败 ${domainEntry}:`, error.message);
      }
    }

    return result;
  }

  // ==================== 批量分类主方法 ====================

  async classifyDomains(domains, progressCallback = null) {
    console.log('开始域名分类...');
    console.log(`需要分类的域名总数: ${domains.length}`);
    
    const startTime = Date.now();
    
    try {
      // 重置统计
      this.stats = {
        total: 0,
        cloudflare: 0,
        pingable: 0,
        other: 0,
        errors: 0,
        cached: 0,
        timeouts: 0,
        performance: {
          dnsQueries: 0,
          tcpTests: 0,
          totalTime: 0,
          avgDNSResponse: 0,
          avgTCPResponse: 0
        }
      };

      this.classificationResults = {
        cloudflare: [],
        pingable: [],
        other: []
      };

      // 初始化DNS客户端
      this.initDNSClient();

      // 过滤有效域名
      const validDomains = domains.filter(entry => {
        if (typeof entry !== 'string') return false;
        if (!entry.includes('domain:')) return false;
        const domain = entry.replace('domain:', '').trim();
        return !!domain;
      });

      console.log(`有效域名数量: ${validDomains.length}/${domains.length}`);
      console.log(`并发设置: DNS=${this.concurrencyLimit}, TCP=${this.tcpConcurrencyLimit}`);
      console.log(`缓存: ${this.enableCache ? '启用' : '禁用'}`);

      // 分批次处理
      const batchSize = this.config.concurrency?.batch_size || 10;
      let processedCount = 0;

      for (let i = 0; i < validDomains.length; i += batchSize) {
        const batch = validDomains.slice(i, i + batchSize);
        
        // 批量处理当前批次的域名
        const promises = batch.map(async (domain) => {
          try {
            const result = await this.classifyDomain(domain);
            return result;
          } catch (error) {
            console.error(`处理域名失败 ${domain}:`, error.message);
            return 'error';
          }
        });

        await Promise.allSettled(promises);
        
        processedCount += batch.length;
        
        // 更新进度
        if (progressCallback) {
          progressCallback(processedCount, validDomains.length);
        }
        
        // 批次间添加小延迟，避免请求过密
        if (i + batchSize < validDomains.length) {
          await new Promise(resolve => setTimeout(resolve, 50));
        }
      }

      const endTime = Date.now();
      this.stats.performance.totalTime = (endTime - startTime) / 1000;

      // 输出详细报告
      this.printClassificationReport();

    } catch (error) {
      console.error('分类过程中发生严重错误:', error.message);
      // 优雅降级：将所有域名归为other类别
      this.classificationResults.other = domains;
      this.stats.total = domains.length;
      this.stats.other = domains.length;
      console.log('已启用降级模式：所有域名归为other类别');
    } finally {
      this.close();
    }

    return this.classificationResults;
  }

  // ==================== 辅助方法 ====================

  // 打印分类报告
  printClassificationReport() {
    console.log('\n' + '='.repeat(60));
    console.log('域名分类完成！');
    console.log('='.repeat(60));
    
    console.log('\n📊 分类统计:');
    console.log(`   总域名数: ${this.stats.total}`);
    console.log(`   Cloudflare: ${this.stats.cloudflare} (${((this.stats.cloudflare/this.stats.total)*100).toFixed(1)}%)`);
    console.log(`   可Ping通: ${this.stats.pingable} (${((this.stats.pingable/this.stats.total)*100).toFixed(1)}%)`);
    console.log(`   其他: ${this.stats.other} (${((this.stats.other/this.stats.total)*100).toFixed(1)}%)`);
    console.log(`   错误: ${this.stats.errors} (${((this.stats.errors/this.stats.total)*100).toFixed(1)}%)`);
    
    console.log('\n🚀 性能统计:');
    console.log(`   总耗时: ${this.stats.performance.totalTime.toFixed(2)}秒`);
    console.log(`   平均每个域名: ${(this.stats.performance.totalTime/this.stats.total).toFixed(2)}秒`);
    console.log(`   DNS查询次数: ${this.stats.performance.dnsQueries}`);
    console.log(`   TCP测试次数: ${this.stats.performance.tcpTests}`);
    console.log(`   缓存命中: ${this.stats.cached}`);
    console.log(`   超时次数: ${this.stats.timeouts}`);
    
    if (this.stats.performance.dnsQueries > 0) {
      console.log(`   平均DNS响应: ${this.stats.performance.avgDNSResponse.toFixed(0)}ms`);
    }
    if (this.stats.performance.tcpTests > 0) {
      console.log(`   平均TCP响应: ${this.stats.performance.avgTCPResponse.toFixed(0)}ms`);
    }
    
    console.log('\n💾 分类结果文件:');
    console.log(`   cloudflare: data/cloudflare (${this.classificationResults.cloudflare.length}个)`);
    console.log(`   pingable: data/pingable (${this.classificationResults.pingable.length}个)`);
    console.log(`   other: data/other (${this.classificationResults.other.length}个)`);
    console.log('='.repeat(60));
  }

  // 清理资源
  close() {
    this.dnsClient = null;
    this.dnsCache.clear();
    this.dnsQueue = [];
    this.tcpQueue = [];
  }
}

// 文件输出器
class FileExporter {
  static generateHeader(config, domainCount, type = '') {
    const header = `
# Generated at: ${format(new Date(), "yyyy-MM-dd HH:mm:ss")}
# Author: ${config.author}
# Distribution: ${config.distribution_url}
# Type: ${type || 'all'}
# Total Domains: ${domainCount}
# ------------------------------------------
`;
    return header;
  }

  static async exportDomains(domains, filePath) {
    // 按域名字母排序
    const sortedDomains = domains.sort((a, b) => {
      const domainA = a.replace("domain:", "").toLowerCase();
      const domainB = b.replace("domain:", "").toLowerCase();
      return domainA.localeCompare(domainB);
    });

    // 每行一个域名，直接输出 domain:domain1 格式
    const content = sortedDomains.join("\n");
    await fs.writeFile(filePath, content);
  }

  static async exportClassifiedDomains(classifiedResults, baseDir = "data") {
    // 确保目录存在
    await fs.mkdir(baseDir, { recursive: true });

    // 导出每个分类
    const exportPromises = Object.entries(classifiedResults).map(async ([type, domains]) => {
      if (domains.length > 0) {
        const filePath = `${baseDir}/${type}`;
        await this.exportDomains(domains, filePath);
        console.log(`✓ ${type} 分类已生成: ${filePath} (${domains.length} 个域名)`);
        return { type, count: domains.length };
      }
      return { type, count: 0 };
    });

    const results = await Promise.all(exportPromises);

    //  生成汇总文件
    // const summary = results.map(r => `${r.type}: ${r.count}`).join('\n');
    // await fs.writeFile(`${baseDir}/summary.txt`, `分类统计:\n${summary}\n\n生成时间: ${format(new Date(), "yyyy-MM-dd HH:mm:ss")}`);

    return results;
  }

  static async exportDNSConfig(config, dnsEntries) {
    // 按域名字母排序
    const sortedEntries = dnsEntries.sort((a, b) => {
      // 提取域名部分进行比较：[/domain/]DNS
      const domainA = a.match(/\[\/(.*?)\/\]/)?.[1] || "";
      const domainB = b.match(/\[\/(.*?)\/\]/)?.[1] || "";
      return domainA.localeCompare(domainB);
    });

    const header = this.generateHeader(config, sortedEntries.length);
    const upstreamDNS = config.upstream_DNS.join("\n");
    const content = [header, upstreamDNS, "", ...sortedEntries].join("\n");
    await fs.writeFile(config.output_file, content);
  }
}

// 重构后的主类
class DNSConfigGenerator {
  constructor() {
    this.configManager = new ConfigManager();
    this.domainListResults = [];
    this.dnsConfigResults = [];
    this.classifiedResults = null;
  }

  async run() {
    try {
      console.log("开始生成DNS配置...");

      // 加载配置
      const config = await this.configManager.load();

      // 确保输出目录存在
      const outputDir = "data";
      try {
        await fs.access(outputDir);
      } catch (error) {
        // 如果目录不存在，创建它
        await fs.mkdir(outputDir, { recursive: true });
      }

      // 获取数据
      const rawData = await DataFetcher.fetchData(config);
      const lines = rawData.split(/\r?\n/);

      // 处理域名
      const processor = new DomainProcessor(
        config.Whitelist_DNS,
        config.upstream_DNS
      );

      // 分别处理两种输出
      this.domainListResults = processor.processBatchForDomainList(
        lines,
        config.debug
      );
      this.dnsConfigResults = processor.processBatchForDNSConfig(
        lines,
        config.debug
      );

      // 输出基础文件
      await FileExporter.exportDomains(
        this.domainListResults,
        config.domain_output
      );
      await FileExporter.exportDNSConfig(config, this.dnsConfigResults);

      console.log(`✓ 域名列表已生成: ${config.domain_output}`);
      console.log(`✓ DNS配置已生成: ${config.output_file}`);
      console.log(`✓ 域名列表数量: ${this.domainListResults.length} 个域名`);
      console.log(`✓ DNS配置数量: ${this.dnsConfigResults.length} 个条目`);

      // 如果需要分类域名
      if (config.classify_domains) {
        console.log('\n开始域名分类处理...');
        const classifier = new DomainClassifier(config);

        // 进度显示函数
        const showProgress = (processed, total) => {
          const percentage = Math.round((processed / total) * 100);
          process.stdout.write(`\r分类进度: ${processed}/${total} (${percentage}%)`);
        };

        this.classifiedResults = await classifier.classifyDomains(
          this.domainListResults,
          showProgress
        );

        console.log('\n'); // 换行

        // 导出分类结果
        await FileExporter.exportClassifiedDomains(this.classifiedResults);

        classifier.close();
      }

      if (config.debug) {
        console.log("\n域名列表前5个结果:");
        this.domainListResults.slice(0, 5).forEach((domain, index) => {
          console.log(`  ${index + 1}. ${domain}`);
        });

        console.log("\nDNS配置前5个结果:");
        this.dnsConfigResults.slice(0, 5).forEach((entry, index) => {
          console.log(`  ${index + 1}. ${entry}`);
        });
      }
    } catch (error) {
      console.error("❌ 执行失败:", error.message);
      process.exit(1);
    }
  }
}

// 启动应用
(async () => {
  const generator = new DNSConfigGenerator();
  await generator.run();
})();

// 放在文件最开头
process.on('uncaughtException', (err) => {
  console.error('!!! 捕获到未处理的异常，防止进程崩溃:');
  console.error('错误类型:', err.name);
  console.error('错误信息:', err.message);
  console.error('错误栈:', err.stack);
  // 可以选择记录错误后继续运行，或优雅重启
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('!!! 未处理的Promise拒绝:', reason);
});
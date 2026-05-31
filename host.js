import { promises as fs } from "fs";
import yaml from "js-yaml";
import { get } from "https";
import { format } from "date-fns";

// ==================== 配置管理 ====================
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
      this.config.Whitelist_DNS,
    );

    // 设置合理的默认值
    this.config.domain_output = this.config.domain_output || "data/all";
    this.config.output_file = this.config.output_file || "dnsmasq.conf";
    this.config.author = this.config.author || "System";
    this.config.distribution_url = this.config.distribution_url || "";
    this.config.debug = Boolean(this.config.debug);
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

// ==================== 数据获取 ====================
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
          if (
            response.statusCode >= 300 &&
            response.statusCode < 400 &&
            response.headers.location
          ) {
            if (redirectCount >= maxRedirects) {
              reject(new Error(`重定向次数过多（超过${maxRedirects}次）`));
              return;
            }
            const newUrl = new URL(response.headers.location, currentUrl).href;
            console.log(`重定向: ${currentUrl} -> ${newUrl}`);
            fetchWithRedirect(newUrl, redirectCount + 1);
            return;
          }

          if (response.statusCode === 200) {
            const chunks = [];
            response.on("data", (chunk) => chunks.push(chunk));
            response.on("end", () => resolve(Buffer.concat(chunks).toString()));
            return;
          }

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

// ==================== 域名处理器 ====================
class DomainProcessor {
  constructor(whiteListDNS, upstreamDNS) {
    this.whiteListDNS = whiteListDNS.join(" ");
    this.upstreamDNS = upstreamDNS.join(" ");
    this.domainSet = new Set();
    this.dnsConfigSet = new Set();

    this.patterns = {
      domain:
        /^(?=^.{3,255}$)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$/,
      prefixPattern: /^(\|\||\.)/,
      whiteListPattern: /^@@\|\|/,
      ipAddress: /^\d{1,3}(\.\d{1,3}){3}$/,
    };
  }

  // 提取域名（用于 domain:xxx 格式）
  extractDomain(line) {
    const trimmedLine = line.trim();
    if (!trimmedLine) return null;

    let processedDomain = trimmedLine;

    // 处理白名单 (@@||domain) - 提取域名但不生成白名单配置
    if (this.patterns.whiteListPattern.test(trimmedLine)) {
      processedDomain = trimmedLine.replace(this.patterns.whiteListPattern, "");
    }

    // 处理前缀 (||domain or .domain)
    if (this.patterns.prefixPattern.test(processedDomain)) {
      processedDomain = processedDomain.replace(
        this.patterns.prefixPattern,
        "",
      );
    }

    // 验证域名格式
    if (this.isValidDomain(processedDomain)) {
      return processedDomain;
    }

    return null;
  }

  // 处理域名列表输出（只输出 domain:xxx 格式）
  processForDomainList(line) {
    const domain = this.extractDomain(line);
    if (domain && !this.domainSet.has(domain)) {
      this.domainSet.add(domain);
      return `domain:${domain}`;
    }
    return null;
  }

  // 处理 DNS 配置输出（[/domain/]DNS 格式）
  processForDNSConfig(line) {
    const trimmedLine = line.trim();
    if (!trimmedLine) return null;

    // 处理白名单域名 (@@||domain)
    if (this.patterns.whiteListPattern.test(trimmedLine)) {
      const domain = trimmedLine.replace(this.patterns.whiteListPattern, "");
      if (this.isValidDomain(domain)) {
        const result = `[/${domain}/]${this.upstreamDNS}`;
        if (!this.dnsConfigSet.has(result)) {
          this.dnsConfigSet.add(result);
          return result;
        }
      }
      return null;
    }

    let processedDomain = trimmedLine;

    if (this.patterns.prefixPattern.test(trimmedLine)) {
      processedDomain = trimmedLine.replace(this.patterns.prefixPattern, "");
    }

    if (this.isValidDomain(processedDomain)) {
      const result = `[/${processedDomain}/]${this.whiteListDNS}`;
      if (!this.dnsConfigSet.has(result)) {
        this.dnsConfigSet.add(result);
        return result;
      }
    }

    return null;
  }

  // 批量处理域名列表
  processBatchForDomainList(lines, debug = false) {
    const results = [];
    this.domainSet.clear();

    for (const line of lines) {
      const result = this.processForDomainList(line);
      if (result) {
        results.push(result);
      }
    }

    if (debug) {
      console.log(
        `[域名列表] 去重前: ${lines.length} 行，去重后: ${results.length} 个域名`,
      );
    }

    return results;
  }

  // 批量处理 DNS 配置
  processBatchForDNSConfig(lines, debug = false) {
    const results = [];
    this.dnsConfigSet.clear();

    for (const line of lines) {
      const result = this.processForDNSConfig(line);
      if (result) {
        results.push(result);
      }
    }

    if (debug) {
      console.log(
        `[DNS配置] 去重前: ${lines.length} 行，去重后: ${results.length} 个条目`,
      );
    }

    return results;
  }

  isValidDomain(domain) {
    if (this.patterns.ipAddress.test(domain)) return false;
    return this.patterns.domain.test(domain);
  }
}

// ==================== 文件输出 ====================
class FileExporter {
  static generateHeader(config, domainCount, type = "") {
    return `# Generated at: ${format(new Date(), "yyyy-MM-dd HH:mm:ss")}
# Author: ${config.author}
# Distribution: ${config.distribution_url}
# Type: ${type || "all"}
# Total Domains: ${domainCount}
# ------------------------------------------
`;
  }

  static async exportDomains(domains, filePath, config) {
    // 保持 domain: 前缀，按域名排序
    const sortedDomains = domains.sort((a, b) => {
      const domainA = a.replace("domain:", "");
      const domainB = b.replace("domain:", "");
      return domainA.toLowerCase().localeCompare(domainB.toLowerCase());
    });

    const header = this.generateHeader(config, sortedDomains.length, "all");
    const content = sortedDomains.join("\n");
    await fs.writeFile(filePath, content);
  }

  static async exportDNSConfig(config, dnsEntries) {
    const sortedEntries = dnsEntries.sort((a, b) => {
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

// ==================== 主程序 ====================
class DNSConfigGenerator {
  constructor() {
    this.configManager = new ConfigManager();
    this.domainListResults = [];
    this.dnsConfigResults = [];
  }

  async run() {
    try {
      console.log("开始生成 DNS 配置...");

      // 加载配置
      const config = await this.configManager.load();

      // 确保 data 目录存在
      await fs.mkdir("data", { recursive: true });

      // 获取并解码数据
      const rawData = await DataFetcher.fetchData(config);

      // Base64 解码（GFWList 默认是 Base64 编码）
      let decodedData;
      try {
        decodedData = Buffer.from(rawData, "base64").toString("utf-8");
        // 检查解码是否成功（简单检查是否包含 AutoProxy 头或域名）
        if (
          !decodedData.includes("[AutoProxy") &&
          !decodedData.includes("||")
        ) {
          // 解码失败，可能是已经是明文
          decodedData = rawData;
        }
      } catch (e) {
        decodedData = rawData;
      }

      const lines = decodedData.split(/\r?\n/);

      // 处理域名
      const processor = new DomainProcessor(
        config.Whitelist_DNS,
        config.upstream_DNS,
      );

      // 处理两种输出
      this.domainListResults = processor.processBatchForDomainList(
        lines,
        config.debug,
      );
      this.dnsConfigResults = processor.processBatchForDNSConfig(
        lines,
        config.debug,
      );

      // 输出文件
      await FileExporter.exportDomains(
        this.domainListResults,
        config.domain_output,
        config,
      );
      await FileExporter.exportDNSConfig(config, this.dnsConfigResults);

      console.log(`\n✅ 完成！`);
      console.log(
        `   - 域名列表: ${config.domain_output} (${this.domainListResults.length} 个域名)`,
      );
      console.log(
        `   - DNS 配置: ${config.output_file} (${this.dnsConfigResults.length} 个条目)`,
      );

      if (config.debug && this.domainListResults.length > 0) {
        console.log("\n📝 域名列表前 10 个示例:");
        this.domainListResults.slice(0, 10).forEach((domain, i) => {
          console.log(`   ${i + 1}. ${domain}`);
        });
      }
    } catch (error) {
      console.error("❌ 执行失败:", error.message);
      process.exit(1);
    }
  }
}

// ==================== 启动 ====================
process.on("uncaughtException", (err) => {
  console.error("未捕获的异常:", err.message);
});

process.on("unhandledRejection", (reason) => {
  console.error("未处理的 Promise 拒绝:", reason);
});

// 立即执行函数
(async () => {
  const generator = new DNSConfigGenerator();
  await generator.run();
})();

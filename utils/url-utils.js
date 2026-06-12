import { SUSPICIOUS_TLD_PATTERNS } from './constants.js';

/**
 * Virus Detector — URL 解析工具
 *
 * 提供域名提取、主域解析、可疑 TLD 检测等 URL 处理能力。
 * 所有方法均为静态同步方法，依赖 constants.js 中的 SUSPICIOUS_TLD_PATTERNS。
 *
 * @module url-utils
 * @version 1.2.1
 */
export class UrlUtils {
  /**
   * 从完整URL中提取主机名（域名）
   * @param {string} url - 完整URL
   * @returns {string} 主机名
   */
  static extractHostname(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname;
    } catch (e) {
      // 尝试修复不完整的URL
      if (!url.startsWith('http')) {
        try {
          const fixed = new URL('https://' + url);
          return fixed.hostname;
        } catch (e2) {
          return url;
        }
      }
      return url;
    }
  }

  /**
   * 获取有效二级域名（eSLD）
   * 简化版本：取最后两个标签作为主域名
   * @param {string} hostname - 主机名
   * @returns {string} 主域名
   */
  static getMainDomain(hostname) {
    const parts = hostname.replace(/^www\./i, '').split('.');
    if (parts.length <= 2) {
      return hostname;
    }

    // 处理常见的双段TLD
    const doubleTlds = ['com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
                        'co.uk', 'co.jp', 'co.kr', 'com.hk', 'com.tw'];
    const tld2 = parts.slice(-2).join('.');
    const tld3 = parts.slice(-3).join('.');

    // 检查是否双段TLD
    if (doubleTlds.some(dt => hostname.endsWith('.' + dt))) {
      // 对于 .com.cn 等，返回最后3段
      return parts.slice(-3).join('.');
    }

    // 默认返回最后2段
    return parts.slice(-2).join('.');
  }

  /**
   * 检测域名是否包含可疑的嵌套TLD
   * @param {string} hostname - 主机名
   * @returns {boolean} 是否可疑
   */
  static hasSuspiciousNestedTLD(hostname) {
    return SUSPICIOUS_TLD_PATTERNS.some(pattern => pattern.test(hostname));
  }

  /**
   * 获取可疑TLD的详细信息
   * @param {string} hostname - 主机名
   * @returns {string[]} 匹配的可疑模式
   */
  static getSuspiciousTLDDetails(hostname) {
    const matches = [];
    for (const pattern of SUSPICIOUS_TLD_PATTERNS) {
      if (pattern.test(hostname)) {
        matches.push(pattern.source.replace(/\\/g, ''));
      }
    }
    return matches;
  }

  /**
   * 检查两个域名是否属于同一主域名
   * @param {string} hostname1
   * @param {string} hostname2
   * @returns {boolean}
   */
  static isSameMainDomain(hostname1, hostname2) {
    return this.getMainDomain(hostname1) === this.getMainDomain(hostname2);
  }

  /**
   * 检查URL是否使用HTTPS
   * @param {string} url
   * @returns {boolean}
   */
  static isHttps(url) {
    try {
      return new URL(url).protocol === 'https:';
    } catch (e) {
      return url.toLowerCase().startsWith('https://');
    }
  }

  /**
   * 获取URL的完整来源（协议+主机名）
   * @param {string} url
   * @returns {string}
   */
  static getOrigin(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.origin;
    } catch (e) {
      return url;
    }
  }

  /**
   * 从主机名中移除开头的www
   * @param {string} hostname
   * @returns {string}
   */
  static removeWWW(hostname) {
    return hostname.replace(/^www\./i, '');
  }
}

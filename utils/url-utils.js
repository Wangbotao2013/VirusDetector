/**
 * Virus Detector — URL 解析工具
 *
 * 提供域名提取、HTTPS 检测等 URL 处理能力。
 * 域名标准化由 RDAP 协议（RFC 9083）处理，不再依赖 PSL。
 *
 * @module url-utils
 * @version 2.2.3
 */

// ==================== UrlUtils 类 ====================

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
   * 从主机名中移除开头的 www
   * @param {string} hostname
   * @returns {string}
   */
  static removeWWW(hostname) {
    return hostname.replace(/^www\./i, '');
  }
}

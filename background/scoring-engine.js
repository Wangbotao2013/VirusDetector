/**
 * Virus Detector — 评分引擎 (Scoring Engine)
 *
 * 实现 5 规则评分体系，总分 >= 100 分时判定为危险网站。
 *
 * @module scoring-engine
 * @version 1.2.1
 *
 * 评分规则：
 *   规则一 域名仿冒       → 60 分 | 4 层递进：子串包含 → 段级关键词 → 可疑TLD → 编辑距离
 *   规则二 压缩包下载     → 40 分 | 域名已有 >=30 分嫌疑时给高分，否则 10 分弱信号
 *   规则三 ICP 备案缺失   → 50 分 | 对所有网站检测 ICP 备案号（不再限制 .cn 或中国品牌）
 *   规则四 链接分析       → 最高 70 分 | Part A (同页/死链/重复链接) + Part B (外链/下载按钮/文件)
 *   规则五 AI 生成特征    → 30 分 | HTML 简陋 + 无框架 + 内容丰富 = 疑似 AI 钓鱼页面
 *
 * 设计原则：
 *   - 所有规则方法均为纯同步计算，不发起网络请求（数据由 Content Script 预采集）
 *   - 规则可独立调用（如规则二支持下载事件单独触发后重新计算）
 */

import { DomainDatabase } from './domain-database.js';
import { IcpUtils } from './icp-utils.js';
import { UrlUtils } from '../utils/url-utils.js';
import {
  SCORE_THRESHOLD, SCORE_RULE_1, SCORE_RULE_2_HIGH, SCORE_RULE_2_LOW,
  SCORE_RULE_3, SCORE_RULE_5, RISK_LEVEL,
  SCORE_RULE_4A_SAME_PAGE, SCORE_RULE_4A_DEAD_LINK,
  SCORE_RULE_4A_DUPLICATE_LINK, SCORE_RULE_4A_DOWNLOAD_LINK_BONUS,
  SCORE_RULE_4B_DOWNLOAD_BTN, SCORE_RULE_4B_FILE_LINK, SCORE_RULE_4B_ARCHIVE_LINK,
  RULE_2_DOMAIN_SUSPICION_THRESHOLD,
  ARCHIVE_EXTENSIONS, AI_PAGE_THRESHOLDS, SAME_PAGE_LINK_THRESHOLD,
  DUPLICATE_LINK_THRESHOLD
} from '../utils/constants.js';

export class ScoringEngine {
  /**
   * 对指定标签页执行完整评估
   * @param {Object} ctx - 页面上下文
   * @returns {Object} 评估结果
   */
  static async evaluate(ctx) {
    const {
      url, domain, pageText, icpStrings, linkMetrics,
      downloadState, pageMetrics
    } = ctx;

    // 规则一：域名仿冒检测
    const result1 = this._evaluateRule1(domain);
    const existingScore = result1.score;

    // 规则三：ICP检测
    const result3 = this._evaluateRule3(domain, pageText, icpStrings, result1);

    // 规则四：链接分析（同步，无需网络）
    const result4 = this._evaluateRule4(linkMetrics, domain);

    // 规则五：代码工程化
    const result5 = this._evaluateRule5(pageMetrics, domain);

    // 规则二从下载状态获取（由下载事件异步触发）
    const result2 = this._evaluateRule2(downloadState, existingScore);

    const totalScore = result1.score + result2.score + result3.score + result4.score + result5.score;
    const isSuspicious = totalScore >= SCORE_THRESHOLD;

    return {
      totalScore,
      isSuspicious,
      riskLevel: isSuspicious ? RISK_LEVEL.WARNING : RISK_LEVEL.SAFE,
      breakdown: { rule1: result1, rule2: result2, rule3: result3, rule4: result4, rule5: result5 },
      matchedEntry: result1.matchedEntry || null,
      correctUrl: result1.correctUrl || null,
      officialName: result1.officialName || null,
      timestamp: Date.now()
    };
  }

  // ==================== 规则一：域名仿冒 (60分) ====================
  static _evaluateRule1(domain) {
    const result = {
      score: 0, triggered: false,
      detail: '', detailCN: '✓ 域名检查: 无异常',
      matchedEntry: null, correctUrl: null, officialName: null
    };

    // 精确匹配官方域名 → 安全
    const official = DomainDatabase.findByDomain(domain);
    if (official) {
      result.detail = '官方网站，域名匹配';
      result.detailCN = '✓ 域名: 官方网站';
      return result;
    }

    // 检测域名仿冒
    const spoof = DomainDatabase.detectSpoof(domain);
    if (spoof) {
      result.score = SCORE_RULE_1;  // +60
      result.triggered = true;
      result.matchedEntry = spoof.entry;
      result.correctUrl = spoof.correctUrl;
      result.officialName = spoof.entry.name;
      result.detail = `域名仿冒检测: ${spoof.matchedBy}`;
      result.detailCN = `✗ 域名仿冒: 疑似冒充「${spoof.entry.name}」(${spoof.correctUrl})`;
      return result;
    }

    // 可疑TLD但未匹配到具体品牌
    if (UrlUtils.hasSuspiciousNestedTLD(domain)) {
      result.score = SCORE_RULE_1;  // +60（可疑TLD本身就是强信号）
      result.triggered = true;
      result.detail = `检测到可疑嵌套域名: ${domain}`;
      result.detailCN = `✗ 域名可疑: 使用了非常见顶级域名 (${domain})`;
      return result;
    }

    return result;
  }

  // ==================== 规则二：压缩包下载 (40/10分) ====================
  static _evaluateRule2(downloadState, existingSuspicionScore) {
    const result = {
      score: 0, triggered: false,
      detail: '', detailCN: '✓ 下载检测: 未检测到压缩包',
      fileName: null
    };

    if (!downloadState || !downloadState.hasDownloadedArchive) {
      return result;
    }

    result.fileName = downloadState.archiveFileName || '未知文件';

    if (existingSuspicionScore >= RULE_2_DOMAIN_SUSPICION_THRESHOLD) {
      // 域名已有较高嫌疑 → +40
      result.score = SCORE_RULE_2_HIGH;
      result.triggered = true;
      result.detail = `下载压缩包: ${result.fileName} (域名已有${existingSuspicionScore}分嫌疑)`;
      result.detailCN = `✗ 下载检测: 从可疑站点下载压缩包 (${result.fileName})`;
    } else {
      // 弱信号 → +10
      result.score = SCORE_RULE_2_LOW;
      result.triggered = true;
      result.detail = `下载压缩包: ${result.fileName} (弱信号)`;
      result.detailCN = `⚠ 下载检测: 下载了压缩包 (${result.fileName})`;
    }

    return result;
  }

  // ==================== 规则三：ICP备案号缺失 (50分) ====================
  static _evaluateRule3(domain, pageText, icpStrings, rule1Result) {
    const result = {
      score: 0, triggered: false,
      detail: '', detailCN: '', icpFound: false, icpNumbers: []
    };

    // 如果是官方域名本尊，跳过
    const official = DomainDatabase.findByDomain(domain);
    if (official) {
      result.detail = '官方网站，ICP检查通过';
      result.detailCN = '✓ ICP备案: 官方网站';
      return result;
    }

    // 对所有网站搜索ICP备案号
    const icpResult = IcpUtils.searchIcpNumber(pageText, icpStrings);

    if (icpResult.found) {
      result.icpFound = true;
      result.icpNumbers = icpResult.numbers;
      result.detail = `检测到ICP备案号: ${icpResult.numbers[0]}`;
      result.detailCN = `✓ ICP备案: 已检测到 (${icpResult.numbers[0]})`;
    } else {
      result.score = SCORE_RULE_3;  // +50
      result.triggered = true;
      result.detail = `未检测到ICP备案号（域名${domain}）`;
      result.detailCN = `✗ ICP备案: 未检测到备案号`;
    }

    return result;
  }

  // ==================== 规则四：链接分析 ====================
  /**
   * ┌─ Part A（先执行）:
   * │  ① ≥3个链接指向当前页本身（完整URL完全一致）         → +20
   * │  ② ≥1个死链（指向不存在子页面，非hash/js占位）       → +20
   * │  ③ ≥4个不同元素指向同一个链接                         → +20
   * │     若该链接为下载链接（含down/download等）            → 再+10
   * │  ①+②+③ 可叠加（最高+70）
   * └─ Part B（仅当Part A总分为0时才执行）:
   *     a. 外链绑定在"下载"按钮上       → +10
   *     b. 外链指向文件                 → +10
   *        如果是压缩包格式               → 再+10
   */
  static _evaluateRule4(linkMetrics, domain) {
    const result = {
      score: 0, triggered: false,
      detail: '', detailCN: '✓ 链接分析: 正常'
    };

    if (!linkMetrics) {
      result.detail = '未收集到链接数据';
      result.detailCN = '- 链接分析: 未检测';
      return result;
    }

    let partAScore = 0;
    const partAReasons = [];

    // Part A-①：≥5个链接指向当前页本身（完整URL完全一致）
    if (linkMetrics.samePageLinks >= SAME_PAGE_LINK_THRESHOLD) {
      partAScore += SCORE_RULE_4A_SAME_PAGE;
      partAReasons.push(linkMetrics.samePageLinks + '个链接完全指向当前页');
    }

    // Part A-②：≥1个死链（HEAD请求验证为不存在子页面）
    if (linkMetrics.deadLinks >= 1) {
      partAScore += SCORE_RULE_4A_DEAD_LINK;
      partAReasons.push(linkMetrics.deadLinks + '个死链/不存在子页面');
    }

    // Part A-③：≥4个不同元素指向同一个链接
    if (linkMetrics.hasDuplicateLinks && linkMetrics.duplicateLinks) {
      for (const dup of linkMetrics.duplicateLinks) {
        if (dup.elementCount >= DUPLICATE_LINK_THRESHOLD) {
          partAScore += SCORE_RULE_4A_DUPLICATE_LINK;
          partAReasons.push(dup.elementCount + '个不同元素指向同一链接');
          // 附加分：该链接为下载链接
          if (dup.isDownloadLink) {
            partAScore += SCORE_RULE_4A_DOWNLOAD_LINK_BONUS;
            partAReasons.push('该重复链接为下载链接');
          }
          break; // 只计一次（取第一个满足条件的）
        }
      }
    }

    if (partAScore > 0) {
      result.score = partAScore;
      result.triggered = true;
      result.detail = '链接异常(Part A): ' + partAReasons.join('; ');
      result.detailCN = '✗ 链接分析: ' + partAReasons.join(', ') + ' (+' + partAScore + ')';
      return result;
    }

    // Part A 未触发 → Part B
    let partBScore = 0;
    const partBReasons = [];

    if (linkMetrics.externalWithDownloadText >= 1) {
      partBScore += SCORE_RULE_4B_DOWNLOAD_BTN;
      partBReasons.push(linkMetrics.externalWithDownloadText + '个外链在下载按钮上');
    }
    if (linkMetrics.externalFileLinks >= 1) {
      partBScore += SCORE_RULE_4B_FILE_LINK;
      partBReasons.push(linkMetrics.externalFileLinks + '个外链指向文件');
    }
    if (linkMetrics.externalArchiveLinks >= 1) {
      partBScore += SCORE_RULE_4B_ARCHIVE_LINK;
      partBReasons.push(linkMetrics.externalArchiveLinks + '个是压缩包');
    }

    if (partBScore > 0) {
      result.score = partBScore;
      result.triggered = true;
      result.detail = '外链风险(Part B): ' + partBReasons.join('; ');
      result.detailCN = '✗ 链接分析: ' + partBReasons.join(', ') + ' (+' + partBScore + ')';
    } else {
      result.detail = '链接分析未发现异常';
      result.detailCN = '✓ 链接分析: 正常';
    }

    return result;
  }

  // ==================== 规则五：AI生成页面特征 (30分) ====================
  /**
   * 检测AI生成页面的典型代码特征：
   * - HTML行数 < 300
   * - 外部脚本数 < 5
   * - 无主流框架痕迹
   * - 但页面文本内容 > 500字符（内容看似丰富）
   *
   * @param {Object} pageMetrics - 来自content script的页面度量
   */
  static _evaluateRule5(pageMetrics, domain) {
    const result = {
      score: 0, triggered: false,
      detail: '', detailCN: '✓ 代码工程化: 正常',
      metrics: pageMetrics || {}
    };

    if (!pageMetrics) {
      result.detail = '未收集到页面度量信息';
      result.detailCN = '- 代码工程化: 未检测';
      return result;
    }

    let flags = 0;
    const reasons = [];

    // 检查1: HTML行数过少
    if (pageMetrics.htmlLines > 0 && pageMetrics.htmlLines < AI_PAGE_THRESHOLDS.MIN_HTML_LINES) {
      flags++;
      reasons.push(`HTML仅${pageMetrics.htmlLines}行`);
    }

    // 检查2: 外部脚本数过少
    if (pageMetrics.externalScripts < AI_PAGE_THRESHOLDS.MIN_EXTERNAL_SCRIPTS) {
      flags++;
      reasons.push(`外部脚本仅${pageMetrics.externalScripts}个`);
    }

    // 检查3: 无主流框架痕迹
    if (pageMetrics.hasFrameworkMarkers === false) {
      flags++;
      reasons.push('未检测到主流框架');
    }

    // 检查4: 文本内容丰富（排除真正的空白页）
    if (pageMetrics.textLength < AI_PAGE_THRESHOLDS.MIN_TEXT_LENGTH) {
      // 文本太少，不触发（避免空白页误报）
      result.detail = '页面文本内容不足，跳过AI检测';
      result.detailCN = '- 代码工程化: 内容不足';
      return result;
    }

    // 判定：3个条件全部满足 → 高度可疑
    if (flags >= 3) {
      result.score = SCORE_RULE_5;  // +30
      result.triggered = true;
      result.detail = `AI生成页面特征: ${reasons.join('; ')}`;
      result.detailCN = `✗ 代码工程化: AI生成特征 (${reasons.join(', ')})`;
    } else if (flags >= 2) {
      // 2个条件满足 → 中度可疑，不额外加分但记录
      result.detail = `部分AI生成特征: ${reasons.join('; ')}`;
      result.detailCN = `⚠ 代码工程化: 部分可疑 (${reasons.join(', ')})`;
    }

    return result;
  }

  // ==================== 工具方法 ====================

  /**
   * 检测文件是否为压缩包格式
   * 三层检测：文件名扩展名 → 下载URL路径 → MIME类型
   * @param {string} filename - 文件名（可能为空）
   * @param {string} [url=''] - 下载URL（用于回退检测）
   * @param {string} [mime=''] - MIME类型（用于回退检测）
   * @returns {boolean}
   */
  static isArchiveFile(filename, url = '', mime = '') {
    // 第一层：文件名扩展名检测（增加空值安全检查）
    if (filename) {
      const lower = filename.toLowerCase();
      const matchByFilename = ARCHIVE_EXTENSIONS.some(ext => {
        if (ext.startsWith('.')) return lower.endsWith(ext);
        // 处理如 .tar.gz 的复合扩展名
        return lower.endsWith(ext);
      });
      if (matchByFilename) return true;
    }

    // 第二层：下载URL路径检测（去除查询参数后检查扩展名）
    if (url) {
      try {
        const urlObj = new URL(url);
        const pathname = urlObj.pathname.toLowerCase();
        const matchByUrl = ARCHIVE_EXTENSIONS.some(ext => {
          if (ext.startsWith('.')) return pathname.endsWith(ext);
          return pathname.endsWith(ext);
        });
        if (matchByUrl) return true;
      } catch (e) { /* URL解析失败，跳过此层检测 */ }
    }

    // 第三层：MIME类型检测（17种常见压缩包MIME类型）
    if (mime) {
      const ARCHIVE_MIME_TYPES = [
        'application/zip',
        'application/x-rar-compressed',
        'application/x-7z-compressed',
        'application/x-tar',
        'application/gzip',
        'application/x-bzip2',
        'application/x-xz',
        'application/x-compress',
        'application/x-iso9660-image',
        'application/vnd.ms-cab-compressed',
        'application/x-arj',
        'application/x-lzh',
        'application/zstd',
        'application/x-compressed-tar',
        'application/x-gzip',
        'application/x-bzip',
        'application/x-lzma'
      ];
      if (ARCHIVE_MIME_TYPES.includes(mime.toLowerCase())) return true;
    }

    return false;
  }
}

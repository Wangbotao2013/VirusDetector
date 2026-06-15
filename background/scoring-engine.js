/**
 * Virus Detector — 评分引擎 (Scoring Engine)
 *
 * 实现多规则评分体系，总分 >= 100 分时判定为危险网站。
 *
 * @module scoring-engine
 * @version 2.1.0-alpha.1
 *
 * 评分规则：
 *   规则一 域名仿冒         → 60 分 | 5 层递进：子串包含 → 段级关键词 → 可疑TLD → 关键词堆叠 → 编辑距离
 *   规则二 压缩包下载       → 40 分 | 域名已有 >=30 分嫌疑时给高分，否则 10 分弱信号
 *   规则三 ICP 备案缺失     → 50 分 | 对所有网站检测 ICP 备案号
 *   规则四 链接分析         → 最高 70 分 | Part A (同页/死链/重复链接) + Part B (下载按钮/压缩包链接)
 *   规则五 代码工程化       → 最高 30 分 | 三信号组合判定（DOM复杂度+框架检测+外部资源），2信号+20，3信号+30
 *   域名年龄评分             → 最高 60 分 | 基于 Whois API 的 S 型衰减函数计分，新注册域名更可疑
 *   域名年龄减分             → 最高 20 分 | 注册时间长的域名可抵消部分可疑分数（需当前分数 >= 20）
 *   下载链接跨域检测         → 最高 20 分 | 跨域下载 + 新注册域名附加分（由 Service Worker 下载事件触发）
 *
 * 优化策略：
 *   - 官方网站早期退出：域名+ICP 均确认安全后跳过规则四/五
 *   - 规则四 Part B-b 仅对压缩包链接加分，普通文件链接不再单独计分
 *   - 规则五区分三信号组合：DOM节点数+框架标记+外部资源，避免对正常简单页面误报
 *   - Whois API 查询结果缓存 24 小时，避免重复请求
 */

import { DomainDatabase } from './domain-database.js';
import { IcpUtils } from './icp-utils.js';
import { WhoisClient } from './whois-client.js';
import { UrlUtils } from '../utils/url-utils.js';
import {
  SCORE_THRESHOLD, SCORE_RULE_1, SCORE_RULE_2_HIGH, SCORE_RULE_2_LOW,
  SCORE_RULE_3, SCORE_RULE_5, SCORE_RULE_5_PARTIAL, RISK_LEVEL,
  SCORE_RULE_4A_SAME_PAGE, SCORE_RULE_4A_DEAD_LINK,
  SCORE_RULE_4A_DUPLICATE_LINK, SCORE_RULE_4A_DOWNLOAD_LINK_BONUS,
  SCORE_RULE_4B_DOWNLOAD_BTN, SCORE_RULE_4B_FILE_LINK, SCORE_RULE_4B_ARCHIVE_LINK,
  RULE_2_DOMAIN_SUSPICION_THRESHOLD,
  ARCHIVE_EXTENSIONS, AI_PAGE_THRESHOLDS, SAME_PAGE_LINK_THRESHOLD,
  DUPLICATE_LINK_THRESHOLD,
  SCORE_DOMAIN_AGE_MAX, DOMAIN_AGE_DECAY_A, DOMAIN_AGE_DECAY_B,
  SCORE_DOMAIN_AGE_BONUS_MAX, DOMAIN_AGE_BONUS_SCORE_THRESHOLD,
  DOMAIN_AGE_BONUS_MIN_DAYS, DOMAIN_AGE_BONUS_MAX_DAYS
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
    const result3 = this._evaluateRule3(domain, pageText, icpStrings);

    // 优化：域名检测和ICP检测均确认安全 → 跳过规则四/五（官方网站早期退出）
    const isConfirmedOfficial = (
      !result1.triggered && !result3.triggered &&
      result1.detailCN.startsWith('✓') && result3.detailCN.startsWith('✓')
    );

    let result4, result5;
    if (isConfirmedOfficial) {
      result4 = {
        score: 0, triggered: false,
        detail: '官方网站，跳过链接分析',
        detailCN: '✓ 链接分析: 官方网站'
      };
      result5 = {
        score: 0, triggered: false,
        detail: '官方网站，跳过代码工程化检查',
        detailCN: '✓ 代码工程化: 官方网站'
      };
    } else {
      result4 = this._evaluateRule4(linkMetrics, domain);
      result5 = this._evaluateRule5(pageMetrics, domain);
    }

    // 规则二从下载状态获取（由下载事件异步触发）
    const result2 = this._evaluateRule2(downloadState, existingScore);

    // 域名年龄评分（Whois API）：非官方域名时调用，基于注册天数 S 型衰减计分
    let domainAgeResult = { score: 0, triggered: false, detail: '', detailCN: '✓ 域名年龄: 未检测', creationDays: -1 };
    if (!isConfirmedOfficial) {
      domainAgeResult = await this._evaluateDomainAge(domain);
    }

    // 计算初步总分（减分前）
    const preliminaryScore = result1.score + result2.score + result3.score +
      result4.score + result5.score + domainAgeResult.score;

    // 域名年龄减分（Whois API）：仅当初步总分 >= 阈值时应用，基于注册时长抵消可疑性
    let ageBonusResult = { score: 0, triggered: false, detail: '', detailCN: '✓ 域名减分: 未应用', bonusScore: 0 };
    if (!isConfirmedOfficial && preliminaryScore >= DOMAIN_AGE_BONUS_SCORE_THRESHOLD) {
      ageBonusResult = await this._evaluateDomainAgeBonus(domain, preliminaryScore, domainAgeResult);
    }

    // 最终总分 = 初步总分 - 减分分值（减分用负数表示，相加即为减法）
    const totalScore = preliminaryScore + ageBonusResult.score;
    const isSuspicious = totalScore >= SCORE_THRESHOLD;

    return {
      totalScore,
      isSuspicious,
      riskLevel: isSuspicious ? RISK_LEVEL.WARNING : RISK_LEVEL.SAFE,
      breakdown: {
        rule1: result1, rule2: result2, rule3: result3, rule4: result4, rule5: result5,
        domainAge: domainAgeResult, ageBonus: ageBonusResult
      },
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
  /**
   * ICP 备案检测。
   *
   * 判定链路（不再依赖域名推测国籍）：
   *   1. 官方域名                       → 跳过（0 分）
   *   2. 页面中找到 ICP 备案号           → 安全（0 分）
   *   3. 未找到且站点在外国豁免白名单中    → 跳过（0 分，确定无需备案）
   *   4. 未找到但页面有显著中文内容       → +50 分（中国站点缺少备案）
   *   5. 未找到、不在白名单、也无中文内容  → +20 分（弱信号，不确定）
   */
  static _evaluateRule3(domain, pageText, icpStrings) {
    const result = {
      score: 0, triggered: false,
      detail: '', detailCN: '', icpFound: false, icpNumbers: []
    };

    // 1. 官方域名本尊 → 跳过
    const official = DomainDatabase.findByDomain(domain);
    if (official) {
      result.detail = '官方网站，ICP检查通过';
      result.detailCN = '✓ ICP备案: 官方网站';
      return result;
    }

    // 2. 搜索 ICP 备案号
    const icpResult = IcpUtils.searchIcpNumber(pageText, icpStrings);

    if (icpResult.found) {
      result.icpFound = true;
      result.icpNumbers = icpResult.numbers;
      result.detail = `检测到ICP备案号: ${icpResult.numbers[0]}`;
      result.detailCN = `✓ ICP备案: 已检测到 (${icpResult.numbers[0]})`;
      return result;
    }

    // 3. 未找到 → 判定是否需要备案
    // 3a. 外国站点豁免白名单 → 确定不需要 ICP
    if (IcpUtils.isIcpExempt(domain)) {
      result.detail = `外国站点（${domain}），ICP检查不适用`;
      result.detailCN = '- ICP备案: 外国站点（不适用）';
      return result;
    }

    // 3b. 页面内容检测：有显著中文内容 → 中国站点，必须有 ICP
    const cjkResult = IcpUtils.detectCJKContent(pageText);
    if (cjkResult.hasCJK) {
      result.score = SCORE_RULE_3;  // +50
      result.triggered = true;
      result.detail = `未检测到ICP备案号（域名${domain}，页面含${cjkResult.cjkCount}个中文字符，占比${(cjkResult.cjkRatio * 100).toFixed(1)}%）`;
      result.detailCN = `✗ ICP备案: 未检测到备案号`;
      return result;
    }

    // 3c. 不在白名单 + 无 CJK 内容 → 弱信号
    result.score = 20;
    result.detail = `无中文内容且非已知外国站点（域名${domain}），缺少ICP为弱信号`;
    result.detailCN = `⚠ ICP备案: 未检测到备案号（弱信号）`;

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
   *     b. 外链指向压缩包格式文件       → +10
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
    // Part B-b：仅压缩包链接加分（普通文件链接不再单独计分）
    if (linkMetrics.externalArchiveLinks >= 1) {
      partBScore += SCORE_RULE_4B_ARCHIVE_LINK;
      partBReasons.push(linkMetrics.externalArchiveLinks + '个外链指向压缩包');
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

  // ==================== 规则五：代码工程化检测（最高30分） ====================
  /**
   * 检测页面代码质量，基于三信号组合判定体系：
   *
   * 前提：页面文本内容 > 500 字符（排除空白/占位页面，避免误报）
   *
   * 三信号：
   *   信号1 — DOM节点数 < 100       （页面结构过于简单，不受HTML格式化影响）
   *   信号2 — 无主流框架痕迹         （HTML标记 + window全局变量双重检测）
   *   信号3 — 外部资源去重总数 < 5    （脚本+样式+图片+字体+媒体，不含同源资源）
   *
   * 组合判定（信号数替代原OR逻辑，降低对正常简单页面的误报）：
   *   3/3 信号全中 → +30 分（高度可疑：经典钓鱼空壳三特征齐备）
   *   2/3 信号命中 → +20 分（中度可疑：两个维度异常）
   *   0-1 信号     →   0 分（证据不足，不单独加分）
   *
   * 设计原则：
   *   - 正常页面几乎不会三信号全中（即有外部资源、有框架、DOM复杂）
   *   - 单信号在正常页面中常见（如简单博客无框架），不应处罚
   *   - 钓鱼/AI生成页面通常同时满足多个信号，组合判定可精准识别
   *
   * @param {Object} pageMetrics - 来自 content script 的页面度量
   * @param {string} domain - 页面域名（保留参数，供未来扩展）
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

    // 前提检查：文本内容太少 → 跳过（避免空白页/占位页误报）
    if (pageMetrics.textLength < AI_PAGE_THRESHOLDS.MIN_TEXT_LENGTH) {
      result.detail = '页面文本内容不足，跳过代码工程化检测';
      result.detailCN = '- 代码工程化: 内容不足';
      return result;
    }

    const domNodeCount = pageMetrics.domNodeCount || 0;
    const hasExternal = !!(pageMetrics.hasExternalResources);
    const totalExternal = pageMetrics.totalExternalResources || 0;
    const hasFramework = !!(pageMetrics.hasFrameworkMarkers);

    // 收集命中的信号（而非简单的 flags 计数）
    const signals = [];

    // 信号1：DOM节点数过少（页面结构复杂度不足）
    // 使用 DOM 节点总数替代 HTML 行数，不受代码压缩/格式化影响
    if (domNodeCount > 0 && domNodeCount < AI_PAGE_THRESHOLDS.MIN_DOM_NODES) {
      signals.push(`DOM节点仅${domNodeCount}个`);
    }

    // 信号2：无主流框架痕迹
    // content-script 已通过 HTML全文扫描 + window全局变量双重检测
    if (!hasFramework) {
      signals.push('未检测到主流框架');
    }

    // 信号3：外部资源过少
    // 使用去重后的外部资源总数，合理反映页面是否依赖外部基础设施
    if (!hasExternal || totalExternal < AI_PAGE_THRESHOLDS.MIN_EXTERNAL_RESOURCES) {
      signals.push(`外部资源仅${totalExternal}个`);
    }

    const signalCount = signals.length;

    // 组合判定
    if (signalCount >= AI_PAGE_THRESHOLDS.RULE_5_SIGNALS_FULL) {
      // 3/3 信号全中 → 高度可疑（经典钓鱼空壳：结构简单+无框架+无外部资源）
      result.score = SCORE_RULE_5;  // +30
      result.triggered = true;
      result.detail = `代码工程质量差(${signalCount}/3信号): ${signals.join('; ')}`;
      result.detailCN = `✗ 代码工程化: 高度可疑 (${signals.join(', ')})`;
    } else if (signalCount >= AI_PAGE_THRESHOLDS.RULE_5_SIGNALS_PARTIAL) {
      // 2/3 信号命中 → 中度可疑
      result.score = SCORE_RULE_5_PARTIAL;  // +20
      result.triggered = true;
      result.detail = `代码工程化弱信号(${signalCount}/3信号): ${signals.join('; ')}`;
      result.detailCN = `⚠ 代码工程化: 中度可疑 (${signals.join(', ')})`;
    } else if (signalCount === 1) {
      // 1/3 信号 → 证据不足，不扣分（正常简单页面常有单个弱特征）
      result.detail = `代码工程化基本正常（仅${signals[0]}）`;
      result.detailCN = '✓ 代码工程化: 基本正常';
    } else {
      // 0/3 信号 → 完全正常
      result.detail = '代码工程化检测通过（DOM节点' + domNodeCount + '，外部资源' + totalExternal + '个）';
      result.detailCN = '✓ 代码工程化: 正常';
    }

    return result;
  }

  // ==================== 域名年龄评分（Whois API） ====================
  /**
   * 基于 Whois API 返回的域名注册天数（creation_days），通过 S 型衰减函数
   * 计算可疑加分。新注册的域名（creation_days 小）得分更高。
   *
   * 公式：score = floor(MAX / (1 + (x / (60 * b))^a))
   *   其中 x = creation_days, MAX = SCORE_DOMAIN_AGE_MAX,
   *       a = DOMAIN_AGE_DECAY_A, b = DOMAIN_AGE_DECAY_B
   *
   * 设计原理：
   *   - 新注册域名（x → 0）：分母 → 1，score → MAX（最高可疑）
   *   - 随注册天数增加：分母增大，score 衰减
   *   - 注册很久的域名（x 很大）：分母 → ∞，score → 0
   *
   * @param {string} domain - 当前页面域名
   * @returns {Promise<Object>} 包含 score, triggered, detail, detailCN, creationDays 的结果
   */
  static async _evaluateDomainAge(domain) {
    const result = {
      score: 0, triggered: false,
      detail: '', detailCN: '✓ 域名年龄: 正常',
      creationDays: -1
    };

    // 调用 Whois API
    const whoisResult = await WhoisClient.lookup(domain);

    // API 真正失败（网络错误、HTTP 异常、解析失败等）
    if (!whoisResult) {
      const errInfo = WhoisClient.lastError;
      const errPhase = errInfo ? ` [${errInfo.phase}]` : '';
      const errMsg = errInfo ? `: ${errInfo.message}` : '';
      result.detail = `Whois API 查询失败${errPhase}${errMsg} (${domain})`;
      result.detailCN = `- 域名年龄: API 查询失败${errPhase}`;
      return result;
    }

    // API 调用成功，但 creation_days 数据未知或不可靠（如免费 API 返回 0 作为占位值）
    if (whoisResult.creationDays < 0) {
      result.detail = `Whois API 返回的域名注册天数未知 (${domain})`;
      result.detailCN = '- 域名年龄: 注册时间未知';
      return result;
    }

    const x = whoisResult.creationDays;
    result.creationDays = x;

    // S 型衰减函数：score = floor(MAX / (1 + (x / (60 * b))^a))
    const denominator = 1 + Math.pow(x / (60 * DOMAIN_AGE_DECAY_B), DOMAIN_AGE_DECAY_A);
    const rawScore = SCORE_DOMAIN_AGE_MAX / denominator;
    const score = Math.floor(rawScore);

    if (score > 0) {
      result.score = score;
      result.triggered = true;
      result.detail = `域名注册仅${x}天（Whois），可疑加分+${score}（raw=${rawScore.toFixed(2)}）`;
      result.detailCN = `✗ 域名年龄: 注册仅${x}天，可疑 +${score}`;
    } else {
      result.detail = `域名注册${x}天（Whois），年龄正常`;
      result.detailCN = `✓ 域名年龄: 已注册${x}天`;
    }

    return result;
  }

  // ==================== 域名年龄减分（Whois API） ====================
  /**
   * 基于域名注册天数对已累积的可疑分数进行抵消。
   *
   * 减分公式（x = creation_days）：
   *   x < 180             → bonus = 0（新域名不减分）
   *   180 ≤ x < 730       → bonus = floor(MAX_BONUS * (x - 180) / (730 - 180))
   *   x ≥ 730             → bonus = MAX_BONUS（长期注册域名获最大减分）
   *
   * 执行条件：仅当 preliminaryScore >= DOMAIN_AGE_BONUS_SCORE_THRESHOLD 时调用。
   *
   * @param {string} domain        - 当前页面域名
   * @param {number} preliminaryScore - 应用减分前的可疑总分
   * @param {Object} domainAgeResult   - 域名年龄评分结果（复用 creationDays 避免重复 API 调用）
   * @returns {Promise<Object>} 包含 score（负数）, triggered, detail, detailCN, bonusScore 的结果
   */
  static async _evaluateDomainAgeBonus(domain, preliminaryScore, domainAgeResult) {
    const result = {
      score: 0, triggered: false,
      detail: '', detailCN: '✓ 域名减分: 未应用',
      bonusScore: 0
    };

    // 优先复用域名年龄评分中的 creationDays，避免重复 API 调用
    let creationDays = domainAgeResult?.creationDays ?? -1;
    if (creationDays < 0) {
      // 不再重试 API：_evaluateDomainAge 已经调用过 WhoisClient，
      // 若 creationDays < 0 说明数据确实不可用（免费 API 对此域名无数据），
      // 重复请求只会浪费 API 配额并增加延迟（速率限制器每两次请求间隔 2s）
      result.detail = `域名注册天数未知，无法应用域名年龄减分`;
      result.detailCN = '- 域名减分: 注册时间未知';
      return result;
    }

    const x = creationDays;

    // 计算减分分值（正数，表示减去的分数）
    let bonusScore = 0;
    if (x < DOMAIN_AGE_BONUS_MIN_DAYS) {
      // x < 180：新域名，不减分
      bonusScore = 0;
    } else if (x < DOMAIN_AGE_BONUS_MAX_DAYS) {
      // 180 ≤ x < 730：线性插值
      bonusScore = Math.floor(
        SCORE_DOMAIN_AGE_BONUS_MAX * (x - DOMAIN_AGE_BONUS_MIN_DAYS) /
        (DOMAIN_AGE_BONUS_MAX_DAYS - DOMAIN_AGE_BONUS_MIN_DAYS)
      );
    } else {
      // x ≥ 730：封顶最大减分
      bonusScore = SCORE_DOMAIN_AGE_BONUS_MAX;
    }

    if (bonusScore > 0) {
      // 减分分值不能超过当前可疑分数（避免分数变为负数）
      const effectiveBonus = Math.min(bonusScore, preliminaryScore);
      result.score = -effectiveBonus; // 负数表示减分
      result.bonusScore = effectiveBonus;
      result.triggered = true;
      result.detail = `域名注册${x}天，年龄减分-${effectiveBonus}（原始bonus=${bonusScore}，减分前=${preliminaryScore}）`;
      result.detailCN = `✓ 域名减分: 已注册${x}天，年龄抵消 -${effectiveBonus}`;
    } else {
      result.detail = `域名注册${x}天，不足${DOMAIN_AGE_BONUS_MIN_DAYS}天，不适用减分`;
      result.detailCN = `- 域名减分: 仅注册${x}天，不适用`;
    }

    return result;
  }

  // ==================== 下载链接跨域检测（Whois API） ====================
  /**
   * 检测下载链接的域名是否与当前页面跨域，以及下载链接域名是否为新注册。
   * 由 Service Worker 的下载事件处理程序调用。
   *
   * 判定逻辑：
   *   1. 从下载 URL 提取域名，与当前页面域名比较主域名
   *   2. 同主域名 → 不加分（0 分）
   *   3. 跨域 → +10 分（SCORE_DOWNLOAD_CROSS_DOMAIN）
   *   4. 跨域 且 Whois API 返回 valid_days < 365 且 creation_days < 90 → 再 +10 分
   *
   * @param {string} downloadUrl - 下载文件的完整 URL
   * @param {string} pageDomain   - 当前页面的域名
   * @returns {Promise<Object>} 包含 score, triggered, detail, detailCN, downloadDomain, whoisResult 的结果
   */
  static async evaluateDownloadLink(downloadUrl, pageDomain) {
    const result = {
      score: 0, triggered: false,
      detail: '', detailCN: '✓ 下载链接: 同域下载',
      downloadDomain: '',
      whoisResult: null
    };

    if (!downloadUrl || !pageDomain) return result;

    // 提取下载链接的域名
    let downloadDomain;
    try {
      const urlObj = new URL(downloadUrl);
      downloadDomain = urlObj.hostname.toLowerCase();
    } catch (e) {
      result.detail = '无法解析下载链接URL';
      result.detailCN = '- 下载链接: URL 解析失败';
      return result;
    }

    result.downloadDomain = downloadDomain;

    // 提取主域名（去掉子域名）进行比较
    const pageMainDomain = UrlUtils.getMainDomain(pageDomain);
    const downloadMainDomain = UrlUtils.getMainDomain(downloadDomain);

    // 同主域名 → 不跨域，不加分
    if (pageMainDomain === downloadMainDomain) {
      result.detail = `下载链接同域 (${downloadDomain})，不加分`;
      result.detailCN = `✓ 下载链接: 同域 (${downloadDomain})`;
      return result;
    }

    // 跨域 → 基础加分 +10
    result.score = 10;
    result.triggered = true;
    result.detail = `下载链接跨域 (${downloadDomain} ≠ ${pageDomain})，+10`;
    result.detailCN = `✗ 下载链接: 跨域下载 (${downloadDomain}) +10`;

    // 查询下载链接域名的 Whois 信息，检查是否为新注册域名
    const whoisResult = await WhoisClient.lookup(downloadDomain);
    result.whoisResult = whoisResult;

    if (whoisResult && whoisResult.creationDays >= 0 && whoisResult.validDays >= 0) {
      // 条件：valid_days < 365 且 creation_days < 90 → 新注册域名额外加分
      if (whoisResult.validDays < 365 && whoisResult.creationDays < 90) {
        result.score += 10;
        result.detail += `，新注册域名（注册${whoisResult.creationDays}天，剩余${whoisResult.validDays}天）再+10`;
        result.detailCN += `，新注册域名 +10（${whoisResult.creationDays}天）`;
      }
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

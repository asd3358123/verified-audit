[English](README.md) | **繁體中文**

# verified-audit

**做程式碼安全稽核時,「單一強 agent + load-bearing 驗證」在 recall 上跟 multi-agent fan-out 打平 —— 但成本只要 1/8。這個 repo 給你方法、證據、和一個能跑的 Go CI 工具。**

多數「AI 程式碼稽核」不是用一堆幻覺發現淹死你,就是 fan-out 成幾十個 agent、賭「量 = recall」。這個 repo 主張、而且**實際量測**了相反的事:

> 價值不在找得「更多」,而在你報出來的東西是「**真的**」—— 真到可以**無人盯著**(CI gate、排程 triage、批次掃很多 repo)、不必有人逐條複查。

## 三塊,一個故事

| | 是什麼 | 在哪 |
|---|---|---|
| **證據** | 一個 benchmark:遞迴 / fan-out 分解 vs 單一強 agent,跨 5 種配置。fan-out **從沒贏過**。 | [`bench/`](bench/) |
| **方法** | `verified-audit`:單一強 agent → 確定性 + 對抗式驗證 → **失敗大聲講、絕不靜默**。 | [`METHODOLOGY.md`](METHODOLOGY.md) · [`skill/`](skill/) |
| **工具** | 一個 headless Go 安全稽核,把方法接進 CI:`deadcode` 判可達性(確定性)+ LLM 判語義(只在可達的代碼上)。 | [`tool/`](tool/) |

三塊互相加持:benchmark 是「為什麼該信這方法」、方法是「怎麼做」、工具是「今天就能跑的參考實作」。

## 核心想法

1. **可達性是確定性工具的活,不是 LLM 的。** [`deadcode`](https://pkg.go.dev/golang.org/x/tools/cmd/deadcode) 建全程式呼叫圖;落在「確定不可達」函式裡的發現,**不花一次 LLM call 就 auto-refute**。LLM 是被「告知」可達性、而非用猜的 —— 這就是壓掉大多數誤報的關鍵。

2. **驗證是 load-bearing 的。** 每條發現都要過 (a) 確定性檢查 —— 引用的 `file:line` 真的含那個構造 —— 和 (b) 一個對抗式 skeptic 試著推翻它、不確定就預設「不是洞」。LLM 自評會 over-claim;這一步才讓輸出在無人盯著時可信。

3. **失敗絕不能看起來像「乾淨」。** audit call 解析失敗 → 報告頂部標**掃描不完整**,不是當成空。verify call 失敗 → 發現進 **inconclusive** 桶,絕不靜默丟掉 —— 因為「靜默吃掉一條真洞」是安全 gate 最危險的失敗模式。

4. **追 source,不只看 sink。** 注入類的發現,sink 被 confirmed 也只是 provisional,要追到值的來源 —— LLM 很會抓 `fmt.Sprintf` 拼 SQL,但常**假設**輸入可控。若每個 caller 都傳常數,那是 hardening note,不是可利用漏洞。

5. **單一強 agent,不是 fan-out。** 跨 5 種配置量測(4–46 個植入缺陷;強/弱模型;強制/非強制分解;最多 90 檔):fan-out **從沒在 recall 上贏過**單一強 agent —— 只多花成本、多噴誤報。見 [`bench/`](bench/)。

## 快速開始(任何 Go repo)

```bash
pip install openai
go install golang.org/x/tools/cmd/deadcode@v0.47.0
export OPENROUTER_API_KEY=...     # OpenAI 相容;預設走 OpenRouter 用 Claude

python tool/verified_audit.py \
  --repo /path/to/your/go/repo \
  --paths ./internal/handler ./pkg/auth \
  --out report.md
```

接進 Gitea / GitHub Actions 當**出貨前安全 gate**,見 [`tool/README.md`](tool/README.md)。

**或者,指向你本來就在跑的掃描器。** `--sarif gosec.sarif` 把同一套 verify + 可達性層套在 gosec / semgrep / CodeQL 的輸出上,**砍掉它們的誤報**(還附理由)—— 通常這才是最划算的用法,因為多數團隊都被 SAST 噪音淹死。

## 這東西為什麼存在(一段誠實話)

它一開始是個*遞迴 multi-agent 框架*。它自己的 benchmark 否證了它的核心假設 —— 遞迴分解從沒贏過單一強 agent。活下來、也就是這個 repo 的,是經得起量測的那塊:**單一強 agent + 驗證**。那個證偽原始想法的 benchmark 是**刻意**收進來的 —— 證據本身就是重點。

## 結構

```
README.md         英文版 — 主敘事
README.zh-TW.md   本檔
METHODOLOGY.md    方法,runtime-agnostic(自己搭的指南)
skill/            Claude Code drop-in skill
tool/             Go 稽核工具 + CI workflow 範例
bench/            benchmark harness + 負面結果
examples/         配置範例
```

## 授權
[MIT](LICENSE)。

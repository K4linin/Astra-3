#!/usr/bin/env python3
"""
 =============================================================================
 Report Generator - Генерация отчетов о фаззинг-тестах
 =============================================================================
 
 Описание:
   Генерация отчетов в различных форматах:
   - HTML с графиками и интерактивными элементами
   - Markdown для GitHub/GitLab
   - JSON для интеграции с другими системами
   - JUnit XML для CI систем
   
 Использование:
   python generate_report.py --target <target> [options]
"""

import argparse
import base64
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ReportConfig:
    """Конфигурация генератора отчетов"""
    target: str
    logs_dir: Path
    crashes_dir: Path
    reports_dir: Path
    formats: List[str] = field(default_factory=lambda: ['html', 'markdown', 'json'])
    include_corpus: bool = False
    include_inputs: bool = False
    theme: str = 'default'


class ReportGenerator:
    """
    Генератор отчетов о фаззинг-тестах
    
    Создает отчеты в нескольких форматах:
    - HTML: интерактивный отчет с графиками
    - Markdown: для GitHub Pull Requests
    - JSON: для интеграции с CI системами
    - JUnit XML: для совместимости с CI инструментами
    """
    
    def __init__(self, config: ReportConfig):
        self.config = config
        self.data = {
            'target': config.target,
            'timestamp': datetime.now().isoformat(),
            'stats': {},
            'crashes': [],
            'coverage': {},
            'corpus': {}
        }
    
    def log(self, message: str) -> None:
        """Логирование"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} [ReportGenerator] {message}")
    
    def load_data(self) -> None:
        """Загрузка данных из логов и крашей"""
        self.log(f"Loading data for target: {self.config.target}")
        
        # Загружаем статистику
        stats_file = self.config.logs_dir / 'stats.json'
        if stats_file.exists():
            with open(stats_file) as f:
                self.data['stats'] = json.load(f)
        
        # Загружаем краши
        crash_analysis_file = self.config.reports_dir / f"{self.config.target}_crash_analysis.json"
        if crash_analysis_file.exists():
            with open(crash_analysis_file) as f:
                crash_data = json.load(f)
                self.data['crashes'] = crash_data.get('crashes', [])
                self.data['clusters'] = crash_data.get('clusters', [])
        
        # Загружаем логи
        log_file = self.config.logs_dir / 'fuzzing.log'
        if log_file.exists():
            with open(log_file, 'r', errors='ignore') as f:
                self.data['log_content'] = f.read()
        
        # Подсчитываем corpus
        corpus_dir = self.config.crashes_dir.parent / 'corpus' / self.config.target
        if corpus_dir.exists():
            corpus_files = list(corpus_dir.glob('*'))
            self.data['corpus'] = {
                'count': len(corpus_files),
                'total_size': sum(f.stat().st_size for f in corpus_files if f.is_file())
            }
    
    def generate_html(self) -> str:
        """Генерация HTML отчета"""
        template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fuzzing Report - {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #f6f8fa;
            color: #24292f;
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        .header h1 {{ font-size: 2em; margin-bottom: 10px; }}
        .header .meta {{ opacity: 0.9; font-size: 0.9em; }}
        .card {{ 
            background: white;
            border-radius: 10px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .card-header {{ 
            background: #f6f8fa;
            padding: 15px 20px;
            border-bottom: 1px solid #e1e4e8;
            font-weight: 600;
        }}
        .card-body {{ padding: 20px; }}
        .stats-grid {{ 
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }}
        .stat-box {{ 
            background: #f6f8fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-box .value {{ 
            font-size: 2em;
            font-weight: bold;
            color: #0969da;
        }}
        .stat-box .label {{ color: #57606a; font-size: 0.9em; }}
        .stat-box.danger .value {{ color: #cf222e; }}
        .stat-box.success .value {{ color: #1a7f37; }}
        .crashes-table {{ width: 100%; border-collapse: collapse; }}
        .crashes-table th, .crashes-table td {{ 
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e1e4e8;
        }}
        .crashes-table th {{ background: #f6f8fa; font-weight: 600; }}
        .crashes-table tr:hover {{ background: #f6f8fa; }}
        .badge {{ 
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: 600;
        }}
        .badge-critical {{ background: #ffebe9; color: #cf222e; }}
        .badge-high {{ background: #fff3cd; color: #8a6914; }}
        .badge-medium {{ background: #ddf4ff; color: #0969da; }}
        .badge-low {{ background: #dafbe1; color: #1a7f37; }}
        .progress-bar {{ 
            background: #e1e4e8;
            border-radius: 4px;
            height: 20px;
            overflow: hidden;
        }}
        .progress-bar .fill {{ 
            height: 100%;
            background: linear-gradient(90deg, #1a7f37, #2ea44f);
            transition: width 0.3s;
        }}
        pre {{ 
            background: #f6f8fa;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
            font-size: 0.85em;
        }}
        .status-passed {{ color: #1a7f37; }}
        .status-failed {{ color: #cf222e; }}
        .footer {{ 
            text-align: center;
            padding: 20px;
            color: #57606a;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🧪 Fuzzing Report</h1>
            <div class="meta">
                <div>Target: <strong>{target}</strong></div>
                <div>Generated: {timestamp}</div>
            </div>
        </div>
        
        <div class="card">
            <div class="card-header">📊 Summary</div>
            <div class="card-body">
                <div class="stats-grid">
                    <div class="stat-box {status_class}">
                        <div class="value">{status_icon} {status_text}</div>
                        <div class="label">Status</div>
                    </div>
                    <div class="stat-box">
                        <div class="value">{total_executions:,}</div>
                        <div class="label">Total Executions</div>
                    </div>
                    <div class="stat-box {crashes_class}">
                        <div class="value">{total_crashes}</div>
                        <div class="label">Crashes Found</div>
                    </div>
                    <div class="stat-box">
                        <div class="value">{corpus_size}</div>
                        <div class="label">Corpus Size</div>
                    </div>
                    <div class="stat-box">
                        <div class="value">{unique_crashes}</div>
                        <div class="label">Unique Crashes</div>
                    </div>
                    <div class="stat-box">
                        <div class="value">{exec_per_sec:.1f}</div>
                        <div class="label">Executions/sec</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <div class="card-header">🐛 Crashes ({crashes_count})</div>
            <div class="card-body">
                {crashes_table}
            </div>
        </div>
        
        {clusters_section}
        
        <div class="card">
            <div class="card-header">📁 Coverage</div>
            <div class="card-body">
                <div class="stats-grid">
                    <div class="stat-box">
                        <div class="value">{coverage_edges:,}</div>
                        <div class="label">Edges Covered</div>
                    </div>
                    <div class="stat-box">
                        <div class="value">{coverage_blocks:,}</div>
                        <div class="label">Blocks Covered</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            Generated by Fuzzing Report Generator | {timestamp}
        </div>
    </div>
</body>
</html>'''
        
        # Подготавливаем данные для шаблона
        stats = self.data.get('stats', {})
        crashes = self.data.get('crashes', [])
        clusters = self.data.get('clusters', [])
        corpus = self.data.get('corpus', {})
        
        total_crashes = len(crashes)
        unique_crashes = len([c for c in crashes if c.get('is_unique', True)])
        
        # Статус
        status_class = 'success' if total_crashes == 0 else 'danger'
        status_text = 'PASSED' if total_crashes == 0 else 'FAILED'
        status_icon = '✅' if total_crashes == 0 else '❌'
        crashes_class = 'success' if total_crashes == 0 else 'danger'
        
        # Таблица крашей
        if crashes:
            crashes_rows = []
            for c in crashes[:20]:  # Показываем первые 20
                severity = c.get('severity', 'medium')
                badge_class = f'badge-{severity}'
                crashes_rows.append(f'''
                    <tr>
                        <td><code>{c.get('crash_id', 'N/A')}</code></td>
                        <td><span class="badge {badge_class}">{c.get('crash_type', 'Unknown')}</span></td>
                        <td><span class="badge {badge_class}">{severity}</span></td>
                        <td>{'Yes' if c.get('is_false_positive') else 'No'}</td>
                        <td>{c.get('cluster_id', '-')}</td>
                    </tr>
                ''')
            crashes_table = f'''
                <table class="crashes-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Type</th>
                            <th>Severity</th>
                            <th>False Positive</th>
                            <th>Cluster</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(crashes_rows)}
                    </tbody>
                </table>
            '''
        else:
            crashes_table = '<p style="color: #1a7f37;">✅ No crashes found during fuzzing.</p>'
        
        # Кластеры
        if clusters:
            cluster_rows = []
            for cluster in clusters[:10]:
                cluster_rows.append(f'''
                    <div class="stat-box">
                        <div class="value">{cluster.get('crash_count', 0)}</div>
                        <div class="label">{cluster.get('cluster_id', 'N/A')}</div>
                    </div>
                ''')
            clusters_section = f'''
                <div class="card">
                    <div class="card-header">🔍 Crash Clusters ({len(clusters)})</div>
                    <div class="card-body">
                        <div class="stats-grid">
                            {"".join(cluster_rows)}
                        </div>
                    </div>
                </div>
            '''
        else:
            clusters_section = ''
        
        # Заполняем шаблон
        html = template.format(
            target=self.config.target,
            timestamp=self.data['timestamp'],
            status_class=status_class,
            status_text=status_text,
            status_icon=status_icon,
            crashes_class=crashes_class,
            total_executions=stats.get('total_executions', 0),
            total_crashes=total_crashes,
            corpus_size=corpus.get('count', 0),
            unique_crashes=unique_crashes,
            exec_per_sec=stats.get('executions_per_second', 0),
            crashes_count=total_crashes,
            crashes_table=crashes_table,
            clusters_section=clusters_section,
            coverage_edges=stats.get('coverage_edges', 0),
            coverage_blocks=stats.get('coverage_blocks', 0)
        )
        
        return html
    
    def generate_markdown(self) -> str:
        """Генерация Markdown отчета"""
        stats = self.data.get('stats', {})
        crashes = self.data.get('crashes', [])
        clusters = self.data.get('clusters', [])
        corpus = self.data.get('corpus', {})
        
        total_crashes = len(crashes)
        status = '✅ PASSED' if total_crashes == 0 else '❌ FAILED'
        
        md = f'''# 🧪 Fuzzing Report: `{self.config.target}`

**Generated:** {self.data['timestamp']}

## Summary

| Metric | Value |
|--------|-------|
| Status | {status} |
| Total Executions | {stats.get('total_executions', 0):,} |
| Crashes Found | {total_crashes} |
| Unique Crashes | {len([c for c in crashes if c.get('is_unique', True)])} |
| Corpus Size | {corpus.get('count', 0)} |
| Executions/sec | {stats.get('executions_per_second', 0):.1f} |

'''
        
        if crashes:
            md += '''## 🐛 Crashes

| ID | Type | Severity | False Positive | Cluster |
|----|------|----------|----------------|---------|
'''
            for c in crashes[:20]:
                md += f"| `{c.get('crash_id', 'N/A')}` | {c.get('crash_type', 'Unknown')} | {c.get('severity', 'medium')} | {'Yes' if c.get('is_false_positive') else 'No'} | {c.get('cluster_id', '-')} |\n"
        
        if clusters:
            md += f'''
## 🔍 Crash Clusters ({len(clusters)})

'''
            for cluster in clusters[:10]:
                md += f"- **{cluster.get('cluster_id', 'N/A')}**: {cluster.get('crash_count', 0)} crashes\n"
        
        md += f'''
## 📊 Coverage

- **Edges Covered:** {stats.get('coverage_edges', 0):,}
- **Blocks Covered:** {stats.get('coverage_blocks', 0):,}

---

_Report generated by Fuzzing Testing Suite_
'''
        
        return md
    
    def generate_json(self) -> str:
        """Генерация JSON отчета"""
        report = {
            'target': self.config.target,
            'timestamp': self.data['timestamp'],
            'status': 'PASSED' if len(self.data.get('crashes', [])) == 0 else 'FAILED',
            'statistics': self.data.get('stats', {}),
            'crashes': self.data.get('crashes', []),
            'clusters': self.data.get('clusters', []),
            'corpus': self.data.get('corpus', {})
        }
        return json.dumps(report, indent=2, default=str)
    
    def generate_junit_xml(self) -> str:
        """Генерация JUnit XML отчета для CI систем"""
        crashes = self.data.get('crashes', [])
        total = len(crashes)
        failures = len([c for c in crashes if not c.get('is_false_positive')])
        
        xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="fuzzing-{self.config.target}" tests="1" failures="{min(failures, 1)}" errors="0" time="{self.data.get('stats', {}).get('executions_per_second', 0)}">
    <testcase name="fuzz_test" classname="{self.config.target}">
'''
        
        if failures > 0:
            for c in crashes[:5]:
                if not c.get('is_false_positive'):
                    xml += f'''        <failure message="{c.get('crash_type', 'Unknown crash')}" type="{c.get('severity', 'medium')}">
            Crash ID: {c.get('crash_id', 'N/A')}
            Type: {c.get('crash_type', 'Unknown')}
            Stack Trace:
            {c.get('stack_trace', 'N/A')[:500]}
        </failure>
'''
                    break
        
        xml += f'''    </testcase>
</testsuite>
'''
        return xml
    
    def save_reports(self) -> List[Path]:
        """Сохранение всех отчетов"""
        self.config.reports_dir.mkdir(parents=True, exist_ok=True)
        saved_files = []
        
        for fmt in self.config.formats:
            try:
                if fmt == 'html':
                    content = self.generate_html()
                    output = self.config.reports_dir / f"{self.config.target}_report.html"
                elif fmt == 'markdown':
                    content = self.generate_markdown()
                    output = self.config.reports_dir / f"{self.config.target}_report.md"
                elif fmt == 'json':
                    content = self.generate_json()
                    output = self.config.reports_dir / f"{self.config.target}_report.json"
                elif fmt == 'junit':
                    content = self.generate_junit_xml()
                    output = self.config.reports_dir / f"{self.config.target}_junit.xml"
                else:
                    continue
                
                with open(output, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                saved_files.append(output)
                self.log(f"Saved {fmt} report: {output}")
                
            except Exception as e:
                self.log(f"Failed to generate {fmt} report: {e}")
        
        return saved_files
    
    def run(self) -> int:
        """Запуск генерации отчетов"""
        self.log(f"Generating reports for target: {self.config.target}")
        
        # Загружаем данные
        self.load_data()
        
        # Генерируем и сохраняем отчеты
        saved_files = self.save_reports()
        
        if saved_files:
            self.log(f"Generated {len(saved_files)} report files")
            return 0
        else:
            self.log("No reports generated")
            return 1


def main():
    """Главная функция"""
    parser = argparse.ArgumentParser(description='Report Generator')
    
    parser.add_argument('--target', '-t', required=True, help='Target name')
    parser.add_argument('--logs-dir', default='fuzz/logs', help='Logs directory')
    parser.add_argument('--crashes-dir', default='fuzz/crashes', help='Crashes directory')
    parser.add_argument('--reports-dir', default='fuzz/reports', help='Reports directory')
    parser.add_argument('--format', '-f', nargs='+', 
                       choices=['html', 'markdown', 'json', 'junit'],
                       default=['html', 'markdown', 'json'],
                       help='Output formats')
    
    args = parser.parse_args()
    
    config = ReportConfig(
        target=args.target,
        logs_dir=Path(args.logs_dir),
        crashes_dir=Path(args.crashes_dir),
        reports_dir=Path(args.reports_dir),
        formats=args.format
    )
    
    generator = ReportGenerator(config)
    exit_code = generator.run()
    
    print("\n" + "=" * 60)
    print("REPORT GENERATION COMPLETE")
    print("=" * 60)
    print(f"Target: {args.target}")
    print(f"Formats: {', '.join(args.format)}")
    print("=" * 60)
    
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
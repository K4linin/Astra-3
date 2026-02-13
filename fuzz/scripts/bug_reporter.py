#!/usr/bin/env python3
"""
 =============================================================================
 Bug Reporter - Автоматическое создание баг-репортов
 =============================================================================
 
 Описание:
   Автоматическое создание GitHub Issues для найденных крашей:
   - Создание issues с подробным описанием
   - Кластеризация дубликатов
   - Прикрепление артефактов
   - Интеграция с GitHub API
   
 Использование:
   python bug_reporter.py --crashes-dir <dir> --repo <owner/repo> [options]
"""

import argparse
import hashlib
import json
import os
import sys
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class BugReport:
    """Модель баг-репорта"""
    title: str
    body: str
    labels: List[str] = field(default_factory=list)
    assignees: List[str] = field(default_factory=list)
    crash_id: str = ""
    severity: str = "medium"
    crash_type: str = "unknown"
    target: str = ""
    is_duplicate: bool = False
    duplicate_of: Optional[int] = None
    issue_number: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'title': self.title,
            'body': self.body,
            'labels': self.labels,
            'assignees': self.assignees,
            'crash_id': self.crash_id,
            'severity': self.severity,
            'crash_type': self.crash_type,
            'target': self.target,
            'is_duplicate': self.is_duplicate,
            'duplicate_of': self.duplicate_of,
            'issue_number': self.issue_number
        }


class BugReporter:
    """
    Создатель баг-репортов
    
    Функциональность:
    - Создание GitHub Issues для крашей
    - Обнаружение дубликатов
    - Формирование описания
    - Прикрепление файлов
    """
    
    # Метки по severity
    SEVERITY_LABELS = {
        'critical': 'severity: critical',
        'high': 'severity: high',
        'medium': 'severity: medium',
        'low': 'severity: low',
        'info': 'severity: info'
    }
    
    # Метки по типу краша
    TYPE_LABELS = {
        'segfault': 'type: crash',
        'buffer_overflow': 'type: security',
        'use_after_free': 'type: security',
        'null_pointer': 'type: crash',
        'parse_error': 'type: bug',
        'validation_error': 'type: bug',
        'assertion_failure': 'type: crash'
    }
    
    def __init__(self,
                 crashes_dir: Path,
                 repo: str,
                 token: Optional[str] = None,
                 run_id: Optional[str] = None,
                 commit: Optional[str] = None,
                 dry_run: bool = False):
        self.crashes_dir = Path(crashes_dir)
        self.repo = repo
        self.token = token or os.environ.get('GITHUB_TOKEN')
        self.run_id = run_id
        self.commit = commit
        self.dry_run = dry_run
        
        self.crashes: List[Dict] = []
        self.reports: List[BugReport] = []
        self.github = None
        
        if not self.dry_run and self.token:
            self._init_github()
    
    def _init_github(self) -> None:
        """Инициализация GitHub API"""
        try:
            from github import Github
            self.github = Github(self.token)
        except ImportError:
            self.log("PyGithub not installed, running in dry-run mode")
            self.dry_run = True
    
    def log(self, message: str) -> None:
        """Логирование"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} [BugReporter] {message}")
    
    def load_crashes(self) -> None:
        """Загрузка крашей из директории"""
        self.log(f"Loading crashes from {self.crashes_dir}")
        
        if not self.crashes_dir.exists():
            self.log(f"Crashes directory does not exist: {self.crashes_dir}")
            return
        
        # Загружаем crash analysis reports
        for analysis_file in self.crashes_dir.glob('**/*_crash_analysis.json'):
            try:
                with open(analysis_file) as f:
                    data = json.load(f)
                    for crash in data.get('crashes', []):
                        if not crash.get('is_false_positive'):
                            self.crashes.append(crash)
            except Exception as e:
                self.log(f"Failed to load {analysis_file}: {e}")
        
        # Загружаем отдельные crash файлы
        for crash_file in self.crashes_dir.glob('**/*.crash'):
            try:
                with open(crash_file, 'rb') as f:
                    content = f.read()
                
                # Пробуем распарсить как JSON
                crash_data = {'crash_id': hashlib.md5(content).hexdigest()[:12]}
                try:
                    text = content.decode('utf-8')
                    if text.strip().startswith('{'):
                        crash_data.update(json.loads(text))
                except:
                    crash_data['error_message'] = content.decode('utf-8', errors='ignore')[:500]
                
                crash_data['_source_file'] = str(crash_file)
                self.crashes.append(crash_data)
                
            except Exception as e:
                self.log(f"Failed to load crash {crash_file}: {e}")
        
        self.log(f"Loaded {len(self.crashes)} crashes")
    
    def create_report(self, crash: Dict) -> BugReport:
        """Создание баг-репорта из краша"""
        crash_id = crash.get('crash_id', 'unknown')
        crash_type = crash.get('crash_type', 'unknown')
        severity = crash.get('severity', 'medium')
        target = crash.get('target', 'unknown')
        
        # Формируем title
        title = f"[Fuzzing] {crash_type.replace('_', ' ').title()} in {target} (ID: {crash_id})"
        
        # Формируем body
        body_parts = [
            "## 🐛 Bug Report from Fuzzing",
            "",
            f"**Crash ID:** `{crash_id}`",
            f"**Type:** {crash_type}",
            f"**Severity:** {severity}",
            f"**Target:** {target}",
            ""
        ]
        
        # Добавляем информацию об ошибке
        if crash.get('error_message'):
            body_parts.extend([
                "### Error Message",
                "```",
                crash.get('error_message', '')[:1000],
                "```",
                ""
            ])
        
        # Добавляем stack trace
        if crash.get('stack_trace'):
            body_parts.extend([
                "### Stack Trace",
                "```",
                crash.get('stack_trace', '')[:2000],
                "```",
                ""
            ])
        
        # Добавляем информацию об входных данных
        input_size = crash.get('input_size', 0)
        body_parts.extend([
            "### Input",
            f"- **Size:** {input_size} bytes",
            ""
        ])
        
        # Информация о запуске
        body_parts.extend([
            "---",
            "",
            "### Context",
            ""
        ])
        
        if self.run_id:
            body_parts.append(f"- **Run ID:** {self.run_id}")
        if self.commit:
            body_parts.append(f"- **Commit:** `{self.commit}`")
        if self.repo:
            body_parts.append(f"- **Repository:** {self.repo}")
        
        body_parts.extend([
            "",
            "---",
            "*This issue was automatically created by the Fuzzing Testing Suite*"
        ])
        
        # Формируем labels
        labels = ['fuzzing', 'auto-generated']
        
        if severity in self.SEVERITY_LABELS:
            labels.append(self.SEVERITY_LABELS[severity])
        
        if crash_type in self.TYPE_LABELS:
            labels.append(self.TYPE_LABELS[crash_type])
        
        return BugReport(
            title=title,
            body='\n'.join(body_parts),
            labels=labels,
            crash_id=crash_id,
            severity=severity,
            crash_type=crash_type,
            target=target
        )
    
    def check_duplicate(self, report: BugReport) -> Optional[int]:
        """Проверка на дубликаты"""
        if not self.github:
            return None
        
        try:
            repo = self.github.get_repo(self.repo)
            
            # Ищем существующие issues с таким crash_id
            search_query = f'repo:{self.repo} "Crash ID: `{report.crash_id}`" is:issue'
            issues = self.github.search_issues(search_query)
            
            for issue in issues:
                if issue.state == 'open':
                    report.is_duplicate = True
                    report.duplicate_of = issue.number
                    return issue.number
                    
        except Exception as e:
            self.log(f"Failed to check duplicates: {e}")
        
        return None
    
    def create_issue(self, report: BugReport) -> Optional[int]:
        """Создание GitHub Issue"""
        if self.dry_run:
            self.log(f"[DRY-RUN] Would create issue: {report.title}")
            self.log(f"  Labels: {report.labels}")
            return None
        
        if not self.github:
            self.log("GitHub API not available, skipping issue creation")
            return None
        
        try:
            repo = self.github.get_repo(self.repo)
            
            issue = repo.create_issue(
                title=report.title,
                body=report.body,
                labels=report.labels
            )
            
            report.issue_number = issue.number
            self.log(f"Created issue #{issue.number}: {report.title}")
            
            return issue.number
            
        except Exception as e:
            self.log(f"Failed to create issue: {e}")
            return None
    
    def process_crashes(self) -> None:
        """Обработка всех крашей"""
        self.log(f"Processing {len(self.crashes)} crashes")
        
        for crash in self.crashes:
            # Создаем отчет
            report = self.create_report(crash)
            
            # Проверяем дубликаты
            duplicate_of = self.check_duplicate(report)
            
            if duplicate_of:
                self.log(f"Skipping duplicate crash {report.crash_id} (duplicate of #{duplicate_of})")
                continue
            
            # Создаем issue
            issue_number = self.create_issue(report)
            
            self.reports.append(report)
        
        self.log(f"Created {len([r for r in self.reports if r.issue_number])} issues")
    
    def save_summary(self) -> Path:
        """Сохранение сводки"""
        summary = {
            'timestamp': datetime.now().isoformat(),
            'repository': self.repo,
            'run_id': self.run_id,
            'commit': self.commit,
            'total_crashes': len(self.crashes),
            'reports_created': len([r for r in self.reports if r.issue_number]),
            'reports': [r.to_dict() for r in self.reports]
        }
        
        output_path = self.crashes_dir / 'bug_reports_summary.json'
        with open(output_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        self.log(f"Summary saved to {output_path}")
        return output_path
    
    def run(self) -> int:
        """Запуск создания баг-репортов"""
        self.log("Starting bug report creation")
        
        # Загружаем краши
        self.load_crashes()
        
        if not self.crashes:
            self.log("No crashes found")
            return 0
        
        # Обрабатываем краши
        self.process_crashes()
        
        # Сохраняем сводку
        self.save_summary()
        
        self.log("Bug report creation complete")
        return 0


def main():
    """Главная функция"""
    parser = argparse.ArgumentParser(description='Bug Reporter')
    
    parser.add_argument('--crashes-dir', required=True, help='Crashes directory')
    parser.add_argument('--repo', required=True, help='Repository (owner/repo)')
    parser.add_argument('--token', help='GitHub token (or use GITHUB_TOKEN env)')
    parser.add_argument('--run-id', help='GitHub Actions run ID')
    parser.add_argument('--commit', help='Commit SHA')
    parser.add_argument('--dry-run', action='store_true', help='Dry run mode')
    
    args = parser.parse_args()
    
    reporter = BugReporter(
        crashes_dir=Path(args.crashes_dir),
        repo=args.repo,
        token=args.token,
        run_id=args.run_id,
        commit=args.commit,
        dry_run=args.dry_run
    )
    
    exit_code = reporter.run()
    
    print("\n" + "=" * 60)
    print("BUG REPORT SUMMARY")
    print("=" * 60)
    print(f"Repository: {args.repo}")
    print(f"Total crashes: {len(reporter.crashes)}")
    print(f"Issues created: {len([r for r in reporter.reports if r.issue_number])}")
    print("=" * 60)
    
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
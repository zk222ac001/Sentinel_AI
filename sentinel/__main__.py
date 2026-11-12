import argparse
import json
import os
from pathlib import Path
from .core import Engine, report_html


def main():
    parser=argparse.ArgumentParser(description='Local read-only security audit')
    parser.add_argument('folder',help='Authorized scan root')
    parser.add_argument('--data',default='~/.sentinel-ai')
    parser.add_argument('--gitleaks',action='store_true')
    parser.add_argument('--mode', choices=['files', 'git_history'], default='files')
    parser.add_argument('--output',default='sentinel-report',help='Export filename prefix')
    args=parser.parse_args()
    engine=Engine(args.data)
    try:
        sid=engine.start(args.folder,args.gitleaks,mode=args.mode)
    except (ValueError,OSError):
        parser.error('Invalid or inaccessible scope, or unsupported platform.')
    try:
        engine.worker.join()
    except KeyboardInterrupt:
        engine.cancel()
        engine.worker.join()
    report=next(x for x in engine.history() if x['id']==sid)
    for suffix,content in [('.json',json.dumps(report,indent=2)),('.html',report_html(report))]:
        path=Path(args.output+suffix)
        # Do not silently overwrite an existing file.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(content)
    print(f"Status: {report['status']}; files: {report['scanned']}; candidates: {len(report['findings'])}")
    return 2 if report['status'] in {'failed','partial','cancelled'} else 0

if __name__=='__main__':
    raise SystemExit(main())

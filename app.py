from pathlib import Path
import json
import os
import streamlit as st
from sentinel.core import Engine, report_html

st.set_page_config(page_title='Sentinel AI',page_icon='🛡️',layout='wide')
st.title('Sentinel AI')
st.caption('PERSONAL SECURITY AUDITOR · LOCAL MVP · READ ONLY')
st.info('Candidate secrets in selected files or local Git history. Local HEAD history scanning is available. GitHub snapshot auditing is opt-in. Optional local AI guidance is available for completed scans. Billing and system permission auditing are not implemented.')

@st.cache_resource
def engine():
    return Engine(os.environ.get('SENTINEL_DATA_DIR', str(Path.home()/'.sentinel-ai')))

worker=engine()
with st.sidebar:
    st.header('Scan scope')
    mode=st.selectbox('Scan mode', ['files', 'git_history', 'github'], format_func=lambda value: {'files':'Selected files','git_history':'Local Git HEAD history','github':'GitHub repository snapshot'}[value])
    demo=st.checkbox('Use synthetic demo data',value=True)
    folder=st.text_input('Folder on this computer',value=str(Path(__file__).parent/'demo') if demo else str(Path.home()/'Projects'),disabled=demo)
    gitleaks=st.checkbox('Also use installed Gitleaks 8.x',disabled=mode!='files')
    if mode=='git_history':
        st.caption('Select the repository root. Reads committed regular-file blobs, including deleted files and historical versions. Other refs are not scanned. No remote fetch. Turn demo mode off for history scans.')
    st.caption(('Network requests only in explicitly authorized GitHub mode. ' if mode=='github' else 'No network requests. ') + 'Maximum 1 MiB per file/blob and 120 seconds per scan. Symlinks and binary content are skipped.')
    if mode=='files':
        st.caption('File mode excludes Git metadata and protected credential-store directories.')
    repository=st.text_input('GitHub owner/repository', value='') if mode=='github' else ''
    allow_network=st.checkbox('Allow read-only GitHub API requests for this repository', value=False) if mode=='github' else False
    if mode=='github':
        st.caption('Reads the default-branch snapshot only. Set SENTINEL_GITHUB_TOKEN before launch for private repositories; use a fine-grained token restricted to selected repositories with Contents read access. Tokens are never saved by this app. Disable demo mode.')
    approved=st.checkbox('I own or am authorized to audit this folder')
    if st.button('Start scan',disabled=not approved or (demo and mode!='files') or (mode=='github' and not allow_network),type='primary'):
        try:
            st.session_state['scan']=worker.start(repository if mode=='github' else str(Path(__file__).parent/'demo') if demo else folder,gitleaks if mode=='files' else False,mode=mode,allow_network=allow_network)
            st.success('Scan started')
        except (ValueError,OSError):
            st.error('Cannot start: verify the folder and platform, or wait for the active scan.')
    if st.button('Cancel active scan'):
        worker.cancel()

@st.fragment(run_every='2s')
def results():
    scans=worker.history()
    if not scans:
        st.subheader('Your first audit starts here')
        st.write('Run the synthetic demo, then select a folder you want to review.')
        return
    selected=st.selectbox('Scan history',[x['id'] for x in scans],format_func=lambda sid: next(x['started']+' · '+x['status'] for x in scans if x['id']==sid))
    report=next(x for x in scans if x['id']==selected)
    a,b,c=st.columns(3)
    a.metric('Blobs scanned' if report.get('mode') in {'git_history','github'} else 'Files scanned',report['scanned'])
    b.metric('Candidate findings',len(report['findings']))
    c.metric('Status',report['status'].upper())
    st.caption('Scope: '+report['scope'])
    st.caption('Engine: '+report['engine'])
    st.subheader('Findings')
    st.dataframe(report['findings'],width='stretch')
    if not report['findings']:
        st.write('No findings detected within the completed scan scope. This does not establish that the computer is secure.')
    with st.expander('Coverage and limitations',expanded=True):
        if report.get('remote'):
            st.json(report['remote'])
        if report.get('history'):
            st.json(report['history'])
        st.json(report['skipped'])
        if report.get('skipped_details'):
            st.dataframe(report['skipped_details'], width='stretch')
        if report.get('skipped_details_omitted'):
            st.caption(f"Additional skipped entries omitted: {report['skipped_details_omitted']}")
        for limitation in report['limitations']:
            st.write('• '+limitation)
    if report['status']!='running':
        st.download_button('Download JSON',json.dumps(report,indent=2),'sentinel-report.json','application/json')
        st.download_button('Download HTML',report_html(report),'sentinel-report.html','text/html')
    if report['status']!='running':
        from sentinel.ai_ui import render_guidance
        render_guidance(report)
    st.caption('Reports contain relative filenames and the scope path. Review them before sharing. Values are fully redacted.')
results()

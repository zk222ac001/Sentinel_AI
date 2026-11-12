from pathlib import Path
import json
import streamlit as st
from sentinel.core import Engine, report_html

st.set_page_config(page_title='Sentinel AI',page_icon='🛡️',layout='wide')
st.title('Sentinel AI')
st.caption('PERSONAL SECURITY AUDITOR · LOCAL MVP · READ ONLY')
st.info('Phase 1: candidate secrets in selected text files. AI, GitHub, billing and system permission auditing are not implemented.')

@st.cache_resource
def engine():
    return Engine(Path.home()/'.sentinel-ai')

worker=engine()
with st.sidebar:
    st.header('Scan scope')
    demo=st.checkbox('Use synthetic demo data',value=True)
    folder=st.text_input('Folder on this computer',value=str(Path(__file__).parent/'demo') if demo else str(Path.home()/'Projects'),disabled=demo)
    gitleaks=st.checkbox('Also use installed Gitleaks 8.x')
    st.caption('No network requests. Symlinks, binary files, Git history and protected credential stores are skipped. Maximum 1 MiB/file and 120 seconds/scan.')
    approved=st.checkbox('I own or am authorized to audit this folder')
    if st.button('Start scan',disabled=not approved,type='primary'):
        try:
            st.session_state['scan']=worker.start(str(Path(__file__).parent/'demo') if demo else folder,gitleaks)
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
    a.metric('Files scanned',report['scanned'])
    b.metric('Candidate findings',len(report['findings']))
    c.metric('Status',report['status'].upper())
    st.caption('Scope: '+report['scope'])
    st.caption('Engine: '+report['engine'])
    st.subheader('Findings')
    st.dataframe(report['findings'],use_container_width=True)
    if not report['findings']:
        st.write('No findings detected within the completed scan scope. This does not establish that the computer is secure.')
    with st.expander('Coverage and limitations',expanded=True):
        st.json(report['skipped'])
        for limitation in report['limitations']:
            st.write('• '+limitation)
    if report['status']!='running':
        st.download_button('Download JSON',json.dumps(report,indent=2),'sentinel-report.json','application/json')
        st.download_button('Download HTML',report_html(report),'sentinel-report.html','text/html')
    st.caption('Reports contain relative filenames and the scope path. Review them before sharing. Values are fully redacted.')
results()

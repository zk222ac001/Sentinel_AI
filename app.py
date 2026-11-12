"""Sentinel AI's local security review workspace."""
from pathlib import Path
from html import escape
import json
import os
import platform
import streamlit as st
from sentinel import __version__
from sentinel.core import Engine
from sentinel.reviews import ReviewStore, STATUSES
from sentinel import folder_picker
from sentinel.reporting import export_report, report_html

ROOT = Path(__file__).resolve().parent
st.set_page_config(page_title='Sentinel AI · Security workspace', page_icon='🛡️', layout='wide')
st.markdown('''<style>
.stApp{background:radial-gradient(ellipse at 85% 0%,#192a42 0%,#0d1422 48%)}
[data-testid="stSidebar"]{background:#111c2d;border-right:1px solid #263449}
.block-container{max-width:1440px;padding-top:2.5rem;padding-bottom:4rem}
h1,h2,h3{letter-spacing:-.035em}h1{font-size:2.8rem!important}
.hero{background:linear-gradient(115deg,#1b2d47,#142033);border:1px solid #334560;border-radius:20px;padding:32px;margin:16px 0 26px}
.eyebrow{color:#ffb168;font:600 12px/1.5 monospace;letter-spacing:.15em;text-transform:uppercase}
.hero h2{font-size:32px;margin:8px 0}.hero p{color:#b7c5d8;max-width:680px;line-height:1.7}
[data-testid="stMetric"]{border:1px solid #2b3b52;border-radius:14px;background:#142136;padding:18px}
[data-testid="stMetricLabel"]{color:#b7c5d8}[data-testid="stMetricValue"]{font-size:28px}
[data-testid="stVerticalBlockBorderWrapper"]>div{border-radius:14px!important}
.stButton>button{border-radius:9px;min-height:42px}.stDownloadButton>button{border-radius:9px}
@media(max-width:640px){.block-container{padding:1rem}.hero{padding:20px}.hero h2{font-size:25px}}
</style>''', unsafe_allow_html=True)

@st.cache_resource
def engine():
    return Engine(os.environ.get('SENTINEL_DATA_DIR', str(Path.home()/'.sentinel-ai')))

worker = engine()
reviews = ReviewStore(worker.db)

def go(page):
    st.session_state['navigation'] = page

with st.sidebar:
    st.markdown('### 🛡️ Sentinel AI')
    st.caption('YOUR SECURITY WORKSPACE')
    page = st.radio('Workspace', ['Overview','New scan','Findings','Reports','Settings'], key='navigation', label_visibility='collapsed')
    st.divider()
    st.caption('LOCAL FIRST · READ ONLY')
    st.write('Your files. Your control.')
    st.caption('Candidate detection with redacted evidence. Network access requires explicit opt-in.')
    st.caption(f'{platform.system()} · v{__version__}')

st.caption('WORKSPACE / '+page.upper())
st.title({'Overview':'A clearer view of your security.','New scan':'Start with a focused audit.','Findings':'Investigate what matters.','Reports':'Turn findings into action.','Settings':'Built for your environment.'}[page])


def select_report(scans):
    if not scans:
        st.info('No scans yet. Start with the synthetic demo from New scan.')
        st.button('Create your first scan', key='empty_scan', on_click=go, args=('New scan',))
        return None
    ids = [s['id'] for s in scans]
    if st.session_state.get('selected_scan') not in ids:
        st.session_state['selected_scan'] = ids[0]
    sid = st.selectbox('Audit history', ids, key='selected_scan', format_func=lambda v: next(f"{s['started'][:19].replace('T',' ')} UTC · {s.get('mode','files')} · {s['status']} · {v[:8]}" for s in scans if s['id']==v))
    return next(s for s in scans if s['id']==sid)


def metrics(report):
    a,b,c = st.columns(3)
    a.metric('Items scanned', report['scanned'])
    b.metric('Candidate findings', len(report['findings']))
    c.metric('Scan status', report['status'].upper())
    st.caption('Scope: '+report['scope'])
    if report['status']=='running':
        st.info('Scan in progress. Results refresh automatically; counts may change.')
        if st.button('Cancel active scan', key='cancel'): worker.cancel()
    elif report['status']!='completed':
        st.warning('This scan did not complete. Review coverage before drawing conclusions.')


def coverage(report):
    with st.expander('Coverage, exclusions & limitations'):
        st.write('Engine: '+report['engine'])
        for text in report.get('limitations',[]): st.write('• '+text)
        st.json(report.get('skipped',{}))
        for name in ('remote','history'):
            if report.get(name): st.json(report[name])
        if report.get('skipped_details'): st.dataframe(report['skipped_details'], width='stretch', hide_index=True)
        if report.get('skipped_details_omitted'): st.caption(f"Additional skipped entries omitted: {report['skipped_details_omitted']}")


def scope_changed():
    st.session_state.pop('launch_error', None)
    st.session_state.pop('folder_notice', None)
    st.session_state['authorize'] = False


def browse_folder():
    try:
        with st.spinner('Choose a folder in the desktop window (60-second timeout)…'):
            selected = folder_picker.choose_folder(st.session_state.get('folder', ''))
        if selected:
            st.session_state['folder'] = selected
            scope_changed()
            st.session_state['folder_notice'] = 'Folder selected. Confirm authorization below to start the scan.'
        else:
            st.session_state['folder_notice'] = 'Folder selection cancelled. Your existing path is unchanged.'
    except folder_picker.FolderPickerError as error:
        st.session_state['folder_notice'] = str(error)


def new_scan():
    st.write('Choose a scope you own or are authorized to audit. Start small, review the results, then expand.')
    left,right = st.columns([3,2], gap='large')
    with left, st.container(border=True):
        st.subheader('01 / Choose your scope')
        mode = st.selectbox('Scan mode',['files','git_history','github'], key='mode',on_change=scope_changed,format_func=lambda v: {'files':'Selected files','git_history':'Local Git HEAD history','github':'GitHub repository snapshot'}[v])
        demo = st.checkbox('Use synthetic demo data',value=True,key='demo',on_change=scope_changed,disabled=mode!='files') if mode=='files' else False
        folder = st.text_input('Folder on this computer',value=str(ROOT/'demo'),key='folder',disabled=demo,on_change=scope_changed) if mode!='github' else ''
        if mode!='github':
            st.button('Browse folders…',key='browse_folder',on_click=browse_folder,disabled=demo)
            st.caption('Opens a folder chooser on the computer running Sentinel. Selecting a folder does not start a scan. You can also paste a path above.')
            if st.session_state.get('folder_notice'): st.info(st.session_state['folder_notice'])
        repository = st.text_input('GitHub owner/repository',key='repository',on_change=scope_changed) if mode=='github' else ''
        gitleaks = st.checkbox('Also use installed Gitleaks 8.x',key='gitleaks') if mode=='files' else False
        network = st.checkbox('Allow read-only GitHub API requests for this repository', key='network_authorize') if mode=='github' else False
        st.subheader('02 / Confirm & launch')
        approved = st.checkbox('I own or am authorized to audit this scope',key='authorize')
        def launch():
            try:
                sid = worker.start(repository if mode=='github' else str(ROOT/'demo') if demo else folder, gitleaks,mode=mode,allow_network=network)
                st.session_state['selected_scan'] = sid
                st.session_state.pop('launch_error',None)
                go('Findings')
            except ValueError as error: st.session_state['launch_error'] = str(error)
            except OSError: st.session_state['launch_error'] = 'Cannot access this folder. Check its location and your account permissions.'
        st.button('Start scan',key='start_scan',type='primary',disabled=not approved or (mode=='github' and not network),on_click=launch)
        if st.session_state.get('launch_error'): st.error(st.session_state['launch_error'])
    with right:
        st.markdown('<div class="hero"><span class="eyebrow">Know what is being checked</span><h2>Focused. Bounded. Read only.</h2><p>Candidate secrets are detected locally. Secret values are redacted before they enter reports.</p></div>', unsafe_allow_html=True)
        st.write({'files':'Scans selected text files. Git metadata, binary files and protected credential-store directories are excluded.','git_history':'Scans committed regular-file blobs reachable from local HEAD, including historical and deleted content. No remote fetch; other refs are excluded.','github':'Reads a pinned default-branch snapshot via the GitHub API. Git history is excluded. For private repositories, configure SENTINEL_GITHUB_TOKEN before launch with restricted Contents read access.'}[mode])
        st.caption('Limits: 1 MiB per file/blob and 120 seconds per scan. Additional file, entry, commit and response limits apply. Symlinks and Windows reparse points are skipped.')
        st.info('Finding a credential pattern does not confirm it is active, publicly exposed, or costing money.')


@st.fragment(run_every='2s')
def workspace():
    scans = worker.history()
    if page=='Overview':
        st.markdown('<div class="hero"><span class="eyebrow">Personal security, made visible</span><h2>Find forgotten secrets.<br>Build a review habit.</h2><p>Audit selected files, inspect local Git history, or review a GitHub snapshot. Investigate candidates with clear evidence and track your decisions.</p></div>', unsafe_allow_html=True)
        st.button('Start a new audit',type='primary',key='overview_start',on_click=go,args=('New scan',))
        if scans:
            metrics(scans[0])
            st.subheader('Recent audits')
            st.dataframe([{'Started (UTC)':s['started'][:19], 'Mode':s.get('mode','files'),'Status':s['status'],'Scanned':s['scanned'],'Candidates':len(s['findings'])} for s in scans[:10]],hide_index=True,width='stretch')
            st.button('Investigate findings',key='overview_findings',on_click=go,args=('Findings',))
        else:
            st.subheader('Your first audit starts here')
            st.write('The synthetic demo uses intentionally fake credentials to show the complete review workflow.')
        st.caption('No overall security score: scan results describe only the scope and coverage actually examined.')
        return
    report = select_report(scans)
    if not report: return
    metrics(report)
    review = reviews.get(report['id'])
    if page=='Findings':
        st.subheader('Finding inbox')
        a,b,c = st.columns([2,1,1])
        query = a.text_input('Search location or detector',key='finding_search').casefold().strip()
        severity = b.selectbox('Severity',['All','High','Medium','Low'],key='severity')
        status = c.selectbox('Review status',['All',*STATUSES],key='review_filter')
        items = [f for f in report['findings'] if (severity=='All' or f['severity']==severity) and (status=='All' or review.get(f['id'],{}).get('status','Open')==status) and (not query or query in (f['path']+' '+f['rule']).casefold())]
        st.caption(f"{len(items)} of {len(report['findings'])} candidates · Credential validity and billing are not checked.")
        if items:
            st.dataframe([{'Severity':f['severity'],'Detector':f['rule'],'Location':f['path'],'Line':f.get('line'),'Review':review.get(f['id'],{}).get('status','Open')} for f in items],hide_index=True,width='stretch')
            fid = st.selectbox('Inspect finding',[f['id'] for f in items],format_func=lambda v: next(f"{f['rule']} · {f['path']}:{f.get('line','—')} · {v[:8]}" for f in items if f['id']==v),key='inspect_'+report['id'])
            f = next(f for f in items if f['id']==fid)
            with st.container(border=True):
                st.subheader('Evidence & next steps')
                st.code(f"{f['path']}:{f.get('line','—')}\n[REDACTED]",language=None)
                st.write(f.get('remediation','Review the source and rotate the credential with its provider if appropriate.'))
                st.caption(f"Confidence: {f.get('confidence','candidate')} · Exposure: {f.get('exposure','unknown')} · Validity: {f.get('validity','not_checked')}")
                if f.get('commit'): st.code(f['commit'],language=None)
                choice = st.selectbox('Manual review decision',STATUSES,index=STATUSES.index(review.get(fid,{}).get('status','Open')),key='decision_'+fid)
                st.caption('These labels record your assessment. Resolved (manual) does not verify revocation or remediation.')
                if st.button('Save review',key='save_review',disabled=report['status']=='running'):
                    reviews.set(report['id'],fid,choice)
                    st.toast('Review saved locally')
                    st.rerun()
        else:
            st.info('No findings match these filters.' if report['findings'] else 'No candidates detected so far in the scanned scope. This does not establish that the computer is secure.')
        coverage(report)
        if report['status']!='running':
            from sentinel.ai_ui import render_guidance
            render_guidance(report)
    else:
        st.subheader('Export this audit')
        st.write('Download a structured JSON report or a standalone HTML report. Open HTML in your browser and use Print → Save as PDF.')
        minimize = st.toggle('Omit identifying metadata for sharing',value=True,key='minimize_export')
        st.caption('Sharing copies omit paths, URLs, commit IDs, fingerprints and detailed coverage. Counts, detector categories and timestamps remain; review before sharing.' if minimize else 'Full reports include scope paths, filenames and repository metadata. Secret values remain redacted.')
        payload = export_report(report,review,minimize)
        a,b = st.columns(2)
        a.download_button('Download JSON',json.dumps(payload,indent=2),'sentinel-report.json','application/json',disabled=report['status']=='running',width='stretch')
        b.download_button('Download HTML',report_html(payload),'sentinel-report.html','text/html',disabled=report['status']=='running',width='stretch')
        coverage(report)
        with st.expander('Manual review activity'):
            events=reviews.events(report['id'])
            if events: st.dataframe(events,width='stretch',hide_index=True)
            else: st.caption('No review changes recorded for this scan.')

if page=='New scan':
    new_scan()
elif page=='Settings':
    st.subheader('Runtime & storage')
    st.code(f"Sentinel AI {__version__}\nOS: {platform.system()}\nPython: {platform.python_version()}\nApp folder: {ROOT}\nLocal data: {worker.data}",language=None)
    st.subheader('Capabilities')
    st.dataframe([{'Capability':a,'Availability':b} for a,b in [('Selected-file scanning','Windows · macOS · Linux'),('Local Git HEAD history','Requires Git'),('GitHub snapshot','Explicit network opt-in'),('Gitleaks 8.x','Optional local installation'),('Reviewed guidance','Available offline'),('Local AI guidance','Optional local Ollama; explicit opt-in'),('Credential validity / billing','Not implemented'),('System permissions / app posture','Not implemented')]],hide_index=True,width='stretch')
    st.info('The local database is not encrypted. Windows uses inherited account ACLs; POSIX uses owner-only permissions. Protect your account and review report metadata before sharing.')
    st.caption('The dashboard audits files on the machine running Python, not on a remote browser device. Keep the server bound to localhost.')
else:
    workspace()

"""Optional session-only AI UI, invoked for a finished scan."""
import json
import streamlit as st
from .ai_guidance import GUIDANCE, GuidanceJob, fallback, preview


def render_guidance(report):
    with st.expander('Explanations and optional local AI'):
        rows=preview(report)
        st.caption('Reviewed guidance is available without AI. AI only selects from this guidance; it cannot change findings or run actions. At most the first 10 findings are included.')
        if not rows:
            st.write('No candidate findings to explain. This is not a security verdict.')
            return
        # Labels intentionally reference row order, not sensitive source paths.
        st.caption('F1 corresponds to finding row 1, F2 to row 2, and so on in this scan.')
        st.json(rows)
        st.caption('Only the preview above and a fixed guidance catalog are sent. No paths, repository names, values, snippets, fingerprints or tokens are included.')
        model=st.text_input('Installed local Ollama model',key='ai_model')
        local=st.checkbox('I disabled Ollama cloud features on the local server',key='ai_local_only')
        consent=st.checkbox('Allow this preview to be sent to Ollama on this computer',key='ai_consent')
        job=st.session_state.get('ai_job')
        running=job is not None and job.thread.is_alive()
        if st.button('Generate local AI guidance',disabled=not (model and local and consent) or running):
            st.session_state.ai_scan=report['id']
            st.session_state.ai_job=GuidanceJob(rows,model,consent=consent,local_only_confirmed=local)
            job=st.session_state.ai_job
            running=True
        if running:
            st.info('A local-model request is running. Cancellation may wait for the 10-second socket timeout.')
            if st.button('Cancel AI request'):
                job.cancel.set()
        result={'source':'reviewed_fallback','status':'completed','notice':'Reviewed guidance; AI has not been used for this scan.','items':fallback(rows)}
        if job is not None and st.session_state.get('ai_scan')==report['id'] and not job.thread.is_alive():
            if job.error:
                st.warning('AI request could not start. Check the local model name and settings.')
            elif job.result:
                result=job.result
        st.caption(result['notice'])
        for item in result['items']:
            st.write(item['finding_id'])
            for code in item['guidance_ids']:
                st.text(GUIDANCE[code])
        st.download_button('Download guidance JSON',json.dumps(result,indent=2),'sentinel-guidance.json','application/json')
        st.caption('Guidance remains in this browser session only. Scan reports and severity remain unchanged. Configure Ollama cloud disabling before use; a loopback address alone cannot establish how a separate server routes inference.')

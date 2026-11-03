const ui=window.ODYSAFE_I18N;
(() => {
  document.querySelectorAll('.case-head .full-url, .overview-identity h2, .url-evidence code').forEach(node => {
    const value = (node.textContent || '').trim();
    if (value.length <= 140) return;
    const details = document.createElement('details');
    details.className = 'long-value';
    const summary = document.createElement('summary');
    summary.textContent = `${value.slice(0, 110)}…`;
    summary.title = value;
    const full = document.createElement('pre');
    full.textContent = value;
    details.append(summary, full);
    node.replaceWith(details);
  });
  document.addEventListener('click', async event => {
    const copyTarget = event.target.closest('[data-copy-target]');
    if (copyTarget) {
      const node = document.getElementById(copyTarget.dataset.copyTarget);
      try { await navigator.clipboard.writeText(node?.textContent || ''); ui.setText(copyTarget,'Copié'); }
      catch (_) { ui.setText(copyTarget,'Échec'); }
      return;
    }
    const button = event.target.closest('[data-copy]');
    if (!button) return;
    try { await navigator.clipboard.writeText(button.dataset.copy); ui.setText(button,'Copié'); }
    catch (_) { ui.setText(button,'Échec'); }
  });
  document.querySelectorAll('[data-code-search]').forEach(input => input.addEventListener('input', () => {
    const source = document.getElementById('source-content');
    const query = input.value.toLocaleLowerCase();
    document.querySelector('[data-code-view]')?.classList.toggle('search-miss', Boolean(query) && !source.textContent.toLocaleLowerCase().includes(query));
  }));
  document.addEventListener('submit', event => {
    const form = event.target.closest('[data-xpra-launch]'); if (!form) return;
    const button = form.querySelector('button[type="submit"]');
    if (form.dataset.submitted === 'true') { event.preventDefault(); return; }
    form.dataset.submitted = 'true'; if (button) { button.disabled = true; ui.setText(button,'Ouverture…'); }
  });
  document.querySelectorAll('[data-code-view][data-language="javascript"] code').forEach(code => {
    const source = code.textContent;
    const pattern = /(\/\/.*$|\/\*[\s\S]*?\*\/|'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|`(?:\\.|[^`\\])*`|\b(?:const|let|var|function|return|if|else|for|while|new|class|async|await|true|false|null|undefined)\b|\b\d+(?:\.\d+)?\b)/gm;
    let offset = 0;
    for (const match of source.matchAll(pattern)) {
      code.append(document.createTextNode(source.slice(offset, match.index)));
      const token = document.createElement('span');
      token.className = match[0].startsWith('//') || match[0].startsWith('/*') ? 'tok-comment' : /^["'`]/.test(match[0]) ? 'tok-string' : /^\d/.test(match[0]) ? 'tok-number' : 'tok-keyword';
      token.textContent = match[0]; code.append(token); offset = match.index + match[0].length;
    }
    code.append(document.createTextNode(source.slice(offset)));
    code.firstChild?.remove();
  });
  document.querySelectorAll('[data-dirty-form]').forEach(form => {
    let dirty = false; form.addEventListener('input', () => { dirty = true; });
    form.addEventListener('submit', () => { dirty = false; });
    window.addEventListener('beforeunload', event => { if (dirty) { event.preventDefault(); event.returnValue = ''; } });
  });
  document.querySelectorAll('[data-duration-mode]').forEach(control=>{
    const form=control.form,preset=form?.querySelector('[data-duration-preset]'),custom=form?.querySelector('[data-duration-custom]'),amount=custom?.querySelector('input'),unit=custom?.querySelector('select');
    const limits=()=>{if(!amount||!unit)return;amount.min=unit.value==='seconds'?'15':'1';amount.max=unit.value==='hours'?'8':unit.value==='seconds'?'28800':'480';if(Number(amount.value)>Number(amount.max))amount.value=amount.max;if(Number(amount.value)<Number(amount.min))amount.value=amount.min};
    const update=()=>{const useCustom=control.value==='custom';if(preset){preset.hidden=useCustom;preset.querySelectorAll('select,input').forEach(item=>item.disabled=useCustom)}if(custom){custom.hidden=!useCustom;custom.querySelectorAll('select,input').forEach(item=>item.disabled=!useCustom)}limits()};
    control.addEventListener('change',update);unit?.addEventListener('change',limits);update();
  });
  const enhanceRuleInteractions=(root=document)=>{
    if(!window.htmx)return;
    root.querySelectorAll('.rule-open').forEach(link=>{
      link.setAttribute('hx-get',link.href);
      link.setAttribute('hx-target','.rules-layout > article:nth-child(2)');
      link.setAttribute('hx-select','.rules-layout > article:nth-child(2)');
      link.setAttribute('hx-swap','outerHTML show:none');
      link.setAttribute('hx-push-url','true');
      window.htmx.process(link);
    });
  };
  enhanceRuleInteractions();

  // Une seule gestion déléguée pour toutes les bascules d'état présentes ou
  // ajoutées plus tard. Le serveur reste la source de vérité, puis la ligne
  // est mise à jour sans recharger la page entière.
  document.addEventListener('submit',async event=>{
    const form=event.target.closest('form.inline-toggle');
    if(!form)return;
    event.preventDefault();
    if(form.dataset.pending==='true')return;
    const button=form.querySelector('.status-toggle');
    const path=new URL(form.action,window.location.href).pathname;
    const disabling=path.endsWith('/disable');
    form.dataset.pending='true';
    if(button)button.disabled=true;
    try{
      const response=await fetch(form.action,{method:'POST',body:new FormData(form),credentials:'same-origin',headers:{'X-Requested-With':'ODYSAFE-state-toggle'}});
      if(!response.ok)throw new Error(`HTTP ${response.status}`);
      const active=!disabling;
      form.action=form.action.replace(/\/(activate|disable)$/,active?'/disable':'/activate');
      if(button){
        button.classList.toggle('active',active);
        button.classList.toggle('inactive',!active);
        button.setAttribute('aria-checked',active?'true':'false');
        const label=button.getAttribute('aria-label')||'';
        ui.setAttribute(button,'aria-label',(button.dataset.i18nAriaLabel||label).replace(/^(Activer|Désactiver|Enable|Disable)/,active?'Désactiver':'Activer'));
        const marker=document.createElement('span');marker.setAttribute('aria-hidden','true');
        const state=document.createElement('span');ui.setText(state,active?'Active':'Inactive');button.replaceChildren(marker,state);
      }
    }catch(error){
      if(button){ui.setAttribute(button,'title',`La modification a échoué (${error.message}). Réessayez.`);button.classList.add('toggle-error')}
    }finally{
      form.dataset.pending='false';
      if(button)button.disabled=false;
    }
  });
  const sessionSelection=new Set();
  const restoreSessionSelection=()=>{
    const boxes=[...document.querySelectorAll('input[name="selected"][form="session-bulk-remove"]')];
    boxes.forEach(item=>{item.checked=sessionSelection.has(item.value)});
    const master=document.querySelector('[data-check-all]');
    if(master){const checked=boxes.filter(item=>item.checked).length;master.checked=Boolean(boxes.length)&&checked===boxes.length;master.indeterminate=checked>0&&checked<boxes.length}
  };
  document.addEventListener('change',event=>{
    const ruleMaster=event.target.closest('[data-rule-select-all]');
    if(ruleMaster){document.querySelectorAll('input[name="selected"][form="rule-bulk"]').forEach(item=>{item.checked=ruleMaster.checked});return}
    const categoryMaster=event.target.closest('[data-rule-category-select]');
    if(categoryMaster){categoryMaster.closest('.rule-category')?.querySelectorAll('input[name="selected"][form="rule-bulk"]').forEach(item=>{item.checked=categoryMaster.checked});return}
    const sessionMaster=event.target.closest('[data-check-all]');
    if(sessionMaster){document.querySelectorAll('input[name="selected"][form="session-bulk-remove"]').forEach(item=>{item.checked=sessionMaster.checked;sessionMaster.checked?sessionSelection.add(item.value):sessionSelection.delete(item.value)});return}
    const sessionItem=event.target.closest('input[name="selected"][form="session-bulk-remove"]');
    if(sessionItem){sessionItem.checked?sessionSelection.add(sessionItem.value):sessionSelection.delete(sessionItem.value);restoreSessionSelection()}
  });
  document.addEventListener('submit',event=>{
    if(event.target.matches('#rule-bulk')){
      const count=document.querySelectorAll('input[name="selected"][form="rule-bulk"]:checked').length;
      if(!count){event.preventDefault();return}
      if(event.submitter?.matches('[data-rule-delete]')&&!window.confirm(ui.t('Supprimer {count} règle(s) personnalisée(s) ? Les anciens rapports seront conservés.',{count})))event.preventDefault();
    }else if(event.target.matches('[data-rule-single-delete]')){
      if(!window.confirm(ui.t('Supprimer cette règle personnalisée ? Les anciens rapports seront conservés.')))event.preventDefault();
    }else if(event.target.matches('#session-bulk-remove')){
      const count=document.querySelectorAll('input[name="selected"][form="session-bulk-remove"]:checked').length;
      if(!count||!window.confirm(ui.t('Supprimer définitivement {count} investigation(s), leurs rapports et toutes leurs preuves ? Cette action est irréversible.',{count})))event.preventDefault();
    }else if(event.target.matches('[data-reset-odysafe]')){
      if(!window.confirm(ui.t('Effacer les investigations, preuves, sessions, IOC, résultats DNS et dossiers personnalisés ? Les bibliothèques YARA-X et IOC seront vides ; leurs dossiers Défaut seront recréés. Vos réglages et votre configuration DNS seront conservés.')))event.preventDefault();
    }
  });
  document.addEventListener('htmx:afterSwap',event=>{
    restoreSessionSelection();
    enhanceRuleInteractions(event.detail?.target||document);
  });
  const updateLaunchContext=()=>{
    const profile=document.querySelector('select[name="profile"]');
    const network=document.querySelector('select[name="network_policy"]');
    const profileOutput=document.querySelector('[data-launch-profile]');
    const networkOutput=document.querySelector('[data-launch-network]');
    const protectionOutput=document.querySelector('[data-launch-protection]');
    if(profile&&profileOutput)ui.setText(profileOutput,profile.selectedOptions[0]?.textContent||'Non sélectionné');
    if(network&&networkOutput)ui.setText(networkOutput,network.value==='internet'?'Internet via proxy filtrant':'Environnement de test local');
    if(network&&protectionOutput)ui.setText(protectionOutput,network.value==='internet'?'Les sites sont ouverts via un relais filtrant qui bloque les adresses privées et locales.':'Le navigateur reste dans l’environnement de test local.');
  };
  document.addEventListener('change',event=>{
    if(event.target.matches('select[name="profile"],select[name="network_policy"]'))updateLaunchContext();
  });
  updateLaunchContext();
  document.addEventListener('odysafe:languagechange',updateLaunchContext);
})();

// Engine libraries: all moves use the same CSRF-protected server action.
(() => {
  document.addEventListener('submit',event=>{const message=event.submitter?.dataset.confirm||event.target.dataset.confirm;if(message&&!window.confirm(message))event.preventDefault()});
  const analysis=document.querySelector('[data-analysis-form]');
  if(analysis&&!analysis.hasAttribute('data-folder-wizard')){
    const updateAnalysis=()=>{const items=analysis.querySelectorAll('[data-analysis-item]:checked').length;const scans=analysis.querySelectorAll('[name="scan_ids"]:checked').length;const output=analysis.querySelector('[data-analysis-count]');ui.setText(output,`${items?`${items} élément(s) · `:''}${scans} investigation(s)`);const needsItems=Boolean(analysis.querySelector('[data-include-inactive]'));const invalid=scans<1||scans>20||(needsItems&&(items<1||items>100));analysis.querySelector('.analysis-footer button').disabled=invalid;if(scans>20||items>100)ui.setText(output,'Maximum : 100 éléments et 20 investigations.');analysis.querySelectorAll('[data-analysis-group]').forEach(master=>{const children=[...master.closest('.analysis-group').querySelectorAll('[data-analysis-item]:not(:disabled)')];const count=children.filter(box=>box.checked).length;master.checked=count>0&&count===children.length;master.indeterminate=count>0&&count<children.length})};
    analysis.addEventListener('change',event=>{if(event.target.matches('[data-analysis-group]'))event.target.closest('.analysis-group').querySelectorAll('[data-analysis-item]:not(:disabled)').forEach(box=>box.checked=event.target.checked);if(event.target.matches('[data-include-inactive]'))analysis.querySelectorAll('[data-analysis-item][data-active="false"]').forEach(box=>{box.disabled=!event.target.checked||box.dataset.unusable==='true';if(box.disabled)box.checked=false});updateAnalysis()});
    analysis.querySelector('[data-scan-search]')?.addEventListener('input',event=>{const query=event.target.value.toLocaleLowerCase();analysis.querySelectorAll('[data-scan-choice]').forEach(label=>label.hidden=!label.textContent.toLocaleLowerCase().includes(query))});document.addEventListener('odysafe:languagechange',updateAnalysis);updateAnalysis();
  }
})();

if (window.location.pathname === '/settings' && window.location.hash === '#dns-security') {
  window.location.replace('/engines/dns?view=settings');
}

(() => {
  document.addEventListener('change',event=>{
    const kind=event.target.closest('[data-ioc-kind]');if(!kind)return;
    const editor=kind.closest('[data-ioc-editor]'),value=editor.querySelector('[data-ioc-value]'),help=editor.querySelector('[data-ioc-help]'),option=kind.selectedOptions[0];
    ui.setAttribute(value,'placeholder',option.getAttribute('data-i18n-data-example')||option.dataset.example);ui.setText(help,option.getAttribute('data-i18n-data-help')||option.dataset.help);value.removeAttribute('aria-invalid');
  });
  document.addEventListener('submit',async event=>{
    const form=event.target.closest('[data-ioc-editor]');if(!form)return;
    event.preventDefault();const button=form.querySelector('button[type=submit],button.primary');if(button.disabled)return;
    button.disabled=true;
    try{
      const response=await fetch(form.action,{method:'POST',body:new FormData(form),credentials:'same-origin'});
      if(response.ok){window.location.assign(response.url);return}
      const result=new DOMParser().parseFromString(await response.text(),'text/html');const replacement=result.querySelector('.ioc-editor');
      if(replacement){const current=form.closest('.ioc-editor');current.replaceWith(replacement);document.dispatchEvent(new CustomEvent('odysafe:updated'));replacement.querySelector('[aria-invalid=true]')?.focus()}
      else throw new Error();
    }catch(_){let message=form.querySelector('[data-save-error]');if(!message){message=document.createElement('p');message.dataset.saveError='';message.className='field-error';message.setAttribute('role','alert');form.prepend(message)}message.textContent='L’enregistrement n’a pas abouti. Vos saisies sont conservées : réessayez dans un instant.'}
    finally{if(button.isConnected)button.disabled=false}
  });
  document.addEventListener('htmx:beforeSwap',event=>{
    const target=event.detail.target;
    if(target?.contains(document.activeElement)&&document.activeElement?.matches('input,select,textarea,[role=combobox]'))event.detail.shouldSwap=false;
  });
})();

// Stable, keyboard-accessible menus shared by every single-choice select.
// The native select remains the form's source of truth, but no OS popup is opened.
(() => {
  let opened=null;
  const enhance=root=>{
    root.querySelectorAll('select:not([multiple]):not([data-menu-ready])').forEach(select=>{
      select.dataset.menuReady='true';
      const wrapper=document.createElement('span');wrapper.className='select-control';
      const button=document.createElement('button');button.type='button';button.className='select-trigger';
      button.setAttribute('role','combobox');button.setAttribute('aria-haspopup','listbox');button.setAttribute('aria-expanded','false');
      const menu=document.createElement('div');menu.className='select-menu';menu.setAttribute('role','listbox');menu.hidden=true;
      menu.id=`select-menu-${crypto.randomUUID()}`;button.setAttribute('aria-controls',menu.id);
      let label=select.getAttribute('aria-label')||'';
      const originalLabels=[...select.labels||[]];
      for(const associated of select.labels||[]){const copy=associated.cloneNode(true);copy.querySelectorAll('select,small,input,textarea,button').forEach(node=>node.remove());label=label||copy.textContent.trim();if(associated.htmlFor===select.id&&select.id){button.id=`${select.id}-menu`;associated.htmlFor=button.id}}
      select.before(wrapper);wrapper.append(select,button);select.hidden=true;document.body.append(menu);
      let active=0,search='',lastKey=0;
      const position=()=>{const r=button.getBoundingClientRect();const width=Math.min(Math.max(r.width,230),window.innerWidth-24);menu.style.width=`${width}px`;menu.style.left=`${Math.max(12,Math.min(r.left,window.innerWidth-width-12))}px`;const below=window.innerHeight-r.bottom-12,above=r.top-12;const down=below>=Math.min(300,above);menu.style.maxHeight=`${Math.max(90,Math.min(320,down?below:above))}px`;menu.style.top=down?`${r.bottom+6}px`:'auto';menu.style.bottom=down?'auto':`${window.innerHeight-r.top+6}px`};
      const sync=()=>{label=select.getAttribute('aria-label')||originalLabels.map(associated=>{const copy=associated.cloneNode(true);copy.querySelectorAll('select,small,input,textarea,button').forEach(node=>node.remove());return copy.textContent.trim()}).join(' ');button.textContent=select.selectedOptions[0]?.textContent||ui.t('Choisir…');button.disabled=select.disabled;button.setAttribute('aria-label',`${label?label+' : ':''}${button.textContent}`);if(select.getAttribute('aria-invalid'))button.setAttribute('aria-invalid',select.getAttribute('aria-invalid'));else button.removeAttribute('aria-invalid')};
      const close=()=>{menu.hidden=true;button.setAttribute('aria-expanded','false');button.removeAttribute('aria-activedescendant');if(opened?.menu===menu)opened=null};
      const focusOption=index=>{const options=[...menu.children];active=index;options.forEach((node,i)=>node.classList.toggle('highlighted',i===active));const node=options[active];if(node){button.setAttribute('aria-activedescendant',node.id);node.scrollIntoView({block:'nearest'})}};
      const choose=index=>{if(select.options[index]?.disabled)return;select.selectedIndex=index;select.dispatchEvent(new Event('change',{bubbles:true}));sync();close();button.focus()};
      const open=()=>{if(button.disabled)return;opened?.close();menu.replaceChildren();[...select.options].forEach((option,index)=>{const node=document.createElement('button');node.type='button';node.tabIndex=-1;node.id=`${menu.id}-${index}`;node.setAttribute('role','option');node.setAttribute('aria-selected',String(option.selected));node.disabled=option.disabled;node.textContent=option.textContent;node.addEventListener('mousedown',event=>event.preventDefault());node.addEventListener('click',()=>choose(index));node.addEventListener('pointermove',()=>focusOption(index));menu.append(node)});menu.hidden=false;button.setAttribute('aria-expanded','true');position();opened={menu,button,close,position};focusOption(select.selectedIndex)};
      button.addEventListener('click',()=>menu.hidden?open():close());
      button.addEventListener('keydown',event=>{
        if(event.key==='Tab'){close();return}
        if(event.key==='Escape'){close();event.preventDefault();return}
        if(['ArrowDown','ArrowUp','Home','End'].includes(event.key)){event.preventDefault();const wasClosed=menu.hidden;if(wasClosed)open();const choices=[...select.options].map((o,i)=>o.disabled?-1:i).filter(i=>i>=0);let at=choices.indexOf(active);if(event.key==='Home')at=0;else if(event.key==='End')at=choices.length-1;else if(!wasClosed)at=Math.max(0,Math.min(choices.length-1,at+(event.key==='ArrowDown'?1:-1)));focusOption(choices[at]);return}
        if(event.key==='Enter'||event.key===' '){event.preventDefault();if(menu.hidden)open();else choose(active);return}
        if(event.key.length===1&&!event.ctrlKey&&!event.metaKey){event.preventDefault();if(menu.hidden)open();const now=Date.now();search=now-lastKey>700?event.key:search+event.key;lastKey=now;const index=[...select.options].findIndex(o=>!o.disabled&&o.textContent.trim().toLocaleLowerCase().startsWith(search.toLocaleLowerCase()));if(index>=0)focusOption(index)}
      });
      button.addEventListener('blur',()=>setTimeout(()=>{if(!menu.contains(document.activeElement)&&document.activeElement!==button)close()},0));
      select.addEventListener('change',sync);select.addEventListener('invalid',()=>{button.focus();button.setAttribute('aria-invalid','true')});select.form?.addEventListener('reset',()=>setTimeout(sync,0));
      new MutationObserver(sync).observe(select,{attributes:true,childList:true,characterData:true,subtree:true});document.addEventListener('odysafe:languagechange',()=>{sync();close()});sync();
    });
  };
  enhance(document);
  document.addEventListener('click',event=>{if(opened&&!opened.button.contains(event.target)&&!opened.menu.contains(event.target))opened.close()});
  window.addEventListener('resize',()=>opened?.position());document.addEventListener('scroll',event=>{if(opened&&!opened.menu.contains(event.target))opened.position()},true);
  document.addEventListener('htmx:beforeSwap',event=>{if(opened&&event.detail.target?.contains(opened.button))event.detail.shouldSwap=false});
  const refreshMenus=()=>{document.querySelectorAll('.select-menu').forEach(menu=>{const owner=document.querySelector(`[aria-controls="${menu.id}"]`);if(!owner){if(opened?.menu===menu)opened.close();menu.remove()}});enhance(document)};
  document.addEventListener('htmx:afterSwap',refreshMenus);document.addEventListener('odysafe:updated',refreshMenus);
})();

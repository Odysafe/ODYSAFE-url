/* Folder management and analysis deliberately use separate selection modes. */
(() => {
  'use strict';
  const ui=window.ODYSAFE_I18N;
  const library=document.querySelector('[data-library]');
  if(library){
    const form=document.getElementById('library-selection');
    const boxes=()=>[...library.querySelectorAll('[name=selected][form=library-selection]')];
    const selected=()=>boxes().filter(input=>input.checked).map(input=>input.value);
    const update=()=>{const count=selected().length;ui.setText(library.querySelector('[data-library-count]'),`${count} élément${count>1?'s':''} sélectionné${count>1?'s':''}`);library.querySelector('[data-selection-actions]').hidden=count===0;const master=library.querySelector('[data-library-all]');master.checked=count>0&&count===boxes().length;master.indeterminate=count>0&&count<boxes().length};
    const mode=active=>{library.classList.toggle('selection-mode',active);library.querySelector('[data-select-heading]').hidden=!active;library.querySelector('[data-library-select-mode]').hidden=active;if(!active)boxes().forEach(input=>input.checked=false);update()};
    library.querySelector('[data-library-select-mode]')?.addEventListener('click',()=>mode(true));
    library.querySelector('[data-library-cancel-selection]')?.addEventListener('click',()=>mode(false));
    library.addEventListener('change',event=>{if(event.target.matches('[data-library-all]'))boxes().forEach(input=>input.checked=event.target.checked);update()});
    const dialog=document.querySelector('[data-folder-dialog]');
    library.addEventListener('click',event=>{const rename=event.target.closest('[data-folder-rename]');if(rename||event.target.closest('[data-folder-new]')){dialog.querySelector('[name=folder_id]').value=rename?.dataset.folderRename||'';dialog.querySelector('[name=name]').value=rename?.dataset.folderName||'';ui.setText(dialog.querySelector('[data-folder-dialog-title]'),rename?'Renommer le dossier':'Nouveau dossier');ui.setText(dialog.querySelector('[data-folder-save]'),rename?'Enregistrer le nom':'Créer le dossier');dialog.showModal();dialog.querySelector('[name=name]').focus()}
      if(event.target.closest('[data-folder-delete]'))document.querySelector('[data-delete-dialog]')?.showModal();
      if(event.target.closest('[data-library-move]')){const move=document.querySelector('[data-move-dialog]');move.querySelector('form').reset();const inputs=move.querySelector('[data-move-items]');inputs.replaceChildren();selected().forEach(id=>{const input=document.createElement('input');input.type='hidden';input.name='selected';input.value=id;inputs.append(input)});ui.setText(move.querySelector('[data-move-description]'),`Choisissez où ranger ${selected().length} élément(s). Le contenu sera déplacé, sans être dupliqué.`);move.showModal()}
    });
    let dragged=[];
    library.addEventListener('dragstart',event=>{const row=event.target.closest('[data-library-item]');if(!row||event.target.closest('button,input')){event.preventDefault();return}dragged=selected().includes(row.dataset.libraryItem)?selected():[row.dataset.libraryItem];event.dataTransfer.setData('text/plain',dragged.join(','));event.dataTransfer.effectAllowed='move'});
    library.addEventListener('dragover',event=>{const target=event.target.closest('[data-folder-drop]');if(target&&dragged.length){event.preventDefault();target.classList.add('folder-drop-active');event.dataTransfer.dropEffect='move'}});
    library.addEventListener('dragleave',event=>event.target.closest('[data-folder-drop]')?.classList.remove('folder-drop-active'));
    library.addEventListener('dragend',()=>{dragged=[];library.querySelectorAll('.folder-drop-active').forEach(item=>item.classList.remove('folder-drop-active'))});
    library.addEventListener('drop',async event=>{const target=event.target.closest('[data-folder-drop]');if(!target||!dragged.length)return;event.preventDefault();target.classList.remove('folder-drop-active');const body=new FormData();body.set('csrf',form.querySelector('[name=csrf]').value);body.set('folder_id',target.dataset.folderDrop);dragged.forEach(id=>body.append('selected',id));try{const response=await fetch(`/engines/${library.dataset.engine}/move`,{method:'POST',body,credentials:'same-origin'});if(!response.ok)throw new Error();location.assign(response.url)}catch(_){const message=document.createElement('p');message.className='field-error';message.setAttribute('role','alert');ui.setText(message,'Le déplacement n’a pas abouti. Sélectionnez les éléments puis utilisez « Déplacer… » pour réessayer.');library.querySelector('.library-content').prepend(message)}dragged=[]});
    update();
  }
  document.querySelectorAll('.library-dialog [data-dialog-close]').forEach(button=>button.addEventListener('click',()=>button.closest('dialog').close()));
  const wizard=document.querySelector('[data-folder-wizard]');
  if(!wizard)return;
  const groups=[...wizard.querySelectorAll('.analysis-group')],items=()=>[...wizard.querySelectorAll('[data-analysis-item]')],scans=()=>[...wizard.querySelectorAll('[name=scan_ids]')];
  groups.forEach(group=>group.querySelector('[data-analysis-group]').removeAttribute('name'));
  const folderStep=wizard.querySelector('[data-wizard-step=folders]'),scanStep=wizard.querySelector('[data-wizard-step=scans]'),next=wizard.querySelector('[data-wizard-next]'),back=wizard.querySelector('[data-wizard-back]');
  next.hidden=false;back.hidden=false;
  const update=()=>{
    const count=items().filter(input=>input.checked).length,investigations=scans().filter(input=>input.checked).length,names=[];
    groups.forEach(group=>{const usable=[...group.querySelectorAll('[data-analysis-item]:not(:disabled)')],chosen=usable.filter(input=>input.checked).length,master=group.querySelector('[data-analysis-group]');master.disabled=!usable.length;master.checked=chosen>0&&chosen===usable.length;master.indeterminate=chosen>0&&chosen<usable.length;group.classList.toggle('folder-picked',chosen>0);ui.setText(group.querySelector('[data-group-selection]'),chosen?`${chosen} choisi(s)`:'');if(chosen)names.push(group.dataset.groupName)});
    const description=count?`${names.length} dossier(s) · ${count} élément(s) choisi(s)`:'Choisissez au moins un dossier ou un élément.';
    ui.setText(wizard.querySelector('[data-wizard-content-summary]'),count>100?'Choisissez au maximum 100 éléments.':description);
    ui.setText(wizard.querySelector('[data-wizard-recap-count]'),description);wizard.querySelector('[data-wizard-recap-folders]').textContent=names.join(' · ');
    next.disabled=count<1||count>100;
    ui.setText(wizard.querySelector('[data-analysis-count]'),investigations>20?'Choisissez au maximum 20 investigations.':`${count} élément(s) · ${investigations} investigation(s)`);
    wizard.querySelector('.analysis-footer button').disabled=count<1||count>100||investigations<1||investigations>20;
    const visible=scans().filter(input=>!input.closest('[data-scan-choice]').hidden),checked=visible.filter(input=>input.checked).length,master=wizard.querySelector('[data-scans-all]');master.checked=checked>0&&checked===visible.length;master.indeterminate=checked>0&&checked<visible.length;master.disabled=!visible.length;
  };
  const step=which=>{folderStep.hidden=which!=='folders';scanStep.hidden=which!=='scans';wizard.querySelectorAll('[data-step-indicator]').forEach(item=>{if(item.dataset.stepIndicator===which)item.setAttribute('aria-current','step');else item.removeAttribute('aria-current')});const heading=(which==='folders'?folderStep:scanStep).querySelector('h2');heading.tabIndex=-1;heading.focus({preventScroll:true});heading.scrollIntoView({block:'nearest',behavior:'smooth'})};
  wizard.addEventListener('change',event=>{const master=event.target.closest('[data-analysis-group]');if(master)master.closest('.analysis-group').querySelectorAll('[data-analysis-item]:not(:disabled)').forEach(input=>input.checked=master.checked);
    if(event.target.matches('[data-include-inactive]'))items().forEach(input=>{input.disabled=input.dataset.unusable==='true'||(!event.target.checked&&input.dataset.active==='false');if(input.disabled)input.checked=false});
    if(event.target.matches('[data-scans-all]'))scans().filter(input=>!input.closest('[data-scan-choice]').hidden).forEach(input=>input.checked=event.target.checked);
    update();
  });
  wizard.querySelector('[data-scan-search]').addEventListener('input',event=>{const query=event.target.value.toLocaleLowerCase();wizard.querySelectorAll('[data-scan-choice]').forEach(label=>label.hidden=!label.textContent.toLocaleLowerCase().includes(query));update()});
  next.addEventListener('click',()=>{if(!next.disabled)step('scans')});back.addEventListener('click',()=>step('folders'));
  wizard.addEventListener('submit',event=>{if(!folderStep.hidden){event.preventDefault();if(!next.disabled)step('scans')}});
  update();if(items().some(input=>input.checked))step('scans');else scanStep.hidden=true;
})();

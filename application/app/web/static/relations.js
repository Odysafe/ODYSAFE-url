/* A bounded view of observed relations. No inference from shared membership. */
(() => {
  'use strict';
  const ui=window.ODYSAFE_I18N;
  document.querySelectorAll('[data-relations]').forEach(panel => {
    let data;try{data=JSON.parse(panel.dataset.payload)}catch(_){return}
    const $=selector=>panel.querySelector(selector),NS='http://www.w3.org/2000/svg';
    const svg=$('[data-relation-svg]'),inspector=$('[data-relation-details]'),search=$('[data-relation-search]');
    const nodes=Array.isArray(data.nodes)?data.nodes:[],counts=new Map((data.summary||[]).map(item=>[item.host,item.count]));
    const hosts=nodes.filter(item=>item.kind==='host').map(item=>({...item,count:counts.get(item.host)||0}));
    hosts.sort((a,b)=>Number(Boolean(b.primary))-Number(Boolean(a.primary))||b.count-a.count||String(a.host).localeCompare(String(b.host)));
    const byId=new Map(hosts.map(item=>[item.id,item])),edges=(data.host_edges||[]).filter(edge=>byId.has(edge.source)&&byId.has(edge.target)&&edge.source!==edge.target);
    const initial=hosts.find(item=>item.primary)||hosts[0];
    const kinds={initiated:{label:'Déclenche une requête',color:'#76c99d'},navigation:{label:'Navigation observée',color:'#78a8ed'},popup:{label:'Ouvre un onglet',color:'#e7bb68'},http_redirect:{label:'Redirection HTTP',color:'#b69ae9'}};
    let root=initial?.id,selected=root,view='hosts',page=0,scale=1,pan={x:0,y:0},drag=null,scene=null,width=1000;
    const PAGE_SIZE=6;
    const text=(tag,value,className)=>{const el=document.createElement(tag);el.textContent=(tag==='code'||tag==='h3'||tag==='strong'&&value.includes('.'))?value:ui.t(value);if(className)el.className=className;return el};
    const element=(tag,attributes={})=>{const el=document.createElementNS(NS,tag);Object.entries(attributes).forEach(([key,value])=>el.setAttribute(key,String(value)));return el};
    const name=item=>item.host==='unknown'?ui.t('Hôte non identifié'):String(item.host||item.label||ui.t('Hôte non identifié'));
    const matches=item=>name(item).toLocaleLowerCase().includes(search.value.trim().toLocaleLowerCase());
    const relationInfo=edge=>kinds[edge.type||edge.mechanism]||{label:'Lien observé',color:'#a1aab7'};
    const resetCamera=()=>{scale=1;pan={x:0,y:0}};
    const transform=()=>{if(scene)scene.setAttribute('transform',`translate(${pan.x+width/2} ${pan.y+310}) scale(${scale}) translate(${-width/2} -310)`)};
    function selectHost(id){selected=id;showHost(id);svg.querySelectorAll('[data-node]').forEach(node=>node.classList.toggle('selected',node.dataset.node===id))}
    function explore(id){root=id;selected=id;page=0;resetCamera();render()}
    function showHost(id){
      const item=byId.get(id);inspector.replaceChildren();if(!item){inspector.append(text('p','Aucun domaine disponible.'));return}
      inspector.append(text('p',item.primary?'DOMAINE PRINCIPAL':'DOMAINE OBSERVÉ','eyebrow'),text('h3',name(item)),text('p',`${item.count} requête${item.count===1?'':'s'} enregistrée${item.count===1?'':'s'}`,'relations-request-count'));
      const relevant=edges.filter(edge=>edge.source===id||edge.target===id);
      inspector.append(text('h4',id===root?'Ses connexions directes':'Lien avec le domaine exploré'));
      const related=id===root?relevant:relevant.filter(edge=>edge.source===root||edge.target===root);
      related.forEach(edge=>{const source=byId.get(edge.source),target=byId.get(edge.target),info=relationInfo(edge);const line=text('div','','relation-proof');line.dataset.kind=edge.type;line.append(text('strong',info.label),text('p',`${name(source)} → ${name(target)}`),text('small',`${edge.count||1} observation(s) à l’origine de ce lien`));inspector.append(line)});
      if(!related.length)inspector.append(text('p','Aucun lien direct prouvé dans les données collectées. Sa présence dans la capture ne permet pas de déduire qui l’a appelé.','muted'));
      for(const [key,label] of [['connection_ips','Adresses IP de connexion'],['resolved_ips','Adresses IP issues du DNS']]){if(item[key]?.length){inspector.append(text('h4',label),text('p',item[key].join(', '),'mono'))}}
      const actions=text('div','','relations-detail-actions');
      if(id!==root){const button=text('button','Explorer ses connexions');button.type='button';button.addEventListener('click',()=>explore(id));actions.append(button)}
      const link=text('a','Voir les requêtes dans Réseau','button');link.href=`?section=network&q=${encodeURIComponent(item.host)}`;actions.append(link);inspector.append(actions);
      const resources=nodes.filter(node=>node.kind==='resource'&&node.host===item.host);
      if(resources.length){const details=document.createElement('details');details.append(text('summary',`${resources.length} ressource(s) collectée(s)`));const list=document.createElement('ul');resources.slice(0,30).forEach(resource=>{const li=document.createElement('li');li.append(text('small',resource.resource_type||'Ressource'),text('code',resource.url||resource.label));list.append(li)});details.append(list);if(resources.length>30)details.append(text('p','Les 30 premières ressources sont affichées. Consultez Réseau pour la liste complète.','muted'));inspector.append(details)}
    }
    function addNode(item,x,y,isRoot){
      const g=element('g',{class:`relation-domain${isRoot?' root':''}${item.id===selected?' selected':''}`,transform:`translate(${x} ${y})`,tabindex:0,role:'button','aria-label':ui.t('{host}, {count} requêtes. Afficher les détails.',{host:name(item),count:item.count})});g.dataset.node=item.id;
      const title=element('title');title.textContent=name(item);g.append(title,element('rect',{x:-120,y:-38,width:240,height:76,rx:9}));
      const words=name(item),lines=[];let remaining=words;
      while(remaining.length>29&&lines.length<2){let at=remaining.lastIndexOf('.',29);if(at<12)at=29;else at++;lines.push(remaining.slice(0,at));remaining=remaining.slice(at)}
      lines.push(remaining.length>29?remaining.slice(0,26)+"…":remaining);const label=element('text',{'text-anchor':'middle',class:'relation-domain-name',y:lines.length===1?-5:-15});lines.forEach((line,index)=>{const span=element('tspan',{x:0,dy:index?16:0});span.textContent=line;label.append(span)});g.append(label);
      const caption=element('text',{'text-anchor':'middle',class:'relation-domain-count',y:lines.length===3?32:lines.length===2?25:19});ui.setText(caption,`${item.count} requête${item.count===1?'':'s'}`);g.append(caption);
      g.addEventListener('click',()=>selectHost(item.id));g.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();selectHost(item.id)}});scene.append(g);
    }
    function drawLink(source,target,edge,offset){
      const info=relationInfo(edge),forward=target.x>source.x;const start=source.x+(forward?120:-120),end=target.x+(forward?-120:120),bend=Math.max(35,Math.abs(end-start)*.5),sign=forward?1:-1;
      const path=element('path',{d:`M ${start} ${source.y+offset} C ${start+sign*bend} ${source.y+offset}, ${end-sign*bend} ${target.y+offset}, ${end} ${target.y+offset}`,stroke:info.color,class:'relation-connection','marker-end':`url(#relation-arrow-${edge.type||'other'})`});
      const title=element('title');title.textContent=`${ui.t(info.label)} : ${name(byId.get(edge.source))} → ${name(byId.get(edge.target))} (${edge.count||1} observation(s))`;path.append(title);if(edge.type==='popup')path.setAttribute('stroke-dasharray','6 5');scene.append(path);
    }
    function hostMap(){
      const item=byId.get(root),connected=edges.filter(edge=>edge.source===root||edge.target===root),ids=[...new Set(connected.map(edge=>edge.source===root?edge.target:edge.source))];
      const neighbors=ids.map(id=>byId.get(id)).filter(matches).sort((a,b)=>b.count-a.count||name(a).localeCompare(name(b)));
      const pages=Math.max(1,Math.ceil(neighbors.length/PAGE_SIZE));page=Math.min(page,pages-1);const shown=neighbors.slice(page*PAGE_SIZE,(page+1)*PAGE_SIZE);
      width=Math.max(760,Math.round(svg.getBoundingClientRect().width)||1000);svg.setAttribute('viewBox',`0 0 ${width} 620`);svg.replaceChildren();const defs=element('defs');
      for(const [kind,info] of Object.entries({...kinds,other:{color:'#a1aab7'}})){const marker=element('marker',{id:`relation-arrow-${kind}`,viewBox:'0 0 10 10',refX:9,refY:5,markerWidth:7,markerHeight:7,orient:'auto'});marker.append(element('path',{d:'M 0 0 L 10 5 L 0 10 z',fill:info.color}));defs.append(marker)}svg.append(defs);scene=element('g');svg.append(scene);transform();
      if(!item){ui.setText($('[data-relation-heading]'),'Aucune donnée réseau disponible');ui.setText($('[data-relation-explanation]'),'Cette investigation ne contient pas de domaines collectés.');showHost(null);$('[data-relation-previous]').disabled=true;$('[data-relation-next]').disabled=true;const empty=element('text',{x:32,y:70,class:'relation-svg-empty'});ui.setText(empty,'Aucun domaine collecté pour cette investigation.');scene.append(empty);return}
      const positions=new Map([[root,{x:155,y:310}]]);shown.forEach((neighbor,index)=>positions.set(neighbor.id,{x:width-155,y:shown.length===1?310:65+index*(490/Math.max(1,shown.length-1))}));
      const visible=connected.filter(edge=>positions.has(edge.source)&&positions.has(edge.target));const pairs=new Map();visible.forEach(edge=>{const key=[edge.source,edge.target].sort().join('|');if(!pairs.has(key))pairs.set(key,[]);pairs.get(key).push(edge)});
      pairs.forEach(group=>group.forEach((edge,index)=>drawLink(positions.get(edge.source),positions.get(edge.target),edge,(index-(group.length-1)/2)*9)));
      addNode(item,155,310,true);shown.forEach(neighbor=>{const p=positions.get(neighbor.id);addNode(neighbor,p.x,p.y,false)});
      if(!shown.length){const empty=element('text',{x:width/2,y:300,class:'relation-svg-empty'});ui.setText(empty,search.value?'Aucune connexion ne correspond à la recherche.':'Aucune connexion directe prouvée.');scene.append(empty)}
      $('[data-relation-heading]').textContent=name(item);
      ui.setText($('[data-relation-explanation]'),' {count} requête(s) vers ce domaine · {linked} autre(s) domaine(s) directement relié(s) par les preuves.'.trim(),{count:item.count,linked:ids.length});
      ui.setText($('[data-relation-page]'),neighbors.length?`${page*PAGE_SIZE+1}–${Math.min((page+1)*PAGE_SIZE,neighbors.length)} sur ${neighbors.length} domaines liés`:'Aucun lien à afficher');
      $('[data-relation-previous]').disabled=page===0;$('[data-relation-next]').disabled=page>=pages-1;
      const directory=$('[data-relation-directory]');directory.replaceChildren();const matching=hosts.filter(matches);ui.setText($('[data-relation-directory-title]'),`Tous les domaines observés (${matching.length}) — choisir un autre point de départ`);
      matching.forEach(host=>{const button=text('button','','relations-directory-item');button.type='button';button.append(text('strong',name(host)),text('small',`${host.count} requête(s)${host.primary?' · Domaine principal':''}`));button.addEventListener('click',()=>{search.value='';explore(host.id)});directory.append(button)});
      showHost(selected);
    }
    function paths(){
      const browser=view==='browser',query=search.value.trim().toLocaleLowerCase();const all=(browser?data.browser_paths:data.redirects)||[];
      const filtered=all.filter(edge=>`${edge.source} ${edge.target}`.toLocaleLowerCase().includes(query)),pages=Math.max(1,Math.ceil(filtered.length/20));page=Math.min(page,pages-1);
      ui.setText($('[data-relation-heading]'),browser?'Les déplacements observés dans le navigateur':'Les redirections HTTP enregistrées');
      ui.setText($('[data-relation-explanation]'),browser?'Chaque ligne montre un déplacement réellement observé ou l’ouverture d’un onglet. Les appels de scripts et d’images ne figurent pas dans cette vue.':'Chaque ligne relie l’URL d’une requête à sa destination de redirection. Une ressource redirigée ne signifie pas que la page principale a changé.');
      const list=$('[data-relation-paths]');list.replaceChildren();
      filtered.slice(page*20,(page+1)*20).forEach((edge,index)=>{const card=text('article','','relations-path');const info=relationInfo({type:edge.mechanism||'http_redirect'});card.append(text('span',`${page*20+index+1}`,'relations-path-number'));const values=text('div','','relations-path-values');values.append(text('code',edge.source));const transition=text('p',`→ ${ui.t(info.label)}${edge.status?' · HTTP '+edge.status:''}`,'relations-path-transition');transition.style.color=info.color;values.append(transition,text('code',edge.target));card.append(values);list.append(card)});
      if(!filtered.length)list.append(text('div',query?'Aucun passage ne correspond à votre recherche.':browser?'Aucun déplacement de navigation collecté. Consultez les domaines pour voir les connexions réseau.':'Aucune redirection HTTP collectée.','empty'));
      if(filtered.length>20){const controls=text('div','','relations-pagination');for(const [label,delta,disabled] of [['← Précédents',-1,page===0],['Suivants →',1,page===pages-1]]){const button=text('button',label);button.type='button';button.disabled=disabled;button.addEventListener('click',()=>{page+=delta;paths()});controls.append(button)}controls.append(text('span',`Page ${page+1} sur ${pages}`));list.append(controls)}
    }
    function render(){const map=view==='hosts';$('[data-relation-hosts]').hidden=!map;$('[data-relation-paths]').hidden=map;$('[data-relation-home]').hidden=!map;if(map)hostMap();else paths()}
    panel.querySelectorAll('[data-relation-view]').forEach(button=>{button.addEventListener('click',()=>{view=button.dataset.relationView;page=0;panel.querySelectorAll('[data-relation-view]').forEach(tab=>{tab.setAttribute('aria-selected',String(tab===button));tab.tabIndex=tab===button?0:-1});$('#relations-content').setAttribute('aria-labelledby',button.id);resetCamera();render()});button.addEventListener('keydown',event=>{const tabs=[...panel.querySelectorAll('[data-relation-view]')];let index=tabs.indexOf(button);if(event.key==='ArrowRight')index=(index+1)%tabs.length;else if(event.key==='ArrowLeft')index=(index+tabs.length-1)%tabs.length;else if(event.key==='Home')index=0;else if(event.key==='End')index=tabs.length-1;else return;event.preventDefault();tabs[index].focus();tabs[index].click()})});
    search.addEventListener('input',()=>{page=0;render()});$('[data-relation-home]').addEventListener('click',()=>{search.value='';explore(initial?.id)});
    $('[data-relation-previous]').addEventListener('click',()=>{page=Math.max(0,page-1);hostMap()});$('[data-relation-next]').addEventListener('click',()=>{page++;hostMap()});
    $('[data-relation-fit]').addEventListener('click',()=>{resetCamera();transform()});panel.querySelectorAll('[data-relation-zoom]').forEach(button=>button.addEventListener('click',()=>{scale=Math.max(.65,Math.min(2,scale+(button.dataset.relationZoom==='in'?.15:-.15)));transform()}));
    svg.addEventListener('wheel',event=>{if(!event.ctrlKey&&!event.metaKey)return;event.preventDefault();scale=Math.max(.65,Math.min(2,scale+(event.deltaY<0?.1:-.1)));transform()},{passive:false});
    svg.addEventListener('pointerdown',event=>{if(event.target.closest('[data-node]'))return;drag={x:event.clientX,y:event.clientY,pan:{...pan}};svg.setPointerCapture(event.pointerId)});svg.addEventListener('pointermove',event=>{if(!drag)return;const ratio=width/svg.getBoundingClientRect().width;pan={x:drag.pan.x+(event.clientX-drag.x)*ratio,y:drag.pan.y+(event.clientY-drag.y)*ratio};transform()});svg.addEventListener('pointerup',()=>{drag=null});svg.addEventListener('pointercancel',()=>{drag=null});
    let lastWidth=0;new ResizeObserver(entries=>{const current=Math.round(entries[0].contentRect.width);if(current&&current!==lastWidth){lastWidth=current;if(view==='hosts'){resetCamera();hostMap()}}}).observe(svg.parentElement);
    const refreshLanguage=()=>{ui.setText($('[data-relation-total]'),`${hosts.length} domaine(s) observé(s)`);render()};document.addEventListener('odysafe:languagechange',refreshLanguage);refreshLanguage();
  });
})();

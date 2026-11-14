/* Only explicitly marked interface text is localized. Values and evidence are untouched. */
(() => {
  'use strict';
  const catalog=window.ODYSAFE_TRANSLATIONS||{},keys=window.ODYSAFE_TRANSLATION_KEYS||{};
  const escape=value=>value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
  const patterns=Object.keys(catalog).filter(source=>/\{\w+\}/.test(source)).map(source=>{
    const names=[];let offset=0,pattern='^';
    for(const match of source.matchAll(/\{(\w+)\}/g)){pattern+=escape(source.slice(offset,match.index))+'(.+?)';names.push(match[1]);offset=match.index+match[0].length}
    return {source,names,regex:new RegExp(pattern+escape(source.slice(offset))+'$')};
  });
  let lang=document.cookie.split('; ').find(item=>item.startsWith('odysafe_language='))?.split('=')[1]==='en'?'en':'fr';
  const format=(text,params)=>text.replace(/\{(\w+)\}/g,(all,key)=>Object.hasOwn(params,key)?String(params[key]):all);
  function t(source,params={}){
    source=String(source??'');
    if(lang==='fr')return format(source,params);
    if(Object.hasOwn(catalog,source))return format(catalog[source],params);
    for(const pattern of patterns){const match=source.match(pattern.regex);if(match)return format(catalog[pattern.source],Object.fromEntries(pattern.names.map((key,index)=>[key,match[index+1]])))}
    return source;
  }
  // Attributes may contain a translated UI prefix plus an unchanged user value.
  const fragments=Object.keys(catalog).filter(source=>source.length>3&&!source.includes('{')).sort((a,b)=>b.length-a.length);
  function attribute(source){
    const direct=t(source);if(direct!==source||lang==='fr')return direct;
    for(const fragment of fragments){if(source.startsWith(fragment+' '))return t(fragment)+source.slice(fragment.length);if(source.endsWith(' '+fragment))return source.slice(0,-fragment.length)+t(fragment)}
    return source;
  }
  const setText=(node,source,params={})=>{if(!node)return;node.dataset.i18nText=String(source);node.dataset.i18nParams=JSON.stringify(params);const result=t(source,params);if(node.textContent!==result)node.textContent=result};
  const setAttribute=(node,name,source)=>{node.setAttribute('data-i18n-'+name,source);node.setAttribute(name,attribute(source))};
  const attrs=['title','aria-label','placeholder','alt','data-confirm','data-help','data-example','content'];
  function apply(root=document){
    const walker=document.createTreeWalker(root,NodeFilter.SHOW_COMMENT);let comment;
    while((comment=walker.nextNode())){
      if(!comment.data.startsWith('odysafe-i18n:'))continue;
      const [key,encoded]=comment.data.slice(13).split(':');const source=keys[key];if(source===undefined)continue;
      let params={};if(encoded){try{params=JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(encoded),c=>c.charCodeAt(0))))}catch(_){continue}}
      const value=t(source,params),next=comment.nextSibling;
      if(next?.nodeType===Node.TEXT_NODE){if(next.data!==value)next.data=value}
      else if(next?.nodeType===Node.COMMENT_NODE&&next.data==='/odysafe-i18n')comment.after(document.createTextNode(value));
    }
    const selector=attrs.map(name=>'[data-i18n-'+name+']').concat('[data-i18n-text]').join(',');
    const nodes=[...(root.nodeType===Node.ELEMENT_NODE&&root.matches(selector)?[root]:[]),...root.querySelectorAll?.(selector)||[]];
    for(const node of nodes){
      for(const name of attrs){const source=node.getAttribute('data-i18n-'+name);if(source!==null){const value=attribute(source);if(node.getAttribute(name)!==value)node.setAttribute(name,value)}}
      if(node.hasAttribute('data-i18n-text')){let params={};try{params=JSON.parse(node.dataset.i18nParams||'{}')}catch(_){}const value=node.tagName==='TITLE'?attribute(node.dataset.i18nText):t(node.dataset.i18nText,params);if(node.textContent!==value)node.textContent=value}
    }
  }
  function switchLanguage(value,persist=false){
    lang=value==='en'?'en':'fr';document.documentElement.lang=lang;
    if(persist)document.cookie=`odysafe_language=${lang}; Path=/; Max-Age=31536000; SameSite=Strict${location.protocol==='https:'?'; Secure':''}`;
    apply();
    document.querySelectorAll('button[data-language]').forEach(button=>button.setAttribute('aria-pressed',String(button.dataset.language===lang)));
    document.dispatchEvent(new CustomEvent('odysafe:languagechange',{detail:{language:lang}}));
  }
  window.ODYSAFE_I18N={t,setText,setAttribute,apply,get language(){return lang}};
  // The title is not a normal HTML text node: retain its French source separately.
  const title=document.querySelector('title');if(title&&!title.dataset.i18nText){let source=title.textContent;for(const [fr,en] of Object.entries(catalog)){if(source===en){source=fr;break}}title.dataset.i18nText=source}
  document.addEventListener('click',event=>{const button=event.target.closest('button[data-language]');if(button)switchLanguage(button.dataset.language,true)});
  const pending=new Set();let scheduled=false;
  new MutationObserver(records=>{for(const record of records)for(const node of record.addedNodes)if(node.nodeType===Node.ELEMENT_NODE)pending.add(node);if(pending.size&&!scheduled){scheduled=true;queueMicrotask(()=>{scheduled=false;for(const node of pending)if(node.isConnected)apply(node);pending.clear()})}}).observe(document.documentElement,{childList:true,subtree:true});
  document.addEventListener('htmx:afterSwap',event=>apply(event.detail?.target||document));
  document.addEventListener('odysafe:updated',()=>apply());
  switchLanguage(lang);
})();

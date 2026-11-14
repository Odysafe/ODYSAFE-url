"""Offline XLSX reports using portable cells and fixed-size PNG flow diagrams."""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import threading
from collections import defaultdict
from datetime import datetime, timezone
import xlsxwriter

from app.reporting.xlsx_flows import flow_panels

MAX_INPUT = 256 * 1024 * 1024
MAX_FILE = 64 * 1024 * 1024
MAX_ROWS = 2_000_000
EXPORT_LOCK = threading.Lock()
XML_ILLEGAL = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]')
TEXT_SUFFIXES = {'.json', '.har', '.html', '.js', '.css', '.txt'}


class ExportLimitError(ValueError):
    pass


class ExportBusyError(RuntimeError):
    pass


def obj(value): return value if isinstance(value, dict) else {}
def seq(value): return value if isinstance(value, list) else []
def records(value): return [item for item in seq(value) if isinstance(item, dict)]


def display(value):
    if value is None: return '—'
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False, separators=(', ', ': '), default=str)
    return str(value)


class DataSheet:
    """Sequential rows keep export memory bounded; overflow gets a new sheet."""
    def __init__(self, report, title, description, columns):
        self.report, self.title, self.description, self.columns = report, title, description, columns
        self.pages, self.total = [], 0
        self._new_page()

    def _new_page(self):
        suffix = '' if not self.pages else f' {len(self.pages)+1}'
        self.sheet = self.report.book.add_worksheet(self.title[:31-len(suffix)] + suffix)
        self.pages.append(self.sheet);self.row=5
        self.report.decorate(self.sheet,self.title,self.description,len(self.columns))
        for index,(label,width) in enumerate(self.columns):
            self.sheet.set_column(index,index,width)
            self.sheet.write_string(4,index,label,self.report.fmt['table_head'])
        self.sheet.set_row(4,30);self.sheet.freeze_panes(5,1);self.sheet.repeat_rows(0,4)

    def add(self, *values):
        if self.row>=1_048_575:
            self._finish_page();self._new_page()
        self.report.rows+=1
        if self.report.rows>MAX_ROWS: raise ExportLimitError('Le rapport dépasse la capacité de l’export. Exportez les investigations séparément.')
        fmt=self.report.fmt['odd' if self.total%2==0 else 'even'];height=28
        for column,value in enumerate(values[:len(self.columns)]):
            if isinstance(value,(int,float)) and not isinstance(value,bool) and -9_007_199_254_740_992 < value < 9_007_199_254_740_992 and math.isfinite(value):
                self.sheet.write_number(self.row,column,value,fmt)
            else:
                text=XML_ILLEGAL.sub('�',display(value))
                if len(text)>15000:
                    text=text[:14900]+' … [version intégrale dans Sources / full version in Sources]'
                self.sheet.write_string(self.row,column,text,fmt)
                height=max(height,min(76,16*max(1,math.ceil(len(text)/(self.columns[column][1]*1.1)))))
        self.sheet.set_row(self.row,height);self.row+=1;self.total+=1

    def _finish_page(self):
        self.sheet.autofilter(4,0,max(4,self.row-1),len(self.columns)-1)
        self.sheet.print_area(0,0,max(5,self.row-1),len(self.columns)-1)

    def finish(self):
        if self.total==0:
            self.sheet.write_string(5,0,self.report.t('Aucune donnée enregistrée','No data recorded'),self.report.fmt['muted'])
            self.sheet.set_row(5,30)
        self._finish_page()


class InvestigationWorkbook:
    def __init__(self, destination: Path, language='fr'):
        self.en=language=='en';self.rows=0;self.input_bytes=0;self.images=[];self.scan_count=0;self.primary={}
        self.counts={'requests':0,'hosts':0,'detections':0,'dns':0}
        self.generated=datetime.now(timezone.utc).isoformat(timespec='seconds')
        self.book=xlsxwriter.Workbook(str(destination),{'constant_memory':True,'strings_to_formulas':False,'strings_to_urls':False,'strings_to_numbers':False})
        self.book.set_properties({'title':self.t('Rapport d’investigation ODYSAFE','ODYSAFE investigation report'),'author':'ODYSAFE-URL','comments':'Offline evidence export. No macros, formulas or external links.'})
        base={'font_name':'Arial','font_size':10,'font_color':'#25324A','valign':'top'}
        self.fmt={
          'title':self.book.add_format({**base,'font_size':23,'bold':True,'font_color':'#FFFFFF','bg_color':'#202B43','valign':'vcenter'}),
          'subtitle':self.book.add_format({**base,'font_size':10,'font_color':'#62718A','text_wrap':True,'valign':'vcenter'}),
          'section':self.book.add_format({**base,'font_size':12,'bold':True,'font_color':'#7956C8','valign':'vcenter'}),
          'table_head':self.book.add_format({**base,'bold':True,'font_color':'#FFFFFF','bg_color':'#37445D','text_wrap':True,'valign':'vcenter'}),
          'odd':self.book.add_format({**base,'bg_color':'#F2F5FA','text_wrap':True,'bottom':1,'bottom_color':'#E4E9F0'}),
          'even':self.book.add_format({**base,'bg_color':'#FFFFFF','text_wrap':True,'bottom':1,'bottom_color':'#E4E9F0'}),
          'muted':self.book.add_format({**base,'font_color':'#62718A','text_wrap':True}),
          'number':self.book.add_format({**base,'font_size':25,'bold':True,'font_color':'#7956C8','bg_color':'#F2F5FA','valign':'vcenter'}),
          'metric':self.book.add_format({**base,'font_color':'#62718A','bg_color':'#F2F5FA','bold':True,'valign':'vcenter'}),
        }
        self.cover=self.book.add_worksheet(self.t('Synthèse','Overview'))
        self.flows=self.book.add_worksheet(self.t('Flux réseau','Network flows'));self.flow_row=5
        self.decorate(self.flows,self.t('Flux réseau observés','Observed network flows'),self.t('Lecture visuelle des relations enregistrées. Les tableaux conservent les noms complets.','Visual guide to recorded connections. Full names are retained in the data sheets.'),8)
        self.flows.set_column(0,7,17);self.flows.set_paper(8);self.flows.freeze_panes(4,0);self.flows.set_landscape()
        self.tables={}
        def table(key,fr,en,description,columns):
            self.tables[key]=DataSheet(self,self.t(fr,en),self.t(*description),[(self.t(a,b),w) for a,b,w in columns])
        ID=('Investigation','Investigation',38)
        table('investigations','Investigations','Investigations',('Vue d’ensemble des investigations incluses.','Overview of the included investigations.'),[ID,('Domaine','Domain',28),('URL soumise','Submitted URL',58),('URL finale','Final URL',58),('Titre','Title',45),('Date de capture','Capture date',28),('Capture','Capture',20),('Analyse','Analysis',20),('Profil','Profile',18),('Requêtes','Requests',14),('Domaines','Domains',14),('Détections','Detections',14),('Signaux DNS','DNS signals',14)])
        table('engines','Moteurs','Engines',('Une analyse non exécutée est distinguée d’une analyse sans correspondance.','An engine that did not run is distinct from an engine with no matches.'),[ID,('Moteur','Engine',20),('État enregistré','Recorded status',24),('Règles / indicateurs','Rules / indicators',20),('Artefacts / réponses','Artifacts / responses',20),('Correspondances / signaux','Matches / signals',23),('Dernière exécution','Last run',30),('Détails','Details',75)])
        table('hosts','Domaines','Domains',('Les IP HAR décrivent les connexions enregistrées ; les IP DNS restent dans l’onglet DNS.','HAR IPs describe recorded connections; DNS results are kept in the DNS sheet.'),[ID,('Domaine','Domain',35),('Requêtes','Requests',14),('IP de connexion HAR','HAR connection IPs',38),('Octets envoyés','Bytes sent',18),('Octets reçus','Bytes received',18),('Première observation','First seen',28),('Dernière observation','Last seen',28),('MIME','MIME types',40)])
        table('http','Requêtes HTTP','HTTP requests',('Toutes les transactions disponibles, sans pagination de l’interface.','All available transactions, independent of interface pagination.'),[ID,('ID requête','Request ID',24),('Horodatage','Timestamp',29),('Méthode','Method',12),('URL','URL',75),('Domaine','Domain',34),('Code HTTP','HTTP status',13),('MIME','MIME',30),('Durée (ms)','Duration (ms)',17),('Octets envoyés','Bytes sent',18),('Octets reçus','Bytes received',18),('IP de connexion HAR','HAR connection IP',29),('Redirection','Redirect',65),('Détails complets','Full details',75)])
        table('relations','Relations','Connections',('Flèches source → destination. Les simples regroupements de domaines ne sont pas des liens causaux.','Arrows point from source to destination. Group membership alone is not a causal link.'),[ID,('Niveau','Level',20),('Source','Source',65),('Destination','Destination',65),('Type','Type',25),('Observations','Observations',17),('Preuve explicite','Explicit evidence',20),('Détails','Details',75)])
        table('findings','Détections','Detections',('Observations techniques et correspondances, sans verdict global de sûreté.','Technical observations and matches, with no overall safety verdict.'),[ID,('Moteur','Engine',18),('Règle','Rule',38),('Sévérité','Severity',17),('Description','Description',70),('Preuves','Evidence',90)])
        table('yara','Couverture YARA-X','YARA-X coverage',('Artefacts réellement soumis au moteur et correspondances enregistrées.','Artifacts actually submitted to the engine and recorded matches.'),[ID,('Artefact','Artifact',58),('Domaine','Domain',35),('État','Status',25),('Correspondances','Matches',65),('Détails','Details',95)])
        table('ioc','Correspondances IOC','IOC matches',('Comparaisons locales, y compris les résultats des analyses ciblées.','Offline comparisons, including targeted analysis results.'),[ID,('Exécution','Run ID',38),('Type','Type',16),('IOC déclaré','Declared IOC',65),('Valeur observée','Observed value',65),('Nature déclarée','Declared category',22),('Origine déclarée','Declared source',40),('Date','Date',29),('Explication','Explanation',75)])
        table('dns','DNS','DNS',('Réponses des fournisseurs, résultats de cache datés, erreurs et preuves EDE.','Provider responses, timestamped cache results, errors and EDE evidence.'),[ID,('Exécution','Run ID',38),('Domaine','Domain',36),('Fournisseur','Provider',24),('Profil','Profile',24),('Type','Type',12),('Résultat','Result',30),('Code DNS','DNS code',14),('Réponses','Answers',65),('Authority','Authority',65),('EDE','EDE',45),('Date','Date',29),('Cache','Cache',12),('Durée (ms)','Duration (ms)',17),('Justification','Reason',65),('Erreur','Error',55)])
        table('files','Fichiers et preuves','Files and evidence',('Inventaire : les fichiers binaires restent dans les preuves originales, ils ne sont pas incorporés au classeur.','Inventory: binary files remain in the original evidence and are not embedded in the workbook.'),[ID,('Chemin','Path',55),('Nom d’origine','Original name',40),('URL source','Source URL',65),('Type','Type',22),('État','Status',22),('Taille (octets)','Size (bytes)',18),('SHA-256','SHA-256',68),('Présent dans le classeur','Included in workbook',30)])
        table('indicators','Indicateurs','Indicators',('Indicateurs extraits des preuves ; leur présence n’est pas un verdict malveillant.','Indicators extracted from evidence; their presence is not a malicious verdict.'),[ID,('Type','Type',20),('Valeur','Value',100)])
        table('events','Événements','Browser events',('Événements réellement enregistrés par le navigateur.','Events actually recorded by the browser.'),[ID,('ID','ID',25),('Type','Type',24),('Horodatage','Timestamp',29),('URL','URL',70),('Détails','Details',100)])
        table('quality','Qualité et limites','Quality and limits',('Disponibilité des sources, erreurs, avertissements et limites de capture.','Source availability, errors, warnings and capture limits.'),[ID,('Origine','Source',30),('Type','Type',22),('Détails','Details',110)])
        table('sources','Sources complètes','Full sources',('Texte intégral en fragments ordonnés. Lire la cellule dans la barre de formule ; concaténer les fragments pour reconstruire la source.','Full text in ordered chunks. Use the formula bar to read a cell; concatenate chunks to reconstruct each source.'),[ID,('Source','Source',48),('Encodage','Encoding',15),('Fragment','Chunk',13),('Total fragments','Total chunks',17),('SHA-256 source','Source SHA-256',68),('Contenu intégral','Full content',110)])

    def t(self,fr,en): return en if self.en else fr

    def decorate(self,sheet,title,description,columns):
        sheet.hide_gridlines(2);sheet.set_zoom(85);sheet.set_tab_color('#7956C8')
        sheet.set_paper(9);sheet.set_landscape();sheet.fit_to_pages(1,0);sheet.set_margins(.28,.28,.4,.4)
        sheet.set_header('&L&"Arial,Bold"ODYSAFE URL&R'+self.t('Rapport d’investigation','Investigation report'),{'margin':.15})
        sheet.set_footer('&L'+self.generated+'&R&P / &N',{'margin':.18})
        sheet.merge_range(0,0,0,columns-1,title,self.fmt['title']);sheet.set_row(0,44)
        sheet.merge_range(1,0,1,columns-1,description,self.fmt['subtitle']);sheet.set_row(1,38)
        sheet.merge_range(2,0,2,columns-1,self.t('Export local · Horodatages des preuves conservés · Généré en UTC : ','Offline export · Evidence timestamps preserved · Generated in UTC: ')+self.generated,self.fmt['subtitle']);sheet.set_row(2,24)

    def source(self,scan_id,name,data):
        self.input_bytes+=len(data)
        if self.input_bytes>MAX_INPUT:raise ExportLimitError('Les preuves textuelles dépassent 256 Mio. Exportez les investigations séparément.')
        digest=hashlib.sha256(data).hexdigest()
        try:
            content=data.decode('utf-8');encoding='UTF-8'
            if XML_ILLEGAL.search(content):raise UnicodeError()
        except UnicodeError:
            content=base64.b64encode(data).decode('ascii');encoding='base64'
        # At most 24k UTF-16 code units, below Excel's 32,767 limit.
        chunks=[content[i:i+12000] for i in range(0,len(content),12000)] or ['']
        for i,chunk in enumerate(chunks,1):self.tables['sources'].add(scan_id,name,encoding,i,len(chunks),digest,chunk)
        return digest

    def add(self, scan_id, index, directory, database):
        self.scan_count+=1;table=self.tables
        artifacts={};parsed={}
        for relative in _artifact_paths(directory):
            path=directory/relative
            if path.suffix.lower() not in TEXT_SUFFIXES:continue
            try:
                data=_safe_read(directory,relative)
                digest=self.source(scan_id,relative,data);artifacts[relative]=digest
                if relative in {'report.json','meta.json','browser_events.json','network.har'}:
                    try: parsed[relative]=json.loads(data)
                    except (ValueError,UnicodeError):table['quality'].add(scan_id,relative,'invalid_json',self.t('Source conservée, contenu JSON illisible.','Source preserved; JSON could not be parsed.'))
            except ExportLimitError:raise
            except OSError as exc:table['quality'].add(scan_id,relative,'unavailable',str(exc))
        report=obj(parsed.get('report.json'));meta=obj(parsed.get('meta.json'));overview=obj(report.get('overview'))
        network=obj(report.get('network'));requests=records(network.get('requests'));hosts=records(report.get('hosts'))
        if not requests:
            requests=_har_requests(obj(parsed.get('network.har')))
        if not hosts and requests:
            by_host={}
            for request in requests:
                host=str(request.get('hostname') or 'unknown');entry=by_host.setdefault(host,{'hostname':host,'requests':0,'ip_addresses':[]})
                entry['requests']+=1
                if request.get('server_ip_address') and request['server_ip_address'] not in entry['ip_addresses']:entry['ip_addresses'].append(request['server_ip_address'])
            hosts=list(by_host.values())
        traffic_by_host=defaultdict(list)
        for request in requests:traffic_by_host[request.get('hostname')].append(request)
        # Snapshot current enrichment results from SQLite, including targeted runs.
        jobs=[dict(row) for row in database.execute('SELECT * FROM enrichment_jobs WHERE scan_id=? ORDER BY created_at DESC',(scan_id,))]
        dns=[dict(row) for row in database.execute('SELECT * FROM dns_results WHERE scan_id=? ORDER BY checked_at,id',(scan_id,))]
        matches=[dict(row) for row in database.execute('''SELECT m.*,i.type,i.original_value,i.category,i.declared_source FROM ioc_matches m
            LEFT JOIN manual_iocs i ON i.id=m.ioc_id WHERE m.scan_id=? ORDER BY m.matched_at,m.id''',(scan_id,))]
        self.source(scan_id,'database-snapshot.json',json.dumps({'index':index,'jobs':jobs,'dns_results':dns,'ioc_matches':matches},ensure_ascii=False,default=str).encode())
        findings=records(report.get('detections'));blocked={item['domain'] for item in dns if item.get('interpretation')=='blocked'}
        host=index.get('host') or _host(overview.get('submitted_url') or meta.get('submitted_url'))
        if self.scan_count==1:self.primary={'host':host,'url':overview.get('submitted_url') or meta.get('submitted_url') or index.get('submitted_url'),'id':scan_id}
        table['investigations'].add(scan_id,host,overview.get('submitted_url') or meta.get('submitted_url') or index.get('submitted_url'),overview.get('final_url') or meta.get('final_url'),overview.get('title') or meta.get('title'),index.get('capture_date') or meta.get('started_at'),overview.get('capture_status') or meta.get('status') or index.get('capture_status'),report.get('analysis_status') or 'not_performed',overview.get('profile') or meta.get('profile'),len(requests),len(hosts),len(findings),len(blocked))
        for name,engine in obj(report.get('detection_engines')).items():
            engine=obj(engine);execution=obj(engine.get('execution'));rule_set=obj(engine.get('rule_set'))
            table['engines'].add(scan_id,name,engine.get('status'),rule_set.get('active_rules',rule_set.get('custom_rules')),execution.get('artifacts_scanned'),execution.get('matches'),report.get('generated_at'),engine)
        if not obj(report.get('detection_engines')).get('yara_x'):
            table['engines'].add(scan_id,'yara_x','not_performed',None,None,None,None,None)
        yara=obj(obj(report.get('detection_engines')).get('yara_x'))
        for artifact in records(obj(yara.get('execution')).get('artifacts')):
            table['yara'].add(scan_id,artifact.get('artifact'),artifact.get('domain'),artifact.get('status'),artifact.get('matches'),artifact)
        for kind,label,observations,count in [('offline_ioc','IOC',matches,len(matches)),('dns','DNS',dns,len(blocked))]:
            selected=[job for job in jobs if job.get('kind')==kind];latest=selected[0] if selected else {}
            table['engines'].add(scan_id,label,latest.get('status','not_performed'),None,len(observations),count,latest.get('completed_at') or latest.get('created_at'),latest)
        for h in hosts:
            traffic=traffic_by_host.get(h.get('hostname'),[])
            def total_bytes(key):
                values=[request[key] for request in traffic if isinstance(request.get(key),(int,float)) and request[key]>=0]
                return sum(values) if values else None
            times=sorted(str(request['started_at']) for request in traffic if request.get('started_at'))
            table['hosts'].add(scan_id,h.get('hostname'),h.get('transaction_count',h.get('requests',h.get('request_count',len(traffic)))),h.get('ip_addresses'),total_bytes('request_body_size'),total_bytes('response_body_size'),times[0] if times else None,times[-1] if times else None,sorted({str(request['mime_type']) for request in traffic if request.get('mime_type')}))
        for r in requests:
            table['http'].add(scan_id,r.get('id'),r.get('started_at'),r.get('method'),r.get('url'),r.get('hostname'),r.get('status'),r.get('mime_type'),r.get('duration_ms'),r.get('request_body_size'),r.get('response_body_size'),r.get('server_ip_address'),r.get('redirect_url'),r)
        relations=obj(report.get('relations'))
        if not isinstance(relations.get('host_edges'),list):
            table['quality'].add(scan_id,'relations','legacy',self.t('Ce rapport ne contient pas de relations explicites entre domaines. Le schéma affiche les domaines sans flèches causales.','This report has no explicit domain connections. The diagram lists domains without causal arrows.'))
        for name,level in [('host_edges','domain'),('edges','resource'),('browser_paths','browser'),('redirects','HTTP')]:
            for edge in records(relations.get(name)):
                table['relations'].add(scan_id,level,edge.get('source_host') or edge.get('source'),edge.get('target_host') or edge.get('target'),edge.get('type') or edge.get('mechanism'),edge.get('count',1),edge.get('verified') if name in {'host_edges','edges'} else True,edge)
        for image in flow_panels(scan_id,host,relations,hosts,'en' if self.en else 'fr'):
            if len(self.images)>=512:raise ExportLimitError('Le rapport dépasse 512 schémas. Exportez les investigations séparément.')
            if self.flow_row+28>=1_048_575:raise ExportLimitError('Trop de schémas pour un seul classeur.')
            self.flows.merge_range(self.flow_row,0,self.flow_row,7,str(scan_id),self.fmt['section'])
            self.flows.set_row(self.flow_row,27)
            for row in range(self.flow_row+1,self.flow_row+27):self.flows.set_row(row,18)
            self.flows.insert_image(self.flow_row+1,0,'flow.png',{'image_data':image,'x_scale':.72,'y_scale':.72,'object_position':3,'description':self.t('Relations réseau observées','Observed network connections')})
            self.images.append(image);self.flow_row+=27
        for finding in findings:table['findings'].add(scan_id,finding.get('engine'),finding.get('rule_id'),finding.get('severity'),finding.get('description'),finding.get('evidence'))
        for m in matches:table['ioc'].add(scan_id,m.get('job_id'),m.get('type'),m.get('original_value'),m.get('observed_value'),m.get('category'),m.get('declared_source'),m.get('matched_at'),m.get('explanation'))
        for d in dns:table['dns'].add(scan_id,d.get('job_id'),d.get('domain'),d.get('provider_id'),d.get('provider_profile'),d.get('qtype'),d.get('interpretation'),d.get('rcode'),d.get('answers_json'),d.get('authority_json'),d.get('ede_json'),d.get('checked_at'),d.get('cache_hit'),d.get('duration_ms'),d.get('justification'),d.get('error'))
        file_metadata=records(report.get('downloaded_files'))+records(report.get('javascript'))
        metadata={str(item.get('path')):item for item in file_metadata if item.get('path')}
        present=set()
        for relative in _artifact_paths(directory):
            p=directory/relative
            try:size=p.stat(follow_symlinks=False).st_size
            except OSError:continue
            item=metadata.get(relative,{});present.add(relative)
            table['files'].add(scan_id,relative,item.get('original_name'),item.get('source_url') or item.get('url'),item.get('mime_type') or p.suffix,'collected',size,item.get('sha256') or artifacts.get(relative),self.t('Texte intégral','Full text') if relative in artifacts else self.t('Métadonnées seules','Metadata only'))
        for relative,item in metadata.items():
            if relative not in present:table['files'].add(scan_id,relative,item.get('original_name'),item.get('source_url') or item.get('url'),item.get('mime_type'),item.get('status','unavailable'),item.get('size'),item.get('sha256'),self.t('Non disponible sur disque','Unavailable on disk'))
        for item in file_metadata:
            if not item.get('path'):table['files'].add(scan_id,None,item.get('original_name') or item.get('stored_name'),item.get('source_url') or item.get('url'),item.get('mime_type'),item.get('status','unavailable'),item.get('size'),item.get('sha256'),self.t('Non collecté','Not collected'))
        for kind,values in obj(report.get('indicators')).items():
            for value in seq(values):table['indicators'].add(scan_id,kind,value)
        envelope=parsed.get('browser_events.json',report.get('browser_events',{}))
        for event in records(obj(envelope).get('events') if isinstance(envelope,dict) else envelope):table['events'].add(scan_id,event.get('id'),event.get('type'),event.get('timestamp'),event.get('url'),event.get('details'))
        if not report:table['quality'].add(scan_id,'report.json','unavailable',self.t('Rapport structuré indisponible ; seules les preuves disponibles sont exportées.','Structured report unavailable; only available evidence is exported.'))
        for kind in ['warnings','errors']:
            for value in seq(report.get(kind)):table['quality'].add(scan_id,'report.json',kind,value)
        if report.get('capture_limits'):table['quality'].add(scan_id,'capture_limits','limits',report['capture_limits'])
        table['quality'].add(scan_id,'sources','scope',self.t('Les binaires ne sont pas incorporés. Les sources textuelles et résultats SQLite sont conservés dans Sources complètes.','Binaries are not embedded. Full text sources and SQLite results are retained in Full sources.'))
        self.counts['requests']+=len(requests);self.counts['hosts']+=len(hosts);self.counts['detections']+=len(findings);self.counts['dns']+=len(blocked)

    def finish(self):
        for table in self.tables.values():table.finish()
        self.flows.print_area(0,0,max(5,self.flow_row-1),7)
        self.flows.set_h_pagebreaks(list(range(5+27,self.flow_row,27))[:1000])
        self.decorate(self.cover,self.t('Rapport d’investigation','Investigation report'),self.t('Une lecture claire des preuves collectées. Aucun site n’a été revisité pour cet export.','A clear view of collected evidence. No websites were revisited for this export.'),8)
        self.cover.set_column(0,7,17);self.cover.set_portrait();self.cover.freeze_panes(4,0)
        identity=str(self.primary.get('host','—')) if self.scan_count==1 else str(self.scan_count)+' '+self.t('investigations incluses','investigations included')
        scope=str(self.primary.get('url') or self.primary.get('id') or '—') if self.scan_count==1 else self.t('Périmètre complet des investigations sélectionnées pour cet export.','Complete scope of the investigations included in this export.')
        self.cover.merge_range(3,0,3,7,XML_ILLEGAL.sub('�',identity[:500]),self.fmt['section']);self.cover.set_row(3,32)
        self.cover.merge_range(4,0,4,7,XML_ILLEGAL.sub('�',scope[:1500]),self.fmt['subtitle']);self.cover.set_row(4,40)
        metrics=[(self.t('Investigations','Investigations'),self.scan_count),(self.t('Requêtes HTTP','HTTP requests'),self.counts['requests']),(self.t('Détections','Detections'),self.counts['detections']),(self.t('Domaines signalés DNS','DNS-flagged domains'),self.counts['dns'])]
        for i,(label,value) in enumerate(metrics):self.cover.merge_range(5,2*i,5,2*i+1,label,self.fmt['metric'])
        self.cover.set_row(5,32)
        for i,(_,value) in enumerate(metrics):self.cover.merge_range(6,2*i,6,2*i+1,value,self.fmt['number'])
        self.cover.set_row(6,48)
        notes=[self.t('Les compteurs regroupent les investigations ; un même domaine peut apparaître plusieurs fois.','Totals combine investigations; a domain may appear in more than one investigation.'),self.t('Aucune correspondance ne prouve pas qu’un site est sûr. Une analyse non exécutée n’est pas un résultat négatif.','No matches does not prove a site is safe. An engine that did not run is not a negative result.'),self.t('Les dates sont conservées telles qu’enregistrées. Les tailles sont en octets et les durées réseau en millisecondes.','Timestamps are preserved as recorded. Sizes are in bytes and network durations in milliseconds.'),self.t('Mise en page portable : cellules simples, police Arial, dimensions fixes et schémas PNG incorporés.','Portable layout: standard cells, Arial font, fixed dimensions and embedded PNG diagrams.')]
        for i,note in enumerate(notes,9):self.cover.merge_range(i,0,i,7,note,self.fmt['subtitle']);self.cover.set_row(i,37)
        self.cover.merge_range(15,0,15,7,self.t('Parcourir le rapport','Explore the report'),self.fmt['section']);self.cover.set_row(15,32)
        contents=[(self.t('Flux réseau','Network flows'),self.t('Schémas des liens observés, sans relation inventée.','Diagrams of observed connections, with no inferred causal links.'))]+[(table.title,table.description) for table in self.tables.values()]
        for row,(name,description) in enumerate(contents,17):
            self.cover.merge_range(row,0,row,1,name,self.fmt['metric']);self.cover.merge_range(row,2,row,7,description,self.fmt['odd']);self.cover.set_row(row,42)
        self.cover.print_area(0,0,17+len(contents),7)
        self.book.close()


def _host(value):
    from urllib.parse import urlsplit
    try:return urlsplit(str(value or '')).hostname or '—'
    except ValueError:return '—'


def _artifact_paths(directory):
    """Only top-level evidence and the two controlled evidence subdirectories."""
    result=[]
    for p in sorted(directory.iterdir(),key=lambda p:p.name):
        if p.is_symlink():continue
        if p.is_file():result.append(p.name)
        elif p.name in {'scripts','downloads'} and p.is_dir():
            result.extend(str(child.relative_to(directory)) for child in sorted(p.iterdir(),key=lambda p:p.name) if child.is_file() and not child.is_symlink())
    return result


def _safe_read(directory,relative):
    """Open every path component without following links, including races."""
    parts=Path(relative).parts
    if not parts or any(part in {'.','..'} for part in parts) or Path(relative).is_absolute():raise OSError('Invalid evidence path')
    descriptors=[]
    try:
        current=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);descriptors.append(current)
        for part in parts[:-1]:
            current=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=current);descriptors.append(current)
        file=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=current);descriptors.append(file)
        info=os.fstat(file)
        if not stat.S_ISREG(info.st_mode):raise OSError('Not a regular evidence file')
        if info.st_size>MAX_FILE:raise ExportLimitError('Une preuve textuelle dépasse 64 Mio. Utilisez les preuves originales pour ce fichier.')
        with os.fdopen(os.dup(file),'rb') as stream:data=stream.read(MAX_FILE+1)
        if len(data)>MAX_FILE:raise ExportLimitError('Une preuve textuelle dépasse 64 Mio.')
        return data
    finally:
        for descriptor in reversed(descriptors):os.close(descriptor)


def _har_requests(har):
    from urllib.parse import urlsplit
    result=[]
    for i,entry in enumerate(records(obj(har.get('log')).get('entries')),1):
        request=obj(entry.get('request'));response=obj(entry.get('response'));url=request.get('url')
        try:host=urlsplit(str(url or '')).hostname
        except ValueError:host=None
        result.append({'id':f'request-{i:06d}','started_at':entry.get('startedDateTime'),'method':request.get('method'),'url':url,'hostname':host,'status':response.get('status'),'mime_type':obj(response.get('content')).get('mimeType'),'duration_ms':entry.get('time'),'request_body_size':request.get('bodySize'),'response_body_size':response.get('bodySize'),'server_ip_address':entry.get('serverIPAddress'),'redirect_url':response.get('redirectURL')})
    return result


def _export_investigations(database, scans_root: Path, identifiers: list[str], destination: Path, language='fr'):
    """Generate from a read-only DB snapshot and existing evidence. No scanning."""
    import uuid
    report=InvestigationWorkbook(destination,language)
    try:
        with database.connect() as connection:
            connection.execute('BEGIN')
            for identifier in dict.fromkeys(identifiers):
                if str(uuid.UUID(identifier))!=identifier:raise ValueError('Invalid investigation ID')
                directory=scans_root/identifier
                if directory.is_symlink() or not directory.is_dir() or directory.resolve().parent!=scans_root.resolve():raise ValueError('Investigation evidence unavailable')
                row=connection.execute('SELECT * FROM scans WHERE scan_id=?',(identifier,)).fetchone()
                report.add(identifier,dict(row) if row else {},directory,connection)
            connection.rollback()
        report.finish()
    except BaseException:
        # Finalize writer temporary files even when an export hits a budget.
        if not report.book.fileclosed:
            report.book.close()
        destination.unlink(missing_ok=True)
        raise


def export_investigations(database, scans_root: Path, identifiers: list[str], destination: Path, language='fr'):
    if not EXPORT_LOCK.acquire(blocking=False):
        raise ExportBusyError('Un export XLSX est déjà en cours. Patientez avant de réessayer.')
    try:
        return _export_investigations(database,scans_root,identifiers,destination,language)
    finally:
        EXPORT_LOCK.release()

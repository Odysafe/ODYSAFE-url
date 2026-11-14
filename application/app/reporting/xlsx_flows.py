"""Fixed-size PNG diagrams: no office-specific drawing objects or inferred edges."""
from __future__ import annotations

from io import BytesIO
import textwrap
from PIL import Image, ImageDraw, ImageFont

WIDTH, HEIGHT = 1280, 760
COLORS = {'initiated': '#438775', 'navigation': '#4672B8',
          'popup': '#B18132', 'http_redirect': '#8865B5'}
LABELS = {
 'initiated': ('Initiateur enregistré', 'Recorded initiator'),
 'navigation': ('Navigation observée', 'Observed navigation'),
 'popup': ('Ouverture d’un onglet', 'New tab'),
 'http_redirect': ('Redirection HTTP', 'HTTP redirect'),
}


def _font(size, bold=False):
    try:
        return ImageFont.truetype('DejaVuSans-Bold.ttf' if bold else 'DejaVuSans.ttf', size)
    except OSError:
        return ImageFont.load_default(size=size)


def _card(draw, xy, text, accent, subtitle=None):
    x, y, right, bottom = xy
    draw.rounded_rectangle(xy, radius=12, fill='white', outline='#DDE2EB', width=2)
    draw.rounded_rectangle((x, y, x+5, bottom), radius=2, fill=accent)
    lines = textwrap.wrap(str(text), width=32, break_long_words=True) or ['—']
    font = _font(18 if len(lines)>2 else 21, True)
    # Every character remains in the Relations/Domains tables. A diagram label
    # alone may be shortened; it is explicitly a visual reading aid.
    if len(lines)>3: lines=lines[:2]+[lines[2][:28]+'…']
    for i, line in enumerate(lines): draw.text((x+19, y+12+i*23), line, font=font, fill='#202C43')
    if subtitle: draw.text((x+19, bottom-24), subtitle, font=_font(14), fill='#69758A')


def flow_panels(scan_id, host, relations, hosts, language='fr'):
    """Yield all panels in bounded groups. Arrow direction comes from evidence."""
    en=language=='en'
    edges=[e for e in relations.get('host_edges', []) if isinstance(e,dict) and e.get('verified') is True]
    groups=[edges[i:i+5] for i in range(0,len(edges),5)]
    if not groups:
        names=[h for h in hosts if isinstance(h,dict)]
        groups=[names[i:i+10] for i in range(0,len(names),10)] or [[]]
    for page, group in enumerate(groups,1):
        image=Image.new('RGB',(WIDTH,HEIGHT),'#F4F6FA');draw=ImageDraw.Draw(image)
        draw.rectangle((0,0,WIDTH,9),fill='#7956C8')
        draw.text((40,32),'ODYSAFE  /  '+('NETWORK EVIDENCE' if en else 'FLUX RÉSEAU OBSERVÉS'),font=_font(17,True),fill='#7956C8')
        draw.text((40,66),textwrap.shorten(str(host or scan_id),width=76,placeholder='…'),font=_font(29,True),fill='#202C43')
        draw.text((40,111),str(scan_id)+'  ·  '+f'{page}/{len(groups)}',font=_font(14),fill='#69758A')
        if edges:
            draw.text((40,148),'SOURCE',font=_font(13,True),fill='#69758A')
            draw.text((850,148),'DESTINATION',font=_font(13,True),fill='#69758A')
            for row,edge in enumerate(group):
                y=181+row*99;color=COLORS.get(edge.get('type'),'#69758A')
                source=edge.get('source_host') or str(edge.get('source','')).removeprefix('host:')
                target=edge.get('target_host') or str(edge.get('target','')).removeprefix('host:')
                _card(draw,(40,y,428,y+84),source,color)
                _card(draw,(850,y,1238,y+84),target,color)
                draw.line((452,y+51,824,y+51),fill=color,width=3)
                draw.polygon([(824,y+51),(810,y+43),(810,y+59)],fill=color)
                label=LABELS.get(edge.get('type'),('Relation observée','Observed connection'))[int(en)]
                bounds=draw.textbbox((0,0),label,font=_font(16,True));w=bounds[2]-bounds[0]
                draw.text((638-w/2,y+9),label,font=_font(16,True),fill=color)
                count=edge.get('count',1)
                draw.text((572,y+61),f'{count} '+('observation' if count==1 else 'observations'),font=_font(13),fill='#69758A')
        else:
            draw.text((40,155),'Domains recorded; no causal arrows inferred.' if en else 'Domaines enregistrés ; aucune relation causale inventée.',font=_font(18),fill='#69758A')
            if not group:
                draw.text((40,235),'No network data available.' if en else 'Aucune donnée réseau disponible.',font=_font(23),fill='#69758A')
            for row,h in enumerate(group):
                x=40+(row%2)*620;y=205+(row//2)*94
                _card(draw,(x,y,x+580,y+82),h.get('hostname') or h.get('host') or '—','#7956C8')
        draw.line((40,701,1238,701),fill='#DDE2EB',width=2)
        draw.text((40,718),'Colors describe connection types, not threat levels.' if en else 'Les couleurs indiquent le type de lien, pas un niveau de danger.',font=_font(15),fill='#69758A')
        stream=BytesIO();image.save(stream,format='PNG',dpi=(96,96));stream.seek(0)
        yield stream

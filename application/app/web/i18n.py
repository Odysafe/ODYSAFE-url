"""Presentation-only localization; never translate stored indicators or evidence."""
from __future__ import annotations

import base64
import re
import hashlib
import json
from pathlib import Path

from jinja2 import pass_context
from markupsafe import Markup, escape

CATALOG = json.loads((Path(__file__).parent / 'locales' / 'en.json').read_text(encoding='utf-8'))
KEYS = {hashlib.sha256(source.encode()).hexdigest()[:16]: source for source in CATALOG}
STATUS_LABELS = {
    'queued': 'En attente', 'starting': 'Démarrage', 'running': 'En cours',
    'finalizing': 'Finalisation', 'analyzing': 'Analyse en cours',
    'completed': 'Terminé', 'failed': 'Échec', 'interrupted': 'Interrompu',
    'cancelled': 'Annulé', 'canceled': 'Annulé', 'partial': 'Partiel',
    'not_run': 'Non exécuté', 'not run': 'Non exécuté', 'not_executed': 'Non exécuté',
    'not executed': 'Non exécuté', 'unavailable': 'Non disponible',
    'not_available': 'Non disponible', 'disabled': 'Désactivé', 'enabled': 'Activé',
    'not_checked': 'Non vérifié', 'not checked': 'Non vérifié',
    'not_applicable': 'Non applicable', 'not applicable': 'Non applicable',
    'indeterminate': 'Indéterminé', 'error': 'Erreur', 'blocked': 'Signal de filtrage',
    'not_blocked_observed': 'Aucun signal observé', 'automatic': 'Automatique',
    'interactive': 'Interactif', 'fixture': 'Fixture interne', 'internet': 'Internet public filtré',
    'info': 'Information', 'low': 'Faible', 'medium': 'Moyenne', 'high': 'Élevée',
    'critical': 'Critique', 'absente': 'Absente', 'pending': 'En attente',
    'skipped': 'Ignoré', 'available': 'Disponible', 'success': 'Réussi',
}


SOURCE_ALIASES = {'Saved': 'Préférences enregistrées', 'Index reconciled': 'Liste des investigations actualisée', 'IOC updated': 'IOC mis à jour', 'Session created': 'Session créée', 'Stop requested': 'Arrêt demandé', 'Scan not found': 'Investigation introuvable', 'IOC not found': 'Indicateur introuvable', 'Select at least one analysis engine': 'Choisissez au moins un moteur d’analyse', 'Invalid DNS limits': 'Limites DNS invalides', 'Invalid page size': 'Nombre d’éléments par page invalide', 'Unknown provider': 'Fournisseur inconnu', 'Resolver not found': 'Résolveur introuvable', 'This resolver is already configured': 'Ce résolveur est déjà configuré', 'Resolver address must be a public IP address': 'L’adresse du résolveur doit être une IP publique', 'Resolver address must be an IP address': 'L’adresse du résolveur doit être une adresse IP', 'Resolver name must contain 1 to 80 characters': 'Le nom du résolveur doit contenir entre 1 et 80 caractères', 'An active investigation cannot be deleted': 'Impossible de supprimer une investigation en cours', 'Public capture is disabled by the administrator': 'La capture Internet est désactivée par l’administrateur', 'Invalid CSRF token': 'La session de sécurité a expiré. Actualisez la page puis réessayez.', 'Local CSRF session required': 'La session de sécurité a expiré. Actualisez la page puis réessayez.', 'Origin refused': 'Requête refusée depuis cette origine', 'Artifact too large': 'Fichier trop volumineux', 'Select between 1 and 100 IOCs': 'Sélectionnez entre 1 et 100 IOC', 'Select between 1 and 20 investigations': 'Sélectionnez entre 1 et 20 investigations', 'No collected download available': 'Aucun fichier téléchargé disponible', 'Scan DOM unavailable': 'Le DOM de l’investigation est indisponible', 'Scan DOM too large': 'Le DOM de l’investigation est trop volumineux'}

def _formatted_patterns():
    result = []
    for source in CATALOG:
        names = re.findall(r'\{(\w+)\}', source)
        if names:
            chunks = re.split(r'\{\w+\}', source)
            result.append((re.compile('(.+?)'.join(re.escape(chunk) for chunk in chunks)), names, source))
    return result


FORMATTED = _formatted_patterns()


@pass_context
def ui_plain(context, value):
    source = STATUS_LABELS.get(str(value), str(value))
    return translated(source, language(context['request']))


def language(request):
    return 'en' if request.cookies.get('odysafe_language') == 'en' else 'fr'


def translated(source, lang):
    return CATALOG.get(source, source) if lang == 'en' else source


def marked(source, lang, params=None):
    if source not in CATALOG:
        return escape(source)
    key = hashlib.sha256(source.encode()).hexdigest()[:16]
    text = translated(source, lang)
    if params:
        key += ':' + base64.b64encode(json.dumps(params).encode()).decode()
        text = re.sub(r'\{(\w+)\}', lambda match: str(params.get(match[1], match[0])), text)
    return Markup('<!--odysafe-i18n:{}-->{}<!--/odysafe-i18n-->').format(key, escape(text))


@pass_context
def text(context, key):
    return marked(KEYS[key], language(context['request']))


@pass_context
def attribute(context, key):
    return translated(KEYS[key], language(context['request']))


@pass_context
def ui(context, value):
    value = str(value)
    value = SOURCE_ALIASES.get(value, STATUS_LABELS.get(value, value))
    lang = language(context['request'])
    if value in CATALOG:
        return marked(value, lang)
    for pattern, names, source in FORMATTED:
        match = pattern.fullmatch(value)
        if match:
            return marked(source, lang, dict(zip(names, match.groups())))
    # Validation messages may combine two app-owned sentences. Each fragment
    # remains independently switchable; arbitrary provider details stay intact.
    for prefix in ('Cette valeur n’est pas valide.', 'Ce dossier ne peut pas être préparé :',
                   'Nom déjà utilisé ou dossier invalide :'):
        if value.startswith(prefix + ' '):
            rest = value[len(prefix) + 1:]
            return marked(prefix, lang) + Markup(' ') + ui(context, rest)
    return value


@pass_context
def folder_name(context, item):
    if item.get('is_default') and item.get('name') == 'Défaut':
        return marked('Défaut', language(context['request']))
    return item.get('name', '')


def configure(templates):
    templates.env.globals.update(_i=text, _a=attribute, ui=ui, ui_plain=ui_plain, folder_name=folder_name)

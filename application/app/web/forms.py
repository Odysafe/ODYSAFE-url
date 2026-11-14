"""French field guidance shared by server validation and the IOC editor."""
IOC_INPUTS = {
    "domain": {"label": "Domaine", "example": "example.org ou *.ru", "help": "Sans https:// ni chemin. Exemple : example.org. Le motif *.ru couvre tous les domaines en .ru ; *.example.org couvre ses sous-domaines, mais pas example.org lui-même."},
    "hostname": {"label": "Nom d’hôte", "example": "login.example.org ou *.example.org", "help": "Sans protocole ni chemin. Une étoile est acceptée au début : *.example.org couvre les sous-domaines à tous les niveaux, mais pas example.org lui-même."},
    "url": {"label": "Adresse web (URL)", "example": "https://example.org/connexion", "help": "Une URL complète commençant par http:// ou https://, sans identifiant ni mot de passe."},
    "ipv4": {"label": "Adresse IPv4", "example": "192.0.2.10 ou 8.*.8.8", "help": "Quatre nombres de 0 à 255 séparés par des points. Une étoile remplace un nombre entier : 8.*.8.8 correspond par exemple à 8.1.8.8 et 8.255.8.8. Gardez au moins un nombre fixe."},
    "ipv6": {"label": "Adresse IPv6", "example": "2001:db8::10", "help": "Une adresse IPv6. Exemple : 2001:db8::10."},
    "cidr4": {"label": "Plage d’adresses IPv4", "example": "192.0.2.0/24", "help": "Une adresse IPv4 suivie de / et d’un préfixe de 0 à 32. Exemple : 192.0.2.0/24."},
    "cidr6": {"label": "Plage d’adresses IPv6", "example": "2001:db8::/32", "help": "Une adresse IPv6 suivie de / et d’un préfixe de 0 à 128. Exemple : 2001:db8::/32."},
    "sha256": {"label": "Empreinte SHA-256 d’un fichier", "example": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "help": "Identifie le contenu exact d’un fichier : exécutable, PDF, archive ou script. Collez par exemple l’empreinte d’un fichier malveillant connu, composée de 64 caractères (0 à 9 et a à f). ODYSAFE la compare aux empreintes enregistrées dans les preuves de l’investigation. Un fichier renommé garde la même empreinte ; un contenu modifié la change. La détection est possible uniquement si le fichier a été collecté et son empreinte calculée."},
}


def ioc_form_error(message: str, ioc_type: str) -> tuple[str, str]:
    if "already exists" in message:
        return "value", "Cet indicateur existe déjà dans la bibliothèque. Recherchez-le pour le modifier."
    if "expiration" in message:
        return "expires_at", "Choisissez une date et une heure valides, ou laissez l’expiration vide."
    if "category" in message:
        return "category", "Choisissez une nature de l’indicateur dans la liste."
    if "metadata" in message:
        return "source", "Limitez l’origine à 200 caractères et le commentaire à 2 000 caractères."
    if ioc_type not in IOC_INPUTS:
        return "ioc_type", "Choisissez un type d’indicateur dans la liste."
    return "value", "Cette valeur n’est pas valide. " + IOC_INPUTS[ioc_type]["help"]

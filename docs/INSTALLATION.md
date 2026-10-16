# Guide d'Installation et de Démarrage — NetSentinel Enterprise

> Ce guide détaille pas à pas l'installation, la configuration de l'environnement virtuel et le lancement de **NetSentinel Enterprise** sur Windows et Linux.

---

## 1. Prérequis Système

- **Python :** Version **3.10 ou supérieure** (testé et validé sous Python 3.13)
- **Gestionnaire de paquets :** `pip`
- **Navigateur Web moderne :** Google Chrome, Microsoft Edge, Mozilla Firefox ou Safari
- **Système d'Exploitation :** Windows 10/11, Ubuntu 22.04+, macOS Sonoma+

---

## 2. Cloner le Dépôt

```bash
git clone https://github.com/Mohammed-aichour/NetSentinel-Enterprise.git
cd NetSentinel-Enterprise
```

---

## 3. Configuration de l'Environnement Virtuel Python

L'utilisation d'un environnement virtuel (`.venv`) est recommandée pour isoler les dépendances.

### Sur Windows (PowerShell) :
```powershell
# Créer l'environnement virtuel
python -m venv .venv

# Activer l'environnement virtuel
.venv\Scripts\Activate.ps1
```

> **Astuce Windows :** Si PowerShell bloque l'exécution des scripts, exécutez d'abord :  
> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`

### Sur Linux / macOS (Bash / Zsh) :
```bash
# Créer l'environnement virtuel
python3 -m venv .venv

# Activer l'environnement virtuel
source .venv/bin/activate
```

---

## 4. Installation des Dépendances

Installez l'ensemble des modules requis listés dans `requirements.txt` :

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Modules installés :
- `flask >= 3.0.0` : Serveur d'applications Web et routage de l'API REST.
- `psutil >= 5.9.0` : Collecte des métriques télémétriques matérielles locales réelles.
- `requests >= 2.31.0` : Client HTTP pour sondes réseau et intégrations externes.
- `pytest >= 8.0.0` : Suite d'exécution des tests automatisés.

---

## 5. Lancement de l'Application

Démarrez le serveur NetSentinel Enterprise :

```bash
python run.py
```

### Sortie attendue dans le terminal :
```text
2026-10-16 11:40:00 [INFO] [netsentinel.database]: Database schema initialized successfully.
2026-10-16 11:40:00 [INFO] [netsentinel.server]: Initializing baseline enterprise topology for UniversiaCorp...
2026-10-16 11:40:00 [INFO] [netsentinel.server]: Starting NetSentinel Enterprise Server on 0.0.0.0:5000 (Debug: True)...
 * Running on http://127.0.0.1:5000
 * Running on http://0.0.0.0:5000
```

Ouvrez votre navigateur et accédez à l'URL suivante :  
👉 **`http://localhost:5000`**

---

## 6. Variables d'Environnement (Optionnel)

Les paramètres de fonctionnement peuvent être personnalisés via des variables d'environnement système ou un fichier `.env` :

| Variable | Valeur par défaut | Description |
| :--- | :--- | :--- |
| `NETSENTINEL_HOST` | `0.0.0.0` | Adresse IP d'écoute du serveur Web. |
| `NETSENTINEL_PORT` | `5000` | Port TCP d'écoute. |
| `NETSENTINEL_DEBUG` | `True` | Mode débogage Flask avec rechargement à chaud. |
| `NETSENTINEL_DB` | `netsentinel.db` | Chemin d'accès à la base de données SQLite. |
| `ENTERPRISE_NAME` | `UniversiaCorp Global` | Nom de l'organisation supervisée. |

---

## 7. Mode Démonstration sans Serveur (GitHub Pages)

Pour prévisualiser l'interface SOC sans installer Python, une version autonome statique est accessible directement sur GitHub Pages :  
👉 **`https://mohammed-aichour.github.io/NetSentinel-Enterprise/`**

Le client bascule automatiquement en mode hors-ligne simulé avec des métriques de démonstration réalistes.

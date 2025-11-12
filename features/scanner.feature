# language: fr
Fonctionnalité: Scanner de sécurité PHP
  En tant que développeur
  Je veux scanner mon code PHP pour détecter des vulnérabilités
  Afin de sécuriser mon application

  Contexte:
    Étant donné un projet PHP de test

  Scénario: Scanner un fichier PHP avec injection SQL
    Étant donné un fichier PHP avec une requête SQL non préparée
    Quand je lance le scan de sécurité
    Alors je devrais trouver 1 vulnérabilité de type "sql_injection"
    Et la vulnérabilité devrait avoir une sévérité "critical"
    Et la vulnérabilité devrait avoir un CWE ID 89

  Scénario: Scanner un fichier PHP avec XSS
    Étant donné un fichier PHP avec un echo non échappé
    Quand je lance le scan de sécurité
    Alors je devrais trouver 1 vulnérabilité de type "xss"
    Et la vulnérabilité devrait avoir une sévérité "high"

  Scénario: Scanner un fichier PHP sécurisé
    Étant donné un fichier PHP avec des requêtes préparées
    Quand je lance le scan de sécurité
    Alors je ne devrais trouver aucune vulnérabilité

  Scénario: Scanner avec cache activé
    Étant donné un fichier PHP de test
    Quand je lance le scan avec le cache activé
    Et je lance le scan à nouveau
    Alors le deuxième scan devrait utiliser le cache
    Et le temps de scan devrait être réduit d'au moins 50%

  Plan du Scénario: Scanner différents types de vulnérabilités
    Étant donné un fichier PHP avec une vulnérabilité "<type>"
    Quand je lance le scan de sécurité
    Alors je devrais trouver 1 vulnérabilité de type "<type>"
    Et la vulnérabilité devrait avoir une sévérité "<severity>"

    Exemples:
      | type              | severity  |
      | sql_injection     | critical  |
      | xss               | high      |
      | rce               | critical  |
      | file_inclusion    | high      |
      | path_traversal    | high      |
      | deserialization   | critical  |

  Scénario: Scanner avec exclusion de patterns
    Étant donné un projet PHP avec un dossier vendor
    Et le dossier vendor contient des vulnérabilités
    Quand je lance le scan avec l'exclusion de "vendor/"
    Alors les fichiers du vendor ne devraient pas être scannés
    Et je ne devrais pas trouver de vulnérabilités dans vendor

  Scénario: Scanner avec workers parallèles
    Étant donné un projet PHP avec 100 fichiers
    Quand je lance le scan avec 16 workers
    Alors le scan devrait être terminé en moins de 30 secondes
    Et tous les fichiers devraient être scannés

  Scénario: Générer un rapport SARIF
    Étant donné un scan terminé avec des vulnérabilités
    Quand je génère un rapport SARIF
    Alors le rapport devrait être au format SARIF 2.1.0
    Et le rapport devrait contenir toutes les vulnérabilités
    Et chaque vulnérabilité devrait avoir un CWE ID

  Scénario: Export de résultats multiples formats
    Étant donné un scan terminé avec des vulnérabilités
    Quand j'exporte les résultats en "json"
    Et j'exporte les résultats en "html"
    Et j'exporte les résultats en "sarif"
    Alors tous les exports devraient être créés
    Et tous les exports devraient contenir les mêmes vulnérabilités

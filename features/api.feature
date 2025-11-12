# language: fr
Fonctionnalité: API REST du scanner
  En tant que développeur utilisant l'API
  Je veux pouvoir scanner des projets PHP via REST API
  Afin d'intégrer le scanner dans mon CI/CD

  Contexte:
    Étant donné que l'API est démarrée
    Et que l'API est accessible sur "http://localhost:8000"

  Scénario: Health check de l'API
    Quand j'appelle GET "/api/v1/health"
    Alors le code de réponse devrait être 200
    Et la réponse devrait contenir "status": "healthy"

  @skip
  Scénario: Créer un scan via l'API
    # Nécessite implémentation complète de l'endpoint POST /scan
    Étant donné un projet PHP de test
    Quand j'appelle POST "/api/v1/scan" avec les données:
      """
      {
        "target": "/tmp/test-project",
        "vulnerability_types": ["sql_injection", "xss"],
        "use_cache": true
      }
      """
    Alors le code de réponse devrait être 200
    Et la réponse devrait contenir un "scan_id"
    Et le statut devrait être "queued"

  Scénario: Vérifier le statut d'un scan
    Étant donné un scan en cours avec l'ID "abc123"
    Quand j'appelle GET "/api/v1/scan/abc123/status"
    Alors le code de réponse devrait être 200
    Et la réponse devrait contenir "scan_id": "abc123"
    Et la réponse devrait contenir un "progress"
    Et la réponse devrait contenir un "total_files"

  Scénario: Récupérer les résultats d'un scan
    Étant donné un scan terminé avec l'ID "xyz789"
    Quand j'appelle GET "/api/v1/scan/xyz789/results"
    Alors le code de réponse devrait être 200
    Et la réponse devrait contenir un "vulnerabilities"
    Et la réponse devrait contenir un "statistics"

  @skip
  Scénario: Rate limiting de l'API
    # Nécessite implémentation du rate limiting
    Étant donné que la limite est de 5 requêtes par minute
    Quand j'envoie 6 requêtes en moins d'une minute
    Alors la 6ème requête devrait retourner 429
    Et la réponse devrait contenir le texte "Rate limit exceeded"

  Scénario: Validation des entrées API
    Quand j'appelle POST "/api/v1/scan" avec des données invalides:
      """
      {
        "target": "",
        "vulnerability_types": []
      }
      """
    Alors le code de réponse devrait être 422
    Et la réponse devrait contenir une erreur de validation

  Scénario: Annuler un scan en cours
    Étant donné un scan en cours avec l'ID "running123"
    Quand j'appelle DELETE "/api/v1/scan/running123"
    Alors le code de réponse devrait être 200
    Et le scan devrait être annulé

  Scénario: Récupérer les métriques
    Quand j'appelle GET "/api/v1/metrics"
    Alors le code de réponse devrait être 200
    Et la réponse devrait contenir un "total_scans"
    Et la réponse devrait contenir un "active_scans"
    Et la réponse devrait contenir un "cache_hit_rate"

  @skip
  Scénario: CORS headers
    # Nécessite implémentation des CORS headers
    Quand j'envoie une requête OPTIONS à "/api/v1/scan"
    Alors les headers devraient contenir "Access-Control-Allow-Origin"
    Et les headers devraient contenir "Access-Control-Allow-Methods"

  Scénario: Documentation OpenAPI
    Quand j'appelle GET "/api/docs"
    Alors le code de réponse devrait être 200
    Et la page devrait contenir la documentation Swagger UI

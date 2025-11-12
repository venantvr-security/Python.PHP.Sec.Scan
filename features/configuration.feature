# language: fr
Fonctionnalité: Gestion de la configuration
  En tant qu'administrateur système
  Je veux configurer le scanner de différentes façons
  Afin de l'adapter à mon environnement

  @skip
  Scénario: Configuration par défaut
    Quand je charge la configuration sans fichier
    Alors la configuration devrait utiliser les valeurs par défaut
    Et le cache devrait être activé
    Et le nombre de workers devrait être 32

  @skip
  Scénario: Configuration depuis YAML
    Étant donné un fichier config.yaml avec:
      """
      performance:
        max_workers: 64
      cache:
        enabled: false
      """
    Quand je charge la configuration depuis le fichier
    Alors max_workers devrait être 64
    Et le cache devrait être désactivé

  @skip
  Scénario: Configuration depuis variables d'environnement
    Étant donné les variables d'environnement:
      | Variable          | Valeur                          |
      | MAX_WORKERS       | 16                              |
      | CACHE_ENABLED     | false                           |
      | DATABASE_URL      | postgresql://localhost/scanner  |
    Quand je charge la configuration depuis l'environnement
    Alors max_workers devrait être 16
    Et le cache devrait être désactivé
    Et database_url devrait être "postgresql://localhost/scanner"

  @skip
  Scénario: Priorité de configuration
    Étant donné un fichier config.yaml avec max_workers: 32
    Et une variable d'environnement MAX_WORKERS=64
    Quand je charge la configuration
    Alors la variable d'environnement devrait avoir priorité
    Et max_workers devrait être 64

  @skip
  Scénario: Validation de configuration invalide
    Étant donné une configuration avec max_workers: -1
    Quand je valide la configuration
    Alors une erreur de validation devrait être levée
    Et le message devrait contenir "must be positive"

  @skip
  Scénario: Configuration cache backend Redis
    Étant donné une configuration avec:
      """
      cache:
        backend: redis
        redis_url: redis://localhost:6379/0
      """
    Quand je valide la configuration
    Alors la validation devrait réussir

  @skip
  Scénario: Configuration cache backend Redis sans URL
    Étant donné une configuration avec:
      """
      cache:
        backend: redis
        redis_url: null
      """
    Quand je valide la configuration
    Alors une erreur devrait être levée
    Et le message devrait contenir "redis_url required"

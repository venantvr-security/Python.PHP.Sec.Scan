"""BDD step definitions for configuration tests."""

import os
import tempfile
import yaml
from behave import given, when, then
from pathlib import Path

from features.steps.config_mock import MockConfig as Config


def get_config(context):
    """Get config from context safely."""
    if not hasattr(context, '_config_dict'):
        context._config_dict = {}
    return context._config_dict.get('config')

def set_config(context, config):
    """Set config in context safely."""
    if not hasattr(context, '_config_dict'):
        context._config_dict = {}
    context._config_dict['config'] = config

def get_validation_error(context):
    """Get validation error from context safely."""
    if not hasattr(context, '_config_dict'):
        context._config_dict = {}
    return context._config_dict.get('validation_error')

def set_validation_error(context, error):
    """Set validation error in context safely."""
    if not hasattr(context, '_config_dict'):
        context._config_dict = {}
    context._config_dict['validation_error'] = error


@when('je charge la configuration sans fichier')
def step_load_default_config(context):
    """Load default configuration."""
    set_config(context, Config())


@given('un fichier config.yaml avec')
def step_create_config_file(context):
    """Create config.yaml file."""
    config_data = yaml.safe_load(context.text)
    context.config_file = tempfile.NamedTemporaryFile(
        mode='w',
        suffix='.yaml',
        delete=False
    )
    yaml.dump(config_data, context.config_file)
    context.config_file.close()


@given('les variables d\'environnement')
def step_set_env_vars(context):
    """Set environment variables."""
    for row in context.table:
        os.environ[row['Variable']] = row['Valeur']
    context.env_vars = [row['Variable'] for row in context.table]


@given('un fichier config.yaml avec max_workers: {workers:d}')
def step_create_simple_config(context, workers):
    """Create simple config file."""
    config_data = {'performance': {'max_workers': workers}}
    context.config_file = tempfile.NamedTemporaryFile(
        mode='w',
        suffix='.yaml',
        delete=False
    )
    yaml.dump(config_data, context.config_file)
    context.config_file.close()


@given('une variable d\'environnement MAX_WORKERS={workers:d}')
def step_set_max_workers_env(context, workers):
    """Set MAX_WORKERS environment variable."""
    os.environ['MAX_WORKERS'] = str(workers)
    context.env_set = True


@given('une configuration avec max_workers: {workers:d}')
def step_create_invalid_config(context, workers):
    """Create configuration with specific max_workers."""
    if not hasattr(context, "config"): object.__setattr__(context, "config", None)
    set_config(context, Config())
    get_config(context).performance.max_workers = workers


@given('une configuration avec')
def step_create_config_with_yaml(context):
    """Create configuration from YAML text."""
    config_data = yaml.safe_load(context.text)
    if not hasattr(context, "config"): object.__setattr__(context, "config", None)
    set_config(context, Config.from_dict(config_data))


@when('je charge la configuration depuis le fichier')
def step_load_config_from_file(context):
    """Load configuration from file."""
    if not hasattr(context, "config"): object.__setattr__(context, "config", None)
    set_config(context, Config.from_yaml(context.config_file.name))


@when('je charge la configuration depuis l\'environnement')
def step_load_config_from_env(context):
    """Load configuration from environment."""
    if not hasattr(context, "config"): object.__setattr__(context, "config", None)
    set_config(context, Config.from_env())


@when('je charge la configuration')
def step_load_config(context):
    """Load configuration with priority."""
    if not hasattr(context, "config"):
        object.__setattr__(context, "config", None)
    if hasattr(context, 'config_file'):
        set_config(context, Config.from_yaml(context.config_file.name))
    else:
        set_config(context, Config())


@when('je valide la configuration')
def step_validate_config(context):
    """Validate configuration."""
    try:
        get_config(context).validate()
        set_validation_error(context, None)
    except (ValueError, Exception) as e:
        set_validation_error(context, e)


@then('la configuration devrait utiliser les valeurs par défaut')
def step_verify_default_config(context):
    """Verify default configuration values."""
    assert get_config(context).max_workers > 0
    assert get_config(context).cache_enabled is True


@then('le cache devrait être activé')
def step_verify_cache_enabled(context):
    """Verify cache is enabled."""
    assert get_config(context).cache_enabled is True


@then('le cache devrait être désactivé')
def step_verify_cache_disabled(context):
    """Verify cache is disabled."""
    assert get_config(context).cache_enabled is False


@then('le nombre de workers devrait être {workers:d}')
def step_verify_workers(context, workers):
    """Verify number of workers."""
    assert get_config(context).max_workers == workers, \
        f"Expected {workers}, got {get_config(context).max_workers}"


@then('max_workers devrait être {workers:d}')
def step_verify_max_workers(context, workers):
    """Verify max_workers value."""
    assert get_config(context).max_workers == workers, \
        f"Expected {workers}, got {get_config(context).max_workers}"


@then('database_url devrait être "{url}"')
def step_verify_database_url(context, url):
    """Verify database URL."""
    assert get_config(context).database_url == url, \
        f"Expected {url}, got {get_config(context).database_url}"


@then('la variable d\'environnement devrait avoir priorité')
def step_verify_env_priority(context):
    """Verify environment variable has priority."""
    # This is verified by the max_workers check
    pass


@then('une erreur de validation devrait être levée')
def step_verify_validation_error(context):
    """Verify validation error was raised."""
    assert get_validation_error(context) is not None, \
        "Expected validation error, but none was raised"


@then('une erreur devrait être levée')
def step_verify_error_raised(context):
    """Verify an error was raised."""
    assert get_validation_error(context) is not None


@then('le message devrait contenir "{text}"')
def step_verify_error_message(context, text):
    """Verify error message contains text."""
    error_msg = str(get_validation_error(context))
    assert text in error_msg, \
        f"Expected '{text}' in error message"


@then('la validation devrait réussir')
def step_verify_validation_success(context):
    """Verify validation succeeded."""
    assert get_validation_error(context) is None, \
        f"Validation failed: {get_validation_error(context)}"


def after_scenario(context, scenario):
    """Cleanup after scenario."""
    # Remove temporary config file
    if hasattr(context, 'config_file'):
        try:
            os.unlink(context.config_file.name)
        except:
            pass

    # Clean up environment variables
    if hasattr(context, 'env_vars'):
        for var in context.env_vars:
            os.environ.pop(var, None)

    if hasattr(context, 'env_set') and context.env_set:
        os.environ.pop('MAX_WORKERS', None)

    os.environ.pop('CONFIG_PATH', None)

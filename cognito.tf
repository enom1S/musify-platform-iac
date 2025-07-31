resource "aws_cognito_user_pool" "musify_pool" {
  name = "musify-user-pool"

  # Non richiede verifica email
  auto_verified_attributes = []
  
  # Usa email come username
  username_attributes = ["email"]
  
  # Schema attributi
  schema {
    name                = "email"
    attribute_data_type = "String"
    required           = true
    mutable            = true
  }

  schema {
    name                = "name"
    attribute_data_type = "String"
    required           = true
    mutable            = true
  }

  # Password policy (come nel tuo backend)
  password_policy {
    minimum_length    = 8
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = true
  }

  # Disabilita MFA
  mfa_configuration = "OFF"

  # Recovery disabilitato per Learner Lab
  account_recovery_setting {
    recovery_mechanism {
      name     = "admin_only"
      priority = 1
    }
  }

  # Permetti auto-registrazione
  admin_create_user_config {
    allow_admin_create_user_only = false
  }

  tags = {
    Name        = "musify-user-pool"
    Environment = "development"
    Project     = "musify"
  }
}

# App Client con Secret
resource "aws_cognito_user_pool_client" "musify_client" {
  name         = "musify-app-client"
  user_pool_id = aws_cognito_user_pool.musify_pool.id

  # Il tuo backend richiede il secret
  generate_secret = true

  # Auth flows necessari per il tuo backend
  explicit_auth_flows = [
    "ALLOW_USER_PASSWORD_AUTH",      # Per login normale
    "ALLOW_REFRESH_TOKEN_AUTH",      # Per refresh token
    "ALLOW_ADMIN_USER_PASSWORD_AUTH" # Per adminConfirmSignUp
  ]

  # Token validity
  refresh_token_validity = 30  # giorni
  access_token_validity  = 1  
  id_token_validity      = 1  

  # Previeni errori
  prevent_user_existence_errors = "ENABLED"

  # Attributi che il client può leggere/scrivere
  read_attributes  = ["email", "name", "email_verified"]
  write_attributes = ["email", "name"]
}

# Domain per hosted UI (opzionale, se vuoi usarla in futuro)
resource "aws_cognito_user_pool_domain" "musify_domain" {
  domain       = "musify-${random_string.domain_suffix.result}"
  user_pool_id = aws_cognito_user_pool.musify_pool.id
}

resource "random_string" "domain_suffix" {
  length  = 8
  special = false
  upper   = false
}

# Outputs
output "cognito_user_pool_id" {
  value       = aws_cognito_user_pool.musify_pool.id
  description = "ID del User Pool Cognito"
}

output "cognito_client_id" {
  value       = aws_cognito_user_pool_client.musify_client.id
  description = "ID del Client Cognito"
}

output "cognito_client_secret" {
  value       = aws_cognito_user_pool_client.musify_client.client_secret
  sensitive   = true
  description = "Secret del Client Cognito (usa: terraform output -raw cognito_client_secret)"
}

output "cognito_region" {
  value       = var.aws_region
  description = "Regione AWS"
}

output "cognito_domain" {
  value       = aws_cognito_user_pool_domain.musify_domain.domain
  description = "Domain per hosted UI (se necessario)"
}

# Comando helper per mostrare tutte le info necessarie
output "env_variables" {
  value = <<-EOT
    
    Aggiungi queste variabili al tuo .env:
    
    COGNITO_USER_POOL_ID=${aws_cognito_user_pool.musify_pool.id}
    COGNITO_CLIENT_ID=${aws_cognito_user_pool_client.musify_client.id}
    COGNITO_CLIENT_SECRET=<run: terraform output -raw cognito_client_secret>
    COGNITO_REGION=${var.aws_region}
  EOT
}
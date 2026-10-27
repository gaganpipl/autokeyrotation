# Snowflake service-user RSA key rotation

This Azure DevOps pipeline rotates one Snowflake service user's RSA key and stores the new private key in Azure Key Vault. It stages the public key in `RSA_PUBLIC_KEY_2`, authenticates with the staged private key, writes a new Key Vault secret version, and then promotes the public key. The previously active public key is retained in `RSA_PUBLIC_KEY_2` for rollback.

The pipeline is scheduled monthly (UTC) and can also be run manually. It uses the Microsoft-hosted `windows-latest` agent, so it can be tested without a self-hosted agent pool.

## Azure DevOps setup

Create a variable group named `Snowflake-RSA-Key-Rotation` and authorize this pipeline to use it. Define these variables:

| Variable | Value |
| --- | --- |
| `azure_service_connection` | Azure Resource Manager service connection name used by `AzureCLI@2` |
| `azure_key_vault_url` | URL of the Key Vault, for example `https://<vault-name>.vault.azure.net/` |
| `snowflake_account` | Snowflake account identifier expected by the connector |
| `snowflake_admin_user` | Dedicated Snowflake rotation identity with RSA public-key authentication; it must not be the target user |
| `snowflake_admin_role` | Optional role to activate for the rotation identity |
| `snowflake_admin_private_key_secret` | Key Vault secret containing the rotation identity's PEM private key |
| `snowflake_admin_private_key_passphrase_secret` | Optional Key Vault secret name for the admin key passphrase; define empty for an unencrypted PEM |
| `snowflake_service_user` | Snowflake service user being rotated |
| `snowflake_service_private_key_secret` | Key Vault secret name to receive the service user's new PEM private key |

For a hosted-agent trial, the Snowflake admin identity uses an RSA key stored in Key Vault; Azure WIF managed identity authentication is not used because a Microsoft-hosted agent does not have your Azure managed-identity endpoint. Configure `azure_service_connection` as an Azure Resource Manager service connection that can log in from the hosted pipeline, and grant its identity permission to read the admin key/passphrase secrets and create new versions of the service-key secret in Key Vault. Grant the Snowflake rotation role the minimum permission needed to alter the target user (normally ownership of that user). Ensure the hosted agent can reach both Azure and Snowflake.

The Key Vault client uses the Azure CLI identity established by `AzureCLI@2`; do not put private-key material or passphrases in pipeline variables. The admin RSA key and target service key must use separate Key Vault secret names.

## Rotation status notifications

Azure DevOps sends pipeline-completion emails through notification subscriptions; this is configured in Azure DevOps, not as a YAML task. Create a subscription for the rotation pipeline and choose the `Build completed` event. Filter it to this pipeline, and enable notifications for both successful and failed runs so the owner receives the final rotation status. Add the owner as a recipient (or have the owner subscribe to the pipeline). Verify the subscription by running the pipeline and confirming the completion email arrives.

## Application rollout

The private key is written as a new version of the configured Key Vault secret. Applications must reload that secret version (or use the latest version) to begin using the rotated key. The new public key is staged before the secret is updated, so clients can authenticate during rollout. Keep the previous private-key version for the rollback window; the previous public key remains in Snowflake's secondary slot until a later successful rotation replaces it.

The generated PEM is unencrypted because Key Vault protects the secret at rest and controls access. The pipeline does not print key material or public-key values. It verifies the new key with Snowflake both before and after promotion. If the rotation fails before promotion, the current primary key remains available; after Key Vault is updated, the staged secondary key also remains valid.

## Local checks

Install the dependencies and run the offline tests:

```powershell
python -m pip install -r requirements.txt
python -m unittest discover -s tests
```

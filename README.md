# vault-plugin-secrets-logicmonitor

# Overview
This project provides a custom Vault secret plugin for generating temporary
LogicMonitor account API tokens.

# Getting Started
Reference: https://github.com/hashicorp/vault-auth-plugin-example/blob/master/README.md

## Adding the plugin to the Vault plugin catalog

    $ export SHA256=$(shasum -a 256 "./vault-plugin-secrets-logicmonitor" | cut -d' ' -f1)
    $ vault write sys/plugins/catalog/lm-secrets-plugin \
    >     sha_256="${SHA256}" \
    >     command="vault-plugin-secrets-logicmonitor"
    Success! Data written to: sys/plugins/catalog/lm-secrets-plugin

## Mount the plugin

    $ vault secrets enable \
    >     -path="lm" \
    >     -plugin-name="lm-secrets-plugin" plugin
    Success! Enabled the lm-secrets-plugin plugin at: lm/

# Configuring the backend
The secret backend requires authentication information for identifying and
interacting with your LogicMonitor account.

#### Arguments
* access_id      - Required. LogicMonitor API token Access ID with permissions to create new user accounts and set account roles
* access_key     - Required. LogicMonitor API token Access Key with permissions to create new user accounts and set account roles
* account_domain - Required. LogicMonitor account domain. Example: vault.logicmonitor.com

      $ vault write lm/config \
      >     account_domain=account.logicmonitor.com \
      >     access_id='YOUR_API_ACCESS_ID' \
      >     access_key='YOUR_API_ACCESS_KEY'
      Success! Data written to: lm/config

      $ vault read lm/config
      Key            Value
      ---               -----
      access_id         YOUR_API_ACCESS_ID
      access_key        <sensitive>
      account_domain    account.logicmonitor.com
      max_ttl           0
      ttl               0

# Creating Roles
In order to begin generating tokens, you must first configure a role in the
Vault backend. This role controls the permissions the granted to generated API
tokens.

#### Arguments
* roles - Required. Comma-separated list of LogicMonitor account roles to bind to this role.

Behind the scenes, for each Vault role, Vault will
create a LogicMonitor user that is a member of the specified groups. Generated
tokens will belong to the LogicMonitor user associated with the Vault role
that created them.

    $ vault write lm/roles/dev \
    >     roles="readonly,dev"
    Success! Data written to: lm/roles/test

# Generating Tokens
You can generate tokens for a given role by reading /lm/tokens/{role}. Note
that tokens will be disabled and removed from your account when the lease
expires or is revoked.

    $ vault read /lm/tokens/dev
    Key                Value
    ---                -----
    lease_id           lm/tokens/dev/5790895b-c318-725c-0fba-a7abcdfe3ae7
    lease_duration     768h
    lease_renewable    true
    access_id          enP8w1234z7HJ3Y6B84L
    access_key         =xz1234XEsBL(4y]B$mJ34567JE5=x39y)(T!_E4

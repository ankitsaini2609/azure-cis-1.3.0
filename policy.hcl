policy "cis-v1.30" {
  description = "Azure CIS V1.30 Policy"
  configuration {
    provider "azure" {
      version = ">= 0.2.4"
    }
  }

  policy "azure-cis-section-1" {
    description = "Azure CIS Section 1"

    query "1.1" {
      description = "Azure CIS 1.1 Ensure that multi-factor authentication is enabled for all privileged users (Manual)"
      query = file("queries/manual.sql")
    }

    query "1.2" {
      description = "Azure CIS 1.2 Ensure that multi-factor authentication is enabled for all non-privileged users (Manual)"
      query = file("queries/manual.sql")
    }

    query "1.3" {
      description = "Azure CIS 1.3 Ensure guest users are reviewed on a monthly basis (Automated)"
      query = file("queries/manual.sql")
    }

    query "1.4" {
      description = "Azure CIS 1.4 Ensure that 'Allow users to remember multi-factor authentication on devices they trust' is 'Disabled' (Manual)"
      query = file("queries/manual.sql")
    }

    query "1.5" {
      description = "Azure CIS 1.5 Ensure that 'Number of methods required to reset' is set to '2' (Manual)"
      query = file("queries/manual.sql")
    }

    query "1.6" {
      description = "Azure CIS 1.6 Ensure that 'Number of days before users are asked to re-confirm their authentication information' is not set to \"0\" (Manual)"
      query = file("queries/manual.sql")
    }


    query "1.7" {
      description = "Azure CIS 1.7 Ensure that 'Notify users on password resets?' is set to 'Yes' (Manual)"
      query = file("queries/manual.sql")
    }


    query "1.8" {
      description = "Azure CIS 1.8 Ensure that 'Notify all admins when other admins reset their password?' is set to 'Yes' (Manual)"
      query = file("queries/manual.sql")
    }

    query "1.9" {
      description = "Azure CIS 1.9 Ensure that 'Users can consent to apps accessing company data on their behalf' is set to 'No' (Manual)"
      query = file("queries/manual.sql")
    }

    query "1.10" {
      description = "Azure CIS 1.10 Ensure that 'Users can add gallery apps to their Access Panel' is set to 'No' (Manual)"
      query = file("queries/manual.sql")
    }


    query "1.11" {
      description = "Azure CIS 1.11 Ensure that 'Users can register applications' is set to 'No' (Manual)"
      query = file("queries/manual.sql")
    }


    query "1.12" {
      description = "Azure CIS 1.12 Ensure that 'Guest user permissions are limited' is set to 'Yes' (Manual)"
      query = file("queries/manual.sql")
    }

    query "1.13" {
      description = "Azure CIS 1.13 Ensure that 'Members can invite' is set to 'No' (Manual)"
      query = file("queries/manual.sql")
    }

    query "1.14" {
      description = "Azure CIS 1.14 Ensure that 'Guests can invite' is set to 'No' (Manual)"
      query = file("queries/manual.sql")
    }

    query "1.15" {
      description = "Azure CIS 1.15 Ensure that 'Restrict access to Azure AD administration portal' is set to 'Yes' (Manual)"
      query = file("queries/manual.sql")
    }


    query "1.16" {
      description = "Azure CIS 1.16 Ensure that 'Restrict user ability to access groups features in the Access Pane' is set to 'No' (Manual)"
      query = file("queries/manual.sql")
    }


    query "1.17" {
      description = "Azure CIS 1.17 Ensure that 'Users can create security groups in Azure Portals' is set to 'No' (Manual)"
      query = file("queries/manual.sql")
    }

    query "1.18" {
      description = "Azure CIS 1.18 Ensure that 'Owners can manage group membership requests in the Access Panel' is set to 'No' (Manual)"
      query = file("queries/manual.sql")
    }

    query "1.19" {
      description = "Azure CIS 1.19 Ensure that 'Users can create Microsoft 365 groups in Azure Portals' is set to 'No' (Manual)"
      query = file("queries/manual.sql")
    }


    query "1.20" {
      description = "Azure CIS 1.20 Ensure that 'Require Multi-Factor Auth to join devices' is set to 'Yes' (Manual)"
      query = file("queries/manual.sql")
    }


    query "1.21" {
      description = "Azure CIS 1.21 Ensure that no custom subscription owner roles are created (Automated)"
      query = <<EOF
        --check if definition matches scopes
        WITH assignable_scopes AS (SELECT cq_id, UNNEST(assignable_scopes) AS assignable_scope
        FROM azure_authorization_role_definitions v ), meets_scopes AS (SELECT cq_id
        FROM assignable_scopes a
        WHERE a.assignable_scope = '/'
        OR a.assignable_scope = 'subscription'
        GROUP BY cq_id),
        --check if definition matches actions
        definition_actions AS (SELECT role_definition_cq_id AS cq_id, UNNEST(actions) AS ACTION
        FROM azure_authorization_role_definition_permissions), meets_actions AS (SELECT cq_id
        FROM definition_actions
        WHERE "action" = '*') SELECT d.subscription_id , d.id AS definition_id, d."name" AS definition_name
        FROM azure_authorization_role_definitions d
        JOIN meets_actions a ON
        d.cq_id = a.cq_id
        JOIN meets_scopes s ON
        a.cq_id = s.cq_id
    EOF
    }

    query "1.22" {
      description = "Azure CIS 1.22 Ensure Security Defaults is enabled on Azure Active Directory (Automated)"
      query = file("queries/manual.sql")
    }

    query "1.23" {
      description = "Azure CIS 1.23 Ensure Custom Role is assigned for Administering Resource Locks (Manual)"
      query = file("queries/manual.sql")
    }
  }

  policy "azure-cis-section-2" {
    description = "Azure CIS Section 2"

  }

  policy "azure-cis-section-3" {
    description = "Azure CIS Section 3"

  }

  policy "azure-cis-section-4" {
    description = "Azure CIS Section 4"

  }

  policy "azure-cis-section-5" {
    description = "Azure CIS Section 5"

  }

  policy "azure-cis-section-6" {
    description = "Azure CIS Section 6"

  }

  policy "azure-cis-section-7" {
    description = "Azure CIS Section 7"

  }

  policy "azure-cis-section-8" {
    description = "Azure CIS Section 8"

  }


  policy "azure-cis-section-9" {
    description = "Azure CIS Section 9"

    query "9.1" {
      description = "Azure CIS 9.1 Ensure App Service Authentication is set on Azure App Service (Automated)"
      query = <<EOF
        SELECT awa.subscription_id,
        awa.id AS app_id, awa."name" AS app_name, awaas.enabled AS auth_enabled
        FROM azure_web_apps awa
        LEFT JOIN azure_web_app_auth_settings awaas ON
        awa.cq_id = awaas.app_cq_id
        WHERE awaas.enabled IS NULL
        OR awaas.enabled != TRUE;
    EOF
    }

    query "9.2" {
      description = "Azure CIS 9.2 Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service (Automated)"
      query = <<EOF
        SELECT subscription_id,
        id AS app_id, "name" AS app_name, https_only
        FROM azure_web_apps
        WHERE https_only IS NULL
        OR https_only != TRUE;
    EOF
    }

    query "9.3" {
      description = "Azure CIS 9.3 Ensure web app is using the latest version of TLS encryption (Automated)"
      query = <<EOF
        SELECT subscription_id,
        id AS app_id, "name" AS app_name, site_config -> 'minTlsVersion' AS min_tls_version
        FROM azure_web_apps
        WHERE site_config -> 'minTlsVersion' IS NULL
        OR site_config -> 'minTlsVersion' != '1.2';
    EOF
    }

    query "9.4" {
      description = "Azure CIS 9.4 Ensure the web app has 'Client Certificates (Incoming client certificates)' set to 'On' (Automated)"
      query = <<EOF
        SELECT subscription_id,
        id AS app_id, "name" AS app_name, client_cert_enabled
        FROM azure_web_apps
        WHERE client_cert_enabled IS NULL
        OR client_cert_enabled != TRUE;
    EOF
    }

    query "9.5" {
      description = "Azure CIS 9.5 Ensure that Register with Azure Active Directory is enabled on App Service (Automated)"
      query = <<EOF
        SELECT subscription_id,
        id AS app_id, "name" AS app_name, identity_principal_id
        FROM azure_web_apps
        WHERE identity_principal_id IS NULL
        OR identity_principal_id = '';
    EOF
    }

    query "9.6" {
      description = "Azure CIS 9.6 Ensure that 'PHP version' is the latest, if used to run the web app (Manual)"
      //we can check it but we need the latest php version. we can hardcode it here
      //todo we can show php version to ease check process
      query = file("queries/manual.sql")
    }

    query "9.7" {
      description = "Azure CIS 9.7 Ensure that 'Python version' is the latest, if used to run the web app (Manual)"
      //we can check it but we need the latest php version. we can hardcode it here
      //todo we can show version to ease check process
      query = file("queries/manual.sql")
    }

    query "9.8" {
      description = "Azure CIS 9.8 Ensure that 'Java version' is the latest, if used to run the web app (Manual)"
      //we can check it but we need the latest php version. we can hardcode it here
      //todo we can show version to ease check process
      query = file("queries/manual.sql")
    }


    query "9.9" {
      description = "Azure CIS 9.9 Ensure that 'HTTP Version' is the latest, if used to run the web app (Manual)"
      //we can check it but we need the latest php version. we can hardcode it here
      //todo we can show version to ease check process
      query = file("queries/manual.sql")
    }

    query "9.10" {
      description = "Azure CIS 9.10 Ensure FTP deployments are disabled (Automated)"
      query = <<EOF
      SELECT subscription_id,
        id AS app_id, "name" AS app_name, identity_principal_id, p.user_name
      FROM azure_web_apps a
      LEFT JOIN azure_web_app_publishing_profiles p ON
      a.cq_id = p.app_cq_id
      WHERE p.user_name NOT like concat('%',a."name", '%')
    EOF
    }

    query "9.11" {
      description = "Azure CIS 9.11 Ensure Azure Keyvaults are used to store secrets (Manual)"
      query = file("queries/manual.sql")
    }
  }
}
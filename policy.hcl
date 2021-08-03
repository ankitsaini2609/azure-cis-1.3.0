policy "cis-v1.30" {
  description = "Azure CIS V1.30 Policy"
  configuration {
    provider "azure" {
      version = ">= 0.2.4"
    }
  }

  policy "azure-cis-section-1" {
    description = "Azure CIS Section 1"

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
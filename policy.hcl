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

    view "azure_security_policy_parameters" {
      description = "GCP Log Metric Filter and Alarm"
      query "azure_security_policy_parameters" {
        query = file("queries/policy_assignment_parameters.sql")
      }
    }

    query "2.1" {
      description = "Azure CIS 2.1 Ensure that Azure Defender is set to On for Servers (Manual)"
      expect_output = true
      query = <<EOF
        SELECT id, "name", pricing_properties_tier AS tier
        FROM azure_security_pricings asp
        WHERE "name" = 'VirtualMachines'
        AND pricing_properties_tier = 'Standard';
    EOF
    }

    query "2.2" {
      description = "Azure CIS 2.2 Ensure that Azure Defender is set to On for App Service (Manual)"
      expect_output = true
      query = <<EOF
        SELECT id, "name", pricing_properties_tier AS tier
        FROM azure_security_pricings asp
        WHERE "name" = 'AppServices'
        AND pricing_properties_tier = 'Standard';
    EOF
    }

    query "2.3" {
      description = "Azure CIS 2.3 Ensure that Azure Defender is set to On for Azure SQL database servers (Manual)"
      expect_output = true
      query = <<EOF
        SELECT id, "name", pricing_properties_tier AS tier
        FROM azure_security_pricings asp
        WHERE "name" = 'SqlServers'
        AND pricing_properties_tier = 'Standard';
    EOF
    }

    query "2.4" {
      description = "Azure CIS 2.4 Ensure that Azure Defender is set to On for SQL servers on machines (Manual)"
      expect_output = true
      query = <<EOF
        SELECT id, "name", pricing_properties_tier AS tier
        FROM azure_security_pricings asp
        WHERE "name" = 'SqlserverVirtualMachines'
        AND pricing_properties_tier = 'Standard';
    EOF
    }


    query "2.5" {
      description = "Azure CIS 2.5 Ensure that Azure Defender is set to On for Storage (Manual)"
      expect_output = true
      query = <<EOF
        SELECT id, "name", pricing_properties_tier AS tier
        FROM azure_security_pricings asp
        WHERE "name" = 'StorageAccounts'
        AND pricing_properties_tier = 'Standard';
    EOF
    }

    query "2.6" {
      description = "Azure CIS 2.6 Ensure that Azure Defender is set to On for Kubernetes (Manual)"
      expect_output = true
      query = <<EOF
        SELECT id, "name", pricing_properties_tier AS tier
        FROM azure_security_pricings asp
        WHERE "name" = 'KubernetesService'
        AND pricing_properties_tier = 'Standard';
    EOF
    }

    query "2.7" {
      description = "Azure CIS 2.7 Ensure that Azure Defender is set to On for Container Registries (Manual)"
      expect_output = true
      query = <<EOF
        SELECT id, "name", pricing_properties_tier AS tier
        FROM azure_security_pricings asp
        WHERE "name" = 'ContainerRegistry'
        AND pricing_properties_tier = 'Standard';
    EOF
    }

    query "2.8" {
      description = "Azure CIS 2.8 Ensure that Azure Defender is set to On for Key Vault (Manual)"
      expect_output = true
      query = <<EOF
        SELECT id, "name", pricing_properties_tier AS tier
        FROM azure_security_pricings asp
        WHERE "name" = 'KeyVaults'
        AND pricing_properties_tier = 'Standard';
    EOF
    }

    query "2.9" {
      description = "Azure CIS 2.9 Ensure that Windows Defender ATP (WDATP) integration with Security Center is selected (Manual)"
      expect_output = true
      query = <<EOF
        SELECT id, "name", enabled
        FROM azure_security_settings ass
        WHERE "name" = 'WDATP'
        AND enabled = TRUE;
    EOF
    }

    query "2.10" {
      description = "Azure CIS 2.10 Ensure that Microsoft Cloud App Security (MCAS) integration with Security Center is selected (Manual)"
      expect_output = true
      query = <<EOF
        SELECT id, "name", enabled
        FROM azure_security_settings ass
        WHERE "name" = 'MCAS'
        AND enabled = TRUE;
    EOF
    }

    query "2.11" {
      description = "Azure CIS 2.11 Ensure that 'Automatic provisioning of monitoring agent' is set to 'On' (Automated)"
      expect_output = true
      query = <<EOF
        SELECT id, "name"
        FROM azure_security_auto_provisioning_settings asaps
        WHERE "name" = 'default'
        AND auto_provision = 'On';
    EOF
    }

    query "2.11" {
      description = "Azure CIS 2.11 Ensure that 'Automatic provisioning of monitoring agent' is set to 'On' (Automated)"
      expect_output = true
      query = <<EOF
        SELECT id, "name"
        FROM azure_security_auto_provisioning_settings asaps
        WHERE "name" = 'default'
        AND auto_provision = 'On';
    EOF
    }

    query "2.12" {
      description = "Azure CIS 2.12 Ensure any of the ASC Default policy setting is not set to \"Disabled\" (Manual)"
      query = <<EOF
        SELECT *
        FROM azure_security_policy_parameters
        WHERE value = 'Disabled';
    EOF
    }

    query "2.13" {
      description = "Azure CIS 2.13 Ensure 'Additional email addresses' is configured with a security contact email (Automated)"
      //email should be valid so if there is even not valid email it will pass
      expect_output = true
      query = <<EOF
        SELECT subscription_id, id, email
        FROM azure_security_contacts
        WHERE email IS NOT NULL
        AND email != '';
    EOF
    }

    query "2.14" {
      description = "Azure CIS 2.14 Ensure that 'Notify about alerts with the following severity' is set to 'High' (Automated)"
      expect_output = true
      query = <<EOF
        SELECT  subscription_id, id, email
        FROM azure_security_contacts
        WHERE email IS NOT NULL
        AND email != '' AND alert_notifications = 'On';
    EOF
    }

    query "2.15" {
      description = "Azure CIS 2.15 Ensure that 'All users with the following roles' is set to 'Owner' (Automated)"
      expect_output = true
      query = <<EOF
        SELECT  subscription_id, id, email
        FROM azure_security_contacts
        WHERE email IS NOT NULL
        AND email != '' AND alerts_to_admins = 'On';
    EOF
    }
  }

  policy "azure-cis-section-3" {
    description = "Azure CIS Section 3"

  }

  policy "azure-cis-section-4" {
    description = "Azure CIS Section 4"

    query "4.1.1" {
      description = "Azure CIS 4.1.1 Ensure that 'Auditing' is set to 'On' (Automated)"
      query = <<EOF
        SELECT s.subscription_id , s.id AS server_id, s."name" AS server_name, assdbap.state AS auditing_state
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_server_db_blob_auditing_policies assdbap ON
        s.cq_id = assdbap.server_cq_id
        WHERE assdbap.state != 'Enabled';
    EOF
    }

    query "4.1.2" {
      description = "Azure CIS 4.1.2 Ensure that 'Data encryption' is set to 'On' on a SQL Database (Automated)"
      query = <<EOF
        SELECT s.subscription_id , asd.id AS database_id, asd.transparent_data_encryption -> 'properties' ->> 'status' AS encryption_status
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_databases asd ON
        s.cq_id = asd.server_cq_id
        WHERE asd.transparent_data_encryption -> 'properties' ->> 'status' != 'Enabled';
    EOF
    }

    query "4.1.3" {
      description = "Azure CIS 4.1.3 Ensure that 'Auditing' Retention is 'greater than 90 days' (Automated)"
      query = <<EOF
        SELECT s.subscription_id , s.id AS server_id, s."name" AS server_name, assdbap.retention_days AS auditing_retention_days
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_server_db_blob_auditing_policies assdbap ON
                s.cq_id = assdbap.server_cq_id
        WHERE assdbap.retention_days < 90;
    EOF
    }

    query "4.2.1" {
      description = "Azure CIS 4.2.1 Ensure that Advanced Threat Protection (ATP) on a SQL server is set to 'Enabled' (Automated)"
      query = <<EOF
        SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, d."name" AS database_name, p.state AS policy_state
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_databases d ON
        s.cq_id = d.server_cq_id
        LEFT JOIN azure_sql_database_db_threat_detection_policies p ON
        d.cq_id = p.database_cq_id
        WHERE p.state != 'Enabled';
    EOF
    }

    query "4.2.2" {
      description = "Azure CIS 4.2.2 Ensure that Vulnerability Assessment (VA) is enabled on a SQL server by setting a Storage Account (Automated)"
      // experimentally checked and storage_container_path becomes NULL when storage account is disabled in assessment policy
      query = <<EOF
        SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name , a."name" AS assesment_id
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_server_vulnerability_assessments a ON
        s.cq_id = a.server_cq_id
        WHERE a.storage_container_path IS NULL OR a.storage_container_path = ''
    EOF
    }


    query "4.2.3" {
      description = "Azure CIS 4.2.3 Ensure that VA setting Periodic Recurring Scans is enabled on a SQL server (Automated)"
      query = <<EOF
        SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name , a."name" AS assesment_id
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_server_vulnerability_assessments a ON
        s.cq_id = a.server_cq_id
        WHERE a.recurring_scans_is_enabled IS NULL
        OR a.recurring_scans_is_enabled != TRUE;
    EOF
    }

    query "4.2.4" {
      description = "Azure CIS 4.2.4 Ensure that VA setting Send scan reports to is configured for a SQL server (Automated)"
      query = <<EOF
        WITH vulnerability_emails AS (SELECT id, UNNEST(recurring_scans_emails) AS emails
        FROM azure_sql_server_vulnerability_assessments v), emails_count AS (SELECT id, count(emails) AS emails_number
        FROM vulnerability_emails
        GROUP BY id) SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, sv."name" AS assesment_name, c.emails_number AS emails
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_server_vulnerability_assessments sv ON
        s.cq_id = sv.server_cq_id
        LEFT JOIN emails_count c ON
        sv.id = c.id
        WHERE c.emails_number = 0
        OR c.emails_number IS NULL;
    EOF
    }

    query "4.2.5" {
      description = "Azure CIS 4.2.5 Ensure that VA setting 'Also send email notifications to admins and subscription owners' is set for a SQL server (Automated)"
      query = <<EOF
        SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name , a."name" AS assesment_id
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_server_vulnerability_assessments a ON
        s.cq_id = a.server_cq_id
        WHERE a.recurring_scans_email_subscription_admins IS NULL
        OR a.recurring_scans_email_subscription_admins != TRUE;
    EOF
    }

    query "4.3.1" {
      description = "Azure CIS 4.3.1 Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server (Automated)"
      query = <<EOF
        SELECT subscription_id, id AS server_id, "name", ssl_enforcement AS server_name
        FROM azure_postgresql_servers aps
        WHERE ssl_enforcement != 'Enabled'
        OR ssl_enforcement IS NULL;
    EOF
    }

    query "4.3.2" {
      description = "Azure CIS 4.3.2 Ensure 'Enforce SSL connection' is set to 'ENABLED' for MySQL Database Server (Automated)"
      query = <<EOF
        SELECT subscription_id, id AS server_id, "name" AS server_name, ssl_enforcement
        FROM azure_mysql_servers ams
        WHERE ssl_enforcement != 'Enabled'
        OR ssl_enforcement IS NULL;
    EOF
    }


    query "4.3.3" {
      description = "Azure CIS 4.3.3 Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server (Automated)"
      query = <<EOF
        WITH value_check AS( SELECT aps.cq_id, apsc.value
        FROM azure_postgresql_servers aps
        LEFT JOIN azure_postgresql_server_configurations apsc ON
                aps.cq_id = apsc.server_cq_id
        WHERE apsc."name" = 'log_checkpoints') SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, 'log_checkpoints' AS "name", v.value
        FROM azure_postgresql_servers s
        LEFT JOIN value_check v ON
        s.cq_id = v.cq_id
        WHERE v.value IS NULL
        OR v.value != 'on';
    EOF
    }

    query "4.3.4" {
      description = "Azure CIS 4.3.4 Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server (Automated)"
      query = <<EOF
        WITH value_check AS( SELECT aps.cq_id, apsc.value
        FROM azure_postgresql_servers aps
        LEFT JOIN azure_postgresql_server_configurations apsc ON
                aps.cq_id = apsc.server_cq_id
        WHERE apsc."name" = 'log_connections') SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, 'log_connections' AS "name", v.value
        FROM azure_postgresql_servers s
        LEFT JOIN value_check v ON
        s.cq_id = v.cq_id
        WHERE v.value IS NULL
        OR v.value != 'on';
    EOF
    }

    query "4.3.5" {
      description = "Azure CIS 4.3.5 Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database Server (Automated)"
      query = <<EOF
        WITH value_check AS( SELECT aps.cq_id, apsc.value
        FROM azure_postgresql_servers aps
        LEFT JOIN azure_postgresql_server_configurations apsc ON
                aps.cq_id = apsc.server_cq_id
        WHERE apsc."name" = 'log_disconnections') SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, 'log_disconnections' AS "name", v.value
        FROM azure_postgresql_servers s
        LEFT JOIN value_check v ON
        s.cq_id = v.cq_id
        WHERE v.value IS NULL
        OR v.value != 'on';
    EOF
    }

    query "4.3.6" {
      description = "Azure CIS 4.3.6 Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server (Automated)"
      query = <<EOF
        WITH value_check AS( SELECT aps.cq_id, apsc.value
        FROM azure_postgresql_servers aps
        LEFT JOIN azure_postgresql_server_configurations apsc ON
                aps.cq_id = apsc.server_cq_id
        WHERE apsc."name" = 'connection_throttling') SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, 'connection_throttling' AS "name", v.value
        FROM azure_postgresql_servers s
        LEFT JOIN value_check v ON
        s.cq_id = v.cq_id
        WHERE v.value IS NULL
        OR v.value != 'on';
    EOF
    }

    query "4.3.7" {
      description = "Azure CIS 4.3.7 Ensure server parameter 'log_retention_days' is greater than 3 days for PostgreSQL Database Server (Automated)"
      query = <<EOF
        WITH value_check AS( SELECT aps.cq_id, apsc.value
        FROM azure_postgresql_servers aps
        LEFT JOIN azure_postgresql_server_configurations apsc ON
                        aps.cq_id = apsc.server_cq_id
        WHERE apsc."name" = 'log_retention_days') SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, 'log_retention_days' AS "name", v.value
        FROM azure_postgresql_servers s
        LEFT JOIN value_check v ON
                s.cq_id = v.cq_id
        WHERE v.value IS NULL
        OR v.value::INTEGER < 3;
    EOF
    }

    query "4.3.8" {
      description = "Azure CIS 4.3.8 Ensure 'Allow access to Azure services' for PostgreSQL Database Server is disabled (Manual)"
      query = <<EOF
        SELECT aps.subscription_id, aps.id AS server_id, aps."name" AS server_name, apsfr."name" AS rule_name, apsfr.start_ip_address, apsfr.end_ip_address
        FROM azure_postgresql_servers aps
        LEFT JOIN azure_postgresql_server_firewall_rules apsfr ON
        aps.cq_id = apsfr.server_cq_id
        WHERE apsfr."name" = 'AllowAllAzureIps'
        OR (apsfr.start_ip_address = '0.0.0.0'
        AND apsfr.end_ip_address = '0.0.0.0')
    EOF
    }

    query "4.4" {
      description = "Azure CIS 4.4 Ensure that Azure Active Directory Admin is configured (Automated)"
      query = <<EOF
        WITH ad_admins_count AS( SELECT ass.cq_id, count(*) AS admins_count
        FROM azure_sql_servers ass
        LEFT JOIN azure_sql_server_admins assa  ON
        ass.cq_id = assa.server_cq_id WHERE assa.administrator_type = 'ActiveDirectory' GROUP BY ass.cq_id,
        assa.administrator_type ) SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, a.admins_count AS "ad_admins_count"
        FROM azure_sql_servers s
        LEFT JOIN ad_admins_count a ON
                s.cq_id = a.cq_id
        WHERE a.admins_count IS NULL
        OR a.admins_count = 0;
    EOF
    }

    query "4.5" {
      description = "Azure CIS 4.5 Ensure SQL server's TDE protector is encrypted with Customer-managed key (Automated)"
      query = <<EOF
        SELECT s.subscription_id, s.id AS server_id, s."name" AS server_name, p.kind AS protector_kind
        FROM azure_sql_servers s
        LEFT JOIN azure_sql_server_encryption_protectors p ON
        s.cq_id = p.server_cq_id
        WHERE p.kind != 'azurekeyvault'
        OR p.server_key_type != 'AzureKeyVault'
        OR uri IS NULL;
    EOF
    }
  }

  policy "azure-cis-section-5" {
    description = "Azure CIS Section 5"

  }

  policy "azure-cis-section-6" {
    description = "Azure CIS Section 6"

    view "azure_nsg_rules" {
      description = "Azure network security groups rules with parsed ports"
      query "azure_nsg_rules_query" {
        query = file("queries/nsg_rules_ports.sql")
      }
    }

    query "6.1" {
      description = "Azure CIS 6.1 Ensure that RDP access is restricted from the internet (Automated)"
      query = <<EOF
      SELECT *
      FROM azure_nsg_rules
      WHERE (source_address_prefix = '*'
          OR source_address_prefix = '0.0.0.0'
          OR source_address_prefix = '<nw>/0'
          OR source_address_prefix = '/0'
          OR source_address_prefix = 'internet'
          OR source_address_prefix = 'any')
      AND (single_port = '3389'
          OR 3389 BETWEEN range_start AND range_end)
      AND protocol = 'Tcp'
      AND "access" = 'Allow'
      AND direction = 'Inbound'
    EOF
    }


    query "6.2" {
      description = "Azure CIS 6.2 Ensure that SSH access is restricted from the internet (Automated)"
      query = <<EOF
      SELECT *
      FROM azure_nsg_rules
      WHERE (source_address_prefix = '*'
          OR source_address_prefix = '0.0.0.0'
          OR source_address_prefix = '<nw>/0'
          OR source_address_prefix = '/0'
          OR source_address_prefix = 'internet'
          OR source_address_prefix = 'any')
      AND protocol = 'Udp'
      AND "access" = 'Allow'
      AND direction = 'Inbound'
      AND (single_port = '22'
          OR 22 BETWEEN range_start AND range_end)
    EOF
    }

    query "6.3" {
      description = "Azure CIS 6.3 Ensure no SQL Databases allow ingress 0.0.0.0/0 (ANY IP) (Automated)"
      //todo think about "other combinations which allows access to wider public IP ranges including Windows Azure IP ranges."
      query = <<EOF
      SELECT ass.id AS server_id, ass."name" AS server_name
      FROM azure_sql_servers ass
      LEFT JOIN
       azure_sql_server_firewall_rules assfr ON
      ass.cq_id = assfr.server_cq_id
      WHERE assfr.start_ip_address = '0.0.0.0'
      OR ( assfr.start_ip_address = '255.255.255.255'
          AND assfr.end_ip_address = '0.0.0.0' );
    EOF
    }

    query "6.4" {
      description = "Azure CIS 6.4 Ensure that Network Security Group Flow Log retention period is 'greater than 90 days' (Automated)"
      query = <<EOF
      SELECT ansg."name" AS nsg_name, ansg.id AS nsg_name, ansgfl.retention_policy_enabled, ansgfl.retention_policy_days
      FROM azure_network_security_groups ansg
      LEFT JOIN azure_network_security_group_flow_logs ansgfl ON
      ansg.cq_id = ansgfl.security_group_cq_id
      WHERE ansgfl.retention_policy_enabled != TRUE
      OR ansgfl.retention_policy_enabled IS NULL
      OR ansgfl.retention_policy_days < 90
      OR ansgfl.retention_policy_days IS NULL;
    EOF
    }

    query "6.5" {
      description = "Azure CIS 6.5 Ensure that Network Watcher is 'Enabled' (Manual)"
      query = file("queries/manual.sql")
    }

    query "6.6" {
      description = "Azure CIS 6.6 Ensure that UDP Services are restricted from the Internet (Automated)"
      query = <<EOF
      SELECT *
      FROM azure_nsg_rules
      WHERE (source_address_prefix = '*'
          OR source_address_prefix = '0.0.0.0'
          OR source_address_prefix = '<nw>/0'
          OR source_address_prefix = '/0'
          OR source_address_prefix = 'internet'
          OR source_address_prefix = 'any')
      AND protocol = 'Udp'
      AND "access" = 'Allow'
      AND direction = 'Inbound'
      AND ((single_port = '53'
          OR 53 BETWEEN range_start AND range_end)
      OR (single_port = '123'
          OR 123 BETWEEN range_start AND range_end)
      OR (single_port = '161'
          OR 161 BETWEEN range_start AND range_end)
      OR (single_port = '389'
          OR 389 BETWEEN range_start AND range_end));
    EOF
    }
  }

  policy "azure-cis-section-7" {
    description = "Azure CIS Section 7"

  }

  policy "azure-cis-section-8" {
    description = "Azure CIS Section 8"

    query "8.1" {
      description = "Azure CIS 8.1 Ensure that the expiration date is set on all keys (Automated)"
      query = <<EOF
      SELECT akv.id AS vault_id, akv."name" AS vault_name, akvk.kid AS key_id
      FROM azure_keyvault_vaults akv
      LEFT JOIN
            azure_keyvault_vault_keys akvk ON
            akv.cq_id = akvk.vault_cq_id
      WHERE akvk.kid IS NULL
      OR enabled != TRUE
      OR expires IS NULL;
    EOF
    }

    query "8.2" {
      description = "Azure CIS 8.2 Ensure that the expiration date is set on all Secrets (Automated)"
      query = <<EOF
      SELECT akv.id AS vault_id, akv."name" AS vault_name, akvs.id AS key_id
      FROM azure_keyvault_vaults akv
      LEFT JOIN
            azure_keyvault_vault_secrets akvs ON
            akv.cq_id = akvs.vault_cq_id
      WHERE enabled != TRUE
      OR expires IS NULL;
    EOF
    }

    query "8.3" {
      description = "Azure CIS 8.3 Ensure that Resource Locks are set for mission critical Azure resources (Manual)"
      query = file("queries/manual.sql")
    }

    query "8.4" {
      description = "Azure CIS 8.4 Ensure the key vault is recoverable (Automated)"
      query = <<EOF
      SELECT id, "name", enable_purge_protection
      FROM azure_keyvault_vaults akv
      WHERE enable_soft_delete != TRUE
      OR enable_purge_protection != TRUE;
    EOF
    }

    query "8.5" {
      description = "Azure CIS 8.5 Enable role-based access control (RBAC) within Azure Kubernetes Services (Automated)"
      query = <<EOF
      SELECT id, "name", enable_rbac
      FROM azure_container_managed_clusters acmc
      WHERE enable_rbac != TRUE;
    EOF
    }
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
sudo su postgres
psql
CREATE DATABASE sca;

\c sca
CREATE SCHEMA sca;
GRANT USAGE ON SCHEMA sca TO sca;

ALTER ROLE sca SET search_path = "sca";
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sca TO sca;

DROP TABLE sca.vulnerable_package_history;
DROP TABLE sca.package_version_deployment_environment;
DROP TABLE sca.package_version;
DROP TABLE sca.package;
DROP TABLE sca.sbom;
DROP TABLE sca.product_line_product;
DROP TABLE sca.product;
DROP TABLE sca.product_line;
DROP TABLE sca.deployment_environment;

CREATE TABLE sca.deployment_environment
(
	id             SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	title          TEXT NOT NULL,
	internal       BOOLEAN NOT NULL DEFAULT FALSE,
	CONSTRAINT deploy_env_title_unique UNIQUE (title)
);
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON sca.deployment_environment TO sca;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sca TO sca;
COMMENT ON TABLE sca.deployment_environment IS 'DEV, TST, ACC, PRD';

/** 	owners         TEXT[]*/
CREATE TABLE sca.product_line
(
	id             SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	title          TEXT NOT NULL UNIQUE
);
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON sca.product_line TO sca;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sca TO sca;

CREATE TABLE sca.product
(
	id             INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	title          TEXT NOT NULL,
	product_line_id SMALLINT NOT NULL,
	UNIQUE(title, product_line_id),
	CONSTRAINT product_fk_product_line FOREIGN KEY (product_line_id) REFERENCES sca.product_line ON DELETE CASCADE
);
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON sca.product TO sca;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sca TO sca;
COMMENT ON TABLE sca.product IS 'The product line is the accountable owner.';

CREATE TABLE sca.product_line_product
(
	product_id     INT NOT NULL,
	product_line   SMALLINT NOT NULL,
	CONSTRAINT product_line_product_fk_product FOREIGN KEY (product_id) REFERENCES sca.product,
	CONSTRAINT product_line_product_fk_product_line FOREIGN KEY (product_line) REFERENCES sca.product_line,
	CONSTRAINT product_line_product_pk PRIMARY KEY(product_id, product_line)
);
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON sca.product_line_product TO sca;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sca TO sca;
COMMENT ON TABLE sca.product_line_product IS 'Additional product line maintaining the product code.';

/**
TODO original SBOM (can be signed and tampered proof) & enriched SBOM with vulns
*/
CREATE TABLE sca.sbom
(
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    sbom_enriched       JSONB,
    sbom_original       JSONB,
	s3_uuid_enriched    TEXT,
	s3_uuid_original    TEXT,
	sha256              TEXT NOT NULL,
	CONSTRAINT sbom_unique_sha256 UNIQUE (sha256)
);
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON sca.sbom TO sca;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sca TO sca;
COMMENT ON TABLE sca.sbom IS 'The SBOM of deployed package/application is stored in the database. This sbom will be rescan when the vulnerability database is updated. The SBOM of previous version is backup in an S3 storage.';

CREATE INDEX sbom_index_sha256 ON sca.sbom(sha256);

/**
What is foreseen in cycloneDX?.
TODO technical fit.
TODO business context. (review, comment,owner,...)
*/
CREATE TABLE sca.package
(
	id             INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	title          TEXT NOT NULL,
	description    TEXT,
	product_id     SMALLINT NOT NULL,
	CONSTRAINT package_unique_title_product_id UNIQUE (title, product_id),
	CONSTRAINT package_fk_product FOREIGN KEY (product_id) REFERENCES sca.product ON DELETE CASCADE
);
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON sca.package TO sca;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sca TO sca;
COMMENT ON TABLE sca.package IS 'The deployable/application. Can be a container images, a server, an OS, an AI model,...';

CREATE TABLE sca.package_version
(
	id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	title          TEXT NOT NULL,
	latest_scan    TIMESTAMP WITH TIME ZONE,

	package_id     INT NOT NULL,
	sbom_id        BIGINT,
	CONSTRAINT package_version_unique_title_package_id UNIQUE (title, package_id),
	CONSTRAINT package_version_fk_sbom FOREIGN KEY (sbom_id) REFERENCES sca.sbom ON DELETE CASCADE,
	CONSTRAINT package_version_fk_package FOREIGN KEY (package_id) REFERENCES sca.package ON DELETE CASCADE
);
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON sca.package_version TO sca;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sca TO sca;
COMMENT ON TABLE sca.package_version IS 'The deployable/application';

CREATE TABLE sca.package_version_deployment_environment
(
	package_version_id              BIGINT NOT NULL,
	deployment_environment_id   SMALLINT NOT NULL,
	CONSTRAINT package_version_deployment_env_fk_package_version FOREIGN KEY (package_version_id) REFERENCES sca.package_version ON DELETE CASCADE,
	CONSTRAINT package_version_deployment_env_fk_deployment_env FOREIGN KEY (deployment_environment_id) REFERENCES sca.deployment_environment,
	CONSTRAINT package_version_deployment_environment_pk PRIMARY KEY(package_version_id, deployment_environment_id)
);
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON sca.package_version_deployment_environment TO sca;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sca TO sca;


CREATE TABLE sca.vulnerable_package_history
(
	id                   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	critical             SMALLINT NOT NULL DEFAULT 0,
	high                 SMALLINT NOT NULL DEFAULT 0,
	medium               SMALLINT NOT NULL DEFAULT 0,
	low                  SMALLINT NOT NULL DEFAULT 0,
	info                 SMALLINT NOT NULL DEFAULT 0,
	_unknown              SMALLINT NOT NULL DEFAULT 0,
	_none                 SMALLINT NOT NULL DEFAULT 0,
	created_date         TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
	package_version_id   BIGINT NOT NULL,
	CONSTRAINT vulnerable_package_history_fk_package_version FOREIGN KEY (package_version_id) REFERENCES sca.package_version ON DELETE CASCADE
);
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON sca.vulnerable_package_history TO sca;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sca TO sca;
COMMENT ON TABLE sca.vulnerable_package_history IS 'When the number of vulnerabilty of the previous scan changes, this table is updated with a new entry. Only the deployed artifacts are scanned.';


/**
Create table component
create table componenet_version

USE to know which package can be infected by a specific component.
componenet_version_package_version
    id
    id
*/

/**
I NEED vulnerability and a date.
*/
CREATE TABLE app_vulnerability (
	app_version int,
	vulnerability_id bigint,
	scan_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
);

CREATE TABLE vulnerability(
	id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	cve            TEXT NOT NULL,
	euvd           TEXT NOT NULL,
	ghsa           TEXT NOT NULL,
	vendor_id	   TEXT NOT NULL

);
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON sca.app_vulnerability TO sca;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sca TO sca;
COMMENT ON TABLE sca.vulnerability IS 'Identifier is the CVE ID';

CREATE TABLE sca.min_sbom
(
	id                       INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	supplier_name            TEXT NOT NULL, (SPDX: NOASSERTION, Person,Organization )
	original_component_name  TEXT NOT NULL,
	component_version        TEXT NOT NULL,
	other_unique_identifiers TEXT NOT NULL,
	dependency relationship
	author_sbom_data
	timestamp_record
	CONSTRAINT app_version_fk_app FOREIGN KEY (app_id) REFERENCES sca.app
);
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON sca.app_version TO sca;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sca TO sca;
COMMENT ON TABLE sca.app_version IS 'The actual application';


/**
TODO inventory management with CycloneDX service.
https://cyclonedx.org/use-cases/services/
*/

/**
TODO add cycloneDX release NOTE.
https://cyclonedx.org/capabilities/release-notes/
TODO release management with Jira.
*/

sudo su postgres
psql
CREATE DATABASE sca;

\c sca
CREATE SCHEMA sca;
GRANT USAGE ON SCHEMA sca TO sca;

ALTER ROLE sca SET search_path = "sca";
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sca TO sca;



DROP TABLE sca.app_version;
DROP TABLE sca.app;
DROP TABLE sca.product;
DROP TABLE sca.product_line;
DROP TABLE sca.deployment_environment;

CREATE TABLE sca.deployment_environment
(
	id             SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	title          TEXT NOT NULL,
	CONSTRAINT app_version_fk_app FOREIGN KEY (app_id) REFERENCES sca.app
);
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON sca.deployment_environment TO sca;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sca TO sca;

CREATE TABLE sca.product_line
(
	id             SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	title          TEXT NOT NULL UNIQUE,
	owners         TEXT[]
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
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON sca.product_line TO sca;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sca TO sca;
COMMENT ON TABLE sca.product IS 'Additional product line maintaining the product code.';


/**
app vs project/initiative

What is foreseen in cycloneDX?.
TODO technical fit.
TODO business context. (review, comment,...)
*/
CREATE TABLE sca.app
(
	id             INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	title          TEXT NOT NULL,
	description    TEXT,
	product_id SMALLINT NOT NULL,
	CONSTRAINT app_fk_product FOREIGN KEY (product_id) REFERENCES sca.product ON DELETE CASCADE
);
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON sca.app TO sca;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sca TO sca;
COMMENT ON TABLE sca.app IS 'The actual application';

CREATE TABLE sca.app_version
(
	id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	_version       TEXT NOT NULL,
	production     BOOLEAN NOT NULL DEFAULT FALSE,
	latest_scan    TIMESTAMP WITH TIME ZONE,
	critical       SMALLINT NOT NULL DEFAULT 0,
	high           SMALLINT NOT NULL DEFAULT 0,
	medium         SMALLINT NOT NULL DEFAULT 0,
	small          SMALLINT NOT NULL DEFAULT 0,
	app_id         INT NOT NULL,
	CONSTRAINT app_version_fk_app FOREIGN KEY (app_id) REFERENCES sca.app ON DELETE CASCADE
);
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON sca.app_version TO sca;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sca TO sca;
COMMENT ON TABLE sca.app_version IS 'The actual application';

CREATE TABLE sca.app_version_deployment_environment
(
	app_version_id              BIGINT NOT NULL,
	deployment_environment_id   SMALLINT NOT NULL,
	CONSTRAINT app_version_deployment_environment_fk_app_version FOREIGN KEY (app_version_id) REFERENCES sca.app_version ON DELETE CASCADE,
	CONSTRAINT app_version_deployment_environment_fk_deployment_environment FOREIGN KEY (deployment_environment_id) REFERENCES sca.deployment_environment,
	CONSTRAINT product_line_product_pk PRIMARY KEY(product_id, product_line)
);
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON sca.product_line TO sca;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sca TO sca;

UNKNOWN = 0;
LOW = 1;
MEDIUM = 2;
HIGH = 3;
CRITICAL = 4;

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

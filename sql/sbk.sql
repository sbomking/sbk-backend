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


CREATE TABLE sca.product_line
(
	id             SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	title          TEXT NOT NULL UNIQUE
);
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON sca.product_line TO sca;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sca TO sca;

CREATE TABLE sca.product
(
	id             SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	title          TEXT NOT NULL,
	product_line_id SMALLINT NOT NULL,
	UNIQUE(title, product_line_id),
	CONSTRAINT product_fk_product_line FOREIGN KEY (product_line_id) REFERENCES sca.product_line ON DELETE CASCADE
);
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON sca.product TO sca;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sca TO sca;

CREATE TABLE sca.app
(
	id             INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	title          TEXT NOT NULL,
	product_id SMALLINT NOT NULL,
	CONSTRAINT app_fk_product FOREIGN KEY (product_id) REFERENCES sca.product
);
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON sca.app TO sca;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sca TO sca;
COMMENT ON TABLE sca.app IS 'The actual application';

CREATE TABLE sca.app_version
(
	id             INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	_version       TEXT NOT NULL,
	production     BOOLEAN NOT NULL DEFAULT FALSE, 
	latest_scan    TIMESTAMP WITH TIME ZONE,
	critical       SMALLINT NOT NULL DEFAULT 0,
	high           SMALLINT NOT NULL DEFAULT 0,
	medium         SMALLINT NOT NULL DEFAULT 0,
	small          SMALLINT NOT NULL DEFAULT 0,
	app_id         INT NOT NULL,
	CONSTRAINT app_version_fk_app FOREIGN KEY (app_id) REFERENCES sca.app
);
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON sca.app_version TO sca;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sca TO sca;
COMMENT ON TABLE sca.app_version IS 'The actual application';

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

INSERT INTO sca.product_line(title) VALUES ('Security');
INSERT INTO sca.product(title, product_line_id) VALUES ('Sbomking',1);
INSERT INTO sca.app(title,product_id) VALUES ('sbk-backend', 1);
INSERT INTO sca.app(title,product_id) VALUES ('sbk-frontend', 1);

INSERT INTO sca.deployment_environment(title) VALUES('dev');
INSERT INTO sca.deployment_environment(title) VALUES('test');
INSERT INTO sca.deployment_environment(title) VALUES('acceptance');
INSERT INTO sca.deployment_environment(title) VALUES('production');

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use validator::Validate;

use crate::model::CdxBom;

#[derive(Serialize, Deserialize, FromRow)]
pub struct InsSbom {
    pub sbom: Option<CdxBom>,
    pub s3_uuid: Option<String>,
}

/**
 * The original SBOM can be in CycloneDx or SPDX format.
 * The enriched will be converted to CycloneDX and enriched with vulnerabilities.
 */
#[derive(Serialize, Deserialize, FromRow, Validate)]
pub struct EnSbom {
    pub id: i64,
    pub sbom_enriched: Option<sqlx::types::Json<CdxBom>>,
    pub sbom_original: Option<sqlx::types::Json<String>>, //sqlx::types::Json<serde_json::Value>,
    pub s3_uuid_enriched: Option<String>,
    pub s3_uuid_original: Option<String>,
}

impl EnSbom {
    pub fn validate_sbom_or_s3(&self) -> Result<(), (&str, Option<HashMap<String, String>>)> {
        if self.sbom_original.is_none() && self.s3_uuid_original.is_none() {
            return Err((&"original-sbom-required", None));
        }
        Ok(())
    }

    pub fn validate_and_get_message(&self, lang: &str) -> Result<(), String> {
        match crate::util::validate_entity(&self) {
            Ok(ok) => {}
            Err(validation_errors) => match validation_errors.first() {
                Some(validation_error) => {
                    return Err(crate::util::get_message(
                        lang,
                        &validation_error.0,
                        &validation_error.1,
                    ));
                }
                None => {}
            },
        }

        match self.validate_all() {
            Ok(_) => {}
            Err(validation_error) => {
                return Err(crate::util::get_message(
                    lang,
                    &validation_error.0,
                    &validation_error.1,
                ));
            }
        }
        Ok(())
    }

    pub fn validate_all(
        &self,
    ) -> Result<(), (&str, Option<std::collections::HashMap<String, String>>)> {
        self.validate_sbom_or_s3()?;
        Ok(())
    }
}
/*
pub article: sqlx::types::Json<String>,


    #[derive(Serialize, Deserialize, FromRow)]
    pub struct InsNewletterArticle {
        pub lang: String,
        pub newsletter_id: i32,
        pub article: TipTapJsonContent,
    }


    #[derive(Serialize, Deserialize, FromRow)]
    pub struct EnNewsletterArticle {
    pub id: i32,
        pub lang: String,
        pub newsletter_id: i32,
        pub article: sqlx::types::Json<String>,
        pub mod_date: Option<chrono::DateTime<chrono::Utc>>,
    pub created_date: chrono::DateTime<chrono::Utc>
    }


    pub async fn insert_new_page_article(tx: &mut Transaction<'static, Postgres>, new_page_article: &InsNewPageArticle) -> Result<i16, sqlx::Error> {
        let row: (i16,) = sqlx::query_as("INSERT INTO new_page_article(new_page_id,lang,article,title,desc_seo) VALUES ($1,$2,$3,$4,$5) returning id")
            .bind(new_page_article.new_page_id)
            .bind(&new_page_article.lang).bind(sqlx::types::Json(serde_json::to_string(&new_page_article.article).unwrap()))
            .bind(&new_page_article.title).bind(&new_page_article.desc_seo)
            .fetch_one(&mut **tx)
            .await?;

        Ok(row.0)
    }
 */

use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Serialize, Deserialize, FromRow)]
pub struct EnProductLine {
    pub id: i16,
    pub title: String
}

#[derive(Serialize, Deserialize, FromRow)]
pub struct EnProductLineProducts {
    pub id: i16,
    pub title: String,
    pub products: Vec<EnProduct>
}

#[derive(Serialize, Deserialize, FromRow)]
pub struct EnProduct {
    pub id: i16,
    pub title: String,
    pub product_line_id: i16
}


#[derive(Serialize, Deserialize, FromRow)]
pub struct FromQueryProductLineProduct {
    pub pl_id: i16,
    pub pl_title: String,
    pub p_id: Option<i16>,
    pub p_title: Option<String>,
    pub p_product_line_id: Option<i16>
}

pub fn map_product_line(items: Vec<FromQueryProductLineProduct>) -> Vec<EnProductLineProducts> {
    let mut product_lines: Vec<EnProductLineProducts> = vec![];

    for res in items
    {
        match product_lines.iter_mut().find(|pl| pl.id == res.pl_id) {
            Some(_product_line) => { },
            None => {
                let product_line: EnProductLineProducts = EnProductLineProducts {
                    id: res.pl_id,
                    title: res.pl_title,
                    products: vec![],
                };
                product_lines.push(product_line);
            }
        };

        if let Some(p_id) = res.p_id {
            if let Some(p_title) = res.p_title {
                if let Some(p_product_line_id) = res.p_product_line_id {
                    if let Some(product_line) = product_lines.iter_mut().find(|pl| pl.id == res.pl_id) {
                        product_line.products.push(EnProduct {
                            id: p_id,
                            title: p_title,
                            product_line_id: p_product_line_id
                        });
                    };
                };
            };
        };
    }

    product_lines.sort_by(|a, b| a.title.cmp(&b.title));
    product_lines
}

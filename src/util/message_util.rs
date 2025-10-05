use std::{collections::HashMap};

use fluent::FluentArgs;
use fluent_resmgr::ResourceManager;
use unic_langid::LanguageIdentifier;
//type fluent::concurrent::FluentBundle;

//pub static MGR: ResourceManager = fluent_resmgr::resource_manager::ResourceManager::new("./resources/{locale}/{res_id}".into());

pub fn get_message(lang: &str, message_key: &str, error_params_opt: &Option<HashMap<String,String>>) -> String
{
    let mut error_params_fluent = FluentArgs::new();
    let error_params_fluent = match error_params_opt {
        Some(error_params) => {
            for (key, value) in error_params {
                error_params_fluent.set(key, value);
            }
            Some(&error_params_fluent)
        },
        None => None,
    };
    
    let li: LanguageIdentifier = if !lang.eq("fr") && !lang.eq("en") && !lang.eq("nl") {
        "en".parse().expect("Parsing failed.")
    } else {
        lang.parse().expect("Parsing failed.")
    };

    let mgr: ResourceManager = fluent_resmgr::resource_manager::ResourceManager::new("./resources/{locale}/{res_id}".into());

    match mgr.get_bundle(vec![li], vec![String::from("messages.ftl")])
    {
        Ok(bundle) => {
            let msg = match bundle.get_message(message_key) {
                Some(m) => m,
                None => {
                    let mut err = "".to_owned();
                    err.push_str(message_key);
                    err.push_str(" does not exist");
                    return err.to_string();
                },
            };
        
            let pattern = msg.value()
                .expect("Message has no value.");
        
            let mut errors = vec![];
            let trad = bundle.format_pattern(pattern, error_params_fluent, &mut errors);
            trad.to_string()
        },
        Err(errs) => {
            let mut errors: Vec<String> = vec![];
            for err in errs {
                errors.push(err.to_string());
            }
            let errors_str = String::from_iter(errors);

            tracing::error!("message_util get_message {}", errors_str);
            String::from("An internal error occurs")
        }
    }

    //let langid_en = langid!("en-US");
    //let mut bundle: FluentBundle<FluentResource, _> = FluentBundle::new_concurrent(vec![li]);
    
}


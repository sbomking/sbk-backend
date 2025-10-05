use std::collections::HashMap;
use validator::{Validate, ValidationError, ValidationErrors, ValidationErrorsKind};
use crate::util::get_message;

/**
 * Use validator validate macro.
 * Return list of error translated.
 */
pub fn validate_entity<T: Validate>(entity: &T, lang: &str) -> Vec<String>
{
    let mut error_msgs: Vec<String> = vec![];
    match entity.validate() {
        Ok(_) => (),
        Err(validation_errors) => {
            validate_entity_recursive(&validation_errors, lang, &mut error_msgs);   
        }
    };

    error_msgs
}

/**
 * Recursive must never be inline!!!
 */
#[inline(never)]
pub fn validate_entity_recursive(validation_errors: &ValidationErrors, 
    lang: &str, error_msgs: &mut Vec<String>)
{
    for value in validation_errors.errors().values()
    {
        match value {
            ValidationErrorsKind::Field(fields) => {
                for val in fields {
                    error_msgs.push(validate_entity_recursive_impl(val, lang));
                }
            }
            ValidationErrorsKind::Struct(validation_errors) => {
                validate_entity_recursive(validation_errors, lang, error_msgs);
            },
            ValidationErrorsKind::List(btree_map) => {
                for validation_errors in btree_map.values() {
                    validate_entity_recursive(validation_errors, lang, error_msgs);
                }
            },
        }
    }
}

/**
 * TODO implement more type of error!!!
 * Only range and length are implemented for the moment!
 */
pub fn validate_entity_recursive_impl(val: &ValidationError, lang: &str) -> String
{
    let mut error_msg = String::from("");
    let mut args: HashMap<String,String> = HashMap::new();
    if &val.code == "range"
    {
        if let Some(min_opt) = val.params.get("min") {
            args.insert("min".to_owned(), min_opt.to_string());
        };
        if let Some(max_opt) = val.params.get("max") {
            args.insert("max".to_owned(), max_opt.to_string());  
        };
    }
    else if &val.code == "length" {
        if let Some(equal_opt) = val.params.get("equal") {
            args.insert("equal".to_owned(), equal_opt.to_string());
        }
        else {
            if let Some(min_opt) = val.params.get("min") {
                args.insert("min".to_owned(), min_opt.to_string());
            };
            if let Some(max_opt) = val.params.get("max") {
                args.insert("max".to_owned(), max_opt.to_string());
            };
        }    
    }
    /*
    else if let Some(min_opt) = val.params.get("equal") {
        if let Some(min) = min_opt.as_str() {  {
            if let Some(message_key) = &val.message/*.as_ref()*/ {
                let mut args = FluentArgs::new();
                args.set("equal", min);
                error_msg = get_message(&lang, &message_key, Some(&args), &mgr);
            };
        };};
    };}
     */
    if let Some(message_key) = &val.message.as_ref() {    
        error_msg = get_message(lang, message_key, &Some(args));
    };

    error_msg
}


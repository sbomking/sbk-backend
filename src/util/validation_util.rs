use crate::util::get_message;
use std::collections::HashMap;
use validator::{Validate, ValidationError, ValidationErrors, ValidationErrorsKind};

/**
 * Use validator validate macro.
 * Return list of error translated.
 */
pub fn validate_entity<T: Validate>(
    entity: &T,
) -> Result<(), Vec<(String, Option<HashMap<String, String>>)>> {
    let mut error_msgs: Vec<(String, Option<HashMap<String, String>>)> = vec![];
    match entity.validate() {
        Ok(_) => Ok(()),
        Err(validation_errors) => {
            validate_entity_recursive(&validation_errors, &mut error_msgs);
            Err(error_msgs)
        }
    }
}

/**
 * Recursive must never be inline!!!
 */
#[inline(never)]
pub fn validate_entity_recursive(
    validation_errors: &ValidationErrors,
    error_msgs: &mut Vec<(String, Option<HashMap<String, String>>)>,
) {
    for value in validation_errors.errors().values() {
        match value {
            ValidationErrorsKind::Field(fields) => {
                for val in fields {
                    match validate_entity_recursive_impl(val) {
                        Ok(()) => {}
                        Err(err) => error_msgs.push(err),
                    }
                }
            }
            ValidationErrorsKind::Struct(validation_errors) => {
                validate_entity_recursive(validation_errors, error_msgs);
            }
            ValidationErrorsKind::List(btree_map) => {
                for validation_errors in btree_map.values() {
                    validate_entity_recursive(validation_errors, error_msgs);
                }
            }
        }
    }
}

/**
 * TODO implement more type of error!!!
 * Only range and length are implemented for the moment!
 */
pub fn validate_entity_recursive_impl(
    val: &ValidationError,
) -> Result<(), (String, Option<HashMap<String, String>>)> {
    let mut args: HashMap<String, String> = HashMap::new();
    if &val.code == "range" {
        if let Some(min_opt) = val.params.get("min") {
            args.insert("min".to_owned(), min_opt.to_string());
        };
        if let Some(max_opt) = val.params.get("max") {
            args.insert("max".to_owned(), max_opt.to_string());
        };
    } else if &val.code == "length" {
        if let Some(equal_opt) = val.params.get("equal") {
            args.insert("equal".to_owned(), equal_opt.to_string());
        } else {
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
        //error_msg = get_message(lang, message_key, &Some(args));
        return Err((message_key.to_string(), Some(args)));
    };

    Ok(())
}

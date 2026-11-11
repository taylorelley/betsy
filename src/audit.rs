//! A read-only report on the weakness cards: what each language is asked, which cards are asked
//! of every function, and where the cards are inconsistent or thin. Nothing here calls a model.
use crate::weakness::{self, Role, Selection, Status};
use anyhow::Result;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// The languages cards can be planned for.
pub const LANGUAGES: [&str; 7] = weakness::LANGUAGES;

fn status_name(status: Status) -> &'static str {
    match status {
        Status::Draft => "draft",
        Status::Reviewed => "reviewed",
        Status::Validated => "validated",
    }
}

/// Audits the embedded cards. `errors` lists defects that should fail a build; everything else
/// describes coverage and consistency so gaps can be seen and tracked.
pub fn audit() -> Result<Value> {
    let cat = weakness::catalog();
    let traits = weakness::traits();
    let syntax = traits.syntax_mask();
    let mut errors: Vec<Value> = vec![];
    let mut error = |check: &str, id: &str, detail: String| {
        errors.push(json!({"check":check,"id":id,"detail":detail}));
    };

    let mut by_catalog = BTreeMap::<&str, usize>::new();
    let mut by_status = BTreeMap::<&str, usize>::new();
    for w in &cat.entries {
        *by_catalog.entry(w.catalog.as_str()).or_default() += 1;
        *by_status.entry(status_name(w.status)).or_default() += 1;
    }

    let mut languages = BTreeMap::new();
    let mut planned_anywhere = BTreeSet::new();
    let mut gate_anywhere = BTreeSet::new();
    let mut planned_in = BTreeMap::<&str, Vec<&str>>::new();
    for language in LANGUAGES {
        let plan = weakness::plan(language, &Selection::default())?;
        let mut findings_by_catalog = BTreeMap::<&str, usize>::new();
        let (mut always, mut syntax_settled, mut trait_reachable) = (vec![], 0usize, 0usize);
        let (mut general_only, mut sometimes_root) = (0usize, vec![]);
        for n in &plan.nodes {
            let w = cat.get(&n.id).expect("planned card exists");
            planned_anywhere.insert(w.id.as_str());
            planned_in.entry(w.id.as_str()).or_default().push(language);
            if n.role == Role::Gate {
                gate_anywhere.insert(w.id.as_str());
            } else {
                *findings_by_catalog.entry(w.catalog.as_str()).or_default() += 1;
            }
            for (field, patterns) in [
                ("present_when", &w.present_when),
                ("not_present_when", &w.not_present_when),
            ] {
                if weakness::patterns_for(patterns, language).is_empty() {
                    error(
                        "no_pattern_for_language",
                        &w.id,
                        format!("{field} has nothing {language} reads"),
                    );
                }
            }
            let specific = [&w.present_when, &w.not_present_when].iter().any(|p| {
                weakness::patterns_for(p, language).len() > p.get("any").map_or(0, Vec::len)
            });
            general_only += usize::from(!specific);
            if n.parent.is_none() && !w.parents.is_empty() {
                sometimes_root.push(w.id.as_str());
            }
            if n.wave == 1 {
                match n.requires {
                    // Asked of every function: nothing can rule it out beforehand.
                    None if n.role == Role::Finding => always.push(w.id.as_str()),
                    None => {}
                    Some(mask) if mask & !syntax == 0 => syntax_settled += 1,
                    Some(_) => trait_reachable += 1,
                }
            }
            if let Some(mask) = n.requires {
                // A requirement made only of syntax traits that list no node kinds for this
                // language can never be settled here, so it filters nothing.
                let decidable = traits.traits.iter().enumerate().any(|(i, t)| {
                    mask & (1 << i) != 0 && (!t.syntax || t.present_if.contains_key(language))
                });
                if !decidable && !w.requires.is_empty() {
                    error(
                        "requirement_never_settles",
                        &w.id,
                        format!(
                            "requires {:?}, none of which {language} can settle",
                            w.requires
                        ),
                    );
                }
            }
        }
        languages.insert(
            language,
            json!({
                "planned": plan.nodes.len(),
                "findings": plan.findings(),
                "gates": plan.nodes.len() - plan.findings(),
                "findings_by_catalog": findings_by_catalog,
                "roots": plan.roots.len(),
                "rounds": plan.depth(),
                "round1": {
                    "questions": plan.first_wave(),
                    "settled_by_parser": syntax_settled,
                    "prunable_with_traits": trait_reachable,
                    "always_asked_findings": always,
                },
                "roots_whose_parents_are_not_planned": sometimes_root,
                "cards_with_only_general_patterns": general_only,
            }),
        );
    }

    let (mut one_way, mut links, mut no_distinguish) = (0usize, 0usize, 0usize);
    let (mut unsourced, mut detached, mut restricted_general) = (vec![], vec![], vec![]);
    for w in &cat.entries {
        if w.gate && w.function_checkable && !gate_anywhere.contains(w.id.as_str()) {
            error(
                "gate_never_planned",
                &w.id,
                "no language has a checkable card beneath this gate".into(),
            );
        }
        if w.function_checkable && !planned_anywhere.contains(w.id.as_str()) && !w.gate {
            error(
                "card_never_planned",
                &w.id,
                "checkable, but no language plans it".into(),
            );
        }
        if !w.detached.is_empty() {
            detached.push(w.id.as_str());
        }
        if w.catalog != "security" && w.sources.is_empty() {
            unsourced.push(w.id.as_str());
        }
        for (base, superset) in [
            ("javascript", "typescript"),
            ("javascript", "tsx"),
            ("typescript", "tsx"),
        ] {
            let has = |l: &str| w.languages.iter().any(|x| x == l);
            if has(base) && !has(superset) {
                error(
                    "language_superset_gap",
                    &w.id,
                    format!("applies to {base} but not {superset}, which accepts the same code"),
                );
            }
        }
        if !w.function_checkable {
            continue;
        }
        let general = |p: &weakness::Patterns| p.keys().all(|k| k == "any");
        if !w.languages.is_empty() && general(&w.present_when) && general(&w.not_present_when) {
            restricted_general.push(w.id.as_str());
        }
        no_distinguish += usize::from(w.distinguish_from.is_empty());
        let mine = planned_in.get(w.id.as_str());
        for other in w.distinguish_from.keys() {
            links += 1;
            let o = cat.get(other).expect("validated when loaded");
            one_way += usize::from(o.function_checkable && !o.distinguish_from.contains_key(&w.id));
            let shared = mine.is_some_and(|m| {
                planned_in
                    .get(o.id.as_str())
                    .is_some_and(|theirs| m.iter().any(|l| theirs.contains(l)))
            });
            if o.function_checkable && planned_in.contains_key(o.id.as_str()) && !shared {
                error(
                    "distinguish_without_shared_language",
                    &w.id,
                    format!("{other} is never planned for a language this card is planned for"),
                );
            }
        }
    }
    let trait_cards = |key: &str| {
        cat.entries
            .iter()
            .filter(|w| w.requires.iter().any(|k| k == key))
            .count()
    };
    let trait_use: Vec<Value> = traits
        .traits
        .iter()
        .map(|t| json!({"key":t.key,"syntax":t.syntax,"cards":trait_cards(&t.key)}))
        .collect();
    let checkable = cat.entries.iter().filter(|w| w.function_checkable).count();
    Ok(json!({
        "catalog_hash": cat.hash,
        "profile": weakness::PROFILE,
        "cards": {
            "total": cat.entries.len(),
            "checkable": checkable,
            "not_function_checkable": cat.entries.len() - checkable,
            "gates": cat.entries.iter().filter(|w| w.gate).count(),
            "by_catalog": by_catalog,
            "by_status": by_status,
            "detached": detached,
            "without_sources": unsourced,
            // Limited to some languages although every pattern is language-neutral: the limit
            // may be narrower than the weakness.
            "restricted_with_only_general_patterns": restricted_general,
        },
        "distinguish_from": {
            "links": links,
            "one_way": one_way,
            "checkable_cards_with_none": no_distinguish,
        },
        "traits": trait_use,
        "languages": languages,
        "errors": errors,
    }))
}

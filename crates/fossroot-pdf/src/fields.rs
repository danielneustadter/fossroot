//! Read-only enumeration of AcroForm signature fields.

use lopdf::{Document, Object, ObjectId};
use serde::Serialize;

use crate::{Error, Result};

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SigField {
    /// Fully-qualified field name (parent names joined with '.').
    pub name: String,
    /// 1-based page the field's widget appears on (0 if not placed on a page).
    pub page: u32,
    /// Widget rectangle [x0, y0, x1, y1] in PDF points (empty if none).
    pub rect: Vec<f32>,
    /// True if the field already carries a signature (`/V` present).
    pub signed: bool,
}

/// Parse `pdf` and return every AcroForm signature field.
pub fn enumerate(pdf: &[u8]) -> Result<Vec<SigField>> {
    let doc = Document::load_mem(pdf).map_err(|e| Error::Pdf(e.to_string()))?;
    let page_of = build_widget_page_index(&doc);

    let acroform = match doc
        .catalog()
        .ok()
        .and_then(|c| c.get(b"AcroForm").ok())
        .and_then(|o| resolve_dict(&doc, o))
    {
        Some(a) => a,
        None => return Ok(Vec::new()),
    };
    let Ok(Object::Array(fields)) = acroform.get(b"Fields") else {
        return Ok(Vec::new());
    };

    let mut out = Vec::new();
    for f in fields {
        if let Object::Reference(id) = f {
            walk_field(&doc, *id, None, &page_of, &mut out);
        }
    }
    Ok(out)
}

/// Recursively walk a field and its `/Kids`, collecting `/FT /Sig` terminals.
fn walk_field(
    doc: &Document,
    id: ObjectId,
    inherited_name: Option<&str>,
    page_of: &PageIndex,
    out: &mut Vec<SigField>,
) {
    let Ok(dict) = doc.get_dictionary(id) else {
        return;
    };
    let partial = dict
        .get(b"T")
        .ok()
        .and_then(|o| o.as_str().ok())
        .map(|s| String::from_utf8_lossy(s).into_owned());
    let full_name = match (inherited_name, &partial) {
        (Some(parent), Some(p)) => format!("{parent}.{p}"),
        (None, Some(p)) => p.clone(),
        (Some(parent), None) => parent.to_string(),
        (None, None) => String::new(),
    };

    // Field type may be inherited; check this dict, else treat kids.
    let ft = dict.get(b"FT").ok().and_then(|o| o.as_name().ok());
    let is_sig = ft == Some(b"Sig".as_ref());

    if let Ok(Object::Array(kids)) = dict.get(b"Kids") {
        for k in kids {
            if let Object::Reference(kid) = k {
                walk_field(doc, *kid, Some(&full_name), page_of, out);
            }
        }
        return;
    }

    if is_sig {
        let rect = dict
            .get(b"Rect")
            .ok()
            .and_then(|o| o.as_array().ok())
            .map(|a| a.iter().filter_map(number_f32).collect::<Vec<_>>())
            .unwrap_or_default();
        let signed = dict.get(b"V").is_ok();
        let page = page_of.get(doc, id, dict);
        out.push(SigField {
            name: full_name,
            page,
            rect,
            signed,
        });
    }
}

/// Index for resolving which page a widget sits on. Holds both an
/// annotation-id → page map (from each page's `/Annots`) and a page-object-id →
/// page-number map (so a widget's own `/P` reference can be resolved).
struct PageIndex {
    by_annot: std::collections::HashMap<ObjectId, u32>,
    by_page_obj: std::collections::HashMap<ObjectId, u32>,
}

impl PageIndex {
    fn get(&self, doc: &Document, field_id: ObjectId, dict: &lopdf::Dictionary) -> u32 {
        // Prefer the widget's explicit /P page reference.
        if let Ok(Object::Reference(p)) = dict.get(b"P") {
            if let Some(n) = self.by_page_obj.get(p) {
                return *n;
            }
        }
        if let Some(n) = self.by_annot.get(&field_id) {
            return *n;
        }
        // Single-page documents: everything is on page 1.
        if self.by_page_obj.len() == 1 {
            return 1;
        }
        let _ = doc;
        0
    }
}

fn build_widget_page_index(doc: &Document) -> PageIndex {
    let mut by_annot = std::collections::HashMap::new();
    let mut by_page_obj = std::collections::HashMap::new();
    for (num, page_id) in doc.get_pages() {
        by_page_obj.insert(page_id, num);
        let Ok(page) = doc.get_dictionary(page_id) else {
            continue;
        };
        if let Ok(Object::Array(annots)) = page.get(b"Annots") {
            for a in annots {
                if let Object::Reference(id) = a {
                    by_annot.insert(*id, num);
                }
            }
        }
    }
    PageIndex {
        by_annot,
        by_page_obj,
    }
}

fn resolve_dict<'a>(doc: &'a Document, obj: &'a Object) -> Option<&'a lopdf::Dictionary> {
    match obj {
        Object::Dictionary(d) => Some(d),
        Object::Reference(id) => doc.get_dictionary(*id).ok(),
        _ => None,
    }
}

fn number_f32(o: &Object) -> Option<f32> {
    match o {
        Object::Integer(i) => Some(*i as f32),
        Object::Real(r) => Some(*r),
        _ => None,
    }
}

/// True if the document has at least one signature field.
pub fn has_signature_field(pdf: &[u8]) -> bool {
    enumerate(pdf).map(|v| !v.is_empty()).unwrap_or(false)
}

/// Look up a single field by fully-qualified name.
pub fn find(pdf: &[u8], name: &str) -> Result<SigField> {
    enumerate(pdf)?
        .into_iter()
        .find(|f| f.name == name)
        .ok_or_else(|| Error::FieldNotFound(name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lopdf::{dictionary, Document, Object};

    /// Build a minimal one-page PDF with a single AcroForm signature field, so
    /// enumeration is tested in CI without shipping a binary fixture.
    fn minimal_pdf_with_sig_field(name: &str) -> Vec<u8> {
        let mut doc = Document::with_version("1.7");
        let pages_id = doc.new_object_id();
        let field_id = doc.new_object_id();
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
            "Annots" => vec![field_id.into()],
        });
        doc.set_object(
            field_id,
            dictionary! {
                "Type" => "Annot",
                "Subtype" => "Widget",
                "FT" => "Sig",
                "T" => Object::string_literal(name),
                "Rect" => vec![72.into(), 700.into(), 300.into(), 740.into()],
                "P" => page_id,
            },
        );
        doc.set_object(
            pages_id,
            dictionary! { "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1 },
        );
        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
            "AcroForm" => dictionary! { "Fields" => vec![field_id.into()], "SigFlags" => 3 },
        });
        doc.trailer.set("Root", catalog_id);
        let mut buf = Vec::new();
        doc.save_to(&mut buf).unwrap();
        buf
    }

    #[test]
    fn enumerates_a_generated_sig_field() {
        let pdf = minimal_pdf_with_sig_field("Signature1");
        let fields = enumerate(&pdf).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "Signature1");
        assert_eq!(fields[0].page, 1);
        assert!(!fields[0].signed);
        assert_eq!(fields[0].rect, vec![72.0, 700.0, 300.0, 740.0]);
        assert!(has_signature_field(&pdf));
        assert!(find(&pdf, "Signature1").is_ok());
        assert!(find(&pdf, "Nope").is_err());
    }

    #[test]
    fn no_acroform_yields_empty() {
        let mut doc = Document::with_version("1.7");
        let pages_id = doc.add_object(
            dictionary! { "Type" => "Pages", "Kids" => Vec::<Object>::new(), "Count" => 0 },
        );
        let cat = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", cat);
        let mut buf = Vec::new();
        doc.save_to(&mut buf).unwrap();
        assert!(enumerate(&buf).unwrap().is_empty());
        assert!(!has_signature_field(&buf));
    }
}

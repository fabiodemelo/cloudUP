//! "About CloudUp" (macOS): the standard About panel, with a credits line
//! "Powered by demelos LLC" linking to demelos.com.

use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2::{AllocAnyThread, MainThreadMarker};
use objc2_app_kit::{NSAboutPanelOptionCredits, NSApplication};
use objc2_foundation::{NSAttributedString, NSData, NSDictionary, NSString};

const CREDITS_HTML: &str = r#"<div style="text-align:center;font-family:-apple-system;font-size:11px;color:#86868b">
Powered by <a href="https://www.demelos.com">demelos LLC</a></div>"#;

/// Show the About panel. Must run on the main thread.
pub fn show() {
    let Some(mtm) = MainThreadMarker::new() else { return };
    let app = NSApplication::sharedApplication(mtm);
    let data = NSData::with_bytes(CREDITS_HTML.as_bytes());
    let credits: Option<Retained<NSAttributedString>> = unsafe {
        objc2_app_kit::NSAttributedStringAppKitDocumentFormats::initWithHTML_documentAttributes(
            NSAttributedString::alloc(),
            &data,
            None,
        )
    };
    let Some(credits) = credits else {
        app.orderFrontStandardAboutPanel(None);
        return;
    };
    let key: &NSString = unsafe { NSAboutPanelOptionCredits };
    let value: &AnyObject = &credits;
    let options = NSDictionary::from_slices(&[key], &[value]);
    unsafe { app.orderFrontStandardAboutPanelWithOptions(&options) };
    #[allow(deprecated)]
    app.activateIgnoringOtherApps(true);
}

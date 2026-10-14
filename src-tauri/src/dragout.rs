//! Drag files out of the in-app browser into Finder (macOS).
//!
//! Uses AppKit file promises (`NSFilePromiseProvider`): the drag starts
//! immediately, and only when the user drops does macOS ask us to write the
//! file at the chosen place. We then download it from the cloud (folders are
//! downloaded recursively). Downloads run on a background queue, so the app
//! stays responsive; Finder shows its own progress while it waits.

use std::path::{Path, PathBuf};

use block2::DynBlock;
use objc2::rc::Retained;
use objc2::runtime::{NSObject, NSObjectProtocol, ProtocolObject};
use objc2::{define_class, msg_send, AllocAnyThread, DefinedClass, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSApplication, NSDragOperation, NSDraggingContext, NSDraggingItem, NSDraggingSession,
    NSDraggingSource, NSFilePromiseProvider, NSFilePromiseProviderDelegate, NSWindow, NSWorkspace,
};
use objc2_foundation::{NSArray, NSError, NSOperationQueue, NSPoint, NSRect, NSSize, NSString, NSURL};

use crate::backend::Backend;

/// One thing being dragged out.
#[derive(Clone, serde::Deserialize)]
pub struct DragItem {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
}

pub struct Ivars {
    backend: Backend,
    item: DragItem,
    queue: Retained<NSOperationQueue>,
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements; we don't implement Drop.
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "CloudUpDragPromise"]
    #[ivars = Ivars]
    struct Promise;

    unsafe impl NSObjectProtocol for Promise {}

    unsafe impl NSFilePromiseProviderDelegate for Promise {
        #[unsafe(method_id(filePromiseProvider:fileNameForType:))]
        fn file_name(&self, _p: &NSFilePromiseProvider, _t: &NSString) -> Retained<NSString> {
            NSString::from_str(&self.ivars().item.name)
        }

        #[unsafe(method(filePromiseProvider:writePromiseToURL:completionHandler:))]
        fn write(&self, _p: &NSFilePromiseProvider, url: &NSURL, done: &DynBlock<dyn Fn(*mut NSError)>) {
            let ok = match url.path() {
                Some(dest) => {
                    let iv = self.ivars();
                    let dest = PathBuf::from(dest.to_string());
                    tauri::async_runtime::block_on(fetch(&iv.backend, &iv.item, &dest))
                        .map_err(|e| eprintln!("cloudup drag-out {}: {e}", iv.item.path))
                        .is_ok()
                }
                None => false,
            };
            if ok {
                done.call((std::ptr::null_mut(),));
            } else {
                let domain = NSString::from_str("net.cloudup.drag");
                let err = NSError::new(1, &domain);
                done.call((Retained::as_ptr(&err) as *mut NSError,));
            }
        }

        // Download off the main thread (the default queue is the main one).
        #[unsafe(method_id(operationQueueForFilePromiseProvider:))]
        fn queue(&self, _p: &NSFilePromiseProvider) -> Retained<NSOperationQueue> {
            self.ivars().queue.clone()
        }
    }

    unsafe impl NSDraggingSource for Promise {
        #[unsafe(method(draggingSession:sourceOperationMaskForDraggingContext:))]
        fn mask(&self, _s: &NSDraggingSession, _c: NSDraggingContext) -> NSDragOperation {
            NSDragOperation::Copy
        }
    }
);

async fn fetch(backend: &Backend, item: &DragItem, dest: &Path) -> Result<(), String> {
    backend.download_tree(&item.path, item.is_dir, dest).await
}

/// Start a native drag of `items` from `ns_window`. Must run on the main
/// thread while the mouse button is still down (called from the page's
/// `dragstart`).
pub fn start(ns_window: *mut std::ffi::c_void, backend: Backend, items: Vec<DragItem>) -> Result<(), String> {
    let mtm = MainThreadMarker::new().ok_or("not on the main thread")?;
    let window: &NSWindow = unsafe { &*(ns_window as *const NSWindow) };
    let view = window.contentView().ok_or("no content view")?;
    let app = NSApplication::sharedApplication(mtm);
    let event = app.currentEvent().ok_or("no current mouse event")?;
    let at: NSPoint = view.convertPoint_fromView(event.locationInWindow(), None);

    let queue = NSOperationQueue::new();
    let ws = NSWorkspace::sharedWorkspace();
    let mut drag_items = Vec::new();
    let mut source: Option<Retained<Promise>> = None;
    for (i, item) in items.into_iter().enumerate() {
        let file_type = if item.is_dir { "public.folder" } else { "public.data" };
        let icon = if item.is_dir {
            ws.iconForFileType(&NSString::from_str("public.folder"))
        } else {
            let ext = item.name.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
            ws.iconForFileType(&NSString::from_str(ext))
        };
        let delegate = Promise::alloc(mtm).set_ivars(Ivars { backend: backend.clone(), item, queue: queue.clone() });
        let delegate: Retained<Promise> = unsafe { msg_send![super(delegate), init] };
        let provider = NSFilePromiseProvider::initWithFileType_delegate(
            NSFilePromiseProvider::alloc(),
            &NSString::from_str(file_type),
            ProtocolObject::from_ref(&*delegate),
        );
        let drag = NSDraggingItem::initWithPasteboardWriter(NSDraggingItem::alloc(), ProtocolObject::from_ref(&*provider));
        let off = 8.0 * i as f64;
        let frame = NSRect::new(NSPoint::new(at.x - 24.0 + off, at.y - 24.0 - off), NSSize::new(48.0, 48.0));
        unsafe { drag.setDraggingFrame_contents(frame, Some(&icon)) };
        drag_items.push(drag);
        // The provider keeps a weak delegate: keep each one alive for the
        // whole drag by leaking it (a few bytes per drag).
        std::mem::forget(delegate.clone());
        std::mem::forget(provider);
        source.get_or_insert(delegate);
    }
    let source = source.ok_or("nothing to drag")?;
    let array = NSArray::from_retained_slice(&drag_items);
    view.beginDraggingSessionWithItems_event_source(&array, &event, ProtocolObject::from_ref(&*source));
    Ok(())
}

/* Stub libfuse for builds on machines without macFUSE/osxfuse.
 * fuser 0.15 (fuser_mount_impl="libfuse2") needs exactly one symbol at link
 * time: fuse_mount_compat25, called only from Mount::new (i.e. when the user
 * actually mounts). The stub fails that call cleanly (fd -1 -> Err) so the
 * app still ships and works for browsing; mounting requires macFUSE at runtime.
 */
int fuse_mount_compat25(const char *mp, void *args) { (void)mp; (void)args; return -1; }

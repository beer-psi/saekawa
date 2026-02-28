pub mod winapi_ext;

#[must_use = "Defer MUST be bound to a variable, otherwise it will be dropped immediately"]
pub struct Defer<T: FnOnce()>(Option<T>);

impl<T: FnOnce()> Defer<T> {
    pub fn new(deferred: T) -> Self {
        Self(Some(deferred))
    }
}

impl<T: FnOnce()> Drop for Defer<T> {
    fn drop(&mut self) {
        // This is safe, as there is no way to have a `Defer` struct containing a `None` value
        unsafe { (self.0.take().unwrap_unchecked())() }
    }
}

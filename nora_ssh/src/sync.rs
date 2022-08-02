use core::{
	cell::{Cell, RefCell, RefMut},
	future::Future,
	ops::{Deref, DerefMut},
	pin::Pin,
	task::{Context, Poll, Waker},
};

pub struct LocalMutex<T> {
	inner: RefCell<T>,
	queue: Cell<Vec<Waker>>,
}

impl<T> LocalMutex<T> {
	pub fn new(value: T) -> Self {
		Self { inner: RefCell::new(value), queue: Cell::new(Vec::new()) }
	}

	pub fn lock(&self) -> LocalMutexGuardFuture<'_, T> {
		LocalMutexGuardFuture { inner: self, registered: false }
	}

	fn push_waker(&self, waker: Waker) {
		let mut q = self.queue.take();
		q.push(waker);
		self.queue.set(q);
	}

	fn pop_waker(&self) -> Option<Waker> {
		let mut q = self.queue.take();
		let w = q.pop();
		self.queue.set(q);
		w
	}
}

pub struct LocalMutexGuardFuture<'a, T> {
	inner: &'a LocalMutex<T>,
	registered: bool,
}

impl<'a, T> Future for LocalMutexGuardFuture<'a, T> {
	type Output = LocalMutexGuard<'a, T>;

	fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		match self.inner.inner.try_borrow_mut() {
			Ok(lock) => Poll::Ready(LocalMutexGuard { inner: self.inner, lock }),
			Err(_) => {
				if !self.registered {
					self.inner.push_waker(cx.waker().clone());
					self.registered = true;
				}
				Poll::Pending
			}
		}
	}
}

pub struct LocalMutexGuard<'a, T> {
	inner: &'a LocalMutex<T>,
	lock: RefMut<'a, T>,
}

impl<'a, T> Deref for LocalMutexGuard<'a, T> {
	type Target = T;

	fn deref(&self) -> &Self::Target {
		self.lock.deref()
	}
}

impl<'a, T> DerefMut for LocalMutexGuard<'a, T> {
	fn deref_mut(&mut self) -> &mut Self::Target {
		self.lock.deref_mut()
	}
}

impl<'a, T> Drop for LocalMutexGuard<'a, T> {
	fn drop(&mut self) {
		self.inner.pop_waker().map(|w| w.wake());
	}
}

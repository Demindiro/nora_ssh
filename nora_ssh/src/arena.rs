pub struct Arena<T>(Vec<Option<T>>);

impl<T> Arena<T> {
	pub fn new() -> Self {
		Self(Vec::new())
	}

	pub fn insert(&mut self, value: T) -> u32 {
		if let Some((i, v)) = self.0.iter_mut().enumerate().find(|v| v.1.is_none()) {
			*v = Some(value);
			i
		} else {
			self.0.push(Some(value));
			self.0.len() - 1
		}
		.try_into()
		.unwrap()
	}

	pub fn remove(&mut self, i: u32) -> Option<T> {
		self.0
			.get_mut(usize::try_from(i).unwrap())
			.map(Option::take)
			.flatten()
	}

	pub fn get_mut(&mut self, i: u32) -> Option<&mut T> {
		self.0
			.get_mut(usize::try_from(i).unwrap())
			.map(Option::as_mut)
			.flatten()
	}
}

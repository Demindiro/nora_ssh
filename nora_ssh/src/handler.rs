use core::future::Future;

// Based on the Handler trait in actix_web.
// It's alot nicer than the soup that is:
//
//     fn blah<F, Ffut, Fret, ...>(..)
//     where
//         F: Fn(A, B) -> Ffut
//         Ffut: Future<Output = Fret>
//
// times a billion
pub trait Handler<Args> {
    type Output;
    type Future: Future<Output = Self::Output>;
    fn call(&self, args: Args) -> Self::Future;
}

macro_rules! impl_handler {
    ($($arg:ident)*) => {
        impl<Func, Fut, $($arg,)*> Handler<($($arg,)*)> for Func
        where
            Func: Fn($($arg,)*) -> Fut,
            Fut: Future,
        {
            type Output = Fut::Output;
            type Future = Fut;

            #[allow(non_snake_case)]
            fn call(&self, ($($arg,)*): ($($arg,)*)) -> Self::Future {
                (self)($($arg,)*)
            }
        }
    };
}

impl_handler!();
impl_handler!(A);
impl_handler!(A B);
impl_handler!(A B C);
impl_handler!(A B C D);
impl_handler!(A B C D E);
impl_handler!(A B C D E F);
impl_handler!(A B C D E F G);
impl_handler!(A B C D E F G H);
impl_handler!(A B C D E F G H I);
impl_handler!(A B C D E F G H I J);
impl_handler!(A B C D E F G H I J K);

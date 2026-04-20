//! Async TLS streams backed by BoringSSL.
//!
//! This crate provides a wrapper around the [`btls`] crate's [`SslStream`](ssl::SslStream) type
//! that works with with [`tokio`]'s [`AsyncRead`] and [`AsyncWrite`] traits rather than std's
//! blocking [`Read`] and [`Write`] traits.
//!
//! This file reimplements tokio-btls with the [overhauled](https://github.com/sfackler/tokio-openssl/commit/56f6618ab619f3e431fa8feec2d20913bf1473aa)
//! tokio-openssl interface while the tokio APIs from official [boring](https://github.com/cloudflare/boring) crate is not yet caught up
//! to it.

use std::{
    fmt, future,
    io::{self, Read, Write},
    pin::Pin,
    task::{Context, Poll},
};

use btls::{
    error::ErrorStack,
    ssl::{self, ErrorCode, ShutdownResult, Ssl, SslRef, SslStream as SslStreamCore},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct StreamWrapper<S> {
    stream: S,
    context: usize,
}

impl<S> fmt::Debug for StreamWrapper<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.stream, fmt)
    }
}

impl<S> StreamWrapper<S> {
    /// # Safety
    ///
    /// Must be called with `context` set to a valid pointer to a live `Context` object, and the
    /// wrapper must be pinned in memory.
    unsafe fn parts(&mut self) -> (Pin<&mut S>, &mut Context<'_>) {
        debug_assert_ne!(self.context, 0);
        let stream = Pin::new_unchecked(&mut self.stream);
        let context = &mut *(self.context as *mut _);
        (stream, context)
    }
}

impl<S> Read for StreamWrapper<S>
where
    S: AsyncRead,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (stream, cx) = unsafe { self.parts() };
        let mut buf = ReadBuf::new(buf);
        match stream.poll_read(cx, &mut buf)? {
            Poll::Ready(()) => Ok(buf.filled().len()),
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

impl<S> Write for StreamWrapper<S>
where
    S: AsyncWrite,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (stream, cx) = unsafe { self.parts() };
        match stream.poll_write(cx, buf) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let (stream, cx) = unsafe { self.parts() };
        match stream.poll_flush(cx) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

fn cvt<T>(r: io::Result<T>) -> Poll<io::Result<T>> {
    match r {
        Ok(v) => Poll::Ready(Ok(v)),
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
        Err(e) => Poll::Ready(Err(e)),
    }
}

fn cvt_ossl<T>(r: Result<T, ssl::Error>) -> Poll<Result<T, ssl::Error>> {
    match r {
        Ok(v) => Poll::Ready(Ok(v)),
        Err(e) => match e.code() {
            ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => Poll::Pending,
            _ => Poll::Ready(Err(e)),
        },
    }
}

/// An asynchronous version of [`btls::ssl::SslStream`].
#[derive(Debug)]
pub struct SslStream<S>(SslStreamCore<StreamWrapper<S>>);

impl<S: AsyncRead + AsyncWrite> SslStream<S> {
    #[inline]
    /// Like [`SslStream::new`](ssl::SslStream::new).
    pub fn new(ssl: Ssl, stream: S) -> Result<Self, ErrorStack> {
        SslStreamCore::new(ssl, StreamWrapper { stream, context: 0 }).map(SslStream)
    }

    #[inline]
    /// Like [`SslStream::connect`](ssl::SslStream::connect).
    pub fn poll_connect(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ssl::Error>> {
        self.with_context(cx, |s| cvt_ossl(s.connect()))
    }

    #[inline]
    /// A convenience method wrapping [`poll_connect`](Self::poll_connect).
    pub async fn connect(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_connect(cx)).await
    }

    #[inline]
    /// Like [`SslStream::accept`](ssl::SslStream::accept).
    pub fn poll_accept(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), ssl::Error>> {
        self.with_context(cx, |s| cvt_ossl(s.accept()))
    }

    #[inline]
    /// A convenience method wrapping [`poll_accept`](Self::poll_accept).
    pub async fn accept(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_accept(cx)).await
    }

    #[inline]
    /// Like [`SslStream::do_handshake`](ssl::SslStream::do_handshake).
    pub fn poll_do_handshake(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ssl::Error>> {
        self.with_context(cx, |s| cvt_ossl(s.do_handshake()))
    }

    #[inline]
    /// A convenience method wrapping [`poll_do_handshake`](Self::poll_do_handshake).
    pub async fn do_handshake(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_do_handshake(cx)).await
    }

    // ─── Split handshake for REALITY protocol ────────────────────────

    /// Generates a ClientHello into an internal buffer without sending it.
    ///
    /// The memory BIO swap technique means no real network I/O occurs.
    /// However, `SSL_do_handshake` may attempt to read through rbio
    /// (returning WouldBlock), so we set the async context first.
    ///
    /// After this call, use `pending_client_hello()` to read the raw bytes,
    /// modify them (e.g., inject REALITY session_id), then call
    /// `finish_connect()`.
    #[inline]
    pub fn poll_build_client_hello(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ErrorStack>> {
        self.with_context(cx, |s| {
            match s.build_client_hello() {
                Ok(()) => Poll::Ready(Ok(())),
                Err(e) => Poll::Ready(Err(e)),
            }
        })
    }

    /// Async convenience wrapper for [`poll_build_client_hello`](Self::poll_build_client_hello).
    #[inline]
    pub async fn build_client_hello(mut self: Pin<&mut Self>) -> Result<(), ErrorStack> {
        future::poll_fn(|cx| self.as_mut().poll_build_client_hello(cx)).await
    }

    /// Like [`SslStream::finish_connect`](ssl::SslStream::finish_connect).
    ///
    /// Sends the (possibly modified) ClientHello and completes the handshake.
    #[inline]
    pub fn poll_finish_connect(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ssl::Error>> {
        self.with_context(cx, |s| cvt_ossl(s.finish_connect()))
    }

    /// Async convenience wrapper for [`poll_finish_connect`](Self::poll_finish_connect).
    #[inline]
    pub async fn finish_connect(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_finish_connect(cx)).await
    }
}

impl<S> SslStream<S> {
    /// Returns the captured ClientHello bytes, if available.
    ///
    /// This delegates to the inner [`SslStream::pending_client_hello`](ssl::SslStream::pending_client_hello).
    #[inline]
    pub fn pending_client_hello(&self) -> Option<&[u8]> {
        self.0.pending_client_hello()
    }

    /// Replaces the pending ClientHello with modified bytes.
    ///
    /// The length must match the original exactly.
    #[inline]
    pub fn set_client_hello(&mut self, data: &[u8]) -> Result<(), ErrorStack> {
        self.0.set_client_hello(data)
    }
}

impl<S> SslStream<S> {
    #[inline]
    /// Returns a shared reference to the `Ssl` object associated with this stream.
    pub fn ssl(&self) -> &SslRef {
        self.0.ssl()
    }

    #[inline]
    /// Returns a mutable reference to the `Ssl` object associated with this stream.
    pub fn ssl_mut(&mut self) -> &mut SslRef {
        self.0.ssl_mut()
    }

    #[inline]
    /// Returns a shared reference to the underlying stream.
    pub fn get_ref(&self) -> &S {
        &self.0.get_ref().stream
    }

    #[inline]
    /// Returns a mutable reference to the underlying stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.0.get_mut().stream
    }

    #[inline]
    /// Returns a pinned mutable reference to the underlying stream.
    pub fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut S> {
        unsafe { Pin::new_unchecked(&mut self.get_unchecked_mut().0.get_mut().stream) }
    }

    fn with_context<F, R>(self: Pin<&mut Self>, ctx: &mut Context<'_>, f: F) -> R
    where
        F: FnOnce(&mut SslStreamCore<StreamWrapper<S>>) -> R,
    {
        let this = unsafe { self.get_unchecked_mut() };
        this.0.get_mut().context = ctx as *mut _ as usize;
        let r = f(&mut this.0);
        this.0.get_mut().context = 0;
        r
    }
}

impl<S> AsyncRead for SslStream<S>
where
    S: AsyncRead + AsyncWrite,
{
    fn poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.with_context(ctx, |s| {
            // SAFETY: read_uninit does not de-initialize the buffer.
            match cvt(s.read_uninit(unsafe { buf.unfilled_mut() }))? {
                Poll::Ready(nread) => {
                    // SAFETY: read_uninit guarantees that nread bytes have been initialized.
                    unsafe { buf.assume_init(nread) };
                    buf.advance(nread);
                    Poll::Ready(Ok(()))
                }
                Poll::Pending => Poll::Pending,
            }
        })
    }
}

impl<S> AsyncWrite for SslStream<S>
where
    S: AsyncRead + AsyncWrite,
{
    #[inline]
    fn poll_write(self: Pin<&mut Self>, ctx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.with_context(ctx, |s| cvt(s.write(buf)))
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> {
        self.with_context(ctx, |s| cvt(s.flush()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> {
        match self.as_mut().with_context(ctx, |s| s.shutdown()) {
            Ok(ShutdownResult::Sent) | Ok(ShutdownResult::Received) => {}
            Err(ref e) if e.code() == ErrorCode::ZERO_RETURN => {}
            Err(ref e) if e.code() == ErrorCode::WANT_READ || e.code() == ErrorCode::WANT_WRITE => {
                return Poll::Pending;
            }
            Err(e) => {
                return Poll::Ready(Err(e.into_io_error().unwrap_or_else(io::Error::other)));
            }
        }

        self.get_pin_mut().poll_shutdown(ctx)
    }
}

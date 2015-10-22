This is a port of the OAuth PECL PHP extension to HHVM's HNI interface.

Everything that was part of the original extension is implemented, excluding `OAuthProvider->checkOAuthRequest`, as-is constructing an instance of `OAuthProvider` that obtains an auth header, either explicitly or implicitly. These simply have not yet been implemented yet.
While the rest of the code is implemented, it is entirely untested, and may not work at all.


It is currently intended only for use as an in-tree extension, and is not setup to be able to be used as a DSO.

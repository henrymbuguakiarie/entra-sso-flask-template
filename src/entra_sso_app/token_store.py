from __future__ import annotations

from typing import Optional


class TokenStore:
	"""Abstract interface for storing tokens server-side."""

	def save_tokens(
		self,
		subject: str,
		access_token: str,
		refresh_token: Optional[str] = None,
	) -> None:
		raise NotImplementedError

	def save_access_token(self, subject: str, token: str) -> None:
		"""Backward-compatible helper for storing only an access token."""
		self.save_tokens(subject, token, None)

	def get_access_token(self, subject: str) -> Optional[str]:  # pragma: no cover - interface
		raise NotImplementedError

	def get_refresh_token(self, subject: str) -> Optional[str]:  # pragma: no cover - interface
		raise NotImplementedError

	def revoke_access_token(self, subject: str) -> None:  # pragma: no cover - interface
		self.revoke_tokens(subject)

	def revoke_tokens(self, subject: str) -> None:  # pragma: no cover - interface
		raise NotImplementedError


class InMemoryTokenStore(TokenStore):
	"""Simple in-memory token store for development and testing.

	Tokens are stored per subject (e.g. the user's object id). This is not
	suitable for multi-process production deployments but keeps the example
	implementation straightforward.
	"""

	def __init__(self) -> None:
		self._access_tokens: dict[str, str] = {}
		self._refresh_tokens: dict[str, str] = {}

	def save_tokens(
		self,
		subject: str,
		access_token: str,
		refresh_token: Optional[str] = None,
	) -> None:
		self._access_tokens[subject] = access_token
		if refresh_token is not None:
			self._refresh_tokens[subject] = refresh_token

	def get_access_token(self, subject: str) -> Optional[str]:
		return self._access_tokens.get(subject)

	def get_refresh_token(self, subject: str) -> Optional[str]:
		return self._refresh_tokens.get(subject)

	def revoke_tokens(self, subject: str) -> None:
		self._access_tokens.pop(subject, None)
		self._refresh_tokens.pop(subject, None)


# Module-level store instance used by the app. In a real application this
# could be swapped for a Redis-backed implementation via configuration.
token_store = InMemoryTokenStore()

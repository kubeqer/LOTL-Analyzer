from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence

from sentence_transformers import SentenceTransformer

from ..config import settings

logger = logging.getLogger(__name__)


class Embedder:
    def __init__(self, model_name: str) -> None:
        logger.info("loading embedding model: %s", model_name)
        self._model = SentenceTransformer(model_name)
        self._dim = int(self._model.get_sentence_embedding_dimension())

    @property
    def dim(self) -> int:
        return self._dim

    def encode_sync(self, texts: Sequence[str]) -> list[list[float]]:
        if not texts:
            return []
        vectors = self._model.encode(
            list(texts),
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        return [v.tolist() for v in vectors]

    async def encode(self, texts: Sequence[str]) -> list[list[float]]:
        return await asyncio.to_thread(self.encode_sync, list(texts))


_embedder: Embedder | None = None


def get_embedder() -> Embedder:
    global _embedder
    if _embedder is None:
        _embedder = Embedder(settings.rag_embed_model)
    return _embedder

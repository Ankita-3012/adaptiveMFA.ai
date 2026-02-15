from typing import List, Dict, Any
from app.config import settings
from app.utils.logger import logger
from app.services.embedding_service import EmbeddingService
from app.vector_db.pinecone_client import PineconeClient


class RAGService:
    def __init__(self):
        try:
            self.embedding_service = EmbeddingService()
            self.pinecone = PineconeClient()
            self.index = self.pinecone.index

            if self.index is None:
                raise RuntimeError("Pinecone index not initialized")

            logger.info("RAG service initialized with Pinecone")

        except Exception as e:
            logger.error(f"RAG init failed: {e}")
            self.index = None
            self.embedding_service = None

    #insert single event
    def add_event(
        self,
        event_id: str,
        login_event: Dict[str, Any],
        explanation: str
    ) -> bool:
        try:
            if not self.index or not self.embedding_service:
                return False

            vector = self.embedding_service.embed_text(explanation)
            if vector is None:
                return False

            metadata = {
                "explanation": explanation,
                "ip_address": login_event.get("ip_address", ""),
                "location": login_event.get("location", ""),
                "timestamp": login_event.get("timestamp", ""),
                "outcome": login_event.get("user_action", "pending"),
            }

            self.index.upsert(
                vectors=[
                    {
                        "id": event_id,
                        "values": vector.tolist(),
                        "metadata": metadata,
                    }
                ]
            )

            return True

        except Exception as e:
            logger.error(f"Pinecone insert failed: {e}")
            return False

    #batch insert
    def add_events_batch(self, events: List[Dict[str, Any]]) -> bool:
        try:
            if not self.index or not self.embedding_service:
                return False

            vectors = []

            for event in events:
                text = event.get("explanation", "")
                embedding = self.embedding_service.embed_text(text)

                if embedding is None:
                    continue

                login_event = event.get("event", {})

                vectors.append({
                    "id": event.get("id"),
                    "values": embedding.tolist(),
                    "metadata": {
                        "explanation": text,
                        "ip_address": login_event.get("ip_address", ""),
                        "location": login_event.get("location", ""),
                        "timestamp": login_event.get("timestamp", ""),
                        "outcome": login_event.get("user_action", "pending"),
                    },
                })

            if vectors:
                self.index.upsert(vectors=vectors)

            return True

        except Exception as e:
            logger.error(f"Batch insert failed: {e}")
            return False

    #Vector similarity
    def retrieve_similar_cases(
        self,
        login_event: Dict[str, Any],
        top_k: int = 3
    ) -> List[Dict[str, Any]]:
        try:
            if not self.index or not self.embedding_service:
                return []

            query_text = self._create_query_text(login_event)
            query_vector = self.embedding_service.embed_text(query_text)

            if query_vector is None:
                return []

            response = self.index.query(
                vector=query_vector.tolist(),
                top_k=top_k,
                include_metadata=True,
            )

            results = []

            for match in response.matches:
                meta = match.metadata or {}
                results.append({
                    "id": match.id,
                    "explanation": meta.get("explanation", ""),
                    "ip_address": meta.get("ip_address", ""),
                    "location": meta.get("location", ""),
                    "timestamp": meta.get("timestamp", ""),
                    "outcome": meta.get("outcome", ""),
                    "similarity_score": match.score,
                })

            return results

        except Exception as e:
            logger.error(f"Retrieval failed: {e}")
            return []

    #Helpers
    def _create_query_text(self, login_event: Dict[str, Any]) -> str:
        return (
            f"Login from IP {login_event.get('ip_address', 'unknown')} "
            f"in {login_event.get('location', 'unknown')} "
            f"using device {login_event.get('device_fingerprint', 'unknown')}"
        )

    #Stats
    def get_collection_stats(self) -> Dict[str, Any]:
        try:
            stats = self.index.describe_index_stats()
            return {
                "index_name": settings.PINECONE_INDEX_NAME,
                "total_vectors": stats.total_vector_count,
            }
        except Exception as e:
            logger.error(f"Stats error: {e}")
            return {}

    #Pinecone limitation notice
    def clear_collection(self) -> bool:
        logger.warning("Pinecone does not support full index wipe via SDK")
        return False

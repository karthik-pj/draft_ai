import pinecone
import os
from sentence_transformers import SentenceTransformer
import hashlib
import uuid

class PineconeManager:
    def __init__(self):
        self.api_key = "pcsk_34ujt3_Sg56hdoBmpAPJrxubCteDeCrrwNKAhK8aZeHwiWaYkNK9UCpiCtgFR5weBxp9hU"
        self.index_name = "legal-draft-assistant"
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        self.init_pinecone()
    
    def init_pinecone(self):
        try:
            # Initialize Pinecone with the new SDK
            self.pc = pinecone.Pinecone(api_key=self.api_key)
            
            # Create index if not exists - using FREE TIER supported region
            if self.index_name not in [index.name for index in self.pc.list_indexes()]:
                self.pc.create_index(
                    name=self.index_name,
                    dimension=384,
                    metric="cosine",
                    spec=pinecone.ServerlessSpec(
                        cloud="aws",
                        region="us-east-1"
                    )
                )
            
            # Wait for index to be ready
            import time
            while not self.pc.describe_index(self.index_name).status.ready:
                time.sleep(1)
            
            self.index = self.pc.Index(self.index_name)
            
        except Exception as e:
            raise Exception(f"Pinecone initialization failed: {str(e)}")
    
    def generate_embedding(self, text):
        return self.model.encode(text).tolist()
    
    def store_document(self, text, metadata, document_id=None):
        if document_id is None:
            document_id = str(uuid.uuid4())
        
        embedding = self.generate_embedding(text)
        
        # Prepare metadata
        full_metadata = {
            "text": text[:10000],  # Limit text size for free tier
            **metadata
        }
        
        try:
            # Upsert to Pinecone with error handling
            self.index.upsert(vectors=[(document_id, embedding, full_metadata)])
            return document_id
        except Exception as e:
            print(f"Error storing document: {e}")
            return None
    
    def search_similar(self, query, filter_dict=None, top_k=5):
        try:
            query_embedding = self.generate_embedding(query)
            
            search_params = {
                "vector": query_embedding,
                "top_k": top_k,
                "include_metadata": True
            }
            
            if filter_dict:
                search_params["filter"] = filter_dict
            
            results = self.index.query(**search_params)
            return results
        except Exception as e:
            print(f"Search error: {e}")
            return type('obj', (object,), {'matches': []})()
    
    def delete_document(self, document_id):
        try:
            self.index.delete(ids=[document_id])
        except Exception as e:
            print(f"Delete error: {e}")
    
    def get_index_stats(self):
        """Get index statistics"""
        try:
            return self.index.describe_index_stats()
        except Exception as e:
            print(f"Stats error: {e}")
            return {}
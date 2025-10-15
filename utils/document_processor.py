import PyPDF2
import docx
import fitz  # PyMuPDF
from typing import List
import io

class DocumentProcessor:
    @staticmethod
    def extract_text_from_pdf(file):
        try:
            # Reset file pointer to beginning
            file.seek(0)
            
            # Method 1: Try PyMuPDF (fitz)
            try:
                pdf_document = fitz.open(stream=file.read(), filetype="pdf")
                text = ""
                for page_num in range(len(pdf_document)):
                    page = pdf_document.load_page(page_num)
                    text += page.get_text()
                pdf_document.close()
                if text.strip():
                    return text
            except Exception as e:
                print(f"PyMuPDF failed: {e}")
            
            # Method 2: Try PyPDF2 as fallback
            file.seek(0)
            try:
                pdf_reader = PyPDF2.PdfReader(file)
                text = ""
                for page in pdf_reader.pages:
                    text += page.extract_text() + "\n"
                if text.strip():
                    return text
            except Exception as e:
                print(f"PyPDF2 failed: {e}")
            
            return "Unable to extract text from PDF (may be scanned image or encrypted)"
            
        except Exception as e:
            return f"Error extracting PDF text: {str(e)}"
    
    @staticmethod
    def extract_text_from_docx(file):
        try:
            file.seek(0)
            doc = docx.Document(io.BytesIO(file.read()))
            text = ""
            for paragraph in doc.paragraphs:
                text += paragraph.text + "\n"
            return text
        except Exception as e:
            return f"Error extracting DOCX text: {str(e)}"
    
    @staticmethod
    def extract_text_from_txt(file):
        try:
            file.seek(0)
            return file.read().decode('utf-8')
        except Exception as e:
            return f"Error extracting text: {str(e)}"
    
    @staticmethod
    def process_uploaded_file(file):
        file_extension = file.name.split('.')[-1].lower()
        
        # Reset file pointer before processing
        file.seek(0)
        
        if file_extension == 'pdf':
            return DocumentProcessor.extract_text_from_pdf(file)
        elif file_extension == 'docx':
            return DocumentProcessor.extract_text_from_docx(file)
        elif file_extension == 'txt':
            return DocumentProcessor.extract_text_from_txt(file)
        else:
            return f"Unsupported file type: {file_extension}"
    
    @staticmethod
    def chunk_text(text, chunk_size=1000, overlap=200):
        if not text or not text.strip():
            return []
            
        words = text.split()
        chunks = []
        
        for i in range(0, len(words), chunk_size - overlap):
            chunk = ' '.join(words[i:i + chunk_size])
            chunks.append(chunk)
            if i + chunk_size >= len(words):
                break
        
        return chunks
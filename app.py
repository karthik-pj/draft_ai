import streamlit as st
import os
import json
from datetime import datetime
import base64
import re
import pandas as pd
import sqlite3

# Import utility modules
from utils.auth import (
    initialize_authentication, login, check_authentication, get_user_role,
    create_user, update_user, delete_user, get_all_users, get_audit_logs,
    save_draft_to_db, load_user_drafts, get_user_drafts_count, get_all_drafts_stats,
    save_training_doc, get_training_docs, test_database_connection, debug_get_all_users_including_inactive
)
from utils.pinecone_utils import PineconeManager
from utils.groq_utils import GroqManager
from utils.document_processor import DocumentProcessor

# Page configuration
st.set_page_config(
    page_title="AI Legal Draft Assistant",
    page_icon="⚖️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ----------------------------
# Manager factories (session-safe)
# ----------------------------
def get_pinecone_manager():
    if 'pinecone_mgr' not in st.session_state:
        st.session_state.pinecone_mgr = PineconeManager()
    return st.session_state.pinecone_mgr

def get_ai_manager():
    if 'ai_mgr' not in st.session_state:
        st.session_state.ai_mgr = GroqManager()
    return st.session_state.ai_mgr

def get_document_processor():
    if 'doc_processor' not in st.session_state:
        st.session_state.doc_processor = DocumentProcessor()
    return st.session_state.doc_processor

# ----------------------------
# Utility functions
# ----------------------------
def check_ai_setup():
    """Check if Groq is properly configured"""
    try:
        ai_mgr = get_ai_manager()
        _ = ai_mgr.client.chat.completions.create(
            messages=[{"role": "user", "content": "ping"}],
            model=ai_mgr.model_name,
            max_tokens=5
        )
        return True, "✅ Groq API is working"
    except Exception as e:
        return False, f"❌ Groq setup failed: {str(e)}"

def format_draft_with_tables(draft_text):
    """Convert markdown tables to properly formatted text tables"""
    draft_text = re.sub(r'^\|[-:\s|]+\|\s*$', '', draft_text, flags=re.MULTILINE)
    table_pattern = r'((?:\|.*\|\n)+)'

    def replace_table(match):
        table_text = match.group(0)
        lines = table_text.strip().split('\n')
        formatted_lines = []
        for line in lines:
            if re.match(r'^\|[-:\s|]+\|\s*$', line.strip()):
                continue
            if '|' in line:
                cells = [cell.strip() for cell in line.strip('|').split('|')]
                formatted_lines.append(" | ".join(cells))
        if formatted_lines:
            return "\n" + "\n".join(formatted_lines) + "\n"
        return table_text

    formatted_draft = re.sub(table_pattern, replace_table, draft_text, flags=re.MULTILINE)
    return formatted_draft

def rewrite_draft_with_ai(original_draft, improvement_goal):
    """Use AI to rewrite and improve the draft with better error handling"""
    ai_mgr = get_ai_manager()
    try:
        improved_draft = ai_mgr.rewrite_draft(original_draft, improvement_goal)
        
        # Check if we got a valid draft back (not empty and not an error message)
        if (improved_draft and 
            improved_draft.strip() and 
            not improved_draft.startswith("Error") and
            "error generating" not in improved_draft.lower() and
            "error rewriting" not in improved_draft.lower()):
            
            improved_draft = format_draft_with_tables(improved_draft)
            return improved_draft
        else:
            # If AI returned an error or empty response, return original
            return original_draft
            
    except Exception as e:
        print(f"Rewrite error: {e}")  # For debugging
        return original_draft  # Return original draft on any error"

def create_fallback_draft(case_details, medical_text):
    """Create a fallback draft when AI unavailable"""
    current_date = datetime.now().strftime("%B %d, %Y")
    medical_preview = medical_text[:500] + "..." if len(medical_text) > 500 else medical_text
    return f"""
**DEMAND LETTER - {case_details.get('case_type', 'Personal Injury').upper()} CASE**

{current_date}

TO:
{case_details.get('defendant', 'Defendant')}
Jurisdiction: {case_details.get('jurisdiction', 'California')}

RE: {case_details.get('case_type', 'Personal Injury')} Claim - {case_details.get('plaintiff', 'Plaintiff')} vs. {case_details.get('defendant', 'Defendant')}

Dear Claims Adjuster,

This law firm represents {case_details.get('plaintiff', 'our client')} in connection with injuries sustained due to your negligence.

**INCIDENT SUMMARY**
{case_details.get('additional_details', 'Our client suffered injuries as a result of your negligent conduct.')}

**INJURIES AND MEDICAL TREATMENT**
Our client sustained {case_details.get('injury_type', 'serious injuries')} requiring medical attention.

Medical Summary:
{medical_preview}

The total medical expenses incurred amount to ${case_details.get('treatment_cost', '10,000'):,}.

**DAMAGES BREAKDOWN**
| Category | Amount (USD) |
|----------|-------------:|
| Medical Expenses | ${case_details.get('treatment_cost', '10,000'):,} |
| Pain and Suffering | $15,000 |
| Lost Wages | $5,000 |
| **TOTAL DEMAND** | **$30,000** |

**DEMAND FOR COMPENSATION**
We hereby demand payment of $30,000 to fully compensate our client for medical expenses, pain and suffering, and other damages resulting from this incident.

Please forward this demand to your insurance carrier and have them contact us within 30 days to resolve this matter. Failure to respond may compel us to pursue legal action.

Sincerely,

{case_details.get('attorney_name', 'Legal Counsel')}
{case_details.get('law_firm_name', 'Law Offices of Legal Counsel')}
"""

def create_professional_word_download(text, filename):
    """Create a professional Word document with proper formatting like MS Word"""
    from docx import Document
    from docx.shared import Inches, Pt, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml.ns import qn
    from docx.oxml import OxmlElement
    import io
    
    def set_cell_background(cell, color):
        """Set cell background color"""
        tcPr = cell._tc.get_or_add_tcPr()
        shd = OxmlElement('w:shd')
        shd.set(qn('w:fill'), color)
        tcPr.append(shd)
    
    def set_cell_border(cell):
        """Set cell borders"""
        tcPr = cell._tc.get_or_add_tcPr()
        tcBorders = OxmlElement('w:tcBorders')
        
        # Add all borders
        for border_name in ['top', 'left', 'bottom', 'right']:
            border = OxmlElement(f'w:{border_name}')
            border.set(qn('w:val'), 'single')
            border.set(qn('w:sz'), '4')
            border.set(qn('w:space'), '0')
            border.set(qn('w:color'), '000000')
            tcBorders.append(border)
        
        tcPr.append(tcBorders)
    
    def clean_unicode_text(text):
        """Replace Unicode characters with ASCII equivalents"""
        replacements = {
            '\u2013': '-',  # en dash
            '\u2014': '-',  # em dash
            '\u2018': "'",  # left single quote
            '\u2019': "'",  # right single quote
            '\u201C': '"',  # left double quote
            '\u201D': '"',  # right double quote
            '\u2022': '•',  # bullet (keep this one)
            '\u2026': '...', # ellipsis
        }
        
        cleaned_text = str(text)
        for unicode_char, ascii_replacement in replacements.items():
            cleaned_text = cleaned_text.replace(unicode_char, ascii_replacement)
        
        return cleaned_text
    
    doc = Document()
    
    # Set document margins (like Word default)
    sections = doc.sections
    for section in sections:
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)
    
    # Title - Centered and bold
    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title_run = title.add_run("LEGAL DEMAND DRAFT")
    title_run.font.size = Pt(16)
    title_run.font.color.rgb = RGBColor(0, 0, 128)  # Navy blue
    title_run.bold = True
    title_run.font.name = 'Arial'
    
    doc.add_paragraph()  # Add space
    
    # Preprocess text
    processed_text = clean_unicode_text(text)
    lines = processed_text.split('\n')
    current_table = []
    in_table = False
    
    for line in lines:
        line = line.strip()
        if not line:
            doc.add_paragraph()  # Add empty paragraph for blank lines
            continue
            
        # Handle headings (bold text with **)
        if line.startswith('**') and line.endswith('**'):
            heading_text = line.strip('*').strip()
            heading = doc.add_paragraph()
            heading.alignment = WD_ALIGN_PARAGRAPH.LEFT
            heading_run = heading.add_run(heading_text)
            heading_run.font.size = Pt(14)
            heading_run.font.color.rgb = RGBColor(0, 0, 128)  # Navy blue
            heading_run.bold = True
            heading_run.font.name = 'Arial'
            heading.paragraph_format.space_after = Pt(6)
            continue
            
        # Handle table rows
        if '|' in line and any(cell.strip() for cell in line.split('|')):
            if not in_table:
                current_table = []
                in_table = True
            
            cells = [cell.strip() for cell in line.split('|') if cell.strip()]
            if cells:
                current_table.append(cells)
            continue
        else:
            # Process accumulated table
            if in_table and current_table and len(current_table) > 1:
                max_cols = max(len(row) for row in current_table)
                table = doc.add_table(rows=len(current_table), cols=max_cols)
                table.style = 'Table Grid'
                
                # Set column widths
                for col in table.columns:
                    col.width = Inches(2.5)
                
                for i, row in enumerate(current_table):
                    for j in range(max_cols):
                        cell_text = row[j] if j < len(row) else ""
                        cell = table.cell(i, j)
                        cell.text = cell_text
                        
                        # Set borders for all cells
                        set_cell_border(cell)
                        
                        # Style header row
                        if i == 0:
                            set_cell_background(cell, "2F75B5")  # Blue header
                            for paragraph in cell.paragraphs:
                                paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
                                for run in paragraph.runs:
                                    run.bold = True
                                    run.font.color.rgb = RGBColor(255, 255, 255)  # White text
                                    run.font.name = 'Arial'
                                    run.font.size = Pt(11)
                        else:
                            # Alternate row colors for data rows
                            if i % 2 == 1:  # Even rows
                                set_cell_background(cell, "DDEBF7")  # Light blue
                            else:  # Odd rows
                                set_cell_background(cell, "FFFFFF")  # White
                            
                            for paragraph in cell.paragraphs:
                                paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
                                for run in paragraph.runs:
                                    run.font.name = 'Arial'
                                    run.font.size = Pt(10)
                                    run.font.color.rgb = RGBColor(0, 0, 0)  # Black text
                
                doc.add_paragraph()  # Add space after table
                in_table = False
                current_table = []
            
            # Regular paragraph
            if line.strip():
                p = doc.add_paragraph()
                p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
                p.paragraph_format.space_after = Pt(6)
                run = p.add_run(line)
                run.font.name = 'Arial'
                run.font.size = Pt(11)
                run.font.color.rgb = RGBColor(0, 0, 0)  # Black text
    
    # Handle case where text ends with a table
    if in_table and current_table and len(current_table) > 1:
        max_cols = max(len(row) for row in current_table)
        table = doc.add_table(rows=len(current_table), cols=max_cols)
        table.style = 'Table Grid'
        
        for col in table.columns:
            col.width = Inches(2.5)
        
        for i, row in enumerate(current_table):
            for j in range(max_cols):
                cell_text = row[j] if j < len(row) else ""
                cell = table.cell(i, j)
                cell.text = cell_text
                set_cell_border(cell)
                
                if i == 0:
                    set_cell_background(cell, "2F75B5")
                    for paragraph in cell.paragraphs:
                        paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
                        for run in paragraph.runs:
                            run.bold = True
                            run.font.color.rgb = RGBColor(255, 255, 255)
                            run.font.name = 'Arial'
                            run.font.size = Pt(11)
                else:
                    if i % 2 == 1:
                        set_cell_background(cell, "DDEBF7")
                    else:
                        set_cell_background(cell, "FFFFFF")
                    
                    for paragraph in cell.paragraphs:
                        paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
                        for run in paragraph.runs:
                            run.font.name = 'Arial'
                            run.font.size = Pt(10)
                            run.font.color.rgb = RGBColor(0, 0, 0)
    
    buffer = io.BytesIO()
    doc.save(buffer)
    buffer.seek(0)
    
    return buffer

def create_professional_pdf_download(text, filename):
    """Create a professional PDF document that handles Unicode characters properly"""
    from fpdf import FPDF
    import io
    
    class LegalPDF(FPDF):
        def __init__(self):
            super().__init__()
            self.set_auto_page_break(auto=True, margin=15)
            self.set_margins(left=20, top=20, right=20)
        
        def header(self):
            # Title - Centered and colored
            self.set_fill_color(47, 117, 181)  # Blue background
            self.set_text_color(255, 255, 255)  # White text
            self.set_font('Arial', 'B', 16)
            self.cell(0, 12, 'LEGAL DEMAND DRAFT', 0, 1, 'C', fill=True)
            self.ln(10)
            self.set_text_color(0, 0, 0)  # Black text
        
        def footer(self):
            self.set_y(-15)
            self.set_font('Arial', 'I', 9)
            self.set_text_color(128, 128, 128)
            self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')
        
        def add_heading(self, text, level=1):
            self.set_font('Arial', 'B', 14 if level == 1 else 12)
            self.set_text_color(0, 0, 128)  # Navy blue
            clean_text = self._clean_text(text)
            self.multi_cell(0, 8, clean_text)
            self.ln(4)
            self.set_text_color(0, 0, 0)
        
        def add_paragraph(self, text):
            self.set_font('Arial', '', 11)
            if text and text.strip():
                clean_text = self._clean_text(text)
                # Justify text like Word
                self.multi_cell(0, 6, clean_text)
                self.ln(3)
        
        def add_table(self, rows):
            if not rows or len(rows) < 2:
                return
                
            col_count = max(len(row) for row in rows)
            page_width = self.w - 40  # Account for margins
            col_width = page_width / col_count
            
            # Header row with blue background
            self.set_fill_color(47, 117, 181)  # Blue
            self.set_text_color(255, 255, 255)  # White
            self.set_font('Arial', 'B', 11)
            
            for header in rows[0]:
                clean_header = self._clean_text(str(header))
                self.cell(col_width, 10, clean_header, border=1, align='C', fill=True)
            self.ln(10)
            
            # Data rows with alternating colors
            self.set_font('Arial', '', 10)
            self.set_text_color(0, 0, 0)  # Black text
            
            for i, row in enumerate(rows[1:]):
                # Alternate row colors
                if i % 2 == 0:
                    self.set_fill_color(221, 235, 247)  # Light blue
                else:
                    self.set_fill_color(255, 255, 255)  # White
                
                for j in range(col_count):
                    cell_text = row[j] if j < len(row) else ""
                    clean_cell = self._clean_text(str(cell_text))
                    if len(clean_cell) > 30:
                        clean_cell = clean_cell[:27] + "..."
                    self.cell(col_width, 8, clean_cell, border=1, align='C', fill=True)
                
                self.ln(8)
            
            self.ln(5)
        
        def _clean_text(self, text):
            """Replace Unicode characters with ASCII equivalents for PDF compatibility"""
            if not text:
                return ""
            
            # Common Unicode character replacements
            replacements = {
                '\u2013': '-',  # en dash
                '\u2014': '-',  # em dash
                '\u2018': "'",  # left single quote
                '\u2019': "'",  # right single quote
                '\u201C': '"',  # left double quote
                '\u201D': '"',  # right double quote
                '\u2022': '*',  # bullet
                '\u2026': '...', # ellipsis
                '\u20AC': 'EUR', # euro sign
                '\u00A3': 'GBP', # pound sign
                '\u00A9': '(c)', # copyright
                '\u00AE': '(R)', # registered
                '\u2122': '(TM)', # trademark
            }
            
            cleaned_text = str(text)
            for unicode_char, ascii_replacement in replacements.items():
                cleaned_text = cleaned_text.replace(unicode_char, ascii_replacement)
            
            return cleaned_text
    
    def preprocess_text_for_pdf(text):
        """Preprocess the entire text to handle Unicode characters"""
        replacements = {
            '\u2013': '-',
            '\u2014': '-',
            '\u2018': "'",
            '\u2019': "'",
            '\u201C': '"',
            '\u201D': '"',
            '\u2022': '*',
            '\u2026': '...',
            '\u20AC': 'EUR',
            '\u00A3': 'GBP',
            '\u00A9': '(c)',
            '\u00AE': '(R)',
            '\u2122': '(TM)',
        }
        
        cleaned_text = str(text)
        for unicode_char, ascii_replacement in replacements.items():
            cleaned_text = cleaned_text.replace(unicode_char, ascii_replacement)
        
        return cleaned_text
    
    # Always return a valid buffer
    try:
        # Preprocess the entire text first
        processed_text = preprocess_text_for_pdf(text)
        
        pdf = LegalPDF()
        pdf.add_page()
        
        if not processed_text or not processed_text.strip():
            pdf.add_paragraph("No content available for this draft.")
        else:
            lines = processed_text.split('\n')
            current_table = []
            in_table = False
            
            for line in lines:
                line = line.strip()
                if not line:
                    pdf.ln(3)  # Add space for blank lines
                    continue
                
                # Handle headings (bold text with **)
                if line.startswith('**') and line.endswith('**'):
                    heading_text = line.strip('*').strip()
                    if heading_text:
                        pdf.add_heading(heading_text, level=1)
                    continue
                
                # Handle table rows
                if '|' in line and any(cell.strip() for cell in line.split('|')):
                    if not in_table:
                        current_table = []
                        in_table = True
                    
                    cells = [cell.strip() for cell in line.split('|') if cell.strip()]
                    if cells:
                        current_table.append(cells)
                    continue
                else:
                    # Process table
                    if in_table and current_table and len(current_table) > 1:
                        pdf.add_table(current_table)
                        in_table = False
                        current_table = []
                    
                    # Regular paragraph
                    if (line.strip() and 
                        not re.match(r'^[\s\|:-]+$', line.strip()) and
                        not line.strip().startswith('|---')):
                        pdf.add_paragraph(line)
            
            # Final table
            if in_table and current_table and len(current_table) > 1:
                pdf.add_table(current_table)
        
        # Generate PDF bytes
        pdf_bytes = pdf.output(dest='S').encode('latin-1', 'replace')
        buffer = io.BytesIO(pdf_bytes)
        buffer.seek(0)
        
        return buffer
        
    except Exception as e:
        st.error(f"PDF generation error: {str(e)}")
        # Ultimate fallback - simple PDF
        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font('Arial', 'B', 16)
            pdf.cell(0, 10, 'LEGAL DEMAND DRAFT', 0, 1, 'C')
            pdf.ln(10)
            pdf.set_font('Arial', '', 12)
            
            safe_text = preprocess_text_for_pdf(text) if text else "No content available"
            pdf.multi_cell(0, 8, safe_text[:1500])
            
            pdf_bytes = pdf.output(dest='S').encode('latin-1', 'replace')
            buffer = io.BytesIO(pdf_bytes)
            buffer.seek(0)
            return buffer
        except Exception as final_error:
            # Last resort - empty but valid PDF
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font('Arial', 'B', 16)
            pdf.cell(0, 10, 'LEGAL DEMAND DRAFT', 0, 1, 'C')
            pdf_bytes = pdf.output(dest='S').encode('latin-1', 'replace')
            buffer = io.BytesIO(pdf_bytes)
            buffer.seek(0)
            return buffer

# ----------------------------
# Authentication & session defaults
# ----------------------------
def initialize_session_state():
    """Initialize all session state variables"""
    if 'draft_history' not in st.session_state:
        st.session_state.draft_history = []
    if 'current_draft' not in st.session_state:
        st.session_state.current_draft = ""
    if 'medical_text' not in st.session_state:
        st.session_state.medical_text = ""
    if 'last_snapshot' not in st.session_state:
        st.session_state.last_snapshot = {}
    if 'rewrite_goals' not in st.session_state:
        st.session_state.rewrite_goals = [
            "Make it more persuasive and compelling",
            "Improve legal language and professionalism",
            "Enhance clarity and readability",
            "Strengthen the demand justification",
            "Make it more concise and direct"
        ]
    if 'ai_rewrite_trigger' not in st.session_state:
        st.session_state.ai_rewrite_trigger = False
    if 'ai_rewrite_goal' not in st.session_state:
        st.session_state.ai_rewrite_goal = ""

# Initialize authentication and session state
initialize_authentication()
initialize_session_state()

# Check authentication
if not check_authentication():
    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        st.title("⚖️ Legal Draft Assistant")
        login()
    st.stop()

# ----------------------------
# Sidebar with working logout
# ----------------------------
def setup_sidebar():
    """Setup sidebar content with working logout"""
    st.sidebar.title(f"Welcome {st.session_state.name}!")
    st.sidebar.write(f"Role: {st.session_state.user_role}")
    st.sidebar.markdown("---")
    
    # AI System Status
    ai_working, ai_msg = check_ai_setup()
    if ai_working:
        st.sidebar.success(ai_msg)
    else:
        st.sidebar.error(ai_msg)
    
    # Database Stats
    if st.session_state.user_role == "admin":
        draft_stats = get_all_drafts_stats()
        st.sidebar.markdown("---")
        st.sidebar.subheader("📊 System Stats")
        st.sidebar.write(f"Total Drafts: **{draft_stats['total_drafts']}**")
        st.sidebar.write(f"Active Users: **{len(get_all_users())}**")
    
    # User Stats
    user_draft_count = get_user_drafts_count(st.session_state.user_id)
    st.sidebar.markdown("---")
    st.sidebar.subheader("Your Stats")
    st.sidebar.write(f"📝 Your Drafts: **{user_draft_count}**")
    
    # Logout button with direct action
    if st.sidebar.button("🚪 Logout", key="sidebar_logout"):
        # Clear all session state
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

setup_sidebar()

# ----------------------------
# Training functions
# ----------------------------
def process_training_files(files, document_type):
    pinecone_mgr = get_pinecone_manager()
    doc_processor = get_document_processor()
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    successful_uploads = 0
    
    for i, file in enumerate(files):
        status_text.text(f"Processing {file.name}...")
        
        try:
            text = doc_processor.process_uploaded_file(file)
            
            if text and "Error" not in text and "Unable" not in text:
                # Store in Pinecone
                metadata = {
                    "document_type": document_type,
                    "file_name": file.name,
                    "upload_date": datetime.now().isoformat(),
                    "uploaded_by": st.session_state.username,
                    "category": "legal_draft"
                }
                
                result = pinecone_mgr.store_document(text, metadata)
                
                # Also save to SQL database
                db_success = save_training_doc(file.name, document_type, text, st.session_state.username)
                
                if result and db_success:
                    successful_uploads += 1
                    st.success(f"✅ Successfully stored {file.name} as {document_type}")
                else:
                    st.error(f"❌ Failed to store {file.name}")
            else:
                st.error(f"❌ Failed to extract text from {file.name}: {text}")
        
        except Exception as e:
            st.error(f"❌ Error processing {file.name}: {str(e)}")
        
        progress_bar.progress((i + 1) / len(files))
    
    status_text.text(f"Processing complete! {successful_uploads}/{len(files)} files stored.")
    
    if successful_uploads > 0:
        st.success(f"🎉 Successfully stored {successful_uploads} {document_type} files!")

def show_vector_db_status():
    pinecone_mgr = get_pinecone_manager()
    
    try:
        stats = pinecone_mgr.get_index_stats()
        
        st.write("### Vector Database Status")
        st.write(f"Total Vectors: {stats.get('total_vector_count', 0)}")
        st.write(f"Index Dimension: {stats.get('dimension', 0)}")
        
        st.write("### All Documents in Database")
        all_results = pinecone_mgr.search_similar("legal medical demand", top_k=20)
        
        if not all_results.matches:
            st.error("❌ NO DOCUMENTS FOUND IN DATABASE!")
            st.info("Please upload templates in the 'Train Model' tab")
            return
            
        for i, match in enumerate(all_results.matches):
            doc_type = match.metadata.get('document_type', 'UNKNOWN')
            file_name = match.metadata.get('file_name', 'UNKNOWN')
            with st.expander(f"{doc_type.upper()}: {file_name} (Score: {match.score:.3f})"):
                st.write(f"**Type:** {doc_type}")
                st.write(f"**File:** {file_name}")
                st.text(match.metadata.get('text', '')[:300] + "..." if len(match.metadata.get('text', '')) > 300 else match.metadata.get('text', ''))
    
    except Exception as e:
        st.error(f"Error accessing vector database: {e}")

# ----------------------------
# User Management Functions
# ----------------------------
def show_user_management():
    """User management interface for admin with proper database integration"""
    st.subheader("User Management")
    
    # Test database connection
    if st.button("🔧 Test Database Connection"):
        success, message = test_database_connection()
        if success:
            st.success(message)
        else:
            st.error(message)
    
    # Create new user
    with st.expander("➕ Create New User", expanded=True):
        with st.form("create_user_form", clear_on_submit=True):
            col1, col2 = st.columns(2)
            
            with col1:
                new_username = st.text_input("Username*", placeholder="Enter username")
                new_password = st.text_input("Password*", type="password", placeholder="Enter password")
                confirm_password = st.text_input("Confirm Password*", type="password", placeholder="Confirm password")
            
            with col2:
                new_name = st.text_input("Full Name*", placeholder="Enter full name")
                new_email = st.text_input("Email*", placeholder="Enter email")
                new_role = st.selectbox("Role*", ["staff", "admin"])
            
            create_button = st.form_submit_button("Create User")
            
            if create_button:
                if not all([new_username, new_password, confirm_password, new_name, new_email]):
                    st.error("Please fill all required fields (*)")
                elif new_password != confirm_password:
                    st.error("Passwords do not match")
                elif len(new_password) < 6:
                    st.error("Password must be at least 6 characters")
                else:
                    success, message = create_user(
                        username=new_username,
                        password=new_password,
                        name=new_name,
                        email=new_email,
                        role=new_role,
                        created_by=st.session_state.user_id
                    )
                    if success:
                        st.success(message)
                        st.rerun()
                    else:
                        st.error(message)
    
    # User list and management
    st.subheader("Existing Users")
    
    # Refresh users list
    users = get_all_users()
    
    if not users:
        st.info("No users found in database")
        return
    
    # Display users in a table with actions
    user_data = []
    for username, user_info in users.items():
        user_data.append({
            "ID": user_info['id'],
            "Username": username,
            "Name": user_info.get('name', ''),
            "Email": user_info.get('email', ''),
            "Role": user_info.get('role', 'staff'),
            "Created": user_info.get('created_at', ''),
            "Created By": user_info.get('created_by', 'system'),
            "Last Login": user_info.get('last_login', 'Never')
        })
    
    if user_data:
        # Display user count
        st.write(f"**Total Active Users:** {len(user_data)}")
        
        # User table
        df = pd.DataFrame(user_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
        
        # User actions in separate expanders for better organization
        st.subheader("User Actions")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            with st.expander("✏️ Edit User", expanded=True):
                edit_users = [user for user in user_data if user["Username"] != "admin"]
                if edit_users:
                    edit_username = st.selectbox("Select user to edit", 
                                               [user["Username"] for user in edit_users],
                                               key="edit_select")
                    if edit_username:
                        user_to_edit = users[edit_username]
                        with st.form(f"edit_form_{edit_username}"):
                            st.write(f"Editing: **{edit_username}**")
                            edit_name = st.text_input("Full Name", value=user_to_edit.get('name', ''), key=f"name_{edit_username}")
                            edit_email = st.text_input("Email", value=user_to_edit.get('email', ''), key=f"email_{edit_username}")
                            edit_role = st.selectbox("Role", ["staff", "admin"], 
                                                   index=0 if user_to_edit.get('role') == "staff" else 1,
                                                   key=f"role_{edit_username}")
                            
                            if st.form_submit_button("💾 Update User", use_container_width=True):
                                success, message = update_user(
                                    user_to_edit['id'],
                                    name=edit_name,
                                    email=edit_email,
                                    role=edit_role
                                )
                                if success:
                                    st.success(message)
                                    st.rerun()
                                else:
                                    st.error(message)
                else:
                    st.info("No users available to edit")
        
        with col2:
            with st.expander("🔑 Change Password", expanded=True):
                pwd_users = [user for user in user_data]
                if pwd_users:
                    pwd_username = st.selectbox("Select user", 
                                              [user["Username"] for user in pwd_users],
                                              key="pwd_select")
                    if pwd_username:
                        user_to_pwd = users[pwd_username]
                        with st.form(f"pwd_form_{pwd_username}"):
                            st.write(f"Changing password for: **{pwd_username}**")
                            new_pwd = st.text_input("New Password", type="password", key=f"new_pwd_{pwd_username}")
                            confirm_pwd = st.text_input("Confirm Password", type="password", key=f"confirm_pwd_{pwd_username}")
                            
                            if st.form_submit_button("🔐 Change Password", use_container_width=True):
                                if not new_pwd or not confirm_pwd:
                                    st.error("Please enter both password fields")
                                elif new_pwd != confirm_pwd:
                                    st.error("Passwords do not match")
                                elif len(new_pwd) < 6:
                                    st.error("Password must be at least 6 characters")
                                else:
                                    success, message = update_user(user_to_pwd['id'], password=new_pwd)
                                    if success:
                                        st.success("Password updated successfully")
                                        st.rerun()
                                    else:
                                        st.error(message)
                else:
                    st.info("No users available")
        
        with col3:
            with st.expander("🗑️ Delete User", expanded=True):
                del_users = [user for user in user_data if user["Username"] != "admin"]
                if del_users:
                    del_username = st.selectbox("Select user to delete", 
                                              [user["Username"] for user in del_users],
                                              key="del_select")
                    if del_username:
                        user_to_del = users[del_username]
                        st.warning(f"⚠️ You are about to delete user: **{del_username}**")
                        st.write(f"Name: {user_to_del.get('name', 'N/A')}")
                        st.write(f"Email: {user_to_del.get('email', 'N/A')}")
                        st.write(f"User ID: {user_to_del['id']}")
                        
                        # Add confirmation with user ID for extra safety
                        confirm_text = st.text_input(
                            f"Type 'DELETE {del_username}' to confirm:",
                            placeholder=f"DELETE {del_username}",
                            key=f"confirm_delete_{del_username}"
                        )
                        
                        if st.button("🚫 Confirm Delete User", type="secondary", use_container_width=True, key=f"delete_btn_{del_username}"):
                            if confirm_text == f"DELETE {del_username}":
                                success, message = delete_user(user_to_del['id'], del_username)
                                if success:
                                    st.success(message)
                                    # Force refresh by rerunning
                                    st.rerun()
                                else:
                                    st.error(message)
                            else:
                                st.error("Confirmation text does not match. Please type exactly as shown.")
                else:
                    st.info("No users available to delete")
    
    # Refresh button
    if st.button("🔄 Refresh User List"):
        st.rerun()
    
    # Debug information (can be removed in production)
    with st.expander("🔍 Debug Information"):
        st.write("### Current Session State")
        st.json({
            "user_id": st.session_state.user_id,
            "username": st.session_state.username,
            "user_role": st.session_state.user_role
        })
        
        st.write("### Database Information")
        # Use the debug function from auth.py instead of direct database calls
        all_db_users = debug_get_all_users_including_inactive()
        if all_db_users:
            st.write("All users in database:")
            for user in all_db_users:
                st.write(f"- ID: {user['id']}, Username: {user['username']}, Active: {user['active']}")
        else:
            st.error("Could not fetch database information")

def show_audit_log():
    """Show audit log of user activities"""
    st.subheader("Audit Log - System Activities")
    
    logs = get_audit_logs(limit=50)
    
    if not logs:
        st.info("No audit logs available")
        return
    
    # Convert logs to dataframe
    log_data = []
    for log in logs:
        log_data.append({
            "Timestamp": log[0],
            "Username": log[1],
            "Action": log[2],
            "Details": log[3],
            "User Name": log[4] if log[4] else log[1]
        })
    
    df = pd.DataFrame(log_data)
    st.dataframe(df, use_container_width=True)
    
    # Export audit log
    if st.button("Export Audit Log to CSV"):
        csv = df.to_csv(index=False)
        st.download_button(
            label="Download CSV",
            data=csv,
            file_name=f"audit_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

def show_training_docs():
    """Show training documents from database"""
    st.subheader("Training Documents")
    
    docs = get_training_docs()
    
    if not docs:
        st.info("No training documents uploaded yet")
        return
    
    doc_data = []
    for doc in docs:
        doc_data.append({
            "Document Name": doc[0],
            "Type": doc[1],
            "Uploaded By": doc[2],
            "Uploaded At": doc[3]
        })
    
    df = pd.DataFrame(doc_data)
    st.dataframe(df, use_container_width=True)
    
    st.subheader("Draft Statistics")
    stats = get_all_drafts_stats()
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Drafts", stats['total_drafts'])
    with col2:
        st.metric("Case Types", len(stats['drafts_by_type']))
    with col3:
        st.metric("Active Users", len(get_all_users()))
    
    # Drafts by case type
    if stats['drafts_by_type']:
        st.write("### Drafts by Case Type")
        type_df = pd.DataFrame(list(stats['drafts_by_type'].items()), columns=['Case Type', 'Count'])
        st.bar_chart(type_df.set_index('Case Type'))

# ----------------------------
# Admin dashboard
# ----------------------------
def show_admin_dashboard():
    st.title("👨‍💼 Admin Dashboard")
    st.info("Manage users, upload training data, and monitor system activity.")
    
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["👥 User Management", "📤 Train Model", "📊 Database Status", "📋 Audit Log", "📈 Analytics"])
    
    with tab1:
        show_user_management()
    
    with tab2:
        st.subheader("Upload Templates")
        files = st.file_uploader("Choose template files", type=["txt","docx","pdf"], accept_multiple_files=True, key="admin_upload")
        if files and st.button("Process & Store Templates"):
            process_training_files(files, "template")
        
        # Show training documents
        show_training_docs()
    
    with tab3:
        st.subheader("Vector Database Status")
        if st.button("Check Database Status"):
            show_vector_db_status()
    
    with tab4:
        show_audit_log()
    
    with tab5:
        show_training_docs()

# ----------------------------
# Staff dashboard
# ----------------------------
def show_staff_dashboard():
    st.title("👩‍💻 Staff Dashboard")
    tab1, tab2 = st.tabs(["📝 Generate Draft", "📋 Draft History"])

    with tab1:
        show_draft_generation_interface("staff")
    with tab2:
        st.header("Your Draft History")
        user_drafts = [d for d in st.session_state.draft_history if d['user'] == st.session_state.username]
        if not user_drafts:
            st.info("No drafts generated yet")
        else:
            for i, draft in enumerate(reversed(user_drafts)):
                with st.expander(f"Draft {len(user_drafts)-i} - {draft['timestamp']}"):
                    st.write(f"**Case Type:** {draft['case_type']}")
                    st.text_area("Draft Content", draft['content'], height=200, key=f"history_{i}")

# ----------------------------
# Draft generation interface
# ----------------------------
def show_draft_generation_interface(user_type):
    st.header("Generate Demand Draft")

    # Case Details - Better aligned form
    with st.container():
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("👤 Party Information")
            plaintiff = st.text_input("**Plaintiff Name**", placeholder="Sarah Davis", key="plaintiff_input")
            defendant = st.text_input("**Defendant Name**", placeholder="Mark Thompson", key="defendant_input")
            case_type = st.selectbox(
                "**Case Type**",
                ["Personal Injury", "Medical Malpractice", "Workers Compensation", "Auto Accident", "Other"],
                key="case_type_input"
            )
        
        with col2:
            st.subheader("📍 Case Details")
            jurisdiction = st.selectbox(
                "**Jurisdiction**",
                ["California", "New York", "Texas", "Florida", "Federal", "Other"],
                key="jurisdiction_input"
            )
            injury_type = st.text_input("**Injury Type**", placeholder="Whiplash, Mild Concussion", key="injury_type_input")
            treatment_cost = st.number_input("**Treatment Cost ($)**", min_value=0, value=10000, key="treatment_cost_input")

    # Additional Details
    st.subheader("📋 Incident Details")
    additional_details = st.text_area(
        "**Describe the incident, timeline, and relevant information:**",
        placeholder="e.g., Client was rear-ended at a red light on June 5, 2024. The impact caused immediate neck pain and headache. Client was transported via ambulance to emergency room...",
        height=100,
        key="additional_details_input"
    )

    # Attorney Information
    st.subheader("⚖️ Attorney & Law Firm")
    col1, col2 = st.columns(2)
    with col1:
        attorney_name = st.text_input("**Attorney Name**", placeholder="Elizabeth Grant, Esq.", key="attorney_input")
    with col2:
        law_firm_name = st.text_input("**Law Firm Name**", placeholder="Grant & Associates Legal Group, LLP", key="lawfirm_input")

    if not attorney_name:
        attorney_name = "Legal Counsel"
    if not law_firm_name:
        law_firm_name = "Law Office of Justice & Associates"

    # Medical Records
    st.subheader("🏥 Medical Records")
    
    medical_files = st.file_uploader(
        "**Upload Medical Records (PDF/DOCX/TXT)**",
        type=["pdf", "docx", "txt"],
        accept_multiple_files=True,
        key=f"medical_upload_{user_type}",
        help="Upload medical reports, bills, and treatment records"
    )

    medical_text = st.text_area(
        "**Or enter medical summary directly:**",
        placeholder="Patient presented with neck pain and headache following motor vehicle accident. Emergency room treatment included cervical spine X-rays and pain management. Diagnosed with whiplash and mild concussion. Follow-up treatment included 4 weeks of chiropractic therapy...",
        value=st.session_state.get("medical_text", ""),
        height=150,
        key=f"medical_summary_{user_type}"
    )

    st.session_state.medical_text = medical_text.strip()

    if medical_files:
        processed_text = ""
        for file in medical_files:
            text = get_document_processor().process_uploaded_file(file)
            processed_text += f"\n\n--- {file.name} ---\n{text}"
        st.session_state.medical_text = processed_text
        with st.expander("📄 Extracted Medical Text", expanded=False):
            st.text_area("Medical Records Content", processed_text, height=200, key="extracted_medical")

    # Detect input changes
    current_snapshot = {
        "plaintiff": plaintiff.strip(),
        "defendant": defendant.strip(),
        "case_type": case_type,
        "jurisdiction": jurisdiction,
        "injury_type": injury_type.strip(),
        "treatment_cost": treatment_cost,
        "additional_details": additional_details.strip(),
        "medical_text": st.session_state.medical_text.strip()
    }

    if current_snapshot != st.session_state.last_snapshot:
        st.session_state.current_draft = ""
        st.session_state.last_snapshot = current_snapshot.copy()

    # Generate Draft Button
    st.markdown("---")
    if st.button("🤖 **GENERATE DRAFT**", type="primary", use_container_width=True):
        if not plaintiff or not defendant:
            st.error("❌ Please fill in Plaintiff and Defendant names.")
            return
        if not st.session_state.medical_text.strip():
            st.error("❌ Please provide medical records or a summary before generating.")
            return

        case_details = {
            "plaintiff": plaintiff,
            "defendant": defendant,
            "case_type": case_type,
            "jurisdiction": jurisdiction,
            "injury_type": injury_type,
            "treatment_cost": treatment_cost,
            "additional_details": additional_details,
            "attorney_name": attorney_name,
            "law_firm_name": law_firm_name
        }

        with st.spinner("🔍 Searching templates and generating professional draft..."):
            try:
                pinecone_mgr = get_pinecone_manager()
                ai_mgr = get_ai_manager()
                query_text = f"{case_type.lower()} demand letter template"

                # Retrieve templates
                results = pinecone_mgr.search_similar(
                    query_text,
                    filter_dict={"document_type": {"$in": ["template"]}},
                    top_k=8,
                )

                retrieved_templates = []
                for match in getattr(results, "matches", []):
                    meta = getattr(match, "metadata", {})
                    score = getattr(match, "score", 0)
                    if score > 0.5 and "text" in meta:
                        retrieved_templates.append(meta["text"])

                # Fallback if no templates
                if not retrieved_templates:
                    fallback_results = pinecone_mgr.search_similar(
                        f"{case_type} demand letter {jurisdiction}", top_k=6
                    )
                    for match in getattr(fallback_results, "matches", []):
                        meta = getattr(match, "metadata", {})
                        score = getattr(match, "score", 0)
                        if score > 0.45 and "text" in meta:
                            retrieved_templates.append(meta["text"])

                # Generate draft via AI
                draft = ai_mgr.generate_draft(case_details, st.session_state.medical_text, retrieved_templates)
                if "Error generating draft" in draft:
                    st.warning("⚠️ AI generation failed, using fallback template.")
                    draft = create_fallback_draft(case_details, st.session_state.medical_text)
                else:
                    draft = format_draft_with_tables(draft)

                # Store draft in session state
                st.session_state.current_draft = draft
                
                # Save draft to database
                draft_id = save_draft_to_db(
                    st.session_state.user_id,
                    st.session_state.username,
                    case_type,
                    draft,
                    st.session_state.medical_text,
                    case_details
                )
                
                if draft_id:
                    # Reload drafts from database to ensure consistency
                    load_user_drafts(st.session_state.user_id)
                    st.success("✅ Professional draft generated and saved successfully!")
                else:
                    st.error("❌ Draft generated but failed to save to database")

            except Exception as e:
                st.error(f"❌ Draft generation failed: {str(e)}")
                draft = create_fallback_draft(case_details, st.session_state.medical_text)
                st.session_state.current_draft = draft

    # Handle AI Rewrite Trigger
    if st.session_state.ai_rewrite_trigger:
        with st.spinner("🔄 Rewriting draft with AI..."):
            current_draft_content = st.session_state.get("current_draft", "")
            improvement_goal = st.session_state.ai_rewrite_goal
            
            if current_draft_content.strip() and improvement_goal:
                improved_draft = rewrite_draft_with_ai(current_draft_content, improvement_goal)
                if improved_draft and "Error" not in improved_draft:
                    st.session_state.current_draft = improved_draft
                    st.session_state.ai_rewrite_trigger = False
                    st.session_state.ai_rewrite_goal = ""
                    st.success("✅ Draft improved successfully!")
                else:
                    st.error("❌ Failed to rewrite draft. Please try again.")
                    st.session_state.ai_rewrite_trigger = False
            else:
                st.error("No draft content or improvement goal provided.")
                st.session_state.ai_rewrite_trigger = False

    # Display Generated Draft
    if st.session_state.get("current_draft"):
        st.markdown("---")
        st.subheader("📄 Generated Draft")
        
        # Editable draft area with better styling
        edited_draft = st.text_area(
            "**Review and Edit Draft:**",
            value=st.session_state.current_draft,
            height=400,
            key="draft_editor"
        )
        
        # Update current draft if edited
        if edited_draft != st.session_state.current_draft:
            st.session_state.current_draft = edited_draft

        # Export and Rewrite Options
        st.subheader("🛠️ Document Tools")
        
        # Export buttons in a nice layout
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📄 **Export as Word**", use_container_width=True, key="word_export_btn"):
                current_draft = st.session_state.get("current_draft", "")
                if not current_draft.strip():
                    st.error("❌ No draft content available to export.")
                else:
                    with st.spinner("🔄 Generating Word document..."):
                        word_buffer = create_professional_word_download(current_draft, "legal_demand_draft")
                        # Create unique key for download button
                        download_key = f"word_download_{datetime.now().strftime('%H%M%S')}"
                        st.download_button(
                            label="⬇️ **Download Word Document**",
                            data=word_buffer,
                            file_name="legal_demand_draft.docx",
                            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                            use_container_width=True,
                            key=download_key
                        )
                        st.success("✅ Word document generated successfully!")
                    
        with col2:
            if st.button("📊 **Export as PDF**", use_container_width=True, key="pdf_export_btn"):
                current_draft = st.session_state.get("current_draft", "")
                if not current_draft.strip():
                    st.error("❌ No draft content available to export.")
                else:
                    with st.spinner("🔄 Generating PDF..."):
                        pdf_buffer = create_professional_pdf_download(current_draft, "legal_demand_draft")
                        
                        if pdf_buffer:
                            # Check if buffer has content
                            pdf_buffer.seek(0, 2)
                            size = pdf_buffer.tell()
                            pdf_buffer.seek(0)
                            
                            if size > 100:
                                download_key = f"pdf_download_{datetime.now().strftime('%H%M%S')}"
                                st.download_button(
                                    label="⬇️ **Download PDF Document**",
                                    data=pdf_buffer,
                                    file_name="legal_demand_draft.pdf",
                                    mime="application/pdf",
                                    use_container_width=True,
                                    key=download_key
                                )
                                st.success("✅ PDF generated successfully!")
                            else:
                                st.error("❌ Generated PDF is empty. Please try again.")
                        else:
                            st.error("❌ PDF generation failed. Please try again.")

        # AI Rewrite Section
        st.subheader("✨ AI Rewrite Options")
        col1, col2 = st.columns([3, 1])
        with col1:
            rewrite_goal = st.selectbox(
                "**Choose improvement goal:**",
                st.session_state.rewrite_goals,
                key="rewrite_goal_select"
            )
            custom_goal = st.text_input(
                "**Or enter custom goal:**",
                placeholder="e.g., Make tone more persuasive, improve clarity...",
                key="custom_goal_input"
            )
        with col2:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("🔄 **AI Rewrite**", use_container_width=True, key="ai_rewrite_btn"):
                final_goal = custom_goal.strip() if custom_goal.strip() else rewrite_goal
                if not final_goal:
                    st.warning("⚠️ Please select or enter an improvement goal.")
                else:
                    # Set trigger for AI rewrite
                    st.session_state.ai_rewrite_trigger = True
                    st.session_state.ai_rewrite_goal = final_goal
                    st.rerun()

# ----------------------------
# Main application
# ----------------------------
def main():
    if st.session_state.user_role == "admin":
        show_admin_dashboard()
    else:
        show_staff_dashboard()

if __name__ == "__main__":
    main()
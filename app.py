from flask import Flask, render_template, redirect, url_for, flash, request, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from dotenv import load_dotenv
import uuid

# Import utilities
from utils import extract_text_from_pdf, extract_text_from_docx, score_resume
from models import db, User, Resume, KeywordList
from forms import LoginForm, UserRegistrationForm, AdminRegistrationForm, ResumeUploadForm, KeywordForm

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['RESULTS_FOLDER'] = 'results'

# Ensure upload and results directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULTS_FOLDER'], exist_ok=True)

# Initialize extensions
db.init_app(app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create all database tables
with app.app_context():
    db.create_all()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            if user.is_admin:
                return redirect(next_page) if next_page else redirect(url_for('admin_dashboard'))
            return redirect(next_page) if next_page else redirect(url_for('user_dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('user_dashboard'))
    
    user_form = UserRegistrationForm()
    admin_form = AdminRegistrationForm()
    
    if 'register_user' in request.form and user_form.validate_on_submit():
        hashed_password = generate_password_hash(user_form.password.data)
        user = User(username=user_form.username.data, email=user_form.email.data, 
                    password=hashed_password, is_admin=False)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    if 'register_admin' in request.form and admin_form.validate_on_submit():
        security_code = os.getenv('SECURITY_CODE')
        if admin_form.security_code.data != security_code:
            flash('Invalid security code for admin registration.', 'danger')
            return render_template('register.html', title='Register', 
                                  user_form=user_form, admin_form=admin_form)
        
        hashed_password = generate_password_hash(admin_form.password.data)
        admin = User(username=admin_form.username.data, email=admin_form.email.data, 
                     password=hashed_password, is_admin=True)
        db.session.add(admin)
        db.session.commit()
        flash('Admin account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', title='Register', 
                          user_form=user_form, admin_form=admin_form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard/user', methods=['GET', 'POST'])
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    form = ResumeUploadForm()
    if form.validate_on_submit():
        file = form.resume.data
        filename = secure_filename(file.filename)
        # Generate unique filename to avoid conflicts
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        
        # Extract text from resume
        if filename.endswith('.pdf'):
            text = extract_text_from_pdf(file_path)
        elif filename.endswith('.docx'):
            text = extract_text_from_docx(file_path)
        else:
            text = "Unsupported file format"
        
        # Save resume to database
        resume = Resume(
            filename=filename,
            file_path=file_path,
            content=text,
            user_id=current_user.id
        )
        db.session.add(resume)
        db.session.commit()
        
        flash('Resume uploaded successfully!', 'success')
        return redirect(url_for('user_dashboard'))
    
    # Get all user's resumes
    resumes = Resume.query.filter_by(user_id=current_user.id).order_by(Resume.upload_date.desc()).all()
    return render_template('dashboard_user.html', title='User Dashboard', 
                          form=form, resumes=resumes)

@app.route('/dashboard/admin', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    keyword_form = KeywordForm()
    if keyword_form.validate_on_submit():
        keywords = [keyword.strip() for keyword in keyword_form.keywords.data.split(',')]
        
        # Save keyword list
        keyword_list = KeywordList(
            keywords=keyword_form.keywords.data,
            user_id=current_user.id
        )
        db.session.add(keyword_list)
        db.session.commit()
        
        # Process all resumes with these keywords
        resumes = Resume.query.all()
        for resume in resumes:
            score, matched_keywords = score_resume(resume.content, keywords)
            resume.score = score
            resume.matched_keywords = ', '.join(matched_keywords)
            resume.keyword_count = len(matched_keywords)
        
        db.session.commit()
        flash('Resumes processed successfully!', 'success')
        return redirect(url_for('results'))
    
    # Get recent keyword lists
    keyword_lists = KeywordList.query.filter_by(user_id=current_user.id).order_by(KeywordList.created_at.desc()).limit(5).all()
    
    # Get total user and resume counts
    total_users = User.query.filter_by(is_admin=False).count()
    total_resumes = Resume.query.count()
    
    return render_template('dashboard_admin.html', title='Admin Dashboard', 
                          keyword_form=keyword_form, keyword_lists=keyword_lists,
                          total_users=total_users, total_resumes=total_resumes)

@app.route('/results')
@login_required
def results():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    # Get all resumes ordered by score
    resumes = Resume.query.order_by(Resume.score.desc()).all()
    
    # Get top 20 resumes
    top_resumes = resumes[:20] if len(resumes) >= 20 else resumes
    
    return render_template('results.html', title='Screening Results', 
                          resumes=resumes, top_resumes=top_resumes)

@app.route('/export_results')
@login_required
def export_results():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    import pandas as pd
    # Get all resumes ordered by score
    resumes = Resume.query.order_by(Resume.score.desc()).all()
    
    # Create DataFrame
    data = []
    for resume in resumes:
        user = User.query.get(resume.user_id)
        data.append({
            'User': user.username,
            'Email': user.email,
            'Resume': resume.filename,
            'Score': resume.score,
            'Matched Keywords': resume.matched_keywords,
            'Keyword Count': resume.keyword_count,
            'Upload Date': resume.upload_date
        })
    
    df = pd.DataFrame(data)
    
    # Create CSV file
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    csv_filename = f"resume_results_{timestamp}.csv"
    csv_path = os.path.join(app.config['RESULTS_FOLDER'], csv_filename)
    df.to_csv(csv_path, index=False)
    
    return send_file(csv_path, as_attachment=True)

@app.route('/view_resume/<int:resume_id>')
@login_required
def view_resume(resume_id):
    resume = Resume.query.get_or_404(resume_id)
    
    # Check if the user is the owner or an admin
    if resume.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to view this resume.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    user = User.query.get(resume.user_id)
    return render_template('view_resume.html', title='View Resume', 
                          resume=resume, user=user)

if __name__ == '__main__':
    app.run(debug=True)
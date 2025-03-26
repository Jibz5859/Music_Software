from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import logging
import subprocess
import argparse
import time
import re
import yt_dlp
import warnings
from sqlalchemy import exc as sa_exc
from mutagen.easyid3 import EasyID3
from mutagen.mp3 import MP3
import sys
import io
import librosa
import stripe

# Configure Unicode handling
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Suppress SQLAlchemy 2.0 warnings
warnings.filterwarnings("ignore", category=sa_exc.SAWarning)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key_here')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///music_master.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), "uploads")
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB limit
app.config['ALLOWED_EXTENSIONS'] = {'mp3', 'wav', 'ogg', 'flac', 'm4a', 'webm'}
app.config['STRIPE_PUBLIC_KEY'] = 'your_stripe_public_key'
app.config['STRIPE_SECRET_KEY'] = 'your_stripe_secret_key'
app.config['STRIPE_WEBHOOK_SECRET'] = 'your_webhook_secret'

# Initialize Stripe
stripe.api_key = app.config['STRIPE_SECRET_KEY']

# Ensure FFmpeg is in PATH (Windows specific)
if os.name == 'nt':
    ffmpeg_path = os.path.join(os.environ.get('CONDA_PREFIX', ''), 'Library', 'bin')
    if os.path.exists(ffmpeg_path):
        os.environ['PATH'] = ffmpeg_path + os.pathsep + os.environ['PATH']

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('music_software.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logging.getLogger('werkzeug').setLevel(logging.WARNING)

# Define the User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    stripe_customer_id = db.Column(db.String(100))
    subscription_id = db.Column(db.String(100))
    subscription_status = db.Column(db.String(20), default='inactive')
    plan_type = db.Column(db.String(20))
    free_songs_used = db.Column(db.Integer, default=0)

# Forms
class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=100)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', 
                                   validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class YouTubeForm(FlaskForm):
    youtube_url = StringField('YouTube URL', validators=[DataRequired(), Length(max=500)])
    convert_to_mp3 = BooleanField('Convert to MP3', default=True)
    submit = SubmitField('Download')

class SubscriptionForm(FlaskForm):
    plan = SelectField('Plan', choices=[
        ('monthly', 'Monthly ($9.99/month)'),
        ('quarterly', 'Quarterly ($24.99/quarter)'),
        ('yearly', 'Yearly ($89.99/year)')
    ], validators=[DataRequired()])
    submit = SubmitField('Subscribe')

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def sanitize_filename(filename):
    """Clean up filenames to be filesystem-safe"""
    filename = re.sub(r'[^\w\-_. ]', '', filename)
    return filename[:100]

def sanitize_youtube_title(title):
    """Clean up YouTube video titles for filenames"""
    title = re.sub(r'[^\w\s-]', '', title).strip()
    title = re.sub(r'[-\s]+', '_', title)
    return title[:50]

def is_valid_youtube_url(url):
    """Validate YouTube URL format"""
    patterns = [
        r'^https?://(www\.)?youtube\.com/watch\?v=([^&]+)',
        r'^https?://youtu\.be/([^?]+)',
        r'^https?://(www\.)?youtube\.com/shorts/([^?]+)'
    ]
    return any(re.match(pattern, url) for pattern in patterns)

def convert_audio_to_mp3(input_path, output_folder, metadata=None):
    """Robust audio conversion with Windows MediaFoundation encoder"""
    if not os.path.exists(input_path):
        return None

    try:
        # Create safe filename (ASCII-only)
        base_name = re.sub(r'[^\x00-\x7F]+', '', os.path.basename(input_path))
        base_name = sanitize_filename(os.path.splitext(base_name)[0])
        output_path = os.path.join(output_folder, f"{base_name}.mp3")

        # Conversion command using mp3_mf
        cmd = [
            'ffmpeg',
            '-i', f'"{input_path}"',
            '-c:a', 'mp3_mf',
            '-q:a', '2',
            '-y',
            f'"{output_path}"'
        ]

        # Run conversion with proper encoding handling
        result = subprocess.run(
            ' '.join(cmd),
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding='utf-8',
            errors='replace'
        )

        # Add metadata if successful
        if os.path.exists(output_path):
            try:
                audio = MP3(output_path, ID3=EasyID3)
                audio['title'] = metadata.get('title', 'Unknown')[:30]
                audio['artist'] = metadata.get('artist', 'Unknown')[:30]
                audio.save()
            except Exception as e:
                app.logger.warning(f"Metadata error: {str(e)}")
            return output_path

        return None

    except subprocess.CalledProcessError as e:
        app.logger.error(f"Conversion failed: {e.stderr}")
        return None
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}")
        return None

def download_youtube_audio(url, output_path, should_convert=False):
    """Reliable YouTube audio download with conversion option"""
    max_retries = 2
    retry_delay = 2
    
    for attempt in range(max_retries):
        try:
            ydl_opts = {
                'format': 'bestaudio/best',
                'outtmpl': os.path.join(output_path, '%(title)s.%(ext)s'),
                'quiet': True,
                'no_warnings': True,
                'noplaylist': True,
                'extract_audio': False,
                'http_headers': {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept-Language': 'en-US,en;q=0.9'
                },
                'ignoreerrors': True,
                'retries': 3,
                'fragment_retries': 3,
                'skip_unavailable_fragments': True,
                'windowsfilenames': True,
                'encoding': 'utf-8'
            }
            
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(url, download=True)
                if not info:
                    raise ValueError("Failed to extract video info")
                
                original_path = ydl.prepare_filename(info)
                original_path = os.path.join(output_path, os.path.basename(original_path))
                
                if should_convert:
                    metadata = {
                        'title': info.get('title', 'Unknown'),
                        'artist': info.get('uploader', 'Unknown')
                    }
                    converted_path = convert_audio_to_mp3(original_path, output_path, metadata)
                    if converted_path:
                        try:
                            os.remove(original_path)
                        except OSError:
                            pass
                        return converted_path
                    return original_path
                return original_path
                
        except Exception as e:
            app.logger.error(f"Attempt {attempt + 1} failed: {str(e)}")
            if attempt == max_retries - 1:
                return None
            time.sleep(retry_delay)
    
    return None

def get_user_downloads():
    """Get list of downloaded files for current user"""
    if not current_user.is_authenticated:
        return []
    
    download_dir = app.config['UPLOAD_FOLDER']
    if not os.path.exists(download_dir):
        return []
    
    downloads = []
    for filename in os.listdir(download_dir):
        filepath = os.path.join(download_dir, filename)
        if os.path.isfile(filepath):
            stats = os.stat(filepath)
            downloads.append({
                'filename': filename,
                'size': round(stats.st_size / (1024 * 1024), 2),  # MB
                'date': datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M')
            })
    
    return sorted(downloads, key=lambda x: x['date'], reverse=True)

def check_download_limit():
    """Check if user has reached download limit"""
    if current_user.subscription_status == 'active':
        return True
    return current_user.free_songs_used < 3

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            # Create Stripe customer first
            customer = stripe.Customer.create(email=form.email.data)
            
            # Then create user
            hashed_password = generate_password_hash(form.password.data)
            user = User(
                email=form.email.data,
                password=hashed_password,
                stripe_customer_id=customer.id
            )
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Registration failed: {str(e)}', 'danger')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    downloads = get_user_downloads()
    return render_template('dashboard.html', 
                         downloads=downloads,
                         subscription_status=current_user.subscription_status,
                         free_songs_remaining=max(0, 3 - current_user.free_songs_used))

@app.route('/pricing')
@login_required
def pricing():
    return render_template('pricing.html', 
                         stripe_public_key=app.config['STRIPE_PUBLIC_KEY'],
                         user=current_user)

@app.route('/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    try:
        data = request.get_json()
        price_id = data['priceId']
        
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            mode='subscription',
            success_url=url_for('payment_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('pricing', _external=True),
            customer=current_user.stripe_customer_id,
            metadata={
                'user_id': current_user.id
            }
        )
        
        return jsonify({'sessionId': checkout_session.id})
    except Exception as e:
        return jsonify(error=str(e)), 400

@app.route('/payment-success')
@login_required
def payment_success():
    session_id = request.args.get('session_id')
    try:
        session = stripe.checkout.Session.retrieve(session_id)
        if session.payment_status == 'paid':
            current_user.subscription_status = 'active'
            current_user.plan_type = session.metadata.get('plan_type', 'monthly')
            db.session.commit()
            flash('Payment successful! Your subscription is now active.', 'success')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash(f'Error verifying payment: {str(e)}', 'danger')
        return redirect(url_for('pricing'))

@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, app.config['STRIPE_WEBHOOK_SECRET']
        )
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except stripe.error.SignatureVerificationError as e:
        return jsonify({'error': str(e)}), 400

    # Handle subscription events
    if event['type'] == 'customer.subscription.updated':
        subscription = event['data']['object']
        user = User.query.filter_by(stripe_customer_id=subscription.customer).first()
        if user:
            user.subscription_status = subscription.status
            user.subscription_id = subscription.id
            db.session.commit()

    return jsonify({'success': True}), 200

@app.route('/youtube', methods=['GET', 'POST'])
@login_required
def youtube_download():
    if not check_download_limit():
        flash('You have reached your free download limit. Please subscribe to continue.', 'warning')
        return redirect(url_for('pricing'))

    form = YouTubeForm()
    if form.validate_on_submit():
        url = form.youtube_url.data
        if not is_valid_youtube_url(url):
            flash('Invalid YouTube URL', 'danger')
            return render_template('youtube.html', form=form)
        
        try:
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            audio_path = download_youtube_audio(
                url, 
                app.config['UPLOAD_FOLDER'],
                form.convert_to_mp3.data
            )
            
            if audio_path:
                if current_user.subscription_status != 'active':
                    current_user.free_songs_used += 1
                    db.session.commit()
                
                flash(f'Successfully downloaded: {os.path.basename(audio_path)}', 'success')
                return render_template('youtube.html', 
                                    form=form, 
                                    audio_file=os.path.basename(audio_path),
                                    free_songs_remaining=max(0, 3 - current_user.free_songs_used))
            else:
                flash('Failed to download audio', 'danger')
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
        
        return redirect(url_for('youtube_download'))
    
    return render_template('youtube.html', 
                         form=form,
                         free_songs_remaining=max(0, 3 - current_user.free_songs_used))

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/analyze/<filename>')
@login_required
def analyze(filename):
    """Analyze audio file and return chord progression"""
    try:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Load audio with librosa
        y, sr = librosa.load(filepath)
        
        # Extract chroma features (simplified chord analysis)
        chroma = librosa.feature.chroma_stft(y=y, sr=sr)
        
        # Get most prominent chords (simplified example)
        chords = librosa.hz_to_note(chroma.mean(axis=1))
        
        return jsonify({
            "status": "success",
            "chords": chords.tolist(),
            "tempo": float(librosa.beat.tempo(y=y, sr=sr)[0]),
            "key": librosa.estimate_tuning(y=y, sr=sr)  # Returns pitch offset
        })
        
    except Exception as e:
        logging.error(f"Analysis failed: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--test-youtube', action='store_true', help='Test YouTube download functionality')
    args = parser.parse_args()

    with app.app_context():
        db.create_all()
    
    if args.test_youtube:
        test_youtube_download()
    else:
        app.run(debug=True)
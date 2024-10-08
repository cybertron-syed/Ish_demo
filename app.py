import os
import boto3
from flask import Flask, render_template, request, redirect, url_for, flash, session
from botocore.exceptions import ClientError, NoCredentialsError
import secrets
from dotenv import load_dotenv
import psycopg2
from psycopg2 import sql
from datetime import datetime

load_dotenv()

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

USER_POOL_ID = os.getenv('USER_POOL_ID')
CLIENT_ID = os.getenv('CLIENT_ID')
REGION = os.getenv('REGION')
S3_BUCKET = os.getenv('S3_BUCKET')
S3_REGION = os.getenv('S3_REGION')
SNS_TOPIC_ARN = os.getenv('SNS_TOPIC_ARN')

DB_HOST = os.getenv('DB_HOST')
DB_NAME = os.getenv('DB_NAME')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')

s3 = boto3.client('s3', region_name=S3_REGION)
cognito = boto3.client('cognito-idp', region_name=REGION)
sns = boto3.client('sns', region_name='us-east-1')


@app.route('/', methods=['GET', 'POST'])
def home():
    if 'username' not in session:
        return redirect(url_for('login')) 

    hospital_name = session['username'] 

    create_table_if_not_exists()

    if request.method == 'POST':
        files = request.files.getlist('files') 
        if files:
            s3_folder_path = f"{hospital_name}/" 
            for file in files: 
                if file:
                    s3_file_path = s3_folder_path + file.filename 
                    try:
                        s3.upload_fileobj(file, S3_BUCKET, s3_file_path)
                        file_url = f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/{s3_file_path}"

                        sns.publish(
                            TopicArn=SNS_TOPIC_ARN,
                            Message=f"File '{file.filename}' uploaded successfully to '{s3_folder_path}'. File URL: {file_url}",
                            Subject='File Upload Notification'
                        )

                        log_to_db(file.filename, hospital_name, file_url)

                        flash(f"File '{file.filename}' uploaded successfully to folder '{s3_folder_path}'", "success")
                    except NoCredentialsError:
                        flash("Credentials not available", "danger")
                    except Exception as e:
                        flash(f"Error uploading file: {e}", "danger")
                        return redirect(url_for('home'))
        else:
            flash("No files provided", "warning")

    uploads = get_all_uploads(hospital_name)

    return render_template('home.html', username=hospital_name, uploads=uploads)
    
def create_table_if_not_exists():
    try:
        conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASSWORD)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS file_uploads (
                            id SERIAL PRIMARY KEY,
                            filename VARCHAR(255),
                            hospital_name VARCHAR(255),
                            file_url TEXT,
                            upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )''')
        conn.commit()
        app.logger.info("Table 'file_uploads' created or already exists.")
        cursor.close()
        conn.close()
    except Exception as e:
        app.logger.error(f"Error creating table: {e}")

def log_to_db(filename, hospital_name, file_url):
    try:
        conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASSWORD)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO file_uploads (filename, hospital_name, file_url) VALUES (%s, %s, %s)",
                       (filename, hospital_name, file_url))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        app.logger.error(f"Database logging error: {e}")

def get_all_uploads(hospital_name):
    try:
        conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASSWORD)
        cursor = conn.cursor()
        cursor.execute("SELECT filename, file_url, upload_time FROM file_uploads WHERE hospital_name = %s ORDER BY upload_time DESC", (hospital_name,))
        uploads = cursor.fetchall()
        cursor.close()
        conn.close()
        return uploads
    except Exception as e:
        flash(f"Error retrieving file uploads: {e}", "danger")
        return []

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            response = cognito.initiate_auth(
                ClientId=CLIENT_ID,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password
                }
            )
            session['username'] = username
            session['access_token'] = response['AuthenticationResult']['AccessToken']
            return redirect(url_for('home'))
        except ClientError as e:
            return f'Login failed: {e.response["Error"]["Message"]}'
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        try:
            response = cognito.sign_up(
                ClientId=CLIENT_ID,
                Username=username,
                Password=password,
                UserAttributes=[
                    {
                        'Name': 'email',
                        'Value': email
                    },
                ],
            )
            flash("Sign up successful! Please log in.", "success")
            return redirect(url_for('login'))
        except ClientError as e:
            flash(f"Sign up failed: {e.response['Error']['Message']}", "danger")

    return render_template('signup.html')

@app.route('/confirm', methods=['GET', 'POST'])
def confirm():
    if request.method == 'POST':
        username = request.form['username']
        confirmation_code = request.form['confirmation_code']
        
        try:
            cognito.confirm_sign_up(
                ClientId=CLIENT_ID,
                Username=username,
                ConfirmationCode=confirmation_code
            )
            flash('Account confirmed! You can now log in.')
            return redirect(url_for('login'))
        
        except ClientError as e:
            return f'Confirmation failed: {e.response["Error"]["Message"]}'
    
    return render_template('confirm.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    create_table_if_not_exists()
    app.run(debug=True)

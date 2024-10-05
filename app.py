import os
import boto3
from flask import Flask, render_template, request, redirect, url_for, flash, session
from botocore.exceptions import ClientError, NoCredentialsError
import secrets
from dotenv import load_dotenv
import psycopg2

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

    if request.method == 'POST':
        file = request.files['file']
        hospital_name = request.form.get('hospital_name')

        if file and hospital_name:
            s3_folder_path = f"{hospital_name}/"
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

                flash(f"File uploaded successfully to folder '{s3_folder_path}'. File URL: {file_url}", "success")
                return render_template('home.html', file_url=file_url)
            except NoCredentialsError:
                flash("Credentials not available", "danger")
            except Exception as e:
                flash(f"Error uploading file: {e}", "danger")
                return redirect(url_for('home'))
        else:
            flash("No file or hospital name provided", "warning")
    
    return render_template('home.html')

def log_to_db(filename, hospital_name, file_url):
    try:
        conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASSWORD)
        print("Connected to the database")

        cursor = conn.cursor()
        cursor.execute("INSERT INTO file_uploads (filename, hospital_name, file_url) VALUES (%s, %s, %s)",
                       (filename, hospital_name, file_url))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        app.logger.error(f"Database logging error: {e}")

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

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

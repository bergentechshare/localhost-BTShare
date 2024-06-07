#TO DO:
#Admin (edit account information, delete them)
#report
#presentation

#imports
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
import os, io
from werkzeug.utils import secure_filename
import csv
from sqlalchemy import desc, asc
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from flask_mail import Mail
from flask_mail import Message
from flask_login import LoginManager, UserMixin
from flask_login import login_user, current_user, logout_user, login_required
import random, string
import base64


app = Flask(__name__)
login_manager = LoginManager(app)
login_manager.login_view = 'login' #specify the login route
# Set custom messages
login_manager.login_message = "Unauthorized Access! Please log in!"
login_manager.login_message_category = "danger"

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USERNAME'] = 'bergentechshare@gmail.com'
# Consider using app secrets or environment variables
app.config['MAIL_PASSWORD'] = 'qwfe juvx fmda gbmr'  
# Set the default sender
app.config['MAIL_DEFAULT_SENDER'] = 'bergentechshare@gmail.com'
mail = Mail(app)

# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///BTShare.db"
db = SQLAlchemy(app)

class Projects(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    author = db.Column(db.String(255), nullable=False)
    overall_type = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(255), nullable=False)
    course = db.Column(db.String(255))
    description = db.Column(db.String(999))
    project = db.Column(db.LargeBinary, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f"Name(id={self.title}, author='{self.author}', type='{self.type}' !"

class Reports(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    project_id = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f"Reason(id={self.reason}, user='{self.user_id}', project='{self.project_id}' !"

#user model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email_verification_token = db.Column(db.String(255))
    is_verified = db.Column(db.Boolean, default=False)
    admin_level = db.Column(db.String(255), default="none", nullable=False)

    def __repr__(self):
        return f"Name(id={self.name}, email='{self.email}' !"
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# Create the database tables
with app.app_context():
    db.create_all()

# Generate a Verification Token:
def generate_verification_token():
    return secrets.token_urlsafe(50)  # Adjust the token length as needed


# Send a Verification Email:
def send_verification_email(user):
    verification_link = (
        # f"http://127.0.0.1:5000/verify_email/{user.email_verification_token}"
        f"https://63hsl2h0-9000.use.devtunnels.ms/verify_email/{user.email_verification_token}"
    )
    msg = Message("Verify Your Email", recipients=[user.email])
    msg.body = f"Click the following link to verify your email: {verification_link}"
    mail.send(msg)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#routes
@app.route('/', methods=["GET", "POST"])
def index():
    return render_template("index.html")

@app.route('/full', methods=["GET", "POST"])
def full():
    return render_template("indexfull.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            if not user.email_verification_token:
                #login logic
                login_user(user)
                flash("Logged in successfully!", "success")
                return redirect(url_for('index'))
            else:
                flash("Verify your email!","warning")
        else:
            flash("Invalid credentials!","danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully", "success")
    return redirect(url_for("index"))

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Get form data
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # Validate form data (add your own validation logic)
        if not (
            name
            and email
            and password
            and confirm_password
        ):
        # Handle invalid input
            flash("Please fill in all fields.", "danger")
            return render_template("register.html")
        #handle if existing user
        if email[-11:] != "@bergen.org" and email !="bergentechshare@gmail.com":
            flash("Please use a 'bergen.org' email!", "warning")
            return render_template("register.html")
         
        user = User.query.filter_by(email=email).first()
        if user is not None and email == user.email:
            # Handle password mismatch
            flash("User already exist! Try a different email", "danger")
            return render_template("register.html")
        if password != confirm_password:
            # Handle password mismatch
            flash("Passwords do not match.", "danger")
            return render_template("register.html")
    
        # Create a new user instance
        new_user = User(
            name=name,
            email=email,
            email_verification_token=generate_verification_token(),
        )
        new_user.set_password(password)

        if email == "bergentechshare@gmail.com":
            new_user.admin_level = "super"
            flash("created super admin account", "success")

        # Save the new user to the database
        db.session.add(new_user)
        db.session.commit()
        
        # Send the verification email
        send_verification_email(new_user)
        
        flash("Account created successfully! Please check your email to verify (and spam).", "success")
        return redirect(url_for('login'))
    return render_template("register.html")

# Create an Email Verification Route:
@app.route("/verify_email/<token>", methods=["GET"])
def verify_email(token):
    user = User.query.filter_by(email_verification_token=token).first()
    if user:
        user.email_verification_token = None  # Mark email as verified
        # Set a flag or column in the User model to indicate verified status
        user.is_verified = True  
        db.session.commit()
        flash("Email verified successfully!", "success")
    else:
        flash("Invalid verification token.", "danger")
    return redirect(url_for("login"))  # Redirect to login or home page


@app.route('/admin', methods=["GET", "POST"])
@login_required
def admin():
    if current_user.admin_level != "none":
        users = User.query.all()
        reports = Reports.query.all()
    else:
        flash("Unauthorized Access!", "warning")
        return redirect(url_for('index'))
    if request.method == "POST":
        if "report" in request.form:
            user_id = int(request.form["user_id"])
            proj_id = int(request.form["proj_id"])
            reason = request.form["reason"]
            description = request.form["description"]
            report_delete = Reports.query.filter_by(user_id=user_id).filter_by(project_id=proj_id).filter_by(reason=reason).filter_by(description=description).first()
            try:
                db.session.delete(report_delete)
                db.session.commit()
                flash("Closed sucessfully!", "success")
                reports = Reports.query.all()
            except Exception as e:
                print(e)
                db.session.rollback()
                flash("There's been an issue closing the report", "danger")
        elif "change" in request.form:
            id = request.form["id"]
            user = User.query.get(id)
            name = request.form["name"]
            email = request.form["email"]
            admin = request.form.get("admin")
            try:
                user.name = name
                user.email = email
                user.admin_level = admin
                db.session.commit()
                    # print(user.admin_level)
                users = User.query.all()           
            except:
                db.session.rollback()
                flash("There has been an issue updating, try again later!", "warning")
    return render_template("admin.html", users=users, reports=reports)

@app.route('/explore', methods=["GET", "POST"])
def explore():
    all_proj = Projects.query.all()
    if request.method == "POST":
        if "search" in request.form:
            search_text = request.form["search_text"]
            project_type = request.form["project"]
            query = Projects.query

            # Add search_text filter if present
            if search_text:
                query = query.filter(getattr(Projects, "title").ilike(f"%{search_text}%"))

            # Add project_type filter if present
            if project_type:
                query = query.filter_by(type=project_type)

            # Execute the query
            all_proj = query.all()
                        
    return render_template("explore.html", projects=all_proj)

@app.route('/details', methods=["GET", "POST"])
def details():
    if request.method == "GET":
        if request.args.get("proj_id"):
            project_id = int(request.args.get("proj_id"))
            project = Projects.query.get(project_id)
            if project.overall_type != "code": 
                project_main = base64.b64encode(project.project).decode('utf-8')
            else:
                project_main = (project.project).decode('utf-8')
            return render_template("specific.html", project=project, project_main=project_main)
        else:
            flash("No Project ID entered!", "warning")
            all_proj = Projects.query.all()
            return render_template("explore.html", projects=all_proj)
    if request.method == "POST":
        project_id = int(request.form.get("id"))
        project = Projects.query.get(project_id)
        if "details" in request.form:
            title = request.form.get("title")
            course = request.form.get("class")
            description = request.form.get("description")
            project.title=title
            project.course=course
            project.description=description
            db.session.commit()
            
            if project.overall_type != "code": 
                project_main = base64.b64encode(project.project).decode('utf-8')
            else:
                project_main = (project.project).decode('utf-8')
            flash("Sucessfully updated the details!", "success")
            return render_template("specific.html", project=project, project_main=project_main)
        if "project_change" in request.form:
            if project.overall_type != "code":
                try:
                    if project.overall_type == "text":
                        file = request.files.get('text_file')
                    elif project.overall_type == "image":
                        file = request.files.get('image_file')
                    file_data = file.read()
                    project.project = file_data
                    db.session.commit()
                    flash("Successfully updated the file!", "success")
                except Exception as e:
                    print('Error:', str(e))
                    flash("There's been an issue somewhere! Try again later", "danger")
            else:
                try:
                    link = request.form.get("link")
                    link_binary = link.encode('utf-8')
                    project.project = link_binary
                    db.session.commit()
                    flash("Successfully updated the link!", "success")
                except:
                    flash("There's been an issue somewhere! Try again later", "danger")
            if project.overall_type != "code": 
                project_main = base64.b64encode(project.project).decode('utf-8')
            else:
                project_main = (project.project).decode('utf-8')
            return render_template("specific.html", project=project, project_main=project_main)
        if "report" in request.form:
            proj_id = request.form.get("id")
            print(proj_id)
            reason = request.form.get("report_reason")
            print(reason)
            description = request.form.get("report_description")
            print(description)
            try:
                new_report = Reports(
                project_id=proj_id,
                user_id=current_user.id,
                reason=reason,
                description=description,
            )
                db.session.add(new_report)
                db.session.commit()
                flash("Successfully Reported!", "success")
            except Exception as e:
                db.session.rollback()
                print(e)
                flash("There was an issue reporting!", "warning")
        return redirect(url_for("explore"))

@app.route('/upload', methods=["GET", "POST"])
@login_required
def upload():
    return render_template("upload.html")

@app.route('/upload_text', methods=["GET", "POST"])
@login_required
def upload_text():
    if request.method == "POST":
        text_file = request.files.get('text')
        # print(type(file))
        title = request.form.get("title")
        description = request.form.get("description")
        course = request.form.get("class")
        type = request.form.get("type")

        if not (
            title
            and description
            and course 
            and type
            and text_file
        ):
        # Handle invalid input
            flash("Please fill in all fields.", "danger")
            return render_template("register.html")
        #handle if existing user

        text_data = text_file.read()

        try:
            # Create a new user instance
            new_proj = Projects(
                title=title,
                author=(current_user.name),
                course=course,
                description=description,
                type=type,
                project = text_data,
                overall_type = "text",
                user_id = current_user.id,
            )

            # Save the new user to the database
            db.session.add(new_proj)
            db.session.commit()
            flash("Successfully Added!", "success")
        except Exception as e:
            print('Error:', str(e))
            db.session.rollback()
            flash("There's been an issue! Try again later", "danger")
    return render_template("upload_text.html")

@app.route('/upload_image', methods=["GET", "POST"])
@login_required
def upload_image():
    if request.method == "POST":
        image_file = request.files.get("image")
        title = request.form.get("title")
        description = request.form.get("description")
        course = request.form.get("class")
        type = request.form.get("type")

        if not (
            title
            and description
            and course 
            and type 
            and image_file
        ):
        # Handle invalid input
            flash("Please fill in all fields.", "danger")
            return render_template("register.html")
        #handle if existing user

        image_data = image_file.read()

        try:
            # Create a new user instance
            new_proj = Projects(
                title=title,
                author=current_user.name,
                course=course,
                description=description,
                type=type,
                overall_type = "image",
                project=image_data,
                user_id = current_user.id,
            )

            # Save the new user to the database
            db.session.add(new_proj)
            db.session.commit()
            flash("Successfully Added!", "success")
        except:
            db.session.rollback()
            flash("There's been an issue! Try again later", "danger")
    return render_template("upload_image.html")

@app.route('/upload_code', methods=["GET", "POST"])
@login_required
def upload_code():
    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        course = request.form.get("class")
        type = request.form.get("type")
        link = request.form.get("link")

        if not (
            title
            and description
            and course 
            and type 
            and link
        ):
        # Handle invalid input
            flash("Please fill in all fields.", "danger")
            return render_template("register.html")
        #handle if existing user
        
        link_binary = link.encode('utf-8')
        
        try:
            # Create a new user instance
            new_proj = Projects(
                title=title,
                author=current_user.name,
                course=course,
                description=description,
                type=type,
                project = link_binary,
                overall_type = "code",
                user_id = current_user.id,
            )

            # Save the new user to the database
            db.session.add(new_proj)
            db.session.commit()
            flash("Successfully Added!", "success")
        except:
            db.session.rollback()
            flash("There's been an issue somewhere! Try again", "danger")
    return render_template("upload_code.html")

@app.route("/delete_user")
@login_required
def delete_user():
    user_id = request.args.get("user_id")
    if current_user.admin_level != "none" or int(current_user.id)==int(user_id):
        page = request.args.get("page")
        user_to_delete = User.query.get(user_id)
        db.session.delete(user_to_delete)
        db.session.commit()
        flash("User deleted successfully", "success")
        if page == "admin":
            return redirect("/admin")
        else:
            return redirect("/")
    else:
        flash("You do not have the permissions to be there!", "warning")
        return redirect("/")
    
@app.route("/delete_project")
@login_required
def delete_project():
    user_id = request.args.get("user_id")
    if current_user.admin_level != "none" or int(current_user.id) == int(user_id):
        id = request.args.get("user_id")
        proj_to_delete = Projects.query.get(id)
        db.session.delete(proj_to_delete)
        db.session.commit()
        flash("Project deleted successfully", "warning")
        return redirect("/explore")
    else:
        flash("You do not have the meanings to be there!", "warning")
        return redirect("/explore")


@app.route("/profile")
def profile():
    id = request.args.get("user_id")
    if id == None:
        id = current_user.id
    user = User.query.get(id)
    projects = Projects.query.filter_by(user_id=user.id)

    return render_template("profile.html", user=user, projects=projects)

@app.route("/presentation")
def presentation():
    return render_template("presentation.html")

if __name__ == "__main__":
    app.secret_key = "jfvdjhklvdfhgspierytuepsri5uw43hkjlh" 
    app.run(debug=True, port="9000")
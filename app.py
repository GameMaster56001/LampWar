from flask import *
from datetime import timedelta
import mysql.connector as mysql
import time
from datetime import datetime
currentDate = datetime.now()
currentTime = int(currentDate.timestamp())
finalDate = datetime.fromtimestamp(currentTime)
from requests import get
import hashlib
from hashlib import sha256
import socket

hostname = socket.gethostname()
ip = socket.gethostbyname(hostname)

db = mysql.connect(host="localhost",user="root",password="",database="lampwar")
cursor = db.cursor(buffered=True)
cursor2 = db.cursor(buffered=True)

def turnToStr(var):
	var = str(var).replace(")", "")
	var = str(var).replace("(", "")
	var = str(var).replace("'", "")
	var = str(var).replace(",", "")
	var = str(var).replace("[", "")
	var = str(var).replace("]", "")
	return var



app = Flask(__name__)
app.secret_key = "1001574482"
app.permanent_session_lifeitme = timedelta(days=50)

@app.route("/", methods=["POST", "GET"])
def sign_up():
	if request.method == "POST":
		session.permanent = True
		username = request.form['username']
		password = request.form["password"]
		password = sha256(password.encode('utf-8')).hexdigest()
		email = request.form['email']
		gender = request.form['gender']
		gender = "Male" if gender == "1" else "Female"
		query_vals=(username,email,password,gender,ip,finalDate,"User")
		try:
			cursor.execute("INSERT INTO users (username, email, password, gender, ip, creationDate, role) VALUES (%s,%s,%s,%s,%s,%s,%s)",query_vals)
			db.commit()
			session["username"] = username
			session["role"] = "User"
			session["isBanned"] = False
			session["canPost"] = True
			session["gender"] = gender
			return redirect(url_for('home'))
		except:
			flash("Username is already taken.", "error")
			return redirect(url_for('sign_up'))
	else:
		if "username" in session:
			return redirect(url_for("home"))
		return render_template("sign_up.html")

def unbanUser(username):
	dataList = [username]
	cursor.execute("DELETE FROM bans WHERE username = %s", dataList)
	db.commit()

def getIP(username):
	query_vals = [username]
	cursor.execute("SELECT ip FROM users WHERE username = %s", query_vals)
	return turnToStr(cursor.fetchone())

def banUs(username, reason):
		query_vals = (username, reason, finalDate, session["username"])
		cursor.execute("INSERT INTO bans (username, ban_reason, reviewed, moderator) VALUES (%s,%s,%s,%s)", query_vals)
		db.commit()

def purgeAllPosts(usernamePURGE):
	dataList = ("[Content deleted]",usernamePURGE)
	cursor.execute("UPDATE posts SET content = %s WHERE author = %s", dataList)
	db.commit()

def getPassword(username):
	query_vals = [username]
	cursor.execute("SELECT password FROM users WHERE username = %s", query_vals)
	password = cursor.fetchone()
	password = turnToStr(password)
	return password

def getGender(username):
	query_vals = [username]
	cursor.execute("SELECT gender FROM users WHERE username = %s",query_vals)
	gender = cursor.fetchone()
	return turnToStr(gender)

def getNA(username):
	query_vals = [username]
	cursor.execute("SELECT id FROM notifications WHERE notiOwner = %s",query_vals)
	return int(cursor.rowcount)

def getRole(username):
	query_vals = [username]
	cursor.execute("SELECT role FROM users WHERE username = %s", query_vals)
	role = cursor.fetchone()
	role = turnToStr(role)
	return role

def checkIsBanned(username):
	query_vals = [username]
	cursor.execute("SELECT id FROM bans WHERE username = %s", query_vals)
	if cursor.rowcount >= 1:
		return True
	else:
		return False

def warnUser(username,reason,warning_type):
	query_vals = (username,warning_type,reason,session["username"],finalDate)
	cursor.execute("INSERT INTO warnings (username, warning_type, content, moderator, reviewed_on) VALUES (%s,%s,%s,%s,%s)",query_vals)
	db.commit()


def checkIsValid(username):
	query_vals = [username]
	cursor.execute("SELECT username FROM users WHERE username = %s", query_vals)
	if cursor.rowcount >= 1:
		return True
	else:
		return False

def getWarningLevel(username):
	query_vals = [username]
	cursor.execute("SELECT warning_type FROM warnings WHERE username = %s",query_vals)
	return str(turnToStr(cursor.fetchone()))

@app.route("/home", methods=["POST", "GET"])
def home():
	if "username" in session:
		username = session["username"]
		isBanned = session["isBanned"]
		gender = session["gender"]
		role = session["role"]
		if isBanned:
			return redirect(url_for("suspended"))
		return render_template("home.html", role=role, username=username, gender=gender, noAm=getNA(session["username"]))
	else:
		return redirect(url_for("sign_up"))

@app.route("/unban/<username>")
def unbanus(username):
	if session["username"] and session["role"] == "Admin":
		unbanUser(username)
		flash("Sucesfully unbanned user", "success")
		return redirect(url_for("ban_list"))
	else:
		abort(403)

@app.route("/warnings")
def warnings():
	if "username" in session:
		query_vals=[session["username"]]
		cursor.execute("SELECT * FROM warnings WHERE username = %s",query_vals)
		warn = cursor.fetchall()
		if session["isBanned"]:
			return redirect(url_for("suspended"))
		return render_template("warnings.html", warn=warn)
	else:
		return redirect(url_for("login"))

#Error handlers
@app.errorhandler(404)
def page_not_found(e):
	 return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
	return render_template("403.html"), 403


@app.route("/login", methods=["POST", "GET"])
def login():
	if request.method == "POST":
		session.permanent = True
		username = request.form['username']
		password = request.form['password']
		password = sha256(password.encode('utf-8')).hexdigest()
		query_vals = (username,password)
		cursor.execute("SELECT username FROM users WHERE username = %s AND password = %s",query_vals)
		if cursor.rowcount <= 0:
			flash("Invalid information provided.", "error")
			return redirect(url_for("login"))
		else:
			session["username"] = username
			session["password"] = password
			session["gender"] = getGender(username)
			session["canPost"] = True
			warningLevel = getWarningLevel(session["username"])
			if warningLevel == "3":
				session["canPost"] = False
			userList2 = [session["username"]]
			cursor.execute("SELECT * FROM bans WHERE username = %s",userList2)
			if cursor.rowcount > 0:
				# The user is banned now time to let the website know that the user is banned
				session["isBanned"] = True
			else:
				session["isBanned"] = False
			userList = [session["username"]]
			cursor.execute("SELECT role FROM users WHERE username = %s", userList)
			role = cursor.fetchone()
			role = str(role).replace("(", '')
			role = str(role).replace(")", '')
			role = str(role).replace("'", '')
			role = str(role).replace(",", '')
			session["role"] = role
			return redirect(url_for('home'))
	else:
		if "username" in session:
			return redirect(url_for("home"))
		return render_template("login.html")

@app.route("/users/<Profileid>")
def users(Profileid):
	if "username" in session:
		role = session["role"]
		dataList = [Profileid]
		cursor.execute("SELECT * FROM users WHERE id = %s",dataList)
		if cursor.rowcount <= 0:
			abort(404)

		profileData = cursor.fetchall()
		if session["isBanned"]:
			return redirect(url_for('suspended'))
		return render_template("profile.html", profileData=profileData, role=role)
	else:
		return redirect(url_for("login"))

@app.route("/delete-post/<postId>", methods=["POST", "GET"])
def delete_post(postId):
	if session["isBanned"]:
		return redirect(url_for("suspended"))
	query_vals = [postId]
	cursor.execute("SELECT author FROM posts WHERE id = %s",query_vals)
	val = cursor.fetchone()
	val = turnToStr(val)
	if session["username"] == val or session["role"] == "Admin":
		data_list = [postId]
		cursor.execute("DELETE FROM posts WHERE id = %s",data_list)
		db.commit()
		flash("Sucesfully deleted post", "success")
		return redirect(url_for("posts"))
	else:
		abort(403)

@app.route("/report/<username>", methods=["POST", "GET"])
def report(username):
	if request.method == "POST":
		reason = request.form['reason']
		reporter = session["username"]
		reported = username
		query_vals=(reporter,reported,reason)
		cursor.execute("INSERT INTO reports (reporter, reported, reason) VALUES (%s,%s,%s)",query_vals)
		db.commit()
		flash(f"Sucesfully reported {reported}", "success")
		return redirect(url_for("report", username=username))
	else:
		if "username" in session:
			isBanned = session["isBanned"]
			if isBanned:
				return redirect(url_for("suspended"))
		else:
			return redirect(url_for("login"))
		return render_template("report.html", reported=username)

@app.route("/posts")
def posts():
	if "username" in session:
		username = session["username"]
		role = session["role"]
		cursor.execute("SELECT * FROM posts")
		posts = cursor.fetchall()
		if session['isBanned']:
			return redirect(url_for("suspended"))
		return render_template("posts.html", rank=role, posts=posts)
	else:
		return redirect(url_for("login"))

@app.route("/check-reports/<user>")
def checkUserReports(user):
	if "username" in session:
		if session["role"] == "Admin":
			datalist = [user]
			cursor.execute("SELECT * FROM reports WHERE reported = %s",datalist)
			return render_template("userWarnings.html", warnings=cursor.fetchall())
		else:
			abort(403)
	else:
		return redirect(url_for("login"))


@app.route("/warn", methods=["POST", "GET"])
def warn_user():
	if session["role"] == "Admin":
		if request.method == "POST":
			username = request.form['username']
			reason = request.form['reason']
			warning_type = request.form['warning_type']
			if session["role"] != "Admin":
				abort(403)
			else:
				query_vals = (username,warning_type,reason,session["username"],finalDate)
				cursor.execute("INSERT INTO warnings (username, warning_type, content, moderator, reviewed_on) VALUES (%s,%s,%s,%s,%s)",query_vals)
				db.commit()
				flash(f"Warned {username} sucesfully", "success")
				return redirect(url_for("warn_user"))
				if warning_type == "2":
					purgeAllPosts(username)
				elif warning_type == "3":
					pass
				elif warning_type == "4":
					banUs(username, "Having a warning with level of 4")
		return render_template("warn.html")
	else:
		abort(403)

@app.route("/create-post", methods=["POST", "GET"])
def create_post():
	if session["canPost"] == False:
		return "<h1>Your posting ability has been revoked.</h1>"
	if request.method == "POST":
		author = session["username"]
		post = request.form["text"]
		postedOn = finalDate
		query_vals = (author, postedOn, post)
		cursor.execute("INSERT INTO posts (author, postedOn, content) VALUES (%s,%s,%s)",query_vals)
		db.commit()
		flash("Sucesfully added post", "success")
		return redirect(url_for("posts"))
	else:
		if "username" in session:
			return render_template("newPost.html")
		if session["isBanned"]:
			return redirect(url_for('suspended'))
		else:
			return redirect(url_for('login'))


@app.route("/edit-post/<postId>", methods=["POST", "GET"])
def edit_post(postId):
	if request.method == "POST":
		newPost = request.form["post"]
		dataList = (newPost,postId)
		cursor.execute("UPDATE posts SET content = %s WHERE id = %s",dataList)
		db.commit()
		flash("Sucesfully updated post", "success")
		return redirect(url_for("posts"))
	query_vals = [postId]
	cursor.execute("SELECT author FROM posts WHERE id = %s",query_vals)
	val = cursor.fetchone()
	val = turnToStr(val)
	if session["username"] == val or session["role"] == "Admin":
		cursor.execute("SELECT content FROM posts WHERE id = %s",query_vals)
		postContent = turnToStr(cursor.fetchone())
		if session["isBanned"]:
			return redirect(url_for("suspended"))
		return render_template("edit_post.html", current_content=postContent)
	else:
		abort(403)

@app.route("/settings")
def settings():
		if "username" in session:
			username = session["username"]
			isBanned = session["isBanned"]
			gender = session["gender"]
			role = session["role"]
			if isBanned:
				return redirect(url_for('suspended'))
			return render_template("settings.html", username=username, role=role, gender=gender)
		else:
			return redirect(url_for("login"))




@app.route("/settings/username", methods=["POST", "GET"])
def changeUser():
	if request.method == "POST":
		newUser = request.form["newUsername"]
		query_vals = [newUser, session["username"]]
		try:
			cursor.execute("UPDATE users SET username = %s WHERE username = %s", query_vals)
			db.commit()
			flash("Username updated sucesfully!", "success")
			session["username"] = newUser
			return redirect(url_for("changeUser"))
		except:
			flash("Username is already taken!", "error")
			return redirect(url_for("changeUser"))
	else:
		if "username" in session:
			username = session["username"]
			isBanned = session["isBanned"]
			if isBanned:
				return redirect(url_for('suspended'))
			return render_template("usernameUpdate.html", username=username)
		else:
			return redirect(url_for("login"))

@app.route("/settings/password", methods=["POST", "GET"])
def changePassword():
	if request.method == "POST":
		newPassword = request.form["newPassword"]
		oldPassword = request.form["oldPassword"]
		password2 = request.form["passwordConfirm"]
		oldPassword = sha256(oldPassword.encode('utf-8')).hexdigest()
		currentPassword = getPassword(session["username"])
		if oldPassword != currentPassword:
			flash("Old password does not match with current password!", "error")
			return redirect(url_for("changePassword"))
		elif newPassword != password2:
			flash("Password does not match with the second password!", "error")
			return redirect(url_for("changePassword"))
		else:
			newPassword = sha256(newPassword.encode('utf-8')).hexdigest()
			query_vals = (newPassword, session["username"])
			cursor.execute("UPDATE users SET password = %s WHERE username = %s", query_vals)
			db.commit()
			flash("Password updated sucesfully", "success")
			return redirect(url_for("changePassword"))
			session.pop("username", None)
			session.pop("isBanned", None)
			session.pop("role", None)
			session.pop("canPost", None)
			flash("Please login again", "error")
			return redirect(url_for("login"))
	else:
		if "username" in session:
			isBanned = session["isBanned"]
			if isBanned:
				return redirect(url_for('suspended'))
			return render_template("passwordUpdate.html")
		else:
			return redirect(url_for("login"))

		

@app.route("/staff-only", methods=["POST", "GET"])
def staff():
	if "username" in session:
		if session["role"] == "Admin":
			if request.method == "POST":
				user = request.form['user']
				reason = request.form['reason']
				warning_type = request.form['warning_type']
				action = turnToStr(request.form.getlist('actions'))
				if action == "ban":
					banUs(user, reason)
					flash(f"Banned {user} sucesfully", "success")
					return redirect(url_for('staff'))
				elif action == "purgeposts":
					purgeAllPosts(user)
					flash("Sucesfully purged all user posts", "success")
					return redirect(url_for("staff"))
				elif action == "warn":
					warnUser(user, reason, warning_type)
					flash("User warned sucesfully","success")
					return redirect(url_for('staff'))
				elif action == "reports":
					return redirect(url_for("checkUserReports", user=user))
				elif action == "unban":
					unbanUser(user)
					flash(f"{user} Has been unbanned sucesfully", "success")
					return redirect(url_for('staff'))

			return render_template("staffOnly.html")
		else:
			abort(403)
	else:
		return redirect(url_for('login'))


	return render_template("staffOnly.html")

@app.route("/search/<username>")
def search(username):
	dataList = [username]
	cursor.execute("SELECT id FROM users WHERE username = %s",dataList)
	userId = turnToStr(cursor.fetchone())
	print(userId)
	return redirect(url_for("users", Profileid=userId))

@app.route("/all-users")
def all_users():
	if "username" in session:
		if session["role"] == "Admin":
			cursor.execute("SELECT * FROM users")
			users = cursor.fetchall()
			return render_template("all_users.html", users=users)
		else:
			abort(403)
	else:
		return redirect(url_for("login"))

@app.route("/moderate/<username>", methods=["POST", "GET"])
def moderate(username):
	if "username" in session:
		if session["role"] == "Admin":
			isValid = checkIsValid(username)
			if isValid == True:
				role = getRole(username)
				gender = turnToStr(getGender(username))
				if request.method == "POST":
					rank = request.form["rank"]
					query_vals = (rank,username)
					if session["role"] == "Admin":
						cursor.execute("UPDATE users SET role = %s WHERE username = %s",query_vals)
						db.commit()
						flash("Updated rank sucesfully!", "success")
						return redirect(url_for("moderate", username=username))
					else:
						flash("You do not have permissions!")
						return redirect(url_for("home"))
				else:
					return render_template("moderate.html", role=role, username=username, gender=gender)
			else:
				abort(404)
		else:
			abort(403)
	else:
		return redirect(url_for('login'))

@app.route("/banU/<username>")
def banU(username):
	if "username" in session:
		if session["role"] == "Admin":
			banUs(username, "No reason provided")
			flash("User banned sucesfully", "success")
			return redirect(url_for("moderate", username=username))
		else:
			abort(403)
	else:
		return redirect(url_for("login"))

@app.route("/purge-all-posts/<username>")
def purgeAll(username):
	if "username" in session:
		if session["role"] == "Admin":
			purgeAllPosts(username)
			flash("Purged all user posts sucesfully", "success")
			return redirect(url_for("warn"))
		else:
			abort(403)
	else:
		return redirect(url_for("login"))

@app.route("/admin-testing", methods=["POST", "GET"])
def admin_testing():
	if request.method == "POST":
		name = request.form.get("name")
		email = request.form.get("email")
		message = request.form.get("name")
		s1 = request.form.get("s1")
		s2 = request.form.get("s2")
		s3 = request.form.get("s3")
		return f"{name}, {email}, {message}, {s1}, {s2}, {s3}"
	return render_template("admin_testing.html")


@app.route("/staff-only/ban", methods=["POST", "GET"])
def ban():
	if request.method == "POST":
		userToBan = request.form["userBan"]
		banReason = request.form["reason"]
		dataList = [userToBan]
		cursor.execute("SELECT * FROM users WHERE username = %s", dataList)
		if cursor.rowcount <= 0:
			flash("User does not exist", "error")
			return redirect(url_for("staff"))
		else:
			if session["role"] == "Admin":
				query_vals=(userToBan,banReason,finalDate, session["username"])
				cursor.execute("INSERT INTO bans (username, ban_reason, reviewed, moderator) VALUES (%s,%s,%s,%s)",query_vals)
				db.commit()
				flash("Banned user sucesfully", "success")
				return redirect(url_for("staff"))
			else:
				flash("You do not have permissions!", "error")
				return redirect(url_for("home"))
	else:
		if "username" in session:
			role = session["role"]
			if role == "Admin":
				cursor.execute("SELECT * FROM bans")
				results = cursor.fetchall()
				return render_template("staffBan.html", results=results)
			else:
				abort(403)
		else:
			return redirect(url_for("login"))

@app.route("/staff-only/unban", methods=["POST", "GET"])
def unban():
	if request.method == "POST":
		userToUnBan = request.form["userunBan"]
		dataList = [userToUnBan]
		cursor.execute("SELECT * FROM users WHERE username = %s", dataList)
		if cursor.rowcount <= 0:
			flash("User does not exist", "error")
			return redirect(url_for("staff"))

		else:
			if session["role"] == "Admin":
				query_vals=[userToUnBan]
				cursor.execute("DELETE FROM bans WHERE username = %s", query_vals)
				db.commit()
				flash("Unbanned user sucesfully", "success")
				return redirect(url_for("staff"))
			else:
				flash("You do not have permissions!", "error")
				return redirect(url_for("home"))
	else:
		if "username" in session:
			role = session["role"]
			if role == "Admin":
				cursor.execute("SELECT * FROM bans")
				results = cursor.fetchall()
				return render_template("staffUnban.html", results=results)
			else:
				abort(403)
		else:
			return redirect(url_for("login"))

@app.route("/staff-only/reports")
def reports():
	if "username" in session:
		if session["role"] == "Admin":
			cursor.execute("SELECT * FROM reports")
			reports = cursor.fetchall()
			return render_template("staffReports.html", reports=reports)
		else:
			abort(403)
	else:
		return redirect(url_for("login"))

@app.route("/markDone/<reportId>")
def markDone(reportId):
	if "username" in session:
		if session["role"] == "Admin":
			query_vals = [reportId]
			cursor.execute("DELETE FROM reports WHERE id = %s",query_vals)
			db.commit()
			flash("Sucesfully marked report as done.", "success")
			return redirect(url_for("reports"))
		else:
			abort(403)
	else:
		return redirect(url_for("login"))

@app.route("/suspended")
def suspended():
	if "username" in session:
		if session["role"] == "Admin" or session["isBanned"]:
			dataList = [session["username"]]
			cursor.execute("SELECT reviewed FROM bans WHERE username = %s",dataList)
			reviewed = cursor.fetchone()
			reviewed = str(reviewed).replace("(", '')
			reviewed = str(reviewed).replace(")", '')
			reviewed = str(reviewed).replace("'", '')
			reviewed = str(reviewed).replace(",", '')
			cursor.execute("SELECT moderator FROM bans WHERE username = %s", dataList)
			moderator = cursor.fetchone()
			moderator = str(moderator).replace("(", '')
			moderator = str(moderator).replace(")", '')
			moderator = str(moderator).replace("'", '')
			moderator = str(moderator).replace(",", '')
			cursor.execute("SELECT ban_reason FROM bans WHERE username = %s", dataList)
			reason = cursor.fetchone()
			reason = str(reason).replace("(", '')
			reason = str(reason).replace(")", '')
			reason = str(reason).replace("'", '')
			reason = str(reason).replace(",", '')
			return render_template("banMessage.html", reviewed=reviewed, moderator=moderator, reason=reason)
		else:
			return redirect(url_for("login"))
	else:
		return redirect(url_for("home"))

@app.route("/ban-list")
def ban_list():
	if "username" in session:
		if session["role"] == "Admin":
			cursor.execute("SELECT * FROM bans")
			bans = cursor.fetchall()
			return render_template("ban_list.html", bans=bans)
		else:
			abort(403)
	else:
		return redirect(url_for("login"))

@app.route("/logout")
def logout():
	session.pop("username", None)
	session.pop("isBanned", None)
	session.pop("role", None)
	session.pop("gender", None)
	session.pop("canPost", None)
	return redirect(url_for("login"))

if __name__ == "__main__":
	app.run(debug=True)
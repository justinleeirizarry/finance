import os

import sqlite3
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    user_id = session["user_id"]

    # Get users stocks, shares and cash to display
    stocks = db.execute(
        "SELECT symbol, name, price, SUM(shares) as totalshares FROM portfolio WHERE user_id = ? GROUP BY symbol", user_id)
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

    grandtotal = cash

    # Create a loop to display the informatin accuratly on the index page
    for stock in stocks:
        quote = lookup(stock["symbol"])
        stock["price"] = quote["price"]
        stock["total"] = stock["price"] * stock["totalshares"]
        grandtotal += stock["total"]

    return render_template("index.html", stocks=stocks, cash=usd(cash), grandtotal=grandtotal)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "GET":
        return render_template("buy.html")

    if request.method == "POST":

        stock = request.form.get("symbol")

        if not stock:
            return apology("Please provide at least one stock")

        quote = lookup(stock)

        if not quote:
            return apology("Invalid Symbol")

        if not request.form.get("shares").isdigit():
            return apology("Must provide a valid number of shares")

        shares = int(request.form.get("shares"))

        if not shares:
            return apology("Please provide a valid number of shares")

        user_id = session["user_id"]
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

        name = quote["name"]
        stockprice = quote["price"]
        funds = cash - stockprice * shares

        if funds < 0:
            return apology("Insufficient funds.")

        # Update users
        db.execute("UPDATE users SET cash = ? WHERE id = ?", funds, user_id)

        # Update portfolio
        db.execute("INSERT INTO portfolio (user_id, name, symbol, shares, price, type) VALUES (?, ?, ?, ?, ?, ?)",
                   user_id, name, stock, shares, usd(stockprice), "buy")

        flash("Bought!")

        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    user_id = session["user_id"]

    # Take the relevant information from portfolio to display on the history page
    stocks = db.execute("SELECT symbol, shares, price, time, type FROM portfolio WHERE user_id = ?", user_id)
    return render_template("history.html", stocks=stocks)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "POST":

        # Pull quote
        quote = lookup(request.form.get("symbol"))

        if quote == None:
            return apology("Invalid Symbol")

        # If the stock is valid, render the html page to show the value
        return render_template("quoted.html", stock=quote)

    # If the user reaches the page via GET
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Make sure username is provided
        if not username:
            return apology("please provide username")
        # Make sure password is provided
        elif not password:
            return apology("please provide password")
        # Make sure the password matches the confirmation
        elif password != confirmation:
            return apology("passwords must match")

        # Check users for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # If there is a username already in the table, return apology
        if len(rows) != 0:
            return apology("Username taken")

        # Hash user's password
        hashed = generate_password_hash(password)
        # insert new user into users
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashed)

        flash("Registered!")

        # Redirect users to homepage
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # Retrieve the stocks from a user's portfolio for selling
    if request.method == "GET":
        user_id = session["user_id"]
        stocks = db.execute("SELECT symbol FROM portfolio WHERE user_id = ? GROUP BY symbol", user_id)
        return render_template("sell.html", stocks=stocks)

    if request.method == "POST":

        user_id = session["user_id"]
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        if shares <= 0:
            return aplogy("Must be a positive number of shares")

        # Retrieve all relevant information for each stock
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        price = lookup(symbol)["price"]
        name = lookup(symbol)["name"]
        total = shares * price

        # Retrieve all the owned stocks from user
        owned = db.execute("SELECT shares FROM portfolio WHERE user_id = ? AND symbol = ? GROUP BY symbol",
                           user_id, symbol)[0]["shares"]

        # Make sure user has enough shares to sell
        if owned < shares:
            return apology("You do not have enough shares")

        # Update cash
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash + total, user_id)
        # Update portfolio
        db.execute("INSERT INTO portfolio (user_id, name, shares, price, type, symbol) VALUES (?, ?, ?, ?, ?, ?)",
                   user_id, name, -shares, usd(price), "sell", symbol)

        flash("Sold!")

        return redirect("/")


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    """Change password"""
    if request.method == "POST":

        current = request.form.get("current_password")
        new = request.form.get("new_password")
        confirm = request.form.get("new_password_confirmation")
        user_id = session["user_id"]
        rows = db.execute("SELECT hash FROM users WHERE id = ?", user_id)

        if not current:
            return apology("Please provide current password")

        if not new:
            return apology("Please enter new password")

        if not confirm:
            return apology("Please confirm password")

        elif new != confirm:
            return aplogy("Password must match")

        # Check if the current password is valid
        elif len(rows) != 1 or not check_password_hash(rows[0]["hash"], current):
            return apology("invalid password")

        # Update new password's hash in users
        hash = generate_password_hash(new)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", hash, user_id)

        flash("Password changed!")

        return redirect("/")

    return render_template("password.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

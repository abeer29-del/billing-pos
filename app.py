import csv
import math
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, date, timedelta
from functools import wraps
from io import StringIO

from flask import Flask, render_template, request, redirect, jsonify, session, Response
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
DATABASE = "database.db"

ALLOWED_PAYMENT_METHODS = ("Cash", "Card", "Bank Transfer")


# =========================================================
# SECRET KEY (from environment, otherwise generated once
# and saved next to this file - add .secret_key to .gitignore)
# =========================================================

def load_secret_key():
    key = os.environ.get("SECRET_KEY")
    if key:
        return key

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".secret_key")
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()

    key = secrets.token_hex(32)
    with open(path, "w") as f:
        f.write(key)
    return key


app.secret_key = load_secret_key()

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS") == "1",
)


# =========================================================
# CSRF PROTECTION
# Every POST must carry the token stored in the user's session,
# either as a hidden "csrf_token" form field or an X-CSRFToken header.
# =========================================================

def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = get_csrf_token


@app.before_request
def csrf_protect():
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None

    expected = session.get("csrf_token", "")
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRFToken", "")

    if expected and sent and secrets.compare_digest(str(sent).encode(), expected.encode()):
        return None

    if request.is_json or request.path == "/process_payment":
        return jsonify({
            "success": False,
            "message": "Your session expired. Refresh the page and try again."
        }), 400

    return "Security check failed. Go back, refresh the page and try again.", 400


# =========================================================
# LOGIN LOCKOUT
# 5 wrong attempts from the same address for the same account
# block further attempts for 5 minutes (kept in memory).
# =========================================================

MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 300

_failed_logins = {}
_failed_lock = threading.Lock()


def _now():
    return time.time()


def _recent_failures(key):
    cutoff = _now() - LOCKOUT_SECONDS
    return [t for t in _failed_logins.get(key, []) if t > cutoff]


def lockout_seconds_left(key):
    """Seconds until another attempt is allowed, or 0 if not locked."""
    with _failed_lock:
        recent = _recent_failures(key)

        if recent:
            _failed_logins[key] = recent
        else:
            _failed_logins.pop(key, None)

        if len(recent) >= MAX_FAILED_LOGINS:
            return max(1, int(recent[0] + LOCKOUT_SECONDS - _now()))

    return 0


def record_failure(key):
    with _failed_lock:
        recent = _recent_failures(key)
        recent.append(_now())
        _failed_logins[key] = recent

        if len(_failed_logins) > 5000:
            for k in list(_failed_logins):
                if not _recent_failures(k):
                    _failed_logins.pop(k, None)


def clear_failures(key):
    with _failed_lock:
        _failed_logins.pop(key, None)


def lockout_message(seconds):
    minutes = max(1, math.ceil(seconds / 60))
    return f"Too many failed attempts. Try again in {minutes} minute{'s' if minutes != 1 else ''}."


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# =========================================================
# LOGIN REQUIRED DECORATOR
# =========================================================

def login_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return function(*args, **kwargs)
    return decorated_function


# =========================================================
# INITIALIZE DATABASE & MIGRATIONS
# =========================================================

def init_db():
    conn = get_db_connection()

    # PRODUCTS
    conn.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            barcode TEXT,
            category TEXT,
            price REAL NOT NULL,
            stock INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1
        )
    """)

    # CUSTOMERS
    conn.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT,
            email TEXT,
            address TEXT
        )
    """)

    # SALES
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_no TEXT NOT NULL,
            subtotal REAL DEFAULT 0,
            total REAL NOT NULL,
            discount REAL DEFAULT 0,
            tax REAL DEFAULT 0,
            payment_method TEXT NOT NULL,
            cash_received REAL DEFAULT 0,
            change_amount REAL DEFAULT 0,
            sale_date TEXT NOT NULL,
            customer_id INTEGER
        )
    """)

    # MIGRATIONS: make sure newer columns exist on older databases
    product_columns = [c["name"] for c in conn.execute("PRAGMA table_info(products)").fetchall()]
    if "is_active" not in product_columns:
        conn.execute("ALTER TABLE products ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")

    sales_columns = [c["name"] for c in conn.execute("PRAGMA table_info(sales)").fetchall()]
    if "subtotal" not in sales_columns:
        conn.execute("ALTER TABLE sales ADD COLUMN subtotal REAL DEFAULT 0")
    if "discount" not in sales_columns:
        conn.execute("ALTER TABLE sales ADD COLUMN discount REAL DEFAULT 0")
    if "tax" not in sales_columns:
        conn.execute("ALTER TABLE sales ADD COLUMN tax REAL DEFAULT 0")
    if "customer_id" not in sales_columns:
        conn.execute("ALTER TABLE sales ADD COLUMN customer_id INTEGER")

    # SALE ITEMS
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sale_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sale_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            price REAL NOT NULL,
            subtotal REAL NOT NULL
        )
    """)

    # Invoice numbers must be unique (skipped silently if old data has duplicates)
    try:
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_sales_invoice_no ON sales(invoice_no)")
    except sqlite3.IntegrityError:
        pass

    # USERS
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    # DEFAULT ADMIN USER (set ADMIN_PASSWORD in the environment to change the default)
    existing_user = conn.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone()
    if existing_user is None:
        password_hash = generate_password_hash(os.environ.get("ADMIN_PASSWORD", "admin123"))
        conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("admin", password_hash))

    conn.commit()
    conn.close()


# =========================================================
# AUTHENTICATION (LOGIN / LOGOUT)
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect("/dashboard")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        throttle_key = (request.remote_addr, username.lower())

        wait = lockout_seconds_left(throttle_key)
        if wait:
            return render_template("login.html", error=lockout_message(wait)), 429

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            clear_failures(throttle_key)
            session.clear()  # fresh session (and fresh CSRF token) after login
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect("/dashboard")

        record_failure(throttle_key)

        wait = lockout_seconds_left(throttle_key)
        if wait:
            return render_template("login.html", error=lockout_message(wait)), 429

        return render_template("login.html", error="Invalid username or password."), 401

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


WEAK_PASSWORDS = {"admin123", "password", "12345678", "123456789", "qwerty123", "admin1234"}


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "GET":
        return render_template("change_password.html")

    throttle_key = (request.remote_addr, "change_password:" + str(session["user_id"]))
    wait = lockout_seconds_left(throttle_key)
    if wait:
        return render_template("change_password.html", error=lockout_message(wait)), 429

    current = request.form.get("current_password", "")
    new = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")

    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

    if user is None:
        conn.close()
        session.clear()
        return redirect("/login")

    error = None
    if not check_password_hash(user["password"], current):
        error = "Current password is incorrect."
        record_failure(throttle_key)
    elif len(new) < 8:
        error = "New password must be at least 8 characters."
    elif new.lower() in WEAK_PASSWORDS:
        error = "That password is too common. Choose something harder to guess."
    elif new == current:
        error = "New password must be different from the current one."
    elif new != confirm:
        error = "New passwords do not match."

    if error:
        conn.close()
        return render_template("change_password.html", error=error), 400

    conn.execute(
        "UPDATE users SET password = ? WHERE id = ?",
        (generate_password_hash(new), user["id"])
    )
    conn.commit()
    conn.close()
    clear_failures(throttle_key)

    return render_template("change_password.html", success="Password changed successfully.")


# =========================================================
# PRODUCTS & INVENTORY
# =========================================================

@app.route("/")
@login_required
def products():
    conn = get_db_connection()
    products_list = conn.execute(
        "SELECT * FROM products WHERE is_active = 1 ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return render_template("products.html", products=products_list)


@app.route("/add_product", methods=["POST"])
@login_required
def add_product():
    name = request.form.get("name", "").strip()
    barcode = request.form.get("barcode", "").strip() or None
    category = request.form.get("category", "").strip()
    price = request.form.get("price", "0").strip()
    stock = request.form.get("stock", "0").strip()

    if not name:
        return "Product name is required."

    try:
        price = float(price)
        stock = int(stock)
    except ValueError:
        return "Invalid price or stock."

    if price < 0 or stock < 0:
        return "Price and stock cannot be negative."

    conn = get_db_connection()
    if barcode:
        existing = conn.execute(
            "SELECT id FROM products WHERE barcode = ? AND is_active = 1", (barcode,)
        ).fetchone()
        if existing:
            conn.close()
            return "Error: This barcode already exists."

    try:
        conn.execute(
            "INSERT INTO products (name, barcode, category, price, stock) VALUES (?, ?, ?, ?, ?)",
            (name, barcode, category, price, stock)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        conn.close()
        return "Error: Database error."

    conn.close()
    return redirect("/")


@app.route("/edit_product/<int:id>", methods=["GET", "POST"])
@login_required
def edit_product(id):
    conn = get_db_connection()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        barcode = request.form.get("barcode", "").strip() or None
        category = request.form.get("category", "").strip()
        price = request.form.get("price", "0").strip()
        stock = request.form.get("stock", "0").strip()

        if not name:
            conn.close()
            return "Product name is required."

        try:
            price = float(price)
            stock = int(stock)
        except ValueError:
            conn.close()
            return "Invalid price or stock."

        if price < 0 or stock < 0:
            conn.close()
            return "Price and stock cannot be negative."

        if barcode:
            existing = conn.execute(
                "SELECT id FROM products WHERE barcode = ? AND id != ? AND is_active = 1",
                (barcode, id)
            ).fetchone()
            if existing:
                conn.close()
                return "Error: This barcode already exists."

        conn.execute(
            "UPDATE products SET name = ?, barcode = ?, category = ?, price = ?, stock = ? WHERE id = ?",
            (name, barcode, category, price, stock, id)
        )
        conn.commit()
        conn.close()
        return redirect("/")

    product = conn.execute(
        "SELECT * FROM products WHERE id = ? AND is_active = 1", (id,)
    ).fetchone()
    conn.close()

    if product is None:
        return "Product not found."

    return render_template("edit_product.html", product=product)


@app.route("/restock_product/<int:id>", methods=["POST"])
@login_required
def restock_product(id):
    additional_stock = request.form.get("add_stock", "0").strip()
    try:
        additional_stock = int(additional_stock)
    except ValueError:
        return "Invalid quantity."

    if additional_stock <= 0:
        return "Quantity must be greater than zero."

    conn = get_db_connection()
    cursor = conn.execute(
        "UPDATE products SET stock = stock + ? WHERE id = ? AND is_active = 1",
        (additional_stock, id)
    )
    conn.commit()
    conn.close()

    if cursor.rowcount == 0:
        return "Product not found."

    return redirect("/")


@app.route("/delete_product/<int:id>", methods=["POST"])
@login_required
def delete_product(id):
    conn = get_db_connection()

    used = conn.execute(
        "SELECT 1 FROM sale_items WHERE product_id = ? LIMIT 1", (id,)
    ).fetchone()

    if used:
        # Product appears on old invoices: hide it instead of deleting it,
        # so those invoices keep working.
        conn.execute("UPDATE products SET is_active = 0 WHERE id = ?", (id,))
    else:
        conn.execute("DELETE FROM products WHERE id = ?", (id,))

    conn.commit()
    conn.close()
    return redirect("/")


# =========================================================
# POS & API SEARCH
# =========================================================

@app.route("/pos")
@login_required
def pos():
    conn = get_db_connection()
    products_list = conn.execute(
        "SELECT * FROM products WHERE is_active = 1 ORDER BY name ASC"
    ).fetchall()
    customers_list = conn.execute("SELECT * FROM customers ORDER BY name ASC").fetchall()
    conn.close()
    return render_template("pos.html", products=products_list, customers=customers_list)


@app.route("/api/search_product", methods=["GET"])
@login_required
def api_search_product():
    """Barcode / product name search used by the POS scan box."""
    query = request.args.get("q", "").strip()
    if not query:
        return jsonify([])

    conn = get_db_connection()
    products_list = conn.execute(
        """
        SELECT id, name, barcode, category, price, stock
        FROM products
        WHERE is_active = 1 AND (barcode = ? OR name LIKE ?)
        ORDER BY CASE WHEN barcode = ? THEN 0 ELSE 1 END, name ASC
        LIMIT 10
        """,
        (query, f"%{query}%", query)
    ).fetchall()
    conn.close()

    return jsonify([dict(p) for p in products_list])


# =========================================================
# PROCESS PAYMENT & SALES
# The server recalculates every amount from database prices.
# Totals sent by the browser are never trusted.
# =========================================================

def _fail(conn, message, status=400):
    conn.rollback()
    return jsonify({"success": False, "message": message}), status


@app.route("/process_payment", methods=["POST"])
@login_required
def process_payment():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "No payment data received."}), 400

    cart = data.get("cart") or []
    if not cart:
        return jsonify({"success": False, "message": "Cart is empty."}), 400

    payment_method = data.get("payment_method", "Cash")
    if payment_method not in ALLOWED_PAYMENT_METHODS:
        return jsonify({"success": False, "message": "Invalid payment method."}), 400

    # ---- numeric inputs ----
    try:
        discount_type = data.get("discount_type", "fixed")
        discount_value = float(data.get("discount_value") or 0)
        tax_rate = float(data.get("tax_rate") or 0)
        cash_received = float(data.get("cash_received") or 0) if payment_method == "Cash" else 0.0

        customer_id = data.get("customer_id")
        if customer_id in ("", None, "null"):
            customer_id = None
        else:
            customer_id = int(customer_id)
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid numeric value."}), 400

    for number in (discount_value, tax_rate, cash_received):
        if not math.isfinite(number):
            return jsonify({"success": False, "message": "Invalid numeric value."}), 400

    if discount_type not in ("fixed", "percent"):
        return jsonify({"success": False, "message": "Invalid discount type."}), 400
    if discount_value < 0:
        return jsonify({"success": False, "message": "Discount cannot be negative."}), 400
    if discount_type == "percent" and discount_value > 100:
        return jsonify({"success": False, "message": "Discount cannot exceed 100%."}), 400
    if tax_rate < 0 or tax_rate > 100:
        return jsonify({"success": False, "message": "Tax rate must be between 0 and 100."}), 400

    # ---- merge duplicate cart lines so stock is checked on the real quantity ----
    wanted = {}
    try:
        for item in cart:
            product_id = int(item.get("id"))
            quantity = int(item.get("quantity", 0))
            if quantity <= 0:
                raise ValueError
            wanted[product_id] = wanted.get(product_id, 0) + quantity
    except (TypeError, ValueError, AttributeError):
        return jsonify({"success": False, "message": "Invalid cart item."}), 400

    conn = get_db_connection()

    try:
        conn.execute("BEGIN IMMEDIATE")

        # ---- price every line from the database ----
        lines = []
        subtotal = 0.0

        for product_id, quantity in wanted.items():
            product = conn.execute(
                "SELECT * FROM products WHERE id = ? AND is_active = 1", (product_id,)
            ).fetchone()

            if not product:
                return _fail(conn, "Product not found.")

            if product["stock"] < quantity:
                return _fail(conn, f"Not enough stock for {product['name']}.")

            price = float(product["price"])
            line_total = round(price * quantity, 2)
            lines.append((product_id, quantity, price, line_total))
            subtotal += line_total

        subtotal = round(subtotal, 2)

        # ---- discount, then tax on the discounted amount ----
        if discount_type == "percent":
            discount_amount = round(subtotal * discount_value / 100, 2)
        else:
            discount_amount = round(discount_value, 2)

        if discount_amount > subtotal:
            return _fail(conn, "Discount cannot be more than the subtotal.")

        taxable = round(subtotal - discount_amount, 2)
        tax_amount = round(taxable * tax_rate / 100, 2)
        total = round(taxable + tax_amount, 2)

        if total <= 0:
            return _fail(conn, "Invalid total amount.")

        if payment_method == "Cash" and round(cash_received, 2) < total:
            return _fail(conn, "Cash received is less than total.")

        change_amount = round(cash_received - total, 2) if payment_method == "Cash" else 0.0

        if customer_id is not None:
            customer = conn.execute(
                "SELECT id FROM customers WHERE id = ?", (customer_id,)
            ).fetchone()
            if not customer:
                return _fail(conn, "Customer not found.")

        now = datetime.now()
        invoice_no = now.strftime("INV-%Y%m%d%H%M%S") + "-" + secrets.token_hex(2).upper()
        sale_date = now.strftime("%Y-%m-%d %H:%M:%S")

        cursor = conn.execute("""
            INSERT INTO sales (invoice_no, subtotal, total, discount, tax, payment_method,
                               cash_received, change_amount, sale_date, customer_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (invoice_no, subtotal, total, discount_amount, tax_amount, payment_method,
              cash_received, change_amount, sale_date, customer_id))

        sale_id = cursor.lastrowid

        for product_id, quantity, price, line_total in lines:
            conn.execute(
                "INSERT INTO sale_items (sale_id, product_id, quantity, price, subtotal) VALUES (?, ?, ?, ?, ?)",
                (sale_id, product_id, quantity, price, line_total)
            )

            updated = conn.execute(
                "UPDATE products SET stock = stock - ? WHERE id = ? AND stock >= ?",
                (quantity, product_id, quantity)
            )
            if updated.rowcount == 0:
                return _fail(conn, "Stock changed while processing. Please try again.")

        conn.commit()

        return jsonify({
            "success": True,
            "invoice_no": invoice_no,
            "sale_id": sale_id,
            "total": total,
            "message": "Payment completed successfully."
        })

    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        conn.close()


# =========================================================
# INVOICES & REPORTING
# =========================================================

@app.route("/invoices")
@login_required
def invoices():
    conn = get_db_connection()
    sales_list = conn.execute("""
        SELECT sales.*, customers.name AS customer_name
        FROM sales
        LEFT JOIN customers ON sales.customer_id = customers.id
        ORDER BY sales.id DESC
    """).fetchall()
    conn.close()
    return render_template("invoices.html", sales=sales_list)


@app.route("/invoice/<int:id>")
@login_required
def view_invoice(id):
    conn = get_db_connection()
    sale = conn.execute("""
        SELECT sales.*, customers.name AS customer_name, customers.phone AS customer_phone,
               customers.email AS customer_email, customers.address AS customer_address
        FROM sales
        LEFT JOIN customers ON sales.customer_id = customers.id
        WHERE sales.id = ?
    """, (id,)).fetchone()

    if sale is None:
        conn.close()
        return "Invoice not found."

    items = conn.execute("""
        SELECT sale_items.*, products.name AS product_name, products.barcode AS barcode
        FROM sale_items
        JOIN products ON sale_items.product_id = products.id
        WHERE sale_items.sale_id = ?
        ORDER BY sale_items.id ASC
    """, (id,)).fetchall()

    conn.close()
    return render_template("view_invoice.html", sale=sale, items=items)


def resolve_date_range():
    """Reads ?preset= (today, yesterday, last_7, this_month) or ?start_date=&end_date=.
    Returns (preset, start_date, end_date) as strings; dates are "" when no filter applies."""
    preset = request.args.get("preset", "").strip()
    today = date.today()

    if preset == "today":
        start, end = today, today
    elif preset == "yesterday":
        start = end = today - timedelta(days=1)
    elif preset == "last_7":
        start, end = today - timedelta(days=6), today
    elif preset == "this_month":
        start, end = today.replace(day=1), today
    else:
        preset = ""
        try:
            start = datetime.strptime(request.args.get("start_date", "").strip(), "%Y-%m-%d").date()
            end = datetime.strptime(request.args.get("end_date", "").strip(), "%Y-%m-%d").date()
        except ValueError:
            return "", "", ""
        if start > end:
            start, end = end, start

    return preset, start.isoformat(), end.isoformat()


@app.route("/reports/filter")
@login_required
def reports_filter():
    # Kept for convenience: /reports handles all filtering.
    return redirect("/reports?" + request.query_string.decode())


@app.route("/reports")
@login_required
def reports():
    preset, start_date, end_date = resolve_date_range()

    conn = get_db_connection()

    base_query = """
        SELECT sales.*, customers.name AS customer_name
        FROM sales
        LEFT JOIN customers ON sales.customer_id = customers.id
    """
    params = []

    if start_date and end_date:
        base_query += " WHERE DATE(sales.sale_date) BETWEEN ? AND ?"
        params.extend([start_date, end_date])

    base_query += " ORDER BY sales.id DESC"
    sales_report = conn.execute(base_query, params).fetchall()

    total_sales = len(sales_report)
    total_revenue = sum(row["total"] for row in sales_report)
    total_discount = sum(row["discount"] or 0 for row in sales_report)
    total_tax = sum(row["tax"] or 0 for row in sales_report)

    today = datetime.now().strftime("%Y-%m-%d")
    today_stats = conn.execute(
        "SELECT COUNT(*) AS orders, COALESCE(SUM(total), 0) AS revenue FROM sales WHERE sale_date LIKE ?",
        (today + "%",)
    ).fetchone()

    current_month = datetime.now().strftime("%Y-%m")
    month_revenue = conn.execute(
        "SELECT COALESCE(SUM(total), 0) AS revenue FROM sales WHERE sale_date LIKE ?",
        (current_month + "%",)
    ).fetchone()["revenue"]

    total_products = conn.execute(
        "SELECT COUNT(*) AS count FROM products WHERE is_active = 1"
    ).fetchone()["count"]
    low_stock = conn.execute(
        "SELECT * FROM products WHERE is_active = 1 AND stock <= 5 ORDER BY stock ASC"
    ).fetchall()

    payment_methods = conn.execute("""
        SELECT payment_method, COUNT(*) AS orders, COALESCE(SUM(total), 0) AS revenue
        FROM sales GROUP BY payment_method ORDER BY revenue DESC
    """).fetchall()

    top_products = conn.execute("""
        SELECT products.name AS product_name, SUM(sale_items.quantity) AS quantity_sold, SUM(sale_items.subtotal) AS revenue
        FROM sale_items JOIN products ON sale_items.product_id = products.id
        GROUP BY sale_items.product_id ORDER BY quantity_sold DESC LIMIT 10
    """).fetchall()

    conn.close()

    return render_template(
        "reports.html",
        total_sales=total_sales,
        total_revenue=total_revenue,
        total_discount=total_discount,
        total_tax=total_tax,
        today_orders=today_stats["orders"],
        today_revenue=today_stats["revenue"],
        month_revenue=month_revenue,
        total_products=total_products,
        low_stock=low_stock,
        payment_methods=payment_methods,
        sales_report=sales_report,
        top_products=top_products,
        start_date=start_date,
        end_date=end_date,
        preset=preset
    )


@app.route("/export_sales_csv")
@login_required
def export_sales_csv():
    # Uses the same filters as /reports, e.g. /export_sales_csv?preset=this_month
    preset, start_date, end_date = resolve_date_range()

    query = """
        SELECT sales.invoice_no, sales.sale_date, COALESCE(customers.name, 'Walk-in') AS customer,
               sales.payment_method, sales.subtotal, sales.discount, sales.tax, sales.total
        FROM sales
        LEFT JOIN customers ON sales.customer_id = customers.id
    """
    params = []

    if start_date and end_date:
        query += " WHERE DATE(sales.sale_date) BETWEEN ? AND ?"
        params.extend([start_date, end_date])

    query += " ORDER BY sales.id DESC"

    conn = get_db_connection()
    sales_data = conn.execute(query, params).fetchall()
    conn.close()

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["Invoice No", "Date & Time", "Customer", "Payment Method",
                     "Subtotal", "Discount", "Tax", "Total Amount"])

    for sale in sales_data:
        writer.writerow([
            sale["invoice_no"], sale["sale_date"], sale["customer"], sale["payment_method"],
            sale["subtotal"], sale["discount"], sale["tax"], sale["total"]
        ])

    filename = f"sales_report_{datetime.now().strftime('%Y%m%d')}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )


# =========================================================
# CUSTOMERS & DASHBOARD
# =========================================================

@app.route("/customers")
@login_required
def customers():
    conn = get_db_connection()
    customers_list = conn.execute("SELECT * FROM customers ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("customers.html", customers=customers_list)


@app.route("/add_customer", methods=["POST"])
@login_required
def add_customer():
    name = request.form.get("name", "").strip()
    phone = request.form.get("phone", "").strip()
    email = request.form.get("email", "").strip()
    address = request.form.get("address", "").strip()

    if not name:
        return "Customer name is required."

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO customers (name, phone, email, address) VALUES (?, ?, ?, ?)",
        (name, phone, email, address)
    )
    conn.commit()
    conn.close()
    return redirect("/customers")


@app.route("/edit_customer/<int:id>", methods=["GET", "POST"])
@login_required
def edit_customer(id):
    conn = get_db_connection()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        address = request.form.get("address", "").strip()

        if not name:
            conn.close()
            return "Customer name is required."

        conn.execute(
            "UPDATE customers SET name = ?, phone = ?, email = ?, address = ? WHERE id = ?",
            (name, phone, email, address, id)
        )
        conn.commit()
        conn.close()
        return redirect("/customers")

    customer = conn.execute("SELECT * FROM customers WHERE id = ?", (id,)).fetchone()
    conn.close()
    if customer is None:
        return "Customer not found."

    return render_template("edit_customer.html", customer=customer)


@app.route("/delete_customer/<int:id>", methods=["POST"])
@login_required
def delete_customer(id):
    conn = get_db_connection()
    conn.execute("UPDATE sales SET customer_id = NULL WHERE customer_id = ?", (id,))
    conn.execute("DELETE FROM customers WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    return redirect("/customers")


@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db_connection()
    total_revenue = conn.execute("SELECT COALESCE(SUM(total), 0) AS total FROM sales").fetchone()["total"]
    total_orders = conn.execute("SELECT COUNT(*) AS count FROM sales").fetchone()["count"]
    total_products = conn.execute(
        "SELECT COUNT(*) AS count FROM products WHERE is_active = 1"
    ).fetchone()["count"]
    total_stock = conn.execute(
        "SELECT COALESCE(SUM(stock), 0) AS total FROM products WHERE is_active = 1"
    ).fetchone()["total"]

    low_stock = conn.execute("""
        SELECT * FROM products WHERE is_active = 1 AND stock <= 5
        ORDER BY CASE WHEN stock = 0 THEN 0 ELSE 1 END, stock ASC, name ASC LIMIT 10
    """).fetchall()

    recent_sales = conn.execute("""
        SELECT sales.*, customers.name AS customer_name FROM sales
        LEFT JOIN customers ON sales.customer_id = customers.id
        ORDER BY sales.id DESC LIMIT 10
    """).fetchall()

    chart_rows = conn.execute("""
        SELECT DATE(sale_date) AS sale_day, COALESCE(SUM(total), 0) AS revenue
        FROM sales GROUP BY DATE(sale_date) ORDER BY DATE(sale_date) ASC LIMIT 30
    """).fetchall()

    chart_labels = [row["sale_day"] for row in chart_rows]
    chart_data = [row["revenue"] for row in chart_rows]
    conn.close()

    return render_template(
        "dashboard.html",
        total_revenue=total_revenue,
        total_orders=total_orders,
        total_products=total_products,
        total_stock=total_stock,
        low_stock=low_stock,
        recent_sales=recent_sales,
        chart_labels=chart_labels,
        chart_data=chart_data
    )


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":
    init_db()

    # Optional settings, set as environment variables before running:
    #   HTTPS=1        serve over https with a self-signed certificate. Needed for the
    #                  camera scanner on a phone (also: pip install cryptography).
    #   HOST=0.0.0.0   let other devices on your network connect (default: this computer only).
    #   PORT=5000      port number.
    #   FLASK_DEBUG=1  debug mode (only allowed when HOST is this computer).
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    use_https = os.environ.get("HTTPS") == "1"
    debug = os.environ.get("FLASK_DEBUG") == "1"

    if debug and host not in ("127.0.0.1", "localhost"):
        print("Debug mode is switched off because HOST is open to the network.")
        debug = False

    app.run(host=host, port=port, debug=debug, ssl_context="adhoc" if use_https else None)

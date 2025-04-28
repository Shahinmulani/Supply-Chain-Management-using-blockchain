from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import json
from datetime import datetime
from werkzeug.utils import secure_filename
import os
import time


# Initialize Flask, Flask-Login, and Flask-SQLAlchemy
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'

# Directory to save uploaded images
app.config['UPLOAD_FOLDER'] = 'static/images'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Default login view for user

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    
# Product Model
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    status = db.Column(db.String(150), nullable=False)
    category = db.Column(db.String(150), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(500), nullable=False)
    manufacturer = db.Column(db.String(150), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    image_filename = db.Column(db.String(150), nullable=True)

# Blockchain Block Model
class Block(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    index = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.Float, default=time.time)
    product_id = db.Column(db.Integer, nullable=False)
    data = db.Column(db.Text, nullable=False)
    previous_hash = db.Column(db.String(64), nullable=False)
    hash = db.Column(db.String(64), nullable=False)

    def calculate_hash(self):
        return str(hash((self.index, self.timestamp, self.data, self.previous_hash)))
    
    # Cart Model
class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    quantity = db.Column(db.Integer, default=1)
    
    # Relationship to get the product details
    product = db.relationship('Product', backref='cart_items')


# Wishlist Model
class Wishlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    product = db.relationship('Product', backref='wishlist_items')
    user = db.relationship('User', backref='wishlist_items')

# Order Model
class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(100), default="Pending")  # Order Status (e.g., Pending, Shipped, Delivered)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='orders')
    product = db.relationship('Product', backref='orders')
    





@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Initialize admin user
def initialize_admin_user():
    admin_username = 'admin'
    admin_password = 'admin@123'
    
    # Check if an admin user already exists
    admin_user = User.query.filter_by(username=admin_username).first()
    
    if not admin_user:
        hashed_password = generate_password_hash(admin_password)
        new_admin = User(username=admin_username, password=hashed_password)
        db.session.add(new_admin)
        db.session.commit()
        print("Admin user created.")
    else:
        print("Admin user already exists.")

# Route to choose User or Admin login
@app.route('/')
def home1():
    if current_user.is_authenticated:
        return redirect(url_for('user_home'))  # Redirect to user home if already logged in
    return render_template('home1.html')

# User Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        # Ensure this is not the admin user
        if user and user.username != 'admin' and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            print("User logged in successfully. Redirecting to user home.")
            return redirect(url_for('user_home'))
        else:
            flash('Invalid username or password.', 'danger')
            print("Invalid login attempt.")
            return redirect(url_for('login'))

    return render_template('login.html')

# Admin Login Route
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        # Ensure this is the admin user
        if user and user.username == 'admin' and check_password_hash(user.password, password):
            login_user(user)
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin username or password.', 'danger')
            return redirect(url_for('admin_login'))

    return render_template('admin_login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


# User Home Route
# User Home Route
@app.route('/home')
@login_required
def user_home():
    # Retrieve all products from the database
    products = Product.query.all()
    return render_template('home.html', products=products)

# Admin Dashboard Route
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.username != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('user_home'))
    return render_template('index.html')  # Admin dashboard page

# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home1'))

# Add Product Route
# Add Product Route
@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if request.method == 'POST':
        try:
            product_name = request.form['name']
            product_status = request.form['status']
            product_category = request.form['category']
            product_price = float(request.form['price'])
            product_description = request.form['description']
            product_manufacturer = request.form['manufacturer']
            product_quantity = int(request.form['quantity'])
            image_file = request.files['image']

            # Save the image file if uploaded
            if image_file:
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image_file.save(image_path)
                image_filename = filename
            else:
                image_filename = None

            # Add product to database
            new_product = Product(
                name=product_name,
                status=product_status,
                category=product_category,
                price=product_price,
                description=product_description,
                manufacturer=product_manufacturer,
                quantity=product_quantity,
                image_filename=image_filename
            )
            db.session.add(new_product)
            db.session.commit()

            # Blockchain entry
            last_block = Block.query.order_by(Block.index.desc()).first()
            previous_hash = last_block.hash if last_block else '0'

            # Block data
            block_data = {
                'id': new_product.id,
                'name': product_name,
                'status': product_status,
                'category': product_category,
                'price': product_price,
                'description': product_description,
                'manufacturer': product_manufacturer,
                'quantity': product_quantity,
                'image_filename': image_filename
            }
            new_block = Block(
                index=(last_block.index + 1) if last_block else 0,
                timestamp=time.time(),
                product_id=new_product.id,
                data=json.dumps(block_data),
                previous_hash=previous_hash,
                hash=str(hash((last_block.index + 1 if last_block else 0, time.time(), json.dumps(block_data), previous_hash)))
            )
            db.session.add(new_block)
            db.session.commit()

            return jsonify({"message": "Product added successfully!"}), 200

        except Exception as e:
            print(f"Error adding product: {e}")
            return jsonify({"message": "An error occurred while adding the product."}), 500

    return render_template('add_product.html')

@app.route('/update_product', methods=['GET', 'POST'])
@login_required
def update_product():
    # Fetch all products to display on the page
    products = Product.query.all()
    product = None  # Initialize the product variable to None
    
    if request.method == 'POST':
        try:
            product_id = request.form['product_id']  # Get the product ID from the form
            product = Product.query.get_or_404(product_id)  # Fetch the product to update

            # Get the updated product details from the form
            product.name = request.form['name']
            product.status = request.form['status']
            product.category = request.form['category']
            product.price = float(request.form['price'])
            product.description = request.form['description']
            product.manufacturer = request.form['manufacturer']
            product.quantity = int(request.form['quantity'])

            # Handle image upload if a new image is provided
            image_file = request.files['image']
            if image_file:
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image_file.save(image_path)
                product.image_filename = filename  # Update the image filename in the database

            # Commit the changes to the database
            db.session.commit()
            flash('Product updated successfully!', 'success')
            return redirect(url_for('update_product'))  # Redirect to the update page after saving

        except Exception as e:
            print(f"Error updating product: {e}")
            flash('An error occurred while updating the product.', 'danger')

    # Render the update page with the list of all products
    return render_template('update_product.html', products=products, product=product)


# Show All Products
@app.route('/show_all_products', methods=['GET'])
@login_required
def show_all_products():
    products = Product.query.all()
    return render_template('show_all_products.html', products=products)

# Product Details with Blockchain History
@app.route('/get_product/<int:product_id>', methods=['GET'])
@login_required
def get_product(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_info.html', product=product)

# Blockchain History for a Product
@app.route('/get_product_blockchain/<int:product_id>', methods=['GET'])
@login_required
def get_product_blockchain(product_id):
    product = Product.query.get_or_404(product_id)
    product_blocks = Block.query.filter_by(product_id=product_id).order_by(Block.index).all()

    # Parse JSON data in each block before sending to the template
    parsed_blocks = []
    for block in product_blocks:
        block_data = json.loads(block.data)
        parsed_blocks.append({
            'index': block.index,
            'timestamp': block.timestamp,
            'data': block_data,
            'previous_hash': block.previous_hash,
            'hash': block.hash
        })

    return render_template('product_blockchain.html', product=product, blocks=parsed_blocks)

# Delete Product Route
@app.route('/delete_product/<int:product_id>', methods=['DELETE'])
@login_required
def delete_product(product_id):
    try:
        product = Product.query.get(product_id)
        if product is None:
            return jsonify({"message": "Product not found."}), 404

        # Delete product and related blockchain entries
        db.session.delete(product)
        Block.query.filter_by(product_id=product_id).delete()
        db.session.commit()

        return jsonify({"message": "Product deleted successfully"}), 200

    except Exception as e:
        print(f"Error deleting product: {e}")
        return jsonify({"message": "An error occurred while deleting the product."}), 500

# Custom filter to format timestamps
@app.template_filter('datetimeformat')
def datetimeformat(value):
    return datetime.fromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S')

# View Product Details Route
@app.route('/product/<int:product_id>', methods=['GET'])
def product_details(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_details.html', product=product)

@app.route('/cart')
@login_required
def view_cart():
    # Fetch the cart items for the current user
    cart_items = Cart.query.filter_by(user_id=current_user.id).all()
    total = sum(item.product.price * item.quantity for item in cart_items)
    
    return render_template('cart.html', cart_items=cart_items, total=total)


@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)
    
    # Try to get 'quantity' from the form, default to 1 if not present or invalid
    try:
        quantity = int(request.form.get('quantity', 1))  # Default to 1 if not found
    except ValueError:
        flash('Invalid quantity value.', 'danger')
        return redirect(url_for('user_home'))  # Redirect to home if invalid quantity

    # Check if the product already exists in the user's cart
    existing_cart_item = Cart.query.filter_by(user_id=current_user.id, product_id=product.id).first()
    if existing_cart_item:
        # Update quantity if the product is already in the cart
        existing_cart_item.quantity += quantity
    else:
        # Create a new cart item if the product isn't in the cart yet
        new_cart_item = Cart(user_id=current_user.id, product_id=product.id, quantity=quantity)
        db.session.add(new_cart_item)
    
    db.session.commit()
    flash('Product added to your cart!', 'success')
    return redirect(url_for('view_cart'))  # Redirect to cart page after adding the item


@app.route('/update_cart/<int:cart_item_id>', methods=['POST'])
@login_required
def update_cart(cart_item_id):
    cart_item = Cart.query.get_or_404(cart_item_id)
    if cart_item.user_id != current_user.id:
        flash('You cannot modify someone else\'s cart.', 'danger')
        return redirect(url_for('view_cart'))

    # Check if the 'quantity' key is in the form
    quantity = request.form.get('quantity')
    
    if not quantity:
        flash('Quantity is required.', 'danger')
        return redirect(url_for('view_cart'))  # Redirect to cart page if quantity is missing

    try:
        quantity = int(quantity)  # Convert to integer
    except ValueError:
        flash('Invalid quantity value.', 'danger')
        return redirect(url_for('view_cart'))  # Redirect to cart page if quantity is invalid

    if quantity < 1:
        flash('Quantity must be at least 1.', 'danger')
        return redirect(url_for('view_cart'))  # Redirect to cart page if quantity is invalid

    cart_item.quantity = quantity
    db.session.commit()

    flash('Cart updated!', 'success')
    return redirect(url_for('view_cart'))  # Redirect to cart page after updating
# Add to Wishlist Route
@app.route('/add_to_wishlist/<int:product_id>', methods=['POST'])
@login_required
def add_to_wishlist(product_id):
    product = Product.query.get_or_404(product_id)
    
    # Check if the product is already in the user's wishlist
    existing_item = Wishlist.query.filter_by(user_id=current_user.id, product_id=product.id).first()
    if existing_item:
        flash('Product is already in your wishlist!', 'info')
    else:
        new_item = Wishlist(user_id=current_user.id, product_id=product.id)
        db.session.add(new_item)
        db.session.commit()
        flash('Product added to wishlist!', 'success')
    
    return redirect(url_for('home'))

# Order Product Route
@app.route('/order/<int:product_id>', methods=['POST'])
@login_required
def order_product(product_id):
    product = Product.query.get_or_404(product_id)

    # Check if the quantity in the cart is available
    quantity = request.form.get('quantity', type=int, default=1)

    if product.quantity < quantity:
        flash('Not enough stock available for this product.', 'danger')
        return redirect(url_for('product_details', product_id=product.id))

    # Create a new order
    new_order = Order(user_id=current_user.id, product_id=product.id, quantity=quantity)
    db.session.add(new_order)
    db.session.commit()

    # Update the product quantity
    product.quantity -= quantity
    db.session.commit()

    flash('Order placed successfully!', 'success')
    return redirect(url_for('home'))

# View Orders Route
@app.route('/orders')
@login_required
def view_orders():
    orders = Order.query.filter_by(user_id=current_user.id).all()
    return render_template('orders.html', orders=orders)

# Example search route
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '')  # Get the search query from the request
    # Perform search logic: filter products where the name or description contains the search query (case-insensitive)
    products = Product.query.filter(
        (Product.name.ilike(f'%{query}%')) | (Product.description.ilike(f'%{query}%'))
    ).all()
    
    return render_template('home.html', products=products, query=query)


@app.route('/profile')
def profile():
    return render_template('profile.html')  # Assuming you have a profile.html file

@app.route('/remove_from_cart/<int:cart_item_id>', methods=['POST'])
@login_required
def remove_from_cart(cart_item_id):
    cart_item = Cart.query.get_or_404(cart_item_id)
    if cart_item.user_id != current_user.id:
        flash('You cannot remove someone else\'s cart item.', 'danger')
        return redirect(url_for('view_cart'))
    
    db.session.delete(cart_item)
    db.session.commit()
    flash('Item removed from your cart!', 'success')
    return redirect(url_for('view_cart'))

@app.route('/checkout')
def checkout():
    cart_items = session.get('cart', [])  # Assuming you're storing cart in session
    total = sum(item['price'] * item['quantity'] for item in cart_items)
    return render_template('checkout.html', cart_items=cart_items, total=total)


@app.route('/process_checkout', methods=['POST'])
def process_checkout():
    # Get form data from the request
    name = request.form.get('name')
    address = request.form.get('address')
    city = request.form.get('city')
    state = request.form.get('state')
    zip_code = request.form.get('zip')
    phone = request.form.get('phone')

    # Process the checkout, save order to database, send email, etc.
    # (You can add your logic here)

    # Redirect to a success page or show a confirmation message
    return render_template('checkout_success.html', name=name, address=address, city=city, state=state, zip_code=zip_code, phone=phone)


# Create database and initialize admin user
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        initialize_admin_user()
    app.run(debug=True) 
from flask import render_template,session, request,redirect,url_for,flash,current_app,make_response
from flask_login import login_required, current_user, logout_user, login_user
from shop import app,db,photos, search,bcrypt,login_manager
from .forms import CustomerRegisterForm, CustomerLoginFrom
from .model import Register,CustomerOrder
from authorizenet import apicontractsv1
from authorizenet.apicontrollers import *
from decimal import *
import secrets
import os
import json
import pdfkit
import stripe

buplishable_key ='pk_test_51H3lieBRdZGvpYsWkiRoJcabf0TQpBoJ4BnB0AvuL2U8vMLArlY6ilTJuKU0zNcxjdEg0Yx6v2RBfGn4vKffR2L600YpIEHanV'
stripe.api_key ='sk_test_51H3lieBRdZGvpYsWjppIdDdV3J7gh6NA9Txzp33hgkr03lLmiBdAyTSInUF34O3l16aGASJGM3Z7gnpwutJpveDY00iSFCH2pm'

@app.route('/payment',methods=['POST'])
def payment():
    invoice = request.get('invoice')
    amount = request.form.get('amount')
    stripe.api_key = 'sk_test_51H3lieBRdZGvpYsWjppIdDdV3J7gh6NA9Txzp33hgkr03lLmiBdAyTSInUF34O3l16aGASJGM3Z7gnpwutJpveDY00iSFCH2pm'
    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price': '{{PRICE_ID}}',
            'quantity': 1,
        }],
        payment_intent_data={
            'application_fee_amount': 200,
        },
        mode='payment',
        success_url='https://example.com/success',
        cancel_url='https://example.com/cancel',
        stripe_account='{{CONNECTED_STRIPE_ACCOUNT_ID}}',
    )

    '''
    customer = stripe.Customer.create(
      email=request.form['stripeEmail'],
      source=request.form['stripeToken'],
    )
    charge = stripe.Charge.create(
      customer=customer.id,
      description='Myshop',
      amount=amount,
      currency='usd',
    )
    '''

    orders =  CustomerOrder.query.filter_by(customer_id = current_user.id,invoice=invoice).order_by(CustomerOrder.id.desc()).first()
    orders.status = 'Paid'
    db.session.commit()
    return redirect(url_for('thanks'))

@app.route('/authpayment',methods=['POST'])
def authpayment():
    invoice = request.form.get('invoice')
    amount = request.form.get('amount')
    card_name = request.form.get('card_name')
    card_number = request.form.get('card_number')
    expiry = request.form.get('expiry')
    cvv = request.form.get('cvv')
    merchantAuth = apicontractsv1.merchantAuthenticationType()
    merchantAuth.name = '86UGvvLF6N'
    merchantAuth.transactionKey = '3q6vX7mw74JV37mR'

    creditCard = apicontractsv1.creditCardType()
    creditCard.cardNumber = card_number
    creditCard.expirationDate = expiry
    creditCard.cardCode=cvv

    payment = apicontractsv1.paymentType()
    payment.creditCard = creditCard

    transactionrequest = apicontractsv1.transactionRequestType()
    transactionrequest.transactionType = "authCaptureTransaction"
    transactionrequest.amount = Decimal(amount)
    transactionrequest.payment = payment

    createtransactionrequest = apicontractsv1.createTransactionRequest()
    createtransactionrequest.merchantAuthentication = merchantAuth
    createtransactionrequest.refId = invoice

    createtransactionrequest.transactionRequest = transactionrequest
    createtransactioncontroller = createTransactionController(createtransactionrequest)
    createtransactioncontroller.execute()

    response = createtransactioncontroller.getresponse()

    if (response.messages.resultCode=="Ok"):
        print ("Transaction ID : %s" % response.transactionResponse.transId)
        orders =  CustomerOrder.query.filter_by(customer_id = current_user.id,invoice=invoice).order_by(CustomerOrder.id.desc()).first()
        orders.status = 'Paid'
        db.session.commit()
        return redirect(url_for('thanks'))
    else:
        print ("response code: %s" % response.messages.resultCode)
        flash(f'Failed with code { response.messages.resultCode }', 'error')
        return redirect(url_for('orders',invoice=invoice))

@app.route('/thanks')
def thanks():
    return render_template('customer/thank.html')

@app.route('/customer/register', methods=['GET','POST'])
def customer_register():
    form = CustomerRegisterForm()
    if form.validate_on_submit():
        hash_password = bcrypt.generate_password_hash(form.password.data)
        register = Register(name=form.name.data, username=form.username.data, email=form.email.data,password=hash_password,country=form.country.data, city=form.city.data,contact=form.contact.data, address=form.address.data, zipcode=form.zipcode.data)
        db.session.add(register)
        flash(f'Welcome {form.name.data} Thank you for registering', 'success')
        db.session.commit()
        return redirect(url_for('customerLogin'))
    return render_template('customer/register.html', form=form)


@app.route('/customer/login', methods=['GET','POST'])
def customerLogin():
    form = CustomerLoginFrom()
    if form.validate_on_submit():
        user = Register.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('You are login now!', 'success')
            next = request.args.get('next')
            return redirect(next or url_for('home'))
        flash('Incorrect email and password','danger')
        return redirect(url_for('customerLogin'))
            
    return render_template('customer/login.html', form=form)


@app.route('/customer/logout')
def customer_logout():
    logout_user()
    return redirect(url_for('home'))

def updateshoppingcart():
    for key, shopping in session['Shoppingcart'].items():
        session.modified = True
        del shopping['image']
        del shopping['colors']
    return updateshoppingcart

@app.route('/getorder')
@login_required
def get_order():
    if current_user.is_authenticated:
        customer_id = current_user.id
        invoice = secrets.token_hex(5)
        updateshoppingcart
        try:
            order = CustomerOrder(invoice=invoice,customer_id=customer_id,orders=session['Shoppingcart'])
            db.session.add(order)
            db.session.commit()
            session.pop('Shoppingcart')
            flash('Your order has been sent successfully','success')
            return redirect(url_for('orders',invoice=invoice))
        except Exception as e:
            print(e)
            flash('Some thing went wrong while get order', 'danger')
            return redirect(url_for('getCart'))
        


@app.route('/orders/<invoice>')
@login_required
def orders(invoice):
    if current_user.is_authenticated:
        grandTotal = 0
        subTotal = 0
        customer_id = current_user.id
        customer = Register.query.filter_by(id=customer_id).first()
        orders = CustomerOrder.query.filter_by(customer_id=customer_id, invoice=invoice).order_by(CustomerOrder.id.desc()).first()
        for _key, product in orders.orders.items():
            discount = (product['discount']/100) * float(product['price'])
            subTotal += float(product['price']) * int(product['quantity'])
            subTotal -= discount
            tax = ("%.2f" % (.06 * float(subTotal)))
            grandTotal = ("%.2f" % (1.06 * float(subTotal)))
    else:
        return redirect(url_for('customerLogin'))
    return render_template('customer/order.html', invoice=invoice, tax=tax,subTotal=subTotal,grandTotal=grandTotal,customer=customer,orders=orders)

@app.route('/get_pdf/<invoice>', methods=['POST'])
@login_required
def get_pdf(invoice):
    if current_user.is_authenticated:
        grandTotal = 0
        subTotal = 0
        customer_id = current_user.id
        if request.method =="POST":
            customer = Register.query.filter_by(id=customer_id).first()
            orders = CustomerOrder.query.filter_by(customer_id=customer_id, invoice=invoice).order_by(CustomerOrder.id.desc()).first()
            for _key, product in orders.orders.items():
                discount = (product['discount']/100) * float(product['price'])
                subTotal += float(product['price']) * int(product['quantity'])
                subTotal -= discount
                tax = ("%.2f" % (.06 * float(subTotal)))
                grandTotal = float("%.2f" % (1.06 * subTotal))

            rendered =  render_template('customer/pdf.html', invoice=invoice, tax=tax,grandTotal=grandTotal,customer=customer,orders=orders)
            pdf = pdfkit.from_string(rendered, False)
            response = make_response(pdf)
            response.headers['content-Type'] ='application/pdf'
            response.headers['content-Disposition'] ='inline; filename='+invoice+'.pdf'
            return response
    return request(url_for('orders'))
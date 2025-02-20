# DRF Authentication API

## Overview
This project is a Django REST Framework (DRF) based authentication system that includes the following features:
- User Registration
- Login/Logout
- Two-Factor Authentication (2FA) using Email OTP
- Password Reset (Forgot Password)
- Account Locking after multiple failed login attempts

The project also includes a frontend that interacts with the API for a seamless user experience.


1. Clone the repository:
   ```bash
   git clone https://github.com/shariqsajad88/Django_login_app.git
   cd auth_project
   ```
2. Create a virtual environment and activate it:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Set up environment variables:
   - Create a `.env` file and configure the following:

5. Run database migrations:
   ```bash
   python manage.py migrate
   ```
6. Create a superuser:
   ```bash
   python manage.py createsuperuser
   ```
7. Start the development server:
   ```bash
   python manage.py runserver


Access the application at `http://localhost:8000`.

# Lost and Found Item Tracking

A web-based platform for reporting, searching, and recovering lost and found items.

## Environment Requirements

- Python 3.8 or higher
- pip (Python package manager)
- SQLite (included with Python)

## Setup Instructions

### 1. Clone the Repository

```bash
git clone <repository-url>
cd Lost-FoundTracking-Project
```

### 2. Create a Virtual Environment

```bash
python3 -m venv venv
```

### 3. Activate the Virtual Environment

On macOS and Linux:
```bash
source venv/bin/activate
```

On Windows:
```bash
venv\Scripts\activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Set Up Environment Variables

Create a `.env` file in the project root directory with necessary configuration:

```bash
FLASK_APP=run.py
FLASK_ENV=development
```

### 6. Initialize the Database

```bash
flask db upgrade
```

## How to Run Locally

### Start the Application

```bash
python3 run.py
```

The application will start on `http://localhost:5000` by default.

### Access the Application

Open your web browser and navigate to:
```
http://localhost:5000
```

### Test Credentials

The application includes default test accounts:

- Admin Account
  - Email: admin@test.com
  - Password: admin123

- Test User Account
  - Email: user@test.com
  - Password: user123

## Project Structure

- `app/` - Main application code
  - `controllers/` - Route handlers
  - `models/` - Database models
  - `services/` - Business logic
  - `repositories/` - Database access
  - `utils/` - Helper functions
- `templates/` - HTML templates
- `static/` - CSS and static assets
- `migrations/` - Database migration files

## Features

- User authentication and authorization
- Report lost and found items
- Search and filter items
- Real-time chat between users
- Automated matching suggestions
- Ownership verification system
- Admin dashboard
- Two-factor authentication
- Data encryption
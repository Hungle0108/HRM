# HRM - Human Resource Management System

A comprehensive web-based Human Resource Management System designed to streamline employee management, attendance tracking, scheduling, and payroll operations. Built with Flask, SQLAlchemy, and modern web technologies.

## Project Status

This project is actively maintained and fully functional. Core features including employee management, time tracking, shift scheduling, and payroll management are complete and operational.

## Project Screenshots

*Screenshots can be added here to showcase the main features of the application*

## Features

### 👥 Employee Management
- Add and manage employees with detailed profiles
- Support for contractors and different worker types
- Employee personal details and document management
- Profile picture uploads and management
- Department and role assignment

### ⏰ Time Tracking & Attendance
- Comprehensive time tracking system
- Check-in/check-out functionality
- Break time management
- Automatic and manual time submission methods
- Penalty rules for late arrivals and early departures
- Time keeping and reporting

### 📅 Shift Scheduling
- Create and manage work shifts
- Flexible shift timing configuration
- Assign workers to shifts
- Schedule creation and management
- Multi-step shift configuration wizard

### 💰 Payroll Management
- Payroll template creation
- Integration with attendance data
- Hours and days worked calculation
- Customizable payroll rules

### 🏢 Organization Management
- Organization structure visualization
- Office/location management
- Department hierarchy
- Group settings and management
- Administrative role assignment

### 🔐 Authentication & Security
- Secure user authentication
- Password hashing with Werkzeug
- Password reset via email
- Session management
- Profile access control

### 🌍 Multi-language Support
- Internationalization support
- Language settings management
- Translation system

## Technology Stack

### Backend
- **Flask 2.3.3** - Python web framework
- **SQLAlchemy 1.4.53** - SQL toolkit and ORM
- **Flask-SQLAlchemy 3.0.5** - Flask extension for SQLAlchemy
- **Werkzeug 2.3.7** - WSGI utility library (security utilities)

### Additional Libraries
- **Flask-Mail 0.9.1** - Email sending functionality
- **Flask-CORS 4.0.0** - Cross-Origin Resource Sharing support

### Database
- **SQLite** - Lightweight database for data persistence

### Frontend
- HTML5 templates with Jinja2
- JavaScript for dynamic functionality
- CSS for styling
- Modern responsive design

## Installation and Setup Instructions

### Prerequisites

You will need the following installed on your machine:
- Python 3.7 or higher
- pip (Python package installer)

### Installation Steps

1. **Clone the repository**
```bash
git clone <repository-url>
cd HRM
```

2. **Create a virtual environment (recommended)**
```bash
python -m venv venv
```

3. **Activate the virtual environment**
   - Windows:
     ```bash
     venv\Scripts\activate
     ```
   - macOS/Linux:
     ```bash
     source venv/bin/activate
     ```

4. **Install dependencies**
```bash
pip install -r requirements.txt
```

5. **Configure environment variables (optional)**
   
   For email functionality, set the following environment variables:
   ```bash
   set MAIL_USERNAME=your-email@gmail.com
   set MAIL_PASSWORD=your-app-password
   ```

6. **Initialize the database**
   
   The application will automatically create the database on first run.

7. **Start the application**
```bash
python app.py
```

8. **Access the application**
   
   Open your browser and navigate to:
   ```
   http://localhost:5000
   ```

## Configuration

### Email Setup

To enable email functionality (password reset, notifications), configure your SMTP settings in `app.py`:

```python
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your-app-password'
```

**Note:** For Gmail, you'll need to use an App Password instead of your regular password.

### Secret Key

For production deployment, change the SECRET_KEY in `app.py` to a secure random value:

```python
app.config['SECRET_KEY'] = 'your-secure-secret-key-here'
```

### HTTPS Configuration

For production deployment with HTTPS, enable secure cookies:

```python
app.config['SESSION_COOKIE_SECURE'] = True
```

## Database Schema

The application uses SQLite with the following main models:

- **User** - User accounts and authentication
- **Employee** - Employee information and profiles
- **Shift** - Work shift definitions
- **Schedule** - Employee scheduling
- **Attendance** - Time tracking records
- **Organization** - Company structure
- **Department** - Organizational units
- **Payroll** - Payroll information

## Project Structure

```
HRM/
├── app.py                          # Main application file
├── requirements.txt                # Python dependencies
├── users.db                        # SQLite database
├── static/                         # Static assets
│   ├── images/                    # Image assets
│   ├── js/                        # JavaScript files
│   └── uploads/                   # User uploaded files
│       └── avatars/               # Employee avatars
├── templates/                      # HTML templates
│   ├── base.html                  # Base template
│   ├── login.html                 # Authentication pages
│   ├── home.html                  # Dashboard
│   ├── add_employee.html          # Employee management
│   ├── time_tracking.html         # Attendance tracking
│   ├── schedule.html              # Scheduling
│   └── ...                        # Other templates
└── images/                         # Application images
```

## Usage Guide

### Getting Started

1. **Create an Organization**
   - Navigate to Organization Setup
   - Complete the multi-step organization creation wizard

2. **Add Employees**
   - Go to People Management
   - Use the Add Employee wizard
   - Fill in employee details, contact information, and documents

3. **Create Shifts**
   - Navigate to Shifts section
   - Create shift templates with timing and rules
   - Configure check-in/check-out windows and penalties

4. **Assign Schedules**
   - Create schedules and assign employees to shifts
   - Set up recurring schedules as needed

5. **Track Time**
   - Employees can check in/out through the time tracking interface
   - View attendance reports and time keeping data

6. **Manage Payroll**
   - Create payroll templates
   - Generate payroll based on attendance data

## Development Notes

### Database Models

The application uses Flask-SQLAlchemy ORM for database operations. Key models include:

- Comprehensive shift management with penalty rules
- Time tracking with flexible submission methods
- Employee profiles with document support
- Organization hierarchy and structure

### Session Management

User sessions are managed securely with:
- HTTP-only cookies
- Session timeout configuration
- CSRF protection

### File Uploads

Avatar and document uploads are stored in:
```
static/uploads/avatars/
```

File naming convention: `avatar_{user_id}_{timestamp}.{extension}`

## Reflection

### Project Context

This Human Resource Management System was developed as a comprehensive solution for managing all aspects of employee lifecycle, from recruitment to payroll. The goal was to create an all-in-one platform that small to medium-sized businesses could use to streamline their HR operations.

### Project Goals

The primary objective was to build a fully-featured HRM system that includes:
- Complete employee data management
- Advanced time tracking and attendance monitoring
- Flexible shift scheduling with configurable rules
- Payroll integration based on attendance data
- Organization structure visualization
- Multi-user support with role-based access

### Technical Challenges and Learning

**Database Design Complexity**

One of the main challenges was designing a flexible database schema that could handle various business rules for shifts, penalties, and payroll calculations. The shift model needed to support multiple time windows (check-in, check-out, breaks) with configurable penalty rules stored as JSON.

**Time Zone and Time Calculations**

Handling time tracking across different shifts and calculating worked hours, especially with break times and penalties, required careful consideration of edge cases like overnight shifts and DST transitions.

**Multi-step Wizards**

Implementing the multi-step forms for employee creation, shift setup, and schedule management required managing state across multiple pages and ensuring data consistency.

**File Upload Management**

Handling avatar uploads with proper validation, secure file naming, and storage organization was implemented to prevent security vulnerabilities.

### Technology Choices

**Why Flask?**

Flask was chosen for its simplicity and flexibility. Unlike Django's batteries-included approach, Flask allowed for precise control over the application architecture while keeping the codebase maintainable.

**Why SQLAlchemy ORM?**

SQLAlchemy provides a powerful and flexible ORM layer that made it easy to model complex relationships between employees, shifts, schedules, and attendance records. The ORM approach also makes the code more maintainable and testable.

**Why SQLite?**

For the initial version, SQLite was chosen for its simplicity and zero-configuration approach. It's perfect for small to medium deployments and can easily be migrated to PostgreSQL or MySQL for larger scale operations.

**Why Server-Side Rendering?**

Instead of building a separate REST API and SPA frontend, traditional server-side rendering with Jinja2 templates was chosen to:
- Reduce complexity and deployment overhead
- Improve initial page load performance
- Better SEO capabilities
- Simpler authentication flow

### Future Enhancements

Planned features for future iterations include:

1. **Real-time Notifications** - WebSocket integration for live updates
2. **Advanced Reporting** - Data visualization and analytics dashboard
3. **Mobile Application** - Native mobile apps for time tracking
4. **Leave Management** - Comprehensive leave request and approval system
5. **Performance Reviews** - Employee evaluation and feedback system
6. **Document Management** - Enhanced document storage and retrieval
7. **API Development** - RESTful API for third-party integrations
8. **Multi-tenancy** - Support for multiple organizations in single deployment

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

[Specify your license here]

## Contact

For questions or support, please contact the development team.

---

**Note:** This application is designed for internal business use. Ensure proper security measures are implemented before deploying to production, including:
- Secure SECRET_KEY configuration
- HTTPS enforcement
- Regular database backups
- Input validation and sanitization
- Rate limiting for authentication endpoints


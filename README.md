# 🩸 Blood Bank Management System: Enhancing Blood Donation Accessibility

The Blood Bank Management System is a web-based application designed to streamline blood donation processes for hospitals, donors, and administrators. It addresses key challenges like delayed notifications and inaccurate request filtering by providing real-time updates and hospital-specific request histories. Built with Flask and MySQL, the system supports secure user authentication, blood request management, real-time notifications via Server-Sent Events (SSE), and blood stock management. This includes features like role-based access, eligibility checks for donors, and a responsive user interface.

## 📌 Overview:

The **Blood Bank Management System** is a role-based application built with **Flask** and **MySQL**, developed as of **May 14, 2025**. It facilitates:

- 📬 **Real-time notifications**
- ✅ **Donor eligibility checks**
- 📦 **Blood stock tracking**
- 🔐 **Secure logins for multiple roles**

## 🚀 Key Features:

1. 🔐 **User Authentication**  
   Secure login for **Admins**, **Hospitals**, and **Donors** using `Flask-Login`.

2. 📝 **Blood Request Management**  
   - Hospitals can **create** blood requests.
   - Admins can **approve** or **cancel** them.
   - Data is stored in the `blood_requests` table.

3. ⚡ **Real-Time Notifications**  
   - Implemented using **Server-Sent Events (SSE)** via `/stream` endpoint.
   - Instant updates on request approvals or status changes.

4. 📊 **Request History Viewer**  
   - Hospitals can view **filtered request history** using `request-history.html`.

5. 🧪 **Donor Eligibility Checker**  
   - Donors can check eligibility based on `last_donation` data from the `appointments` table.

6. 🩸 **Blood Stock Management**  
   - Admins can **add/remove** blood units using `blood-stock.html`.

---

## 🛠️ Tech Stack:

### 🎯 Backend
- `Flask`
- `Flask-Login`
- `Flask-MySQLdb`
- `Werkzeug`

### 🧠 Database
- `MySQL` (via `MySQLdb` connector)

### 🎨 Frontend
- `HTML`, `CSS`, `JavaScript`

### 🔄 Data Handling & Communication
- `JSON` for REST-style API data
- `Server-Sent Events (SSE)` for real-time functionality

---

## 🗃️ Database Tables (Overview)

- `users`: Stores user credentials and roles
- `blood_requests`: Handles all hospital blood requests
- `appointments`: Tracks donor visits and last donation dates
- `blood_stock`: Tracks current availability of blood by type


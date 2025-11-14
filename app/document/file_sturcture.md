# User Management API Documentation

## Overview
This module manages user registration, authentication, employee management, and role-based access control.

### Endpoints
- **POST /user/admin/registration** — Register an admin (only HR designation)
- **POST /user/login** — Authenticate and generate JWT token
- **POST /user/logout** — Logout current user
- **GET /user/admin/details** — View admin profile
- **GET /user/employee/details** — View employee profile
- **PATCH /user/admin/profile/update** — Update admin profile
- **PATCH /user/employee/profile/update** — Update employee profile
- **DELETE /user/admin/employee/deletion** — Mark employee for deletion

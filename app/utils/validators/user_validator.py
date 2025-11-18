import re
from fastapi import HTTPException

class UserValidator:

    @staticmethod
    def validate_string(field_name, value, required=True):
        if required and (value is None or value == ""):
            raise HTTPException(400, f"{field_name} is required")

        if value is not None and not isinstance(value, str):
            raise HTTPException(400, f"{field_name} must be a string")

    @staticmethod
    def validate_boolean(field_name, value):
        if value is not None and not isinstance(value, bool):
            raise HTTPException(400, f"{field_name} must be boolean")

    @staticmethod
    def validate_email(value):
        if value is None:
            raise HTTPException(400, "email is required")
        if not isinstance(value, str):
            raise HTTPException(400, "email must be a string")

        pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
        if not re.match(pattern, value):
            raise HTTPException(400, "Invalid email format")

    @staticmethod
    def validate_phone(value):
        if value is None:
            raise HTTPException(400, "phoneNumber is required")

        pattern = r"^[0-9]{8,15}$"
        if not re.match(pattern, value):
            raise HTTPException(400, "phoneNumber must contain only digits (8–15 digits)")

    @staticmethod
    def validate_password(value):
        if value is None:
            raise HTTPException(400, "password is required")
        if len(value) < 6:
            raise HTTPException(400, "Password must be at least 6 characters")

    @staticmethod
    def validate_creation(data: dict):

        required_fields = [
            "userFirstName", "userLastName",
            "designation", "password",
            "email", "phoneNumber"
        ]

        allowed_fields = required_fields + ["address", "isSuperUser"]

        for key in data:
            if key not in allowed_fields:
                raise HTTPException(400, f"Invalid field: {key}")

        UserValidator.validate_string("userFirstName", data.get("userFirstName"))
        UserValidator.validate_string("userLastName", data.get("userLastName"))
        UserValidator.validate_string("designation", data.get("designation"))

        if "address" in data:
            UserValidator.validate_string("address", data.get("address"), required=False)

        UserValidator.validate_email(data.get("email"))
        UserValidator.validate_phone(data.get("phoneNumber"))
        UserValidator.validate_password(data.get("password"))

        if "isSuperUser" in data:
            UserValidator.validate_boolean("isSuperUser", data.get("isSuperUser"))

        return data  

    @staticmethod
    def validate_update(data: dict):

        allowed_fields = [
            "email", "userFirstName", "userLastName",
            "address", "phoneNumber",
            "designation", "password"
        ]

        for key in data:
            if key not in allowed_fields:
                raise HTTPException(400, f"Invalid field: {key}")

        if "email" in data:
            UserValidator.validate_email(data["email"])

        if "password" in data:
            UserValidator.validate_password(data["password"])

        if "phoneNumber" in data:
            UserValidator.validate_phone(data["phoneNumber"])

        for field in ["userFirstName", "userLastName", "designation", "address"]:
            if field in data:
                UserValidator.validate_string(field, data[field], required=False)

        return data 

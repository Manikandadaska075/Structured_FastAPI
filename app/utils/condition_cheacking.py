from fastapi import HTTPException, status
def check_its_employee(isSuperUser):
    if isSuperUser:
        raise HTTPException(status_code=403, detail="Only employee have the access")

def check_its_admin(isSuperUser):
    if not isSuperUser:
        raise HTTPException(status_code=403, detail="Only admins can view there details")
    
def check_employee(employee):
    if not employee:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Employee not found")
    
def check_not_active_user(users):
    if not users:
        raise HTTPException(status_code=404, detail="User not found")
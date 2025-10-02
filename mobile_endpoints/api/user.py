import frappe  
from erpnext import get_default_company  
  
@frappe.whitelist()  
def get_user_default_company():  
    """Get user's default company from session defaults"""  
    return {  
        "default_company": get_default_company()  
    }
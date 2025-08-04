from app import app, update_employee_country_codes

if __name__ == '__main__':
    print("Updating country codes for existing employees...")
    updated_count = update_employee_country_codes()
    print(f"Updated {updated_count} employees with country codes.")
    print("Done!") 
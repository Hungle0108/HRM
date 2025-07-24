from app import db
from app import WorkSchedule
import json

# Query all schedules
schedules = WorkSchedule.query.all()
updated = 0

for schedule in schedules:
    try:
        data = json.loads(schedule.schedule_data)
        details = data.get('scheduleDetails', {})
        num_shifts = details.get('numberOfShifts')
        shifts = details.get('shifts')
        if num_shifts == 1 and isinstance(shifts, dict):
            # Only keep shift 1
            details['shifts'] = {'1': shifts.get('1', {})}
            data['scheduleDetails'] = details
            schedule.schedule_data = json.dumps(data)
            updated += 1
    except Exception as e:
        print(f"Error processing schedule {schedule.id}: {e}")

db.session.commit()
print(f"Updated {updated} schedules to remove extra shifts for single-shift templates.") 
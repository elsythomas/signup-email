# from django_cron import CronJobBase, Schedule
# from django.core.mail import send_mail

# class MyCronJob(CronJobBase):
#     RUN_EVERY_MINS = 1 # every 2 hours

#     schedule = Schedule(run_every_mins=RUN_EVERY_MINS)
#     code = 'myapp.MyCronJob'    # a unique code

#     def do(self):
#          print("Scheduled job is running!")
#          send_mail(
#             "Test Email from Cron Job",
#             "Hello! This is a test email from Django cron job.",
#             "elsythomas36987@gmail.com",  # Replace with your email
#             ["elsyengg11@gmail.com"],  # Replace with recipient's email
#             fail_silently=False,  # Set to False to see errors
#         )

# class Text(models.Model):
#     text = models.CharField(max_length=500)
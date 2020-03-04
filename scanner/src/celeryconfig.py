# Set the Celery task queue
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_IGNORE_RESULTS = True
CELERY_REDIRECT_STDOUTS_LEVEL = "WARNING"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TASK_SERIALIZER = "json"

# in seconds
CELERYD_TASK_SOFT_TIME_LIMIT = 1800
CELERYD_TASK_TIME_LIMIT = 3600

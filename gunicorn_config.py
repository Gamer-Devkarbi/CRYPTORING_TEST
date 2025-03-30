# gunicorn_config.py
bind = "0.0.0.0:8000"
workers = 1
worker_class = "eventlet"
timeout = 120

from celery import Celery

celery_app = Celery(
    "celery_worker",
    broker="amqp://fastapi:pass1@rabbitmq/%2F",  # %2F is URL-encoded form of /
    backend="rpc://",
    include=['main']
)

if __name__ == '__main__':
    celery_app.start()

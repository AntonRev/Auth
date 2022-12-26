from opentelemetry import trace
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

from config.config import config


def configure_tracer() -> None:
    trace.set_tracer_provider(TracerProvider(resource=Resource.create({"service.name": "AuthService"})))
    trace.get_tracer_provider().add_span_processor(
        BatchSpanProcessor(
            JaegerExporter(
                agent_host_name=config.HOST_JAEGER,
                agent_port=config.PORT_JAEGER,
            )
        )
    )
    # Чтобы видеть трейсы в консоли
    if config.JAEGER_CONSOLE:
        trace.get_tracer_provider().add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

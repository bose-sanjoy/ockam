import Config

config :logger, level: :info

config :telemetry_influxdb,
  host: System.get_env("INFLUXDB_HOST"),
  port: System.get_env("INFLUXDB_PORT"),
  bucket: System.get_env("INFLUXDB_BUCKET"),
  org: System.get_env("INFLUXDB_ORG"),
  token: System.get_env("INFLUXDB_TOKEN")

import_config "#{Mix.env()}.exs"

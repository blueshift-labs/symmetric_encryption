defmodule SymmetricEncryption.MixProject do
  use Mix.Project

  def project do
    [
      app: :symmetric_encryption,
      version: "0.0.1",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :crypto],
      mod: {SymmetricEncryption.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ecto, "~> 3.11"},
      {:jason, "~> 1.3"}
    ]
  end
end

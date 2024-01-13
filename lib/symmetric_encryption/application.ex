defmodule SymmetricEncryption.Application do
  use Application

  @impl true
  def start(_type, _args) do
    SymmetricEncryption.load_ciphers!()

    children = []
    opts = [strategy: :one_for_one, name: SymmetricEncryption.Supervisor]
    Supervisor.start_link(children, opts)
  end
end

defmodule SymmetricEncryption.Ecto.Types.Encrypted do
  @moduledoc """
  When dumped, takes string input as type and outputs
  an encrypted version of the string for storage in the database.

  When loaded, the encrypted version of the string is decrypted
  so the unencrypted copy can be used

  """
  use Ecto.ParameterizedType

  @impl true
  def type(_), do: :string

  @impl true
  def init(opts), do: Enum.into(opts, %{})

  @impl true
  def equal?(term1, term2, _opts) do
    term1 == term2
  end

  @impl true
  def cast(value, _), do: {:ok, value}

  @impl true
  def load(nil, _loader, _opts), do: {:ok, nil}

  def load(value, loader, %{type: :json} = opts) do
    with {:ok, data} <- load(value, loader, %{opts | type: nil}) do
      Jason.decode(data)
    end
  end

  def load(value, _loader, _opts) when is_binary(value) do
    decrypted = SymmetricEncryption.decrypt!(value)
    {:ok, decrypted}
  end

  @impl true
  def dump(nil, _dumper, _opts), do: {:ok, nil}

  def dump(value, dumper, %{type: :json} = opts) do
    with {:ok, data} <- Jason.encode(value) do
      dump(data, dumper, %{opts | type: nil})
    end
  end

  def dump(value, _dumper, opts) when is_binary(value) do
    encrypted = SymmetricEncryption.encrypt!(value, opts)
    {:ok, encrypted}
  end

  def embed_as(_), do: :self
end

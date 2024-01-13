defmodule SymmetricEncryption do
  defmodule Opts do
    defstruct version: :primary,
              cipher_name: nil,
              header: true,
              compress: false,
              key: nil,
              iv: nil,
              random_iv: false
  end

  alias SymmetricEncryption.Opts
  alias SymmetricEncryption.Header
  alias SymmetricEncryption.Cipher

  def encrypt!(value, opts \\ %Opts{version: :primary})

  def encrypt!(value, %Opts{version: version} = opts) do
    cipher = cipher!(version)
    encrypted = Cipher.encrypt!(cipher, value, opts)
    Base.encode64(encrypted, padding: true)
  end

  def encrypt!(value, opts) do
    encrypt!(value, to_opts(opts))
  end

  def decrypt!(value) do
    Base.decode64!(value)
    |> Header.parse!()
    |> Cipher.decrypt!()
  end

  def load_ciphers!() do
    :ets.new(__MODULE__, [
      :named_table,
      :set,
      :public,
      read_concurrency: true,
      write_concurrency: true
    ])

    Application.get_env(:symmetric_encryption, :ciphers, [])
    |> Enum.each(fn cipher ->
      cipher =
        Enum.into(cipher, [], fn
          {k, v} when is_binary(k) -> {String.to_atom(k), v}
          {k, v} -> {k, v}
        end)

      {version, cipher} = Keyword.pop!(cipher, :version)

      {cipher_name, cipher} = Keyword.pop!(cipher, :cipher_name)

      cipher_name =
        if is_atom(cipher_name) do
          cipher_name
        else
          String.to_atom(cipher_name)
        end

      {key, cipher} = Keyword.pop!(cipher, :key)
      {:ok, key} = Base.decode64(key, padding: false)

      {iv, _cipher} = Keyword.pop!(cipher, :iv)
      {:ok, iv} = Base.decode64(iv, padding: false)

      cipher = %Cipher{version: version, cipher_name: cipher_name, key: key, iv: iv}

      :ets.insert_new(__MODULE__, {:primary, cipher})
      :ets.insert(__MODULE__, {version, cipher})
    end)
  end

  def cipher!(version) do
    case :ets.lookup(__MODULE__, version) do
      [] -> raise ArgumentError, "cipher doesn't exist for version #{version}"
      [{_, cipher}] -> cipher
    end
  end

  def primary_cipher!() do
    case :ets.lookup(__MODULE__, :primary) do
      [] -> raise ArgumentError, "primary cipher doesn't exist"
      [{_, cipher}] -> cipher
    end
  end

  defp to_opts(opts) do
    opts =
      opts
      |> Enum.reject(&match?({_, nil}, &1))
      |> Enum.into(%{})

    struct(Opts, opts)
  end
end

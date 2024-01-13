defmodule SymmetricEncryption.Cipher do
  defstruct [:version, :cipher_name, :key, :iv]

  alias SymmetricEncryption.Opts
  alias SymmetricEncryption.Header
  alias __MODULE__

  def encrypt!(%Cipher{version: version} = cipher, value, %Opts{} = opts) do
    encrypt!(cipher, value, %{opts | version: nil}, %Header{version: version})
  end

  def encrypt!(%Cipher{cipher_name: cipher_name, key: key, iv: iv}, value, %Header{header: false}) do
    :crypto.crypto_one_time(
      cipher_name,
      key,
      iv,
      value,
      encrypt: true,
      padding: :pkcs_padding
    )
  end

  def encrypt!(
        %Cipher{cipher_name: cipher_name, key: key, iv: iv},
        value,
        %Header{header: true, compress: true} = header
      ) do
    header = Header.to_string!(header)

    encrypted =
      :crypto.crypto_one_time(
        cipher_name,
        key,
        iv,
        compress(value),
        encrypt: true,
        padding: :pkcs_padding
      )

    <<header::binary, encrypted::binary>>
  end

  def encrypt!(
        %Cipher{cipher_name: cipher_name, key: key, iv: iv},
        value,
        %Header{header: true} = header
      ) do
    header = Header.to_string!(header)

    encrypted =
      :crypto.crypto_one_time(
        cipher_name,
        key,
        iv,
        value,
        encrypt: true,
        padding: :pkcs_padding
      )

    <<header::binary, encrypted::binary>>
  end

  defp encrypt!(
         cipher,
         value,
         %Opts{
           cipher_name: cipher_name,
           header: header?,
           compress: compress,
           key: key,
           iv: iv,
           random_iv: random_iv
         } = opts,
         header
       )
       when not is_nil(header?) do
    header? = header? || compress || key || iv || random_iv || cipher_name
    encrypt!(cipher, value, %{opts | header: nil}, %{header | header: header?})
  end

  defp encrypt!(cipher, value, %Opts{compress: true} = opts, %Header{} = header) do
    encrypt!(cipher, value, %{opts | compress: nil}, %{header | compress: true})
  end

  defp encrypt!(cipher, value, %Opts{random_iv: true} = opts, %Header{} = header) do
    iv = :crypto.strong_rand_bytes(16)
    encrypt!(%{cipher | iv: iv}, value, %{opts | iv: iv, random_iv: nil}, %{header | iv: iv})
  end

  defp encrypt!(cipher, value, %Opts{iv: iv} = opts, %Header{} = header) when not is_nil(iv) do
    encrypt!(%{cipher | iv: iv}, value, %{opts | iv: nil}, %{header | iv: iv})
  end

  defp encrypt!(cipher, value, %Opts{key: key} = opts, %Header{} = header) when not is_nil(key) do
    encrypt!(%{cipher | key: key}, value, %{opts | key: nil}, %{header | key: key})
  end

  defp encrypt!(cipher, value, %Opts{cipher_name: cipher_name} = opts, %Header{} = header)
       when not is_nil(cipher_name) do
    encrypt!(cipher, value, %{opts | cipher_name: nil}, %{header | cipher_name: cipher_name})
  end

  defp encrypt!(cipher, value, _opts, %Header{} = header) do
    encrypt!(cipher, value, header)
  end

  defp compress(value) do
    z = :zlib.open()

    try do
      :zlib.deflateInit(z)
      compressed = :zlib.deflate(z, value, :finish)
      :zlib.deflateEnd(z)

      compressed
    after
      :zlib.close(z)
    end
  end

  defp decompress(value) do
    z = :zlib.open()

    try do
      :zlib.inflateInit(z)
      [decompressed] = :zlib.inflate(z, value)
      :zlib.inflateEnd(z)

      decompressed
    after
      :zlib.close(z)
    end
  end

  def decrypt!(%Cipher{cipher_name: cipher_name, key: key, iv: iv}, value) do
    :crypto.crypto_one_time(
      cipher_name,
      key,
      iv,
      value,
      encrypt: false,
      padding: :pkcs_padding
    )
  end

  def decrypt!({nil, value}) do
    decrypt!(SymmetricEncryption.primary_cipher!(), value)
  end

  def decrypt!({%Header{cipher_name: cipher_name, key: nil}, _value})
      when not is_nil(cipher_name) do
    raise ArgumentError, "missing key from header"
  end

  def decrypt!({%Header{cipher_name: cipher_name, iv: nil}, _value})
      when not is_nil(cipher_name) do
    raise ArgumentError, "missing iv from header"
  end

  def decrypt!({%Header{cipher_name: cipher_name, key: key, iv: iv, compress: false}, value})
      when not is_nil(cipher_name) do
    :crypto.crypto_one_time(
      cipher_name,
      key,
      iv,
      value,
      encrypt: false,
      padding: :pkcs_padding
    )
  end

  def decrypt!({%Header{cipher_name: cipher_name, compress: true} = header, value})
      when not is_nil(cipher_name) do
    decrypt!({%{header | compress: false}, value})
    |> decompress()
  end

  def decrypt!({%Header{version: version, key: key, iv: iv, compress: false}, value}) do
    %Cipher{cipher_name: cipher_name, key: cipher_key, iv: cipher_iv} =
      SymmetricEncryption.cipher!(version)

    :crypto.crypto_one_time(
      cipher_name,
      key || cipher_key,
      iv || cipher_iv,
      value,
      encrypt: false,
      padding: :pkcs_padding
    )
  end

  def decrypt!({%Header{compress: true} = header, value}) do
    decrypt!({%{header | compress: false}, value})
    |> decompress()
  end
end

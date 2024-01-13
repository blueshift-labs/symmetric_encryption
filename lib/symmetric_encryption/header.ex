defmodule SymmetricEncryption.Header do
  import Bitwise

  defstruct [:header, :version, :cipher_name, :key, :iv, :compress]

  alias SymmetricEncryption.Cipher
  alias __MODULE__

  @magic_header "@EnC"

  @flag_compress 128
  @flag_iv 64
  @flag_key 32
  @flag_cipher_name 16

  def parse!(<<@magic_header::binary, version::8, flags::8, value::binary>>) do
    header = %Header{
      version: version,
      compress: (flags &&& @flag_compress) == @flag_compress,
      iv: (flags &&& @flag_iv) == @flag_iv,
      key: (flags &&& @flag_key) == @flag_key,
      cipher_name: (flags &&& @flag_cipher_name) == @flag_cipher_name
    }

    parse!(header, value)
  end

  def parse!(value) when is_binary(value) do
    {nil, value}
  end

  defp parse!(%Header{iv: true} = header, <<size::16-little, value::binary>>) do
    <<iv::binary-size(size), rest::binary>> = value
    parse!(%{header | iv: iv}, rest)
  end

  defp parse!(%Header{iv: false} = header, value) do
    parse!(%{header | iv: nil}, value)
  end

  defp parse!(%Header{version: version, key: true} = header, <<size::16-little, value::binary>>) do
    <<encrypted_key::binary-size(size), rest::binary>> = value
    cipher = SymmetricEncryption.cipher!(version)
    key = Cipher.decrypt!(cipher, encrypted_key)
    parse!(%{header | key: key}, rest)
  end

  defp parse!(%Header{key: false} = header, value) do
    parse!(%{header | key: nil}, value)
  end

  defp parse!(%Header{cipher_name: true} = header, <<size::16-little, value::binary>>) do
    <<cipher_name::binary-size(size), rest::binary>> = value
    parse!(%{header | cipher_name: String.to_atom(cipher_name)}, rest)
  end

  defp parse!(%Header{cipher_name: false} = header, value) do
    parse!(%{header | cipher_name: nil}, value)
  end

  defp parse!(header, value) do
    {header, value}
  end

  def to_string!(%Header{version: version} = header) do
    flags = flags(header)
    prefix = <<@magic_header::binary, version::8, flags::8>>
    to_string!(header, prefix)
  end

  defp to_string!(%Header{iv: iv} = header, prefix) when not is_nil(iv) do
    prefix = <<prefix::binary, byte_size(iv)::16-little, iv::binary>>
    to_string!(%{header | iv: nil}, prefix)
  end

  defp to_string!(%Header{key: key, version: version} = header, prefix) when not is_nil(key) do
    encrypted_key = SymmetricEncryption.encrypt!(key, version: version)
    prefix = <<prefix::binary, byte_size(encrypted_key)::16-little, encrypted_key::binary>>
    to_string!(%{header | key: nil}, prefix)
  end

  defp to_string!(%Header{cipher_name: cipher_name} = header, prefix)
       when not is_nil(cipher_name) do
    <<prefix::binary, byte_size(cipher_name)::16-little, cipher_name::binary>>
    to_string!(%{header | cipher_name: nil}, prefix)
  end

  defp to_string!(_header, prefix), do: prefix

  defp flags(header, flags \\ 0)

  defp flags(%Header{compress: true} = header, flags) do
    flags(%{header | compress: nil}, flags ||| @flag_compress)
  end

  defp flags(%Header{iv: iv} = header, flags) when not is_nil(iv) do
    flags(%{header | iv: nil}, flags ||| @flag_iv)
  end

  defp flags(%Header{key: key} = header, flags) when not is_nil(key) do
    flags(%{header | key: nil}, flags ||| @flag_key)
  end

  defp flags(%Header{cipher_name: cipher_name} = header, flags) when not is_nil(cipher_name) do
    flags(%{header | cipher_name: nil}, flags ||| @flag_cipher_name)
  end

  defp flags(%Header{}, flags), do: flags
end

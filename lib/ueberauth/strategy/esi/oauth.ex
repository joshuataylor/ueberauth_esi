defmodule Ueberauth.Strategy.ESI.OAuth do
  @moduledoc """
  An implementation of OAuth2 for ESI.

  To add your `client_id` and `client_secret` include these values in your configuration.

      config :ueberauth, Ueberauth.Strategy.ESI.OAuth,
        client_id: System.get_env("ESI_CLIENT_ID"),
        client_secret: System.get_env("ESI_CLIENT_SECRET")
  """
  use OAuth2.Strategy

  @defaults [
    strategy: __MODULE__,
    site: "https://login.eveonline.com",
    authorize_url: "https://login.eveonline.com/v2/oauth/authorize",
    token_url: "https://login.eveonline.com/v2/oauth/token"
  ]

  def get(token, url, headers \\ [], opts \\ []) do
    [token: token]
    |> client
    |> put_param("client_secret", client().client_secret)
    |> OAuth2.Client.get(url, headers, opts)
  end

  def get_access_token(params \\ [], opts \\ []) do
    case opts |> client |> OAuth2.Client.get_token(params) do
      {:error, %{body: %{"error" => error, "error_description" => description}}} ->
        {:error, {error, description}}
      {:ok, %{token: %{access_token: nil} = token}} ->
        %{"error" => error, "error_description" => description} = token.other_params
        {:error, {error, description}}
      {:ok, %{token: token}} ->
        {:ok, token}
    end
  end

  @doc """
  Construct a client for requests to ESI.
  This will be setup automatically for you in `Ueberauth.Strategy.ESI`.
  These options are only useful for usage outside the normal callback phase of Ueberauth.
  """
  def client(opts \\ []) do
    config = Application.get_env(:ueberauth, __MODULE__, [])
    opts = @defaults |> Keyword.merge(opts) |> Keyword.merge(config) |> resolve_values()
    json_library = Ueberauth.json_library()

    OAuth2.Client.new(opts)
    |> OAuth2.Client.put_serializer("application/json", json_library)
  end

  def get_token(client, params, headers) do
    # We can't use OAuth2.Strategy.AuthCode.get_token here as
    # ESI complains if we have both header and body.
    code = Keyword.pop(params, :code, client.params["code"])

    client
    |> put_param("client_secret", client.client_secret)
    |> put_header("Accept", "application/json")
    |> put_param(:code, code)
    |> put_param(:grant_type, "authorization_code")
    |> merge_params(params)
    |> basic_auth()
    |> put_headers(headers)
  end

  @doc """
  Provides the authorize url for the request phase of Ueberauth. No need to call this usually.
  """
  def authorize_url!(params \\ [], opts \\ []) do
    opts
    |> client
    |> OAuth2.Client.authorize_url!(params)
  end

  def authorize_url(client, params) do
    OAuth2.Strategy.AuthCode.authorize_url(client, params)
  end

  defp resolve_values(list) do
    for {key, value} <- list do
      {key, resolve_value(value)}
    end
  end

  defp resolve_value({m, f, a}) when is_atom(m) and is_atom(f), do: apply(m, f, a)
  defp resolve_value(v), do: v
end

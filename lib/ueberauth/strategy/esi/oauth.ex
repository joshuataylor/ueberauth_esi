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
    authorize_url: "https://login.eveonline.com/oauth/authorize",
    token_url: "https://login.eveonline.com/oauth/token",
  ]

  def get(token, url, headers \\ [], opts \\ []) do
    [token: token]
    |> client
    |> put_param("client_secret", client().client_secret)
    |> OAuth2.Client.get(url, headers, opts)
  end

  def get_authorization_access_token(token) do
    client()
    |> basic_auth()
    |> post!(
         Keyword.get(@defaults, :token_url),
         %{grant_type: "authorization_code", code: token},
         ["Content-Type": "application/json"]
       )
    |> Map.get(:body)
#    |> Map.get("access_token")
  end

  @doc """
  Construct a client for requests to ESI.

  Optionally include any OAuth2 options here to be merged with the defaults.

      Ueberauth.Strategy.ESI.OAuth.client(redirect_uri: "http://localhost:4000/auth/ESI/callback")

  This will be setup automatically for you in `Ueberauth.Strategy.ESI`.
  These options are only useful for usage outside the normal callback phase of Ueberauth.
  """
  def client(opts \\ []) do
    config =
      :ueberauth
      |> Application.fetch_env!(Ueberauth.Strategy.ESI.OAuth)
      |> check_config_key_exists(:client_id)
      |> check_config_key_exists(:client_secret)

    client_opts =
      @defaults
      |> Keyword.merge(config)
      |> Keyword.merge(opts)

    OAuth2.Client.new(client_opts)
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

  defp check_config_key_exists(config, key) when is_list(config) do
    unless Keyword.has_key?(config, key) do
      raise "#{inspect (key)} missing from config :ueberauth, Ueberauth.Strategy.ESI"
    end
    config
  end
  defp check_config_key_exists(_, _) do
    raise "Config :ueberauth, Ueberauth.Strategy.ESI is not a keyword list, as expected"
  end
end

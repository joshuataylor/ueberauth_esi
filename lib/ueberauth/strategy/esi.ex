defmodule Ueberauth.Strategy.ESI do
  @moduledoc """
  Provides an Ueberauth strategy for authenticating with EVE Onlines ESI API.

  ### Setup

  Create an application in ESI for you to use.

  Register a new application [at the EVE Developer Portal](https://developers.eveonline.com/) and get the `client_id` and `client_secret`.

  Include the provider in your configuration for Ueberauth

      config :ueberauth, Ueberauth,
        providers: [
          esi: { Ueberauth.Strategy.ESI, [] }
        ]

  Then include the configuration for ESI.

      config :ueberauth, Ueberauth.Strategy.ESI.OAuth,
        client_id: System.get_env("ESI_CLIENT_ID"),
        client_secret: System.get_env("ESI_CLIENT_SECRET")

  If you haven't already, create a pipeline and setup routes for your callback handler

      pipeline :auth do
        Ueberauth.plug "/auth"
      end

      scope "/auth" do
        pipe_through [:browser, :auth]

        get "/:provider/callback", AuthController, :callback
      end


  Create an endpoint for the callback where you will handle the `Ueberauth.Auth` struct

      defmodule MyApp.AuthController do
        use MyApp.Web, :controller

        def callback_phase(%{ assigns: %{ ueberauth_failure: fails } } = conn, _params) do
          # do things with the failure
        end

        def callback_phase(%{ assigns: %{ ueberauth_auth: auth } } = conn, params) do
          # do things with the auth
        end
      end

  You can edit the behaviour of the Strategy by including some options when you register your provider.

  To set the `uid_field`

      config :ueberauth, Ueberauth,
        providers: [
          esi: { Ueberauth.Strategy.ESI, [uid_field: :email] }
        ]

  Default is `:id`

  To set the default 'scopes' (permissions):

      config :ueberauth, Ueberauth,
        providers: [
          esi: { Ueberauth.Strategy.ESI, [default_scope: "esi-characters.read_contacts.v1"] }
        ]

  Default is "esi-characters.read_contacts.v1"
  """
  use Ueberauth.Strategy,
      uid_field: :id,
      default_scope: "",
      oauth2_module: Ueberauth.Strategy.ESI.OAuth

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra

  @doc """
  Handles the initial redirect to the ESI authentication page.

  To customize the scope (permissions) that are requested by ESI include them as part of your url:

      "/auth/esi?scope=esi-characters.read_contacts.v1"

  You can also include a `state` param that ESI will return to you.
  """
  def handle_request!(conn) do
    scopes = conn.params["scope"] || option(conn, :default_scope)

    params =
      [scope: scopes]
      |> Keyword.put(:state, "stan")

    opts = oauth_client_options_from_conn(conn)
    redirect!(conn, Ueberauth.Strategy.ESI.OAuth.authorize_url!(params, opts))
  end

  defp oauth_client_options_from_conn(conn) do
    base_options = [redirect_uri: callback_url(conn)]
    request_options = conn.private[:ueberauth_request_options].options

    case {request_options[:client_id], request_options[:client_secret]} do
      {nil, _} -> base_options
      {_, nil} -> base_options
      {id, secret} -> [client_id: id, client_secret: secret] ++ base_options
    end
  end

  @doc """
  Handles the callback from ESI. When there is a failure from ESI the failure is included in the
  `ueberauth_failure` struct. Otherwise the information returned from ESI is returned in the `Ueberauth.Auth` struct.
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    params = [code: code]
    opts = oauth_client_options_from_conn(conn)

    case Ueberauth.Strategy.ESI.OAuth.get_access_token(params, opts) do
      {:ok, token} ->
        fetch_user(conn, token)
      {:error, {error_code, error_description}} ->
        set_errors!(conn, [error(error_code, error_description)])
    end
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc """
  Cleans up the private area of the connection used for passing the raw ESI response around during the callback.
  """
  def handle_cleanup!(conn) do
    conn
    |> put_private(:esi_user, nil)
    |> put_private(:esi_token, nil)
  end

  @doc """
  Fetches the uid field from the ESI response. This defaults to the option `uid_field` which in-turn defaults to `id`
  """
  def uid(conn) do
    user =
      conn
      |> option(:uid_field)
      |> to_string
    conn.private.esi_user[user]
  end

  @doc """
  Includes the credentials from the ESI response.
  """
  def credentials(conn) do
    token = conn.private.esi_token
    scope_string = (conn.private.esi_user["Scopes"] || "")
    scopes = String.split(scope_string, ",")

    %Credentials{
      expires: !!token.expires_at,
      expires_at: token.expires_at,
      scopes: scopes,
      token_type: Map.get(token, :token_type),
      refresh_token: token.refresh_token,
      token: token.access_token
    }
  end

  @doc """
  Fetches the fields to populate the info section of the `Ueberauth.Auth` struct.
  """
  def info(conn) do
    user = conn.private.esi_user

    %Info{
      name: user["CharacterName"]
    }
  end

  @doc """
  Stores the raw information (including the token) obtained from the ESI callback.
  """
  def extra(conn) do
    %Extra {
      raw_info: %{
        token: conn.private.esi_token,
        user: conn.private.esi_user
      }
    }
  end


  defp fetch_user(conn, token) do
    conn = put_private(conn, :esi_token, token)

    path = "https://login.eveonline.com/oauth/verify"
    resp = Ueberauth.Strategy.ESI.OAuth.get(token, path)

    case resp do
      {:ok, %OAuth2.Response{status_code: 401, body: _body}} ->
        set_errors!(conn, [error("token", "unauthorized")])
      {:ok, %OAuth2.Response{status_code: status_code, body: user}} when status_code in 200..399 ->
        put_private(conn, :esi_user, user)
      {:error, %OAuth2.Response{status_code: status_code}} ->
        set_errors!(conn, [error("OAuth2", status_code)])
      {:error, %OAuth2.Error{reason: reason}} ->
        set_errors!(conn, [error("OAuth2", reason)])
    end
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end
end

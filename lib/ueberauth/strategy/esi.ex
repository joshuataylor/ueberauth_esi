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
          esi: { Ueberauth.Strategy.ESI, [default_scope: "publicData"] }
        ]

  Default is "publicData"
  """
  use Ueberauth.Strategy,
      uid_field: :id,
      default_scope: "publicData",
      oauth2_module: Ueberauth.Strategy.ESI.OAuth

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra

  @doc """
  Handles the initial redirect to the ESI authentication page.

  To customize the scope (permissions) that are requested by ESI include them as part of your url:

      "/auth/esi?scope=publicData"

  You can also include a `state` param that ESI will return to you.
  """
  def handle_request!(conn) do
    scopes = conn.params["scope"] || option(conn, :default_scope)
    send_redirect_uri = Keyword.get(options(conn), :send_redirect_uri, true)

    opts =
      if send_redirect_uri do
        [redirect_uri: callback_url(conn), scope: scopes]
      else
        [scope: scopes]
      end

    opts =
      if conn.params["state"], do: Keyword.put(opts, :state, conn.params["state"]), else: opts

    module = option(conn, :oauth2_module)
    redirect!(conn, apply(module, :authorize_url!, [opts]))
  end

  @doc """
  Handles the callback from ESI. When there is a failure from ESI the failure is included in the
  `ueberauth_failure` struct. Otherwise the information returned from ESI is returned in the `Ueberauth.Auth` struct.
  """
  def handle_callback!(
        %Plug.Conn{
          params: %{
            "code" => code
          }
        } = conn
      ) do
    token = Ueberauth.Strategy.ESI.OAuth.get_authorization_access_token(code)

    # Now fetch the user
    fetch_user(conn, token)
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
    user = conn.private.esi_user
    scope_string = (conn.private.esi_user["Scopes"] || "")
    scopes = String.split(scope_string, ",")

    %Credentials{
      token: token["access_token"],
      refresh_token: token["refresh_token"],
      expires_at: token["expires_in"],
      token_type: ["token_type"],
      expires: !!["expires_in"],
      scopes: scopes
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
    # Will be better with Elixir 1.3 with/else
    case Ueberauth.Strategy.ESI.OAuth.get(token["access_token"], "https://login.eveonline.com/oauth/verify") do
      {:ok, %OAuth2.Response{status_code: 401, body: _body}} ->
        set_errors!(conn, [error("token", "unauthorized")])
      {:ok, %OAuth2.Response{status_code: status_code, body: user}} when status_code in 200..399 ->
        put_private(conn, :esi_user, user)
      {:error, %OAuth2.Error{reason: reason}} ->
        set_errors!(conn, [error("OAuth2", reason)])
    end
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end
end

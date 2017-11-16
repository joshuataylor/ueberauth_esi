# Überauth ESI

> Eve Online ESI OAuth2 strategy for Überauth.

## Installation

1. Setup your application on the [ESI Developer Portal](https://developers.eveonline.com), copying the secret key and client id.

1. Add `:ueberauth_esi` to your list of dependencies in `mix.exs`:

    ```elixir
    def deps do
      [{:ueberauth_esi, "~> 0.0.1"}]
    end
    ```

1. Add the strategy to your applications:

    ```elixir
    def application do
      [applications: [:ueberauth_esi]]
    end
    ```

1. Add ESI to your Überauth configuration:

    ```elixir
    config :ueberauth, Ueberauth,
      providers: [
        esi: {Ueberauth.Strategy.ESI, []}
      ]
    ```

1.  Update your provider configuration:

    ```elixir
    config :ueberauth, Ueberauth.Strategy.ESI.OAuth,
      client_id: System.get_env("ESI_CLIENT_ID"),
      client_secret: System.get_env("ESI_CLIENT_SECRET")
    ```

1.  Include the Überauth plug in your controller:

    ```elixir
    defmodule MyApp.AuthController do
      use MyApp.Web, :controller

      pipeline :browser do
        plug Ueberauth
        ...
       end
    end
    ```

1.  Create the request and callback routes if you haven't already:

    ```elixir
    scope "/auth", MyApp do
      pipe_through :browser

      get "/:provider", AuthController, :request
      get "/:provider/callback", AuthController, :callback
    end
    ```

1. You controller needs to implement callbacks to deal with `Ueberauth.Auth` and `Ueberauth.Failure` responses.

For an example implementation see the [Überauth Example](https://github.com/ueberauth/ueberauth_example) application.

## Calling

Depending on the configured url you can initial the request through:

    /auth/esi

Or with options:

    /auth/esi?scope=publicData

There is no default requested scope, copy them from the developer portal.

```elixir
config :ueberauth, Ueberauth,
  providers: [
    esi: {Ueberauth.Strategy.ESI, [default_scope: "publicData"]}
  ]
```

It is also possible to disable the sending of the `redirect_uri` to ESI. This is particularly useful
when your production application sits behind a proxy that handles SSL connections. In this case,
the `redirect_uri` sent by `Ueberauth` will start with `http` instead of `https`, and if you configured
your ESI OAuth application's callback URL to use HTTPS, ESI will throw an `uri_missmatch` error.

To prevent `Ueberauth` from sending the `redirect_uri`, you should add the following to your configuration:

```elixir
config :ueberauth, Ueberauth,
  providers: [
    esi: {Ueberauth.Strategy.ESI, [send_redirect_uri: false]}
  ]
```

## License

Please see [LICENSE](https://github.com/joshuataylor/ueberauth_esi/blob/master/LICENSE) for licensing details.

Based on the work of ueberauth-github.
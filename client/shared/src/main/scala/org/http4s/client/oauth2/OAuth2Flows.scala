package org.http4s.client.oauth2

import cats.MonadError
import cats.effect.kernel.Fiber
import cats.effect.{Async, MonadCancelThrow, Ref, Resource, Sync}
import org.http4s.{AuthScheme, Credentials, EntityDecoder, Headers, Method, Request, Uri, UrlForm}
import org.http4s.client.Client
import org.http4s.implicits.*
import cats.syntax.all.*
import org.http4s.headers.Authorization
import cats.effect.syntax.all.*

object OAuth2Flows {

  def clientCredentials[F[_]](authorizationServerUri: Uri, clientId: String, clientSecret: String)(
      client: Client[F]
  )(implicit
      responseDecoder: EntityDecoder[F, AccessTokenResponse],
      f: Async[F],
  ): Resource[F, Client[F]] = {

    val request = Request[F](Method.POST, authorizationServerUri).withEntity(
      UrlForm(
        "grant_type" -> "client_credentials",
        "client_id" -> clientId,
        "client_secret" -> clientSecret,
      )
    )

    val response: F[AccessTokenResponse] = client.expect[AccessTokenResponse](request)

    val validToken: F[Authorization] = for {
      r <- response
      _ <- f.raiseWhen(r.tokenType != "bearer")(
        new Exception(s"unsupported token type, ${r.tokenType}")
      )
    } yield Authorization(Credentials.Token(AuthScheme.Bearer, r.accessToken))

    val authorizedClient: F[Client[F]] = for {
      header <- validToken
    } yield Client.apply { r: Request[F] =>
      client.run(r.putHeaders(header))
    }

    def authorizedClientWithRef(ref: Ref[F, Authorization]): Client[F] =
      Client.apply { r: Request[F] =>
        for {
          header <- Resource.eval(ref.get)
          result <-client.run(r.putHeaders(header))
        } yield result
    }

    def executeBackgroundTask(ref: Ref[F, Authorization]): F[Unit] = f.unit

    val token: F[Ref[F, Authorization]] = validToken.flatMap(Ref[F].of(_))

    val resource: Resource[F, (Fiber[F, Throwable, Unit], Client[F])] = {
      Resource.make(token.flatMap {
        authRef => {
          executeBackgroundTask(authRef).start.map(
            fiber => (fiber, authorizedClientWithRef(authRef))
          )
        }
      }) {
        case (fiber, _) => fiber.cancel
    }
    } //TODO finish it

    for {
      token <- Resource.eval(response)
      x: Client[F] <- if (token.refreshToken.isDefined && token.expiresIn.isDefined) resource.map(_._2) else Resource.eval(authorizedClient)
    } yield x

  }

}

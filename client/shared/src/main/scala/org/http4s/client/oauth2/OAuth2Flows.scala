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

import java.time.Instant
import scala.concurrent.duration.FiniteDuration

case class RefreshTokenCredentials(clientId: String, clientSecret: String)

object OAuth2Flows {

  def clientCredentials[F[_]](
      authorizationServerUri: Uri,
      clientId: String,
      clientSecret: String,
      expirationFactor: Double = 0.8,
  )(
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

    val validToken: F[(Option[FiniteDuration], Authorization)] = for {
      r <- response
      _ <- f.raiseWhen(r.tokenType != "bearer")(
        new Exception(s"unsupported token type, ${r.tokenType}")
      )
    } yield (
      r.expiresIn,
      Authorization(Credentials.Token(AuthScheme.Bearer, r.accessToken)),
    )

    def authorizedClient(authorization: Authorization): Client[F] =
      Client.apply { r: Request[F] =>
        client.run(r.putHeaders(authorization))
      }

    def authorizedClientWithRef(ref: Ref[F, Authorization]): Client[F] =
      Client.apply { r: Request[F] =>
        for {
          header <- Resource.eval(ref.get)
          result <- client.run(r.putHeaders(header))
        } yield result
      }

    def executeBackgroundTaskWithDuration(
        expiresIn: FiniteDuration,
        header: Ref[F, Authorization],
    ): F[Unit] = for {
      _ <- f.sleep(expiresIn * expirationFactor)
      (updatedExpiresIn, authorization) <- validToken
      _ <- header.set(authorization)
      _ <- updatedExpiresIn match {
        case Some(newExpiration) => executeBackgroundTaskWithDuration(newExpiration, header)
        case None => f.unit
      }
    } yield ()

    for {
      (expiresIn, header) <- Resource.eval(validToken)
      client <- expiresIn match {
        case Some(expIn) =>
          Resource
            .make(Ref[F].of(header).flatMap { r =>
              executeBackgroundTaskWithDuration(expIn, r).start
                .map(fiber => (fiber, authorizedClientWithRef(r)))
            }) { case (fiber, _) =>
              fiber.cancel
            }
            .map(_._2)
        case None => Resource.pure[F, Client[F]](authorizedClient(header))
      }
    } yield client
  }

}

package org.http4s.client.oauth2

import scala.concurrent.duration.FiniteDuration

final case class AccessTokenResponse(
    accessToken: String,
    tokenType: String,
    expiresIn: Option[FiniteDuration],
    refreshToken: Option[String],
    scope: Option[String],
)

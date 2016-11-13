name := """rrd-athena-saml"""

version := "1.0-SNAPSHOT"

lazy val root = (project in file(".")).enablePlugins(PlayScala)

scalaVersion := "2.11.7"

libraryDependencies ++= Seq(
  jdbc,
  cache,
  "org.postgresql" % "postgresql" % "9.4-1201-jdbc41",
  "org.opensaml" % "opensaml" % "2.6.4" exclude ("org.bouncycastle", "bcprov-jdk15on"),
  "org.bouncycastle" % "bcprov-jdk16" % "1.46",
  ws
)

libraryDependencies <+= scalaVersion("org.scala-lang" % "scala-compiler" % _ )

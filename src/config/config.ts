import { registerAs } from "@nestjs/config";

export enum ConfigKeys {
    App = "App",
    DB = "DB",
    JWT = "JWT"
}

const AppConfig = registerAs(ConfigKeys.App, () => ({
    port: 3000,
}))
const JwtConfig = registerAs(ConfigKeys.JWT, () => ({
    accessTokenSecret: "86990241c691c00c02fc8383d3ed75117857fbec",
    refreshTokenSecret: "111e8805762331d2b72eeaadea3be3eae513a337",
}))
const DBConfig = registerAs(ConfigKeys.DB, () => ({
    port: 5432,
    host: "localhost",
    username: "postgres",
    password: "112233",
    database: "auth-otp",
}))

export const configuration = [AppConfig, DBConfig, JwtConfig];
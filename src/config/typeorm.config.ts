import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { TypeOrmModuleOptions, TypeOrmOptionsFactory } from "@nestjs/typeorm";

@Injectable()
export class TypeOrmDbConfig implements TypeOrmOptionsFactory {
    constructor(private configService: ConfigService) { }
    createTypeOrmOptions(connectionName?: string): Promise<TypeOrmModuleOptions> | TypeOrmModuleOptions {
        return {
            type: "postgres",
            host: this.configService.get("DB.host"),
            port: this.configService.get("DB.port"),
            username: this.configService.get("DB.username"),
            password: String(this.configService.get("DB.password")),
            database: this.configService.get("DB.database"),
            synchronize: true,
            autoLoadEntities: false,
            entities: [
                "dist/**/**/**/*.entity{.ts,.js}",
                "dist/**/**/*.entity{.ts,.js}",
            ]
        }
    }
}
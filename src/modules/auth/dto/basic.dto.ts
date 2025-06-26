import { IsEmail, IsMobilePhone, IsString, Length } from "class-validator";
import { ConfirmedPassword } from "src/common/decorators/password.decorator";

export class SignupDto {
    @IsString()
    first_name: string;

    @IsString()
    last_name: string;

    @IsString()
    @IsMobilePhone("fa-IR", {}, { message: "شماره تماس باید شماره ایران باشد" })
    mobile: string;

    @IsString()
    @IsEmail({ host_whitelist: ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"] }, {
        message: "ایمیل نادرست است"
    })
    email: string;

    @IsString()
    @Length(6, 20, {
        message: "رمز شما نادرست میباشد"
    })
    password: string;

    @IsString()
    @ConfirmedPassword("password")
    confirm_password: string;
}

export class LoginDto {
    @IsString()
    @IsEmail({ host_whitelist: ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"] }, {
        message: "ایمیل نادرست است"
    })
    email: string;

    @IsString()
    @Length(6, 20, {
        message: "رمز شما نادرست میباشد"
    })
    password: string;
}
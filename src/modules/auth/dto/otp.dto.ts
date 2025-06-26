import { IsMobilePhone, IsString, Length } from "class-validator";

export class SendOtpDto {
    @IsMobilePhone('fa-IR', {}, { message: "موبایل وارد شده اشتباه میباشد" })
    mobile: string;
}

export class CheckOtpDto {
    @IsMobilePhone('fa-IR', {}, { message: "موبایل وارد شده اشتباه میباشد" })
    mobile: string;
    @IsString()
    @Length(5, 5, { message: "کد وارد شده نادرست میباشد" })
    code: string;
}
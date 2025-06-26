import { BadRequestException, ConflictException, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { UserEntity } from '../user/entities/user.entity';
import { Repository } from 'typeorm';
import { OTPEntity } from '../user/entities/otp.entity';
import { CheckOtpDto, SendOtpDto } from './dto/otp.dto';
import { randomInt } from 'crypto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { TokensPayload } from './types/payload';
import { LoginDto, SignupDto } from './dto/basic.dto';
import { hashSync, genSaltSync, compareSync } from "bcrypt"

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(UserEntity) private userRepository: Repository<UserEntity>,
        @InjectRepository(OTPEntity) private otpRepository: Repository<OTPEntity>,
        private jwtService: JwtService,
        private configService: ConfigService,
    ) { }

    async sendOtp(otpDto: SendOtpDto) {
        const { mobile } = otpDto;
        let user = await this.userRepository.findOneBy({ mobile });
        if (!user) {
            user = this.userRepository.create({
                mobile,
            })
            user = await this.userRepository.save(user);
        }
        await this.createOtpForUser(user);
        return {
            message: "کد با موفقیت ارسال شد",
        }
    }

    async checkOtp(otpDto: CheckOtpDto) {
        const { code, mobile } = otpDto;
        const now = new Date();
        const user = await this.userRepository.findOne({
            where: { mobile },
            relations: {
                otp: true
            }
        });

        if (!user || !user?.otp) {
            throw new UnauthorizedException("احراز هویت انجام نشده است...");
        }
        const otp = user?.otp;
        if (otp?.code !== code) {
            throw new UnauthorizedException("کد وارد شده صحیح نمیباشد");
        }
        if (otp.expires_in < now) {
            throw new UnauthorizedException("کد منقضی شده است");
        }
        if (!user.mobile_verify) {
            await this.userRepository.update({ id: user.id }, {
                mobile_verify: true
            })
        }

        const { accessToken, refreshToken } = this.makeTokensForUser({ id: user.id, mobile });
        return {
            accessToken,
            refreshToken,
            message: "ورود با موفقیت انجام شد"
        }
    }

    async signup(signupDto: SignupDto) {
        const { first_name, last_name, email, password, mobile } = signupDto;
        await this.checkEmail(email);
        await this.checkMobile(mobile);
        let hashedPassword = this.hashPassword(password);
        const user = this.userRepository.create({
            first_name,
            last_name,
            mobile,
            email,
            password: hashedPassword,
            mobile_verify: false,
        });
        await this.userRepository.save(user);
        return {
            message: "ایجاد و ورود به حساب کاربری با موفقیت انجام شد"
        }
    }

    async login(loginDto: LoginDto) {
        const { email, password, } = loginDto;
        const user = await this.userRepository.findOneBy({ email });
        if (!user) {
            throw new UnauthorizedException("نام کاربری یا رمز عبور نادرست است");
        }
        if (!compareSync(password, user.password)) {
            throw new UnauthorizedException("نام کاربری یا رمز عبور نادرست است");
        }
        const { accessToken, refreshToken } = this.makeTokensForUser({ mobile: user.mobile, id: user.id });
        return {
            accessToken,
            refreshToken,
            message: "ورود به حساب کاربری با موفقیت انجام شد"
        }
    }

    async checkEmail(email: string) {
        const user = await this.userRepository.findOneBy({ email });
        if (user) throw new ConflictException("ایمیل در سامانه ثبت شده است")
    }
    async checkMobile(mobile: string) {
        const user = await this.userRepository.findOneBy({ mobile });
        if (user) throw new ConflictException("شماره تماس در سامانه ثبت شده است")
    }

    async createOtpForUser(user: UserEntity) {
        const expires_in = new Date(new Date().getTime() + (1000 * 60 * 2));
        let otp = await this.otpRepository.findOneBy({ userId: user.id });
        const code = randomInt(10000, 99999).toString();
        if (otp) {
            if (otp.expires_in > new Date()) {
                throw new BadRequestException("کد منقضی نشده است");
            }
            otp.code = code;
            otp.expires_in = expires_in;
        } else {
            otp = this.otpRepository.create({
                code,
                expires_in: expires_in,
                userId: user.id
            })
        }
        otp = await this.otpRepository.save(otp);
        user.otpId = otp.id;
        await this.userRepository.save(user);
    }

    makeTokensForUser(payload: TokensPayload) {
        const accessToken = this.jwtService.sign({ payload }, {
            secret: this.configService.get("JWT.accessTokenSecret"),
            expiresIn: "30d"
        })
        const refreshToken = this.jwtService.sign({ payload }, {
            secret: this.configService.get("JWT.refreshTokenSecret"),
            expiresIn: "1y"
        })
        return {
            accessToken,
            refreshToken
        }
    }

    // async validateAccessToken(token: string) {
    //     try {

    //         const payload = this.jwtService.verify<TokensPayload>(token, {
    //             secret: this.configService.get("JWT.accessTokenSecret"),
    //         });
    //         console.log("Secret Key => ", this.configService.get("JWT.accessTokenSecret"));
    //         console.log("Access Token => ", token);
    //         if (typeof payload === "object" && payload?.id) {
    //             const user = await this.userRepository.findOneBy({ id: payload.id });
    //             if (!user) {
    //                 throw new UnauthorizedException("وارد حساب کاربری خود شوید");
    //             }
    //             return user;
    //         }
    //         throw new UnauthorizedException("وارد حساب کاربری خود شوید");
    //     } catch (error) {
    //         console.log(error)
    //         throw new UnauthorizedException("وارد حساب کاربری خود شوید");
    //     }
    // }

    async validateAccessToken(token: string) {
        try {
            const decodedToken: any = this.jwtService.verify(token, {
                secret: this.configService.get("JWT.accessTokenSecret"),
            });
            const actualPayload = decodedToken.payload;
            if (typeof actualPayload === "object" && actualPayload !== null && actualPayload?.id) {
                const user = await this.userRepository.findOneBy({ id: actualPayload.id });
                if (!user) {
                    throw new UnauthorizedException("وارد حساب کاربری خود شوید");
                }
                return user;
            }
            throw new UnauthorizedException("وارد حساب کاربری خود شوید");
        } catch (error) {
            console.error(error);
            throw new UnauthorizedException("وارد حساب کاربری خود شوید");
        }
    }

    hashPassword(password: string) {
        const salt = genSaltSync(10);
        return hashSync(password, salt);
    }
}

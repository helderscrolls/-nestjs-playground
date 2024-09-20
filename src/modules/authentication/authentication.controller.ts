import {
  Body,
  Controller,
  HttpCode,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import RegisterDto from './dto/register.dto';
import { LocalAuthenticationGuard } from './guards/local-authentication.guard';
import RequestWithUser from './interfaces/request-with-user.interface';
import { AuthenticationService } from './services/authentication.service';

@Controller('authentication')
export class AuthenticationController {
  constructor(private readonly authenticationService: AuthenticationService) {}

  @Post('register')
  async register(@Body() registrationData: RegisterDto) {
    return this.authenticationService.register(registrationData);
  }

  @HttpCode(200)
  @UseGuards(LocalAuthenticationGuard)
  @Post('login')
  async login(@Req() request: RequestWithUser) {
    const user = request.user;
    user.password = undefined;

    return user;
  }
}

import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AccountService } from 'src/account/account.service';
import { VerifyDto } from './dto/verify.dto';
import { Verify } from './interfaces/verify.interface';
import { Login } from './interfaces/login.interface';
import { ClaimDto } from './dto/claim.dto';

@Injectable()
export class AuthService {
  constructor(
    private accountService: AccountService,
    private jwtService: JwtService,
  ) {}

  //async validateAccount(publicKey: string) {
  //  const account = await this.accountService.findOneByPublicKey(publicKey);
  //  if (!account) {
  //    return null;
  //  }
  //  return account;
  //}

  async verify(dto: VerifyDto): Promise<Verify> {
    const account = await this.accountService.validateSignature(dto);
    if (!account) {
      throw new Error('Invalid signature');
    }
    const accountExists = await this.accountService.findOneByPublicKey(
      account.publicKey,
    );
    if (!accountExists) {
      this.accountService.save(account);
    }
    return {
      accessToken: this.generateAccessToken({ publicKey: account.publicKey }),
      refreshToken: this.generateRefreshToken({
        publicKey: account.publicKey,
      }),
    };
  }

  async claim(dto: ClaimDto): Promise<Login> {
    const { publicKey, nonce } =
      await this.accountService.generateNonceForPublicKey({
        publicKey: dto.publicKey,
      });
    return {
      publicKey: publicKey,
      nonce: nonce,
    };
  }

  async refreshToken(refreshToken: string): Promise<Verify> {
    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: process.env.JWT_SECRET,
      });
      const account = await this.accountService.findOneByPublicKey(
        payload.publicKey,
      );
      if (!account) {
        throw new Error('Account not found');
      }

      const newPayload = { publicKey: payload.publicKey };

      return {
        accessToken: this.generateAccessToken(newPayload),
        refreshToken: this.generateRefreshToken(newPayload),
      };
    } catch {
      throw new Error('Invalid refresh token');
    }
  }

  private generateAccessToken(payload: any) {
    return this.jwtService.sign(payload, {
      expiresIn: '2m',
    });
  }

  private generateRefreshToken(payload: any) {
    return this.jwtService.sign(payload, {
      expiresIn: '30d',
    });
  }
}

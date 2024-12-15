import { BadRequestException, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AccountService } from 'src/account/account.service';
import { VerifyDto } from './dto/verify.dto';
import { Verify } from './interfaces/verify.interface';
import { Login } from './interfaces/login.interface';
import { ClaimDto } from './dto/claim.dto';
import { randomBytes } from 'crypto';
import { ValidateSignatureDto } from './dto/validate-signature.dto';
import bs58 from 'bs58';
import { sign } from 'tweetnacl';
import { AccountCandidates } from './dto/account-candidates.interface';
import { GetNonceDto } from './dto/get-nonce.dto';

@Injectable()
export class AuthService {
  constructor(
    private accountService: AccountService,
    private jwtService: JwtService,
  ) {}
  //TODO: Implement with Nest cache manager
  private accountCandidates: AccountCandidates[] = [];

  async verify(dto: VerifyDto): Promise<Verify> {
    const account = await this.validateSignature(dto);
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
    const { publicKey, nonce } = await this.generateNonceForPublicKey({
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

  private generateAccessToken(payload: any): string {
    return this.jwtService.sign(payload, {
      expiresIn: '2m',
    });
  }

  private generateRefreshToken(payload: any): string {
    return this.jwtService.sign(payload, {
      expiresIn: '30d',
    });
  }

  private findCandidate(publicKey: string): AccountCandidates {
    return this.accountCandidates.find(
      (account) => account.publicKey === publicKey,
    );
  }

  private async validateSignature(dto: ValidateSignatureDto) {
    const candidate = this.findCandidate(dto.publicKey);
    if (!candidate) {
      throw new BadRequestException('Candidate not found');
    }

    const publicKeyUint8 = bs58.decode(dto.publicKey);
    const signatureUint8 = bs58.decode(dto.signature);
    const msgUint8 = new TextEncoder().encode(candidate.nonce);

    const isValid = sign.detached.verify(
      msgUint8,
      signatureUint8,
      publicKeyUint8,
    );

    if (!isValid) {
      throw new BadRequestException('Invalid signature');
    }

    return {
      publicKey: candidate.publicKey,
    };
  }

  private async generateNonceForPublicKey(
    dto: GetNonceDto,
  ): Promise<AccountCandidates> {
    const exists = this.findCandidate(dto.publicKey);
    if (exists) {
      return {
        publicKey: exists.publicKey,
        nonce: exists.nonce,
      };
    }
    const nonce = this.generateNonce();
    this.accountCandidates.push({ publicKey: dto.publicKey, nonce });
    return {
      publicKey: dto.publicKey,
      nonce,
    };
  }

  private generateNonce(): string {
    const payload = randomBytes(32).toString('hex');
    return `insight: ${payload}`;
  }
}

import { sign } from 'tweetnacl';
import bs58 from 'bs58';
import { BadRequestException, Injectable } from '@nestjs/common';
import { GetNonceDto } from './dto/get-nonce.dto';
import { randomBytes } from 'crypto';
import { AccountCandidates } from './interfaces/account-candidates.interface';
import { PrismaService } from 'src/prisma/prisma.service';
import { ValidateSignatureDto } from './dto/validate-signature.dto';
import { SaveAccountDto } from './dto/save-account.dto';
import { AccountEntity } from './entity/account.entity';

@Injectable()
export class AccountService {
  //HACK: use something like redis
  private accountCandidates: AccountCandidates[] = [];

  constructor(private prisma: PrismaService) {}

  async generateNonceForPublicKey(
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

  async validateSignature(dto: ValidateSignatureDto) {
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

  async save(dto: SaveAccountDto): Promise<AccountEntity> {
    return await this.prisma.account.create({
      data: dto,
    });
  }

  async findOneByPublicKey(publicKey: string): Promise<AccountEntity> {
    return await this.prisma.account.findUnique({
      where: {
        publicKey,
      },
    });
  }

  private generateNonce(): string {
    const payload = randomBytes(32).toString('hex');
    return `insight: ${payload}`;
  }

  private findCandidate(publicKey: string) {
    return this.accountCandidates.find(
      (account) => account.publicKey === publicKey,
    );
  }
}

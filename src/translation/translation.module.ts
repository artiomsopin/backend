import { Module } from '@nestjs/common';
import { TranslationGateway } from './translation.gateway';
import { AccountModule } from 'src/account/account.module';

@Module({
  providers: [TranslationGateway],
  imports: [AccountModule],
})
export class TranslationModule {}

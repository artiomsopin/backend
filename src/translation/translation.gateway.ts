import {
  ConnectedSocket,
  MessageBody,
  OnGatewayConnection,
  OnGatewayDisconnect,
  OnGatewayInit,
  SubscribeMessage,
  WebSocketGateway,
  WebSocketServer,
} from '@nestjs/websockets';
import { AccountService } from 'src/account/account.service';
import { Socket } from 'socket.io';
import { AccountEntity } from 'src/account/entity/account.entity';

@WebSocketGateway()
export class TranslationGateway
  implements OnGatewayInit, OnGatewayConnection, OnGatewayDisconnect
{
  constructor(private accountService: AccountService) {}
  @WebSocketServer()
  private server: any;

  private SPEECHMATICS_API_KEY = process.env.SPEECHMATICS_API_KEY;
  private OPENAI_API_KEY = process.env.OPENAI_API_KEY;

  afterInit() {
    console.log('Translation gateway initialized');
  }

  handleConnection() {
    console.log('Extension connected to server');
  }

  handleDisconnect() {
    console.log('Extension disconnected from server');
  }

  //Handle messages from the client
  @SubscribeMessage('message')
  async handleMessage(
    @MessageBody() data: any,
    @ConnectedSocket() client: Socket,
  ): Promise<void> {}
}

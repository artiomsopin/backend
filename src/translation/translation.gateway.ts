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
import { AccountEntity } from 'src/account/entity/account.entity';
import { RealtimeSession } from 'speechmatics';
import sbd from 'sbd';
import { OpenAI } from 'openai';
import { ExtractSentencesResult } from './types/extract-sentences-result.type';
import { Socket } from 'socket.io';

@WebSocketGateway()
export class TranslationGateway
  implements OnGatewayInit, OnGatewayConnection, OnGatewayDisconnect
{
  constructor(private accountService: AccountService) {}
  @WebSocketServer()
  private server: any;

  // Store connected speechmatics sessions using the wsClient ID as key
  private speechmaticsSessions: Map<string, RealtimeSession> = new Map();

  // Configuration
  private readonly SPEECHMATICS_API_KEY = process.env.SPEECHMATICS_API_KEY;
  private readonly OPENAI_API_KEY = process.env.OPENAI_API_KEY;

  // OpenAI setup
  private openai = new OpenAI({
    apiKey: this.OPENAI_API_KEY,
  });

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
    @ConnectedSocket() wsClient: Socket,
  ): Promise<void> {
    // Variables to store user information
    let userPublicKey = null;
    let assignedKey = null;

    // Buffer to accumulate transcriptions
    let transcriptBuffer = '';

    // Variables to store language settings
    let sourceLang: string = 'en';
    let targetLang: string = 'ua';

    console.log('Message received:', data);

    // Check if the message is binary (audio data) or text (JSON)
    if (typeof data === 'string') {
      const message = JSON.parse(data);

      if (message.type === 'authentication') {
        userPublicKey = message.userPublicKey;
        // Get user from the database
        //TODO: rewrite hardcoded user
        let user: AccountEntity =
          await this.accountService.findOneByPublicKey(userPublicKey);
        user = new AccountEntity();
        console.log(user);

        if (user) {
          wsClient.send(JSON.stringify({ type: 'authentication_success' }));

          // Get an available API key
          // TODO: Implement a function to get an available API key
          assignedKey = this.SPEECHMATICS_API_KEY;

          // If no API key is available, send an error message
          if (!assignedKey) {
            console.error(
              'No available Speechmatics API keys to handle a new connection.',
            );
            wsClient.send(
              JSON.stringify({
                type: 'error',
                message: 'Server is busy. Please try again later.',
              }),
            );
            wsClient.disconnect();
            return;
          }

          // Create a RealtimeSession for interacting with Speechmatics
          const speechmaticsSession: RealtimeSession = new RealtimeSession(
            assignedKey,
          );

          // RealtimeSession event handlers
          speechmaticsSession.addListener('RecognitionStarted', () => {
            console.log('RecognitionStarted');
            wsClient.send(
              JSON.stringify({ type: 'status', message: 'RecognitionStarted' }),
            );
          });

          speechmaticsSession.addListener('Error', (error) => {
            console.error('Session error:', error);
            wsClient.send(
              JSON.stringify({ type: 'error', message: error.message }),
            );
          });

          speechmaticsSession.addListener('AddTranscript', async (message) => {
            const transcript: string = message.metadata.transcript;
            console.log('AddTranscript:', transcript);
            wsClient.send(JSON.stringify({ type: 'transcript', transcript }));

            // Add transcription to the buffer
            transcriptBuffer += ' ' + transcript;

            // Extract completed sentences from the buffer
            const {
              completeSentences,
              remainingBuffer,
            }: ExtractSentencesResult = this.extractSentences(transcriptBuffer);

            if (completeSentences) {
              wsClient.send(
                JSON.stringify({
                  type: 'translation_status',
                  message: 'Translating...',
                }),
              );

              try {
                const translatedText = await this.translateTextStream(
                  completeSentences.trim(),
                  sourceLang,
                  targetLang,
                );
                console.log('Translation:', translatedText);
                wsClient.send(
                  JSON.stringify({
                    type: 'translation',
                    translation: translatedText,
                  }),
                );

                wsClient.send(
                  JSON.stringify({
                    type: 'translation_status',
                    message: 'Translation complete',
                  }),
                );

                // Update buffer with incomplete fragments
                transcriptBuffer = remainingBuffer.trim();

                //TODO: add user charge
                // Charge for translation (e.g., 0.01 units)
                //await chargeUser(userPublicKey, 0.02);
              } catch (error) {
                console.error('Error translating transcript:', error);
                wsClient.send(
                  JSON.stringify({
                    type: 'error',
                    message: 'Failed to translate transcript',
                  }),
                );
              }
            }
          });

          speechmaticsSession.addListener('EndOfTranscript', async () => {
            console.log('EndOfTranscript');
            wsClient.send(
              JSON.stringify({ type: 'status', message: 'EndOfTranscript' }),
            );

            // Translate the remaining buffer
            if (transcriptBuffer.trim().length > 0) {
              wsClient.send(
                JSON.stringify({
                  type: 'translation_status',
                  message: 'Translating...',
                }),
              );

              try {
                const translatedText = await this.translateTextStream(
                  transcriptBuffer.trim(),
                  sourceLang,
                  targetLang,
                );
                console.log('Translation:', translatedText);
                wsClient.send(
                  JSON.stringify({
                    type: 'translation',
                    translation: translatedText,
                  }),
                );

                wsClient.send(
                  JSON.stringify({
                    type: 'translation_status',
                    message: 'Translation complete',
                  }),
                );

                // Clear the buffer
                transcriptBuffer = '';

                // TODO: Charge for translation
                //await chargeUser(userPublicKey, 0.02);
              } catch (error) {
                console.error('Error translating transcript:', error);
                wsClient.send(
                  JSON.stringify({
                    type: 'error',
                    message: 'Failed to translate transcript',
                  }),
                );
              }
            }
          });

          try {
            await speechmaticsSession.start({
              transcription_config: {
                language: sourceLang,
                operating_point: 'enhanced',
                enable_partials: true,
                max_delay: 2,
              },
              audio_format: {
                type: 'raw',
                encoding: 'pcm_s16le',
                sample_rate: 16000,
              },
            });
            console.log('Transcription session started');
          } catch (error) {
            console.error('Error starting transcription session:', error);
            wsClient.send(
              JSON.stringify({
                type: 'error',
                message: 'Failed to start transcription session',
              }),
            );
            wsClient.disconnect();
            //TODO: implement releaseSpeechmaticsKey;
            //releaseSpeechmaticsKey(assignedKey);
            return;
          }

          // Save session in the client for further use
          this.speechmaticsSessions.set(wsClient.id, speechmaticsSession);
        } else if (message.type === 'language_settings') {
          sourceLang = message.sourceLanguage || 'en';
          targetLang = message.targetLanguage || 'ua';
          console.log(
            `Languages set: source - ${sourceLang}, target - ${targetLang}`,
          );
        } else {
          // Handle other message types
        }
      } else {
        // Handle audio data
        if (wsClient.id && this.speechmaticsSessions.has(wsClient.id)) {
          try {
            const speechmaticSession: RealtimeSession =
              this.speechmaticsSessions.get(wsClient.id);
            speechmaticSession.sendAudio(Buffer.from(data));
          } catch (error) {
            console.error('Error sending audio:', error);
            wsClient.send(
              JSON.stringify({
                type: 'error',
                message: 'Failed to send audio data',
              }),
            );
          }
        }
      }
    }
  }
  extractSentences(buffer: string): ExtractSentencesResult {
    // Use the sbd library to accurately split sentences
    const sentences: string[] = sbd.sentences(buffer, {
      newline_boundaries: true,
    });
    if (sentences.length > 0) {
      // Collect all found sentences
      const completeSentences: string = sentences.join(' ').trim();
      // Find the last completed sentence index
      const lastSentenceEnd = buffer.lastIndexOf(
        sentences[sentences.length - 1],
      );
      // Leave only incomplete fragments in the buffer
      const remainingBuffer: string = buffer.slice(
        lastSentenceEnd + sentences[sentences.length - 1].length,
      );
      return { completeSentences, remainingBuffer };
    }
    return { completeSentences: null, remainingBuffer: buffer };
  }

  async translateTextStream(
    text: string,
    sourceLang: string = 'en',
    targetLang: string = 'ua',
  ): Promise<string> {
    try {
      const stream = await this.openai.chat.completions.create({
        model: 'gpt-4o-mini', // Use the appropriate model name
        messages: [
          {
            role: 'system',
            content: `You are a professional translator. Translate text from ${sourceLang} to ${targetLang}, considering the context and themes related to the Solana ecosystem.`,
          },
          {
            role: 'user',
            content: text,
          },
        ],
        stream: true,
      });

      let translation: string = '';
      for await (const part of stream) {
        translation += part.choices[0]?.delta?.content || '';
      }
      return translation;
    } catch (error) {
      console.error('Error communicating with OpenAI API:', error);
      throw error;
    }
  }
}

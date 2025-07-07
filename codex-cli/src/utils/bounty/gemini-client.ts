import { GEMINI_API_KEY } from "../config";

export interface GeminiConfig {
  apiKey: string;
  model: string;
  timeout?: number;
}

export interface GeminiMessage {
  role: 'user' | 'model';
  parts: { text: string }[];
}

export interface GeminiRequest {
  contents: GeminiMessage[];
  generationConfig?: {
    temperature?: number;
    topK?: number;
    topP?: number;
    maxOutputTokens?: number;
  };
}

export interface GeminiResponse {
  candidates: {
    content: {
      parts: { text: string }[];
      role: string;
    };
    finishReason: string;
  }[];
}

export class GeminiClient {
  private apiKey: string;
  private model: string;
  private baseUrl: string;
  private timeout: number;

  constructor(config: GeminiConfig) {
    this.apiKey = config.apiKey;
    this.model = config.model || 'gemini-pro';
    this.baseUrl = 'https://generativelanguage.googleapis.com/v1beta';
    this.timeout = config.timeout || 30000;
  }

  async generateContent(request: GeminiRequest): Promise<GeminiResponse> {
    const url = `${this.baseUrl}/models/${this.model}:generateContent?key=${this.apiKey}`;
    
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(this.timeout)
    });

    if (!response.ok) {
      throw new Error(`Gemini API error: ${response.status} ${response.statusText}`);
    }

    return response.json();
  }

  async streamGenerateContent(request: GeminiRequest): Promise<AsyncIterable<GeminiResponse>> {
    const url = `${this.baseUrl}/models/${this.model}:streamGenerateContent?key=${this.apiKey}`;
    
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(this.timeout)
    });

    if (!response.ok) {
      throw new Error(`Gemini API error: ${response.status} ${response.statusText}`);
    }

    if (!response.body) {
      throw new Error('No response body from Gemini API');
    }

    return this.parseStreamResponse(response.body);
  }

  private async *parseStreamResponse(body: ReadableStream<Uint8Array>): AsyncIterable<GeminiResponse> {
    const reader = body.getReader();
    const decoder = new TextDecoder();

    try {
      while (true) {
        const { done, value } = await reader.read();
        
        if (done) break;
        
        const chunk = decoder.decode(value, { stream: true });
        const lines = chunk.split('\n');
        
        for (const line of lines) {
          if (line.trim() && line.startsWith('data: ')) {
            try {
              const data = JSON.parse(line.slice(6));
              yield data;
            } catch (error) {
              // Skip malformed JSON
              continue;
            }
          }
        }
      }
    } finally {
      reader.releaseLock();
    }
  }
}

export function createGeminiClient(apiKey?: string): GeminiClient {
  const key = apiKey || GEMINI_API_KEY;
  if (!key) {
    throw new Error('Gemini API key is required. Set GEMINI_API_KEY environment variable.');
  }

  return new GeminiClient({
    apiKey: key,
    model: 'gemini-pro'
  });
}
import { writeFile } from 'node:fs/promises';
import { xai } from '@ai-sdk/xai';
import { generateImage } from 'ai';

const { image } = await generateImage({
  model: xai.image('grok-imagine-image-2.0'),
  prompt: 'A futuristic city skyline at sunset',
});
await writeFile('output.png', Buffer.from(image.base64, 'base64'));
console.log('Saved output.png');

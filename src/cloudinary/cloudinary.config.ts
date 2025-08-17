import { v2 as cloudinary } from 'cloudinary';
import { ConfigService } from '@nestjs/config';

export const CloudinaryProvider = {
  provide: 'CLOUDINARY',
  useFactory: (config: ConfigService) => {
    const cloudinaryConfig = {
      cloud_name: config.get('CLOUDINARY_CLOUD_NAME'),
      api_key: config.get('CLOUDINARY_API_KEY'),
      api_secret: config.get('CLOUDINARY_API_SECRET'),
    };

    console.log('Initializing Cloudinary with:', {
      cloud_name: cloudinaryConfig.cloud_name,
      api_key: cloudinaryConfig.api_key ? 'SET' : 'NOT SET',
      api_secret: cloudinaryConfig.api_secret ? 'SET' : 'NOT SET',
    });

    return cloudinary.config(cloudinaryConfig);
  },
  inject: [ConfigService],
};

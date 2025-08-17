import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { v2 as cloudinary } from 'cloudinary';
import { ConfigService } from '@nestjs/config';

export interface CloudinaryResponse {
  public_id: string;
  url: string;
  secure_url: string;
  format: string;
  width: number;
  height: number;
  bytes: number;
}

@Injectable()
export class CloudinaryService {
  private readonly logger = new Logger(CloudinaryService.name);

  constructor(private config: ConfigService) {}

  async uploadImage(
    file: Express.Multer.File,
    folder: string = 'avatars',
  ): Promise<CloudinaryResponse> {
    this.logger.log(`Uploading image to Cloudinary folder: ${folder}`);

    // Debug logs
    console.log('File info:', {
      originalname: file.originalname,
      mimetype: file.mimetype,
      size: file.size,
      bufferExists: !!file.buffer,
    });

    try {
      // Use upload_stream instead of upload for buffer
      const result = await new Promise((resolve, reject) => {
        cloudinary.uploader
          .upload_stream(
            {
              resource_type: 'auto',
              folder: `task-manager/${folder}`,
              transformation: [
                { width: 200, height: 200, crop: 'fill', gravity: 'face' },
                { quality: 'auto:good' },
                { format: 'webp' },
              ],
              allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
            },
            (error, result) => {
              if (error) {
                console.error('Cloudinary error:', error);
                reject(error);
              } else {
                resolve(result);
              }
            },
          )
          .end(file.buffer);
      });

      this.logger.log(
        `Image uploaded successfully: ${(result as any).public_id}`,
      );
      return result as CloudinaryResponse;
    } catch (error) {
      console.error('Full Cloudinary error:', error);
      this.logger.error(`Cloudinary upload failed: ${error.message}`);
      throw new BadRequestException(`Failed to upload image: ${error.message}`);
    }
  }

  async deleteImage(publicId: string): Promise<void> {
    this.logger.log(`Deleting image from Cloudinary: ${publicId}`);

    try {
      await cloudinary.uploader.destroy(publicId);
      this.logger.log(`Image deleted successfully: ${publicId}`);
    } catch (error) {
      this.logger.error(`Failed to delete image: ${error.message}`);
      // Don't throw error - this is cleanup, shouldn't fail the main operation
    }
  }
}

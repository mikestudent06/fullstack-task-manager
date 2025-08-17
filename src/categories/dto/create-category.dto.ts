import {
  IsNotEmpty,
  IsString,
  Length,
  IsOptional,
  Matches,
} from 'class-validator';
import { Transform } from 'class-transformer';

export class CreateCategoryDto {
  @IsNotEmpty()
  @IsString()
  @Length(1, 30, {
    message: 'Category name must be between 1 and 30 characters',
  })
  @Transform(({ value }) => value?.trim())
  name: string;

  @IsOptional()
  @IsString()
  @Matches(/^#[0-9A-Fa-f]{6}$/, {
    message: 'Color must be a valid hex color (e.g., #3B82F6)',
  })
  color?: string;
}

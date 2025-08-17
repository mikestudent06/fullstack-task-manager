import {
  IsNotEmpty,
  IsString,
  IsOptional,
  IsEnum,
  IsDateString,
  Length,
  IsUUID,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { TaskStatus, Priority } from '@prisma/client';

export class CreateTaskDto {
  @IsNotEmpty()
  @IsString()
  @Length(1, 200, { message: 'Title must be between 1 and 200 characters' })
  @Transform(({ value }) => value?.trim())
  title: string;

  @IsOptional()
  @IsString()
  @Length(0, 1000, { message: 'Description must be less than 1000 characters' })
  @Transform(({ value }) => value?.trim())
  description?: string;

  @IsOptional()
  @IsEnum(Priority)
  priority?: Priority;

  @IsOptional()
  @IsDateString()
  dueDate?: string;

  @IsOptional()
  @IsUUID()
  categoryId?: string;
}

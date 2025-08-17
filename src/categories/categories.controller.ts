import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { CategoriesService, CategoryResponse } from './categories.service';
import { CreateCategoryDto } from './dto/create-category.dto';
import { UpdateCategoryDto } from './dto/update-category.dto';
import { JwtAuthGuard } from 'src/auth/guards/jwt.guard';
import { GetUser } from 'src/auth/decorators/get-user.decorator';
import { UserPayload } from 'src/auth/auth.dto';

@Controller('categories')
@UseGuards(JwtAuthGuard)
export class CategoriesController {
  private readonly logger = new Logger(CategoriesController.name);

  constructor(private categoriesService: CategoriesService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async createCategory(
    @GetUser() user: UserPayload,
    @Body() dto: CreateCategoryDto,
  ): Promise<{ category: CategoryResponse; message: string }> {
    this.logger.log(`Create category request from user: ${user.sub}`);

    const category = await this.categoriesService.createCategory(user.sub, dto);

    return {
      category,
      message: 'Category created successfully',
    };
  }

  @Get()
  @HttpCode(HttpStatus.OK)
  async getCategories(
    @GetUser() user: UserPayload,
  ): Promise<CategoryResponse[]> {
    this.logger.log(`Get categories request from user: ${user.sub}`);
    return this.categoriesService.getUserCategories(user.sub);
  }

  @Patch(':id')
  @HttpCode(HttpStatus.OK)
  async updateCategory(
    @GetUser() user: UserPayload,
    @Param('id') categoryId: string,
    @Body() dto: UpdateCategoryDto,
  ): Promise<{ category: CategoryResponse; message: string }> {
    this.logger.log(
      `Update category request: ${categoryId} from user: ${user.sub}`,
    );

    const category = await this.categoriesService.updateCategory(
      user.sub,
      categoryId,
      dto,
    );

    return {
      category,
      message: 'Category updated successfully',
    };
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  async deleteCategory(
    @GetUser() user: UserPayload,
    @Param('id') categoryId: string,
  ): Promise<{ message: string }> {
    this.logger.log(
      `Delete category request: ${categoryId} from user: ${user.sub}`,
    );

    await this.categoriesService.deleteCategory(user.sub, categoryId);

    return {
      message: 'Category deleted successfully',
    };
  }
}

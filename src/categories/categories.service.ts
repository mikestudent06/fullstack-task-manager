import {
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateCategoryDto } from './dto/create-category.dto';
import { UpdateCategoryDto } from './dto/update-category.dto';

export interface CategoryResponse {
  id: string;
  name: string;
  color: string;
  taskCount: number;
  createdAt: Date;
  updatedAt: Date;
}

@Injectable()
export class CategoriesService {
  private readonly logger = new Logger(CategoriesService.name);
  constructor(private prisma: PrismaService) {}

  async createCategory(
    userId: string,
    dto: CreateCategoryDto,
  ): Promise<CategoryResponse> {
    this.logger.log(`Creating category for user: ${userId}`);

    // Check if category name already exists for this user
    const existingCategory = await this.prisma.category.findFirst({
      where: { userId, name: dto.name },
    });

    if (existingCategory) {
      throw new ForbiddenException('Category with this name already exists');
    }

    const category = await this.prisma.category.create({
      data: {
        name: dto.name,
        color: dto.color || '#3B82F6',
        userId,
      },
      include: {
        _count: { select: { tasks: true } },
      },
    });
    this.logger.log(`Category created: ${category.id} for user: ${userId}`);

    return {
      id: category.id,
      name: category.name,
      color: category.color,
      taskCount: category._count.tasks,
      createdAt: category.createdAt,
      updatedAt: category.updatedAt,
    };
  }

  async getUserCategories(userId: string): Promise<CategoryResponse[]> {
    this.logger.log(`Getting categories for user: ${userId}`);

    const categories = await this.prisma.category.findMany({
      where: { userId },
      include: {
        _count: { select: { tasks: true } },
      },
      orderBy: { createdAt: 'asc' },
    });

    return categories.map((category) => ({
      id: category.id,
      name: category.name,
      color: category.color,
      taskCount: category._count.tasks,
      createdAt: category.createdAt,
      updatedAt: category.updatedAt,
    }));
  }

  async updateCategory(
    userId: string,
    categoryId: string,
    dto: UpdateCategoryDto,
  ): Promise<CategoryResponse> {
    this.logger.log(`Updating category: ${categoryId} for user: ${userId}`);

    // Verify category belongs to user
    const existingCategory = await this.prisma.category.findFirst({
      where: { id: categoryId, userId },
    });

    if (!existingCategory) {
      throw new NotFoundException('Category not found');
    }

    // Check name uniqueness if updating name
    if (dto.name && dto.name !== existingCategory.name) {
      const nameExists = await this.prisma.category.findFirst({
        where: { userId, name: dto.name },
      });

      if (nameExists) {
        throw new ForbiddenException('Category with this name already exists');
      }
    }

    const updatedCategory = await this.prisma.category.update({
      where: { id: categoryId },
      data: dto,
      include: {
        _count: { select: { tasks: true } },
      },
    });

    this.logger.log(`Category updated: ${categoryId}`);

    return {
      id: updatedCategory.id,
      name: updatedCategory.name,
      color: updatedCategory.color,
      taskCount: updatedCategory._count.tasks,
      createdAt: updatedCategory.createdAt,
      updatedAt: updatedCategory.updatedAt,
    };
  }

  async deleteCategory(userId: string, categoryId: string): Promise<void> {
    this.logger.log(`Deleting category: ${categoryId} for user: ${userId}`);

    // Verify category belongs to user
    const category = await this.prisma.category.findFirst({
      where: { id: categoryId, userId },
    });

    if (!category) {
      throw new NotFoundException('Category not found');
    }

    // Delete category (tasks will have categoryId set to null due to onDelete: SetNull)
    await this.prisma.category.delete({
      where: { id: categoryId },
    });

    this.logger.log(`Category deleted: ${categoryId}`);
  }
}

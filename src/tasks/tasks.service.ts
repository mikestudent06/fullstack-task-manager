import {
  Injectable,
  Logger,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateTaskDto } from './dto/create-task.dto';
import { UpdateTaskDto } from './dto/update-task.dto';
import { QueryTasksDto } from './dto/query-tasks.dto';
import { TaskStatus, Priority } from '@prisma/client';

export interface TaskResponse {
  id: string;
  title: string;
  description: string | null;
  status: TaskStatus;
  priority: Priority;
  dueDate: Date | null;
  position: number;
  completedAt: Date | null;
  category: {
    id: string;
    name: string;
    color: string;
  } | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface TaskListResponse {
  tasks: TaskResponse[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

@Injectable()
export class TasksService {
  private readonly logger = new Logger(TasksService.name);

  constructor(private prisma: PrismaService) {}

  async createTask(userId: string, dto: CreateTaskDto): Promise<TaskResponse> {
    this.logger.log(`Creating task for user: ${userId}`);

    // Verify category belongs to user if provided
    if (dto.categoryId) {
      const category = await this.prisma.category.findFirst({
        where: { id: dto.categoryId, userId },
      });

      if (!category) {
        throw new ForbiddenException(
          'Category not found or does not belong to user',
        );
      }
    }

    const task = await this.prisma.task.create({
      data: {
        title: dto.title,
        description: dto.description,
        priority: dto.priority || Priority.MEDIUM,
        dueDate: dto.dueDate ? new Date(dto.dueDate) : null,
        categoryId: dto.categoryId,
        userId,
      },
      include: {
        category: {
          select: { id: true, name: true, color: true },
        },
      },
    });

    this.logger.log(`Task created: ${task.id} for user: ${userId}`);
    return this.formatTaskResponse(task);
  }

  async getUserTasks(
    userId: string,
    query: QueryTasksDto,
  ): Promise<TaskListResponse> {
    this.logger.log(
      `Getting tasks for user: ${userId} with filters: ${JSON.stringify(query)}`,
    );

    const {
      page = 1,
      limit = 10,
      status,
      priority,
      categoryId,
      search,
      sortBy,
      sortOrder,
    } = query;

    const skip = (page - 1) * limit;

    // Build where clause
    const where: any = { userId };

    if (status) where.status = status;
    if (priority) where.priority = priority;
    if (categoryId) where.categoryId = categoryId;
    if (search) {
      where.OR = [
        { title: { contains: search, mode: 'insensitive' } },
        { description: { contains: search, mode: 'insensitive' } },
      ];
    }

    // Build orderBy clause
    const orderBy: any = {};
    if (sortBy === 'priority') {
      // Custom priority ordering: URGENT > HIGH > MEDIUM > LOW
      orderBy.priority = sortOrder === 'asc' ? 'asc' : 'desc';
    } else {
      orderBy[sortBy as string] = sortOrder;
    }

    const [tasks, total] = await Promise.all([
      this.prisma.task.findMany({
        where,
        include: {
          category: {
            select: { id: true, name: true, color: true },
          },
        },
        orderBy,
        skip,
        take: limit,
      }),
      this.prisma.task.count({ where }),
    ]);

    return {
      tasks: tasks.map((task) => this.formatTaskResponse(task)),
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  async getTaskById(userId: string, taskId: string): Promise<TaskResponse> {
    this.logger.log(`Getting task: ${taskId} for user: ${userId}`);

    const task = await this.prisma.task.findFirst({
      where: { id: taskId, userId },
      include: {
        category: {
          select: { id: true, name: true, color: true },
        },
      },
    });

    if (!task) {
      throw new NotFoundException('Task not found');
    }

    return this.formatTaskResponse(task);
  }

  async updateTask(
    userId: string,
    taskId: string,
    dto: UpdateTaskDto,
  ): Promise<TaskResponse> {
    this.logger.log(`Updating task: ${taskId} for user: ${userId}`);

    // Verify task belongs to user
    const existingTask = await this.prisma.task.findFirst({
      where: { id: taskId, userId },
    });

    if (!existingTask) {
      throw new NotFoundException('Task not found');
    }

    // Verify category belongs to user if provided
    if (dto.categoryId) {
      const category = await this.prisma.category.findFirst({
        where: { id: dto.categoryId, userId },
      });

      if (!category) {
        throw new ForbiddenException(
          'Category not found or does not belong to user',
        );
      }
    }

    // Handle task completion
    const updateData: any = {
      ...dto,
      ...(dto.dueDate && { dueDate: new Date(dto.dueDate) }),
    };

    // Set completedAt when status changes to DONE
    if (
      dto.status === TaskStatus.DONE &&
      existingTask.status !== TaskStatus.DONE
    ) {
      updateData.completedAt = new Date();
    }
    // Clear completedAt when status changes from DONE to something else
    else if (
      dto.status &&
      dto.status !== TaskStatus.DONE &&
      existingTask.status === TaskStatus.DONE
    ) {
      updateData.completedAt = null;
    }

    const updatedTask = await this.prisma.task.update({
      where: { id: taskId },
      data: updateData,
      include: {
        category: {
          select: { id: true, name: true, color: true },
        },
      },
    });

    this.logger.log(`Task updated: ${taskId}`);
    return this.formatTaskResponse(updatedTask);
  }

  async deleteTask(userId: string, taskId: string): Promise<void> {
    this.logger.log(`Deleting task: ${taskId} for user: ${userId}`);

    const task = await this.prisma.task.findFirst({
      where: { id: taskId, userId },
    });

    if (!task) {
      throw new NotFoundException('Task not found');
    }

    await this.prisma.task.delete({
      where: { id: taskId },
    });

    this.logger.log(`Task deleted: ${taskId}`);
  }

  async getTaskStats(userId: string): Promise<any> {
    this.logger.log(`Getting task stats for user: ${userId}`);

    const [totalTasks, completedTasks, statusCounts, priorityCounts] =
      await Promise.all([
        this.prisma.task.count({ where: { userId } }),
        this.prisma.task.count({ where: { userId, status: TaskStatus.DONE } }),
        this.prisma.task.groupBy({
          by: ['status'],
          where: { userId },
          _count: { status: true },
        }),
        this.prisma.task.groupBy({
          by: ['priority'],
          where: { userId },
          _count: { priority: true },
        }),
      ]);

    return {
      totalTasks,
      completedTasks,
      completionRate:
        totalTasks > 0 ? Math.round((completedTasks / totalTasks) * 100) : 0,
      statusBreakdown: statusCounts.reduce((acc, item) => {
        acc[item.status] = item._count.status;
        return acc;
      }, {}),
      priorityBreakdown: priorityCounts.reduce((acc, item) => {
        acc[item.priority] = item._count.priority;
        return acc;
      }, {}),
    };
  }

  private formatTaskResponse(task: any): TaskResponse {
    return {
      id: task.id,
      title: task.title,
      description: task.description,
      status: task.status,
      priority: task.priority,
      dueDate: task.dueDate,
      position: task.position,
      completedAt: task.completedAt,
      category: task.category,
      createdAt: task.createdAt,
      updatedAt: task.updatedAt,
    };
  }
}

import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { TasksService, TaskResponse, TaskListResponse } from './tasks.service';
import { CreateTaskDto } from './dto/create-task.dto';
import { UpdateTaskDto } from './dto/update-task.dto';
import { QueryTasksDto } from './dto/query-tasks.dto';
import { JwtAuthGuard } from 'src/auth/guards/jwt.guard';
import { GetUser } from 'src/auth/decorators/get-user.decorator';
import { UserPayload } from 'src/auth/auth.dto';

@Controller('tasks')
@UseGuards(JwtAuthGuard)
export class TasksController {
  private readonly logger = new Logger(TasksController.name);

  constructor(private tasksService: TasksService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async createTask(
    @GetUser() user: UserPayload,
    @Body() dto: CreateTaskDto,
  ): Promise<{ task: TaskResponse; message: string }> {
    this.logger.log(`Create task request from user: ${user.sub}`);

    const task = await this.tasksService.createTask(user.sub, dto);

    return {
      task,
      message: 'Task created successfully',
    };
  }

  @Get()
  @HttpCode(HttpStatus.OK)
  async getTasks(
    @GetUser() user: UserPayload,
    @Query() query: QueryTasksDto,
  ): Promise<TaskListResponse> {
    this.logger.log(`Get tasks request from user: ${user.sub}`);
    return this.tasksService.getUserTasks(user.sub, query);
  }

  @Get('stats')
  @HttpCode(HttpStatus.OK)
  async getTaskStats(@GetUser() user: UserPayload): Promise<any> {
    this.logger.log(`Get task stats request from user: ${user.sub}`);
    return this.tasksService.getTaskStats(user.sub);
  }

  @Get(':id')
  @HttpCode(HttpStatus.OK)
  async getTask(
    @GetUser() user: UserPayload,
    @Param('id') taskId: string,
  ): Promise<TaskResponse> {
    this.logger.log(`Get task request: ${taskId} from user: ${user.sub}`);
    return this.tasksService.getTaskById(user.sub, taskId);
  }

  @Patch(':id')
  @HttpCode(HttpStatus.OK)
  async updateTask(
    @GetUser() user: UserPayload,
    @Param('id') taskId: string,
    @Body() dto: UpdateTaskDto,
  ): Promise<{ task: TaskResponse; message: string }> {
    this.logger.log(`Update task request: ${taskId} from user: ${user.sub}`);

    const task = await this.tasksService.updateTask(user.sub, taskId, dto);

    return {
      task,
      message: 'Task updated successfully',
    };
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  async deleteTask(
    @GetUser() user: UserPayload,
    @Param('id') taskId: string,
  ): Promise<{ message: string }> {
    this.logger.log(`Delete task request: ${taskId} from user: ${user.sub}`);

    await this.tasksService.deleteTask(user.sub, taskId);

    return {
      message: 'Task deleted successfully',
    };
  }
}

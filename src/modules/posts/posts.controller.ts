import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  Put,
} from '@nestjs/common';
import { CreatePostDto, UpdatePostDto } from './dto';
import PostsService from './services/posts.service';

@Controller('posts')
export class PostsController {
  constructor(private readonly postsService: PostsService) {}

  @Get()
  getAllPosts() {
    return this.postsService.getAllPosts();
  }

  @Get(':id')
  getPostById(@Param('id') id: string) {
    return this.postsService.getPostById(Number(id));
  }

  @Post()
  async createPost(@Body() post: CreatePostDto) {
    return this.postsService.createPost(post);
  }

  @Put(':id')
  async updatePost(@Param('id') id: string, @Body() post: UpdatePostDto) {
    return this.postsService.updatePost(Number(id), post);
  }

  @Delete(':id')
  async deletePost(@Param('id') id: string) {
    return this.postsService.deletePost(Number(id));
  }
}

-- AlterTable
ALTER TABLE "public"."users" ADD COLUMN     "avatar" TEXT,
ADD COLUMN     "resetToken" TEXT,
ADD COLUMN     "resetTokenExpires" TIMESTAMP(3);

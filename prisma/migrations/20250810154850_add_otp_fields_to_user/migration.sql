-- DropIndex
DROP INDEX "public"."users_email_idx";

-- AlterTable
ALTER TABLE "public"."users" ADD COLUMN     "isVerified" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "otp" TEXT,
ADD COLUMN     "otpExpires" TIMESTAMP(3);

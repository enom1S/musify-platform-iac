data "aws_availability_zones" "available" {
  state = "available"
}

# VPC
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  
  name = "musify-vpc"
  cidr = "10.0.0.0/16"
  
  azs             = data.aws_availability_zones.available.names
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24"]
  
  enable_nat_gateway = true
  enable_vpn_gateway = false
  
  tags = {
    Terraform   = "true"
    Environment = "dev"
    Project     = "musify"
  }
}

# Genera password sicura
resource "random_password" "db_password" {
  length  = 16
  special = true
}

resource "aws_db_subnet_group" "db_subnet" {
  name       = "musify-db-subnet-group"
  //subnet_ids = module.vpc.private_subnets 
  subnet_ids = module.vpc.public_subnets 

  tags = {
    Name = "Musify DB subnet group"
  }
}

# Security Group più sicuro
resource "aws_security_group" "rds" {
  name        = "musify-rds-sg"
  description = "Security group per Musify RDS"
  vpc_id      = module.vpc.vpc_id
  
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = [module.vpc.vpc_cidr_block, "2.44.137.133/32"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "musify-rds-sg"
  }
}

# RDS Instance
resource "aws_db_instance" "musify_db" {
  identifier     = "musify-database"
  engine         = "mysql"
  engine_version = "8.0"  
  instance_class = "db.t3.micro"
  
  allocated_storage     = 20
  storage_type         = "gp2"
  storage_encrypted    = true  
  
  db_name  = "musify"
  username = "admin"
  password = random_password.db_password.result  
  
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.db_subnet.name
  
  publicly_accessible = true  
  multi_az           = false   
  skip_final_snapshot = true
  
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  tags = {
    Name        = "musify-database"
    Environment = "dev"
  }
}

# Outputs
output "db_endpoint" {
  value       = aws_db_instance.musify_db.endpoint
  description = "Endpoint RDS"
}

output "db_password" {
  value       = random_password.db_password.result
  sensitive   = true
  description = "Password database"
}
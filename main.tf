provider "aws" {}


data "aws_availability_zones" "working" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_vpcs" "my_vpcs" {}


#************* Default vps ******************************************


resource "aws_default_vpc" "default" {
  tags = {
    Name = "Default VPC"
  }
}


resource "aws_default_subnet" "default_az0" {
  availability_zone = data.aws_availability_zones.working.names[0]

  tags = {
    Name = "Default subnet for eu-central-1a"
  }
}

resource "aws_default_subnet" "default_az1" {
  availability_zone = data.aws_availability_zones.working.names[1]

  tags = {
    Name = "Default subnet for eu-central-1b"
  }
}

resource "aws_default_subnet" "default_az2" {
  availability_zone = data.aws_availability_zones.working.names[2]

  tags = {
    Name = "Default subnet for eu-central-1c"
  }
}
#**********************************************************************


data "aws_security_group" "prod" {
  filter {
    name   = "tag:Name"
    values = ["Prod_SecurityGroup"]
  }
}


data "aws_vpc" "prod" {
  filter {
    name   = "tag:Name"
    values = ["prod-vpc-10"]
  }
}

data "aws_vpc" "test" {
  filter {
    name   = "tag:Name"
    values = ["test-vpc-20"]
  }
}



#***************** PROD public SUBNETS *******************************


data "aws_subnet" "prod_public-a" {
  filter {
    name   = "tag:Name"
    values = ["Sub-public-1 in ${data.aws_availability_zones.working.names[0]}"]
  }
}

data "aws_subnet" "prod_public-b" {
  filter {
    name   = "tag:Name"
    values = ["Sub-public-2 in ${data.aws_availability_zones.working.names[1]}"]
  }
}


data "aws_subnet" "prod_public-c" {
  filter {
    name   = "tag:Name"
    values = ["Sub-public-3 in ${data.aws_availability_zones.working.names[2]}"]
  }
}


#***************** PROD private SUBNETS *******************************


data "aws_subnet" "prod_private-a" {
  filter {
    name   = "tag:Name"
    values = ["Sub-private-1 in ${data.aws_availability_zones.working.names[0]}"]
  }
}

data "aws_subnet" "prod_private-b" {
  filter {
    name   = "tag:Name"
    values = ["Sub-private-2 in ${data.aws_availability_zones.working.names[1]}"]
  }
}


data "aws_subnet" "prod_private-c" {
  filter {
    name   = "tag:Name"
    values = ["Sub-private-3 in ${data.aws_availability_zones.working.names[2]}"]
  }
}

#***************** PROD DB SUBNETS ***********************************

data "aws_subnet" "prod_dbase-a" {
  filter {
    name   = "tag:Name"
    values = ["Sub-db-1 in ${data.aws_availability_zones.working.names[0]}"]
  }
}

data "aws_subnet" "prod_dbase-b" {
  filter {
    name   = "tag:Name"
    values = ["Sub-db-2 in ${data.aws_availability_zones.working.names[1]}"]
  }
}


data "aws_subnet" "prod_dbase-c" {
  filter {
    name   = "tag:Name"
    values = ["Sub-db-3 in ${data.aws_availability_zones.working.names[2]}"]
  }
}


data "aws_db_instance" "prod-sql-db" {
  db_instance_identifier = "prod-sql-db"
}


############################  START LOADB ##############################

resource "aws_launch_configuration" "my_def_slaves" {
  name_prefix            = "terraform-lc-example-"
  image_id               = data.aws_ami.latest_ubuntu.id
  instance_type          = "t2.micro"
  key_name               = aws_key_pair.test-3.id
  security_groups        = [data.aws_security_group.prod.id]
  user_data              = templatefile("attach_script.tpl", {
    public_ip            = "*",
    fs_name              = data.aws_efs_file_system.prod_efs.id,
    db_address           = data.aws_db_instance.prod-sql-db.address,

  })

  lifecycle {
    create_before_destroy = true
  }
}


#...........................................

resource "aws_autoscaling_policy" "web_policy_up" {
  name = "web_policy_up"
  scaling_adjustment = 1
  adjustment_type = "ChangeInCapacity"
  cooldown = 300
  autoscaling_group_name = aws_autoscaling_group.app-back.name
}


resource "aws_cloudwatch_metric_alarm" "web_cpu_alarm_up" {
  alarm_name = "web_cpu_alarm_up"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods = "2"
  metric_name = "CPUUtilization"
  namespace = "AWS/EC2"
  period = "120"
  statistic = "Average"
  threshold = "60"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.app-back.name
  }

  alarm_description = "This metric monitor EC2 instance CPU utilization"
  alarm_actions = [ aws_autoscaling_policy.web_policy_up.arn ]
}


resource "aws_autoscaling_policy" "web_policy_down" {
  name = "web_policy_down"
  scaling_adjustment = -1
  adjustment_type = "ChangeInCapacity"
  cooldown = 300
  autoscaling_group_name = aws_autoscaling_group.app-back.name
}

resource "aws_cloudwatch_metric_alarm" "web_cpu_alarm_down" {
  alarm_name = "web_cpu_alarm_down"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods = "2"
  metric_name = "CPUUtilization"
  namespace = "AWS/EC2"
  period = "120"
  statistic = "Average"
  threshold = "10"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.app-back.name
  }

  alarm_description = "This metric monitor EC2 instance CPU utilization"
  alarm_actions = [ aws_autoscaling_policy.web_policy_down.arn ]
}
#.........................



#.........................
#*********** FRONT CLASTER ****************************



resource "aws_ecs_cluster" "front" {
  name = "front-claster"
}

locals {
  ports_in = [
    0
  ]
  ports_out = [
    0
  ]
}


resource "aws_security_group" "front" {
  name        = "EC2ContainerService"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_default_vpc.default.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name  = "Front SG"
    Owner = "Andrei Shtanakov"
  }
}




resource "aws_iam_role" "ec2_container_access_role" {
  name               = "container-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
  managed_policy_arns = [aws_iam_policy.ecsInstancePolicy.arn]
}



resource "aws_iam_policy" "ecsInstancePolicy" {
  name = "ecsInstancePolicy"

  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeTags",
                "ecs:CreateCluster",
                "ecs:DeregisterContainerInstance",
                "ecs:DiscoverPollEndpoint",
                "ecs:Poll",
                "ecs:RegisterContainerInstance",
                "ecs:StartTelemetrySession",
                "ecs:UpdateContainerInstancesState",
                "ecs:Submit*",
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "*"
        }
    ]
})
}


resource "aws_iam_instance_profile" "ecs_profile" {
  name  = "ecs_profile"
  role = aws_iam_role.ec2_container_access_role.name
}


data "aws_ami" "front" {
  owners      = ["amazon"]
  most_recent = true
  filter {
    name   = "name"
    values = ["amzn2-ami-ecs-hvm-2.0.20210805-x86_64-ebs"]
  }
}



resource "aws_launch_configuration" "front" {
  name                   = "EC2Container-launch-configuration"
  image_id               = data.aws_ami.front.id
  iam_instance_profile   = aws_iam_instance_profile.ecs_profile.name
  instance_type          = "t2.micro"
  key_name               = aws_key_pair.test-3.id
  security_groups        = [aws_security_group.front.id]
  user_data = filebase64("user_data.sh")
  lifecycle {
    create_before_destroy = true
  }
#  depends_on = [aws_instance.my_def_ubuntu]
}



resource "aws_ecs_service" "front-worker" {
  name            = "front-worker"
  cluster         = aws_ecs_cluster.front.id
  task_definition = aws_ecs_task_definition.EC2Container-task-def-front.arn
  desired_count   = 3

  load_balancer {
    target_group_arn = aws_lb_target_group.front.arn
    container_name   = "front"
    container_port   = 5000
  }

}

resource "aws_lb" "front" {
  name               = "aws-lb-front"
  internal           = false
  load_balancer_type = "application"
  subnets            = [aws_default_subnet.default_az0.id,
                        aws_default_subnet.default_az1.id,
                        aws_default_subnet.default_az2.id]

  security_groups    = [aws_security_group.front.id]

  tags = {
    Name = "aws-lb-front"
  }
}


resource "aws_lb_target_group" "front" {
  name     = "front-tg"
  port     = 8000
  protocol = "HTTP"
  vpc_id   = aws_default_vpc.default.id
  health_check {
    path = "/"
    protocol = "HTTP"
    matcher = "200"
    interval = 15
    timeout = 3
    healthy_threshold = 2
    unhealthy_threshold = 2
 }
}


resource "aws_lb_listener" "front" {
  load_balancer_arn = aws_lb.front.arn
  port              = "80"
  protocol          = "HTTP"
#  ssl_policy        = "ELBSecurityPolicy-2016-08"
#  certificate_arn   = "arn:aws:iam::187416307283:server-certificate/test_cert_rab3wuqwgja25ct3n4jdj2tzu4"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.front.arn
  }
}



resource "aws_autoscaling_group" "front" {
  name                      = "EC2Container-Auto-Scaling-front"
  launch_configuration      = aws_launch_configuration.front.name
  min_size                  = 2
  desired_capacity          = 3
  max_size                  = 6
  health_check_grace_period = 0
  health_check_type         = "EC2"

  target_group_arns         = [aws_lb_target_group.front.id]
  force_delete              = true
  vpc_zone_identifier       =  [aws_default_subnet.default_az0.id,
                                aws_default_subnet.default_az1.id,
                                aws_default_subnet.default_az2.id
                               ]

  lifecycle {
    create_before_destroy = true
  }
}
   


resource "aws_ecs_task_definition" "EC2Container-task-def-front" {
  family = "front"

  container_definitions = jsonencode([
    {
      name                 = "front"
      image                = "982781670762.dkr.ecr.eu-central-1.amazonaws.com/front"
      memoryReservation    = 128
      essential = true
      portMappings         = [
                            {
                              containerPort = 5000
                              protocol      = "tcp"
                              hostPort      = 0
                            }
                             ],
     
      environment          =  [
                             {
                              name    = "URL_BACK_ENV"
                              value   = format("http://%s", aws_lb.app-back.dns_name)
                             }
                              ]
      }
   ])
#  placement_constraints {
#    type       = "memberOf"
#    expression = "attribute:ecs.availability-zone in [aws_default_subnet.default_az0.id, aws_default_subnet.default_az1.id, aws_default_subnet.default_az2.id]"

#  }
}




################ END FRONT CLASTER ##########







resource "aws_autoscaling_group" "app-back" {
  name                 = "aws-asg-app-back"
  launch_configuration = aws_launch_configuration.my_def_slaves.name
  min_size             = 2
  max_size             = 6
  health_check_grace_period = 300
  health_check_type         = "ELB"
  desired_capacity          = 3
  target_group_arns         = [aws_lb_target_group.app-back.id]
  force_delete              = true
  vpc_zone_identifier       = [data.aws_subnet.prod_public-a.id,
                               data.aws_subnet.prod_public-b.id,
                               data.aws_subnet.prod_public-c.id
                              ]

  lifecycle {
    create_before_destroy = true
  }
}




resource "aws_lb" "app-back" {
  name               = "aws-lb-app-back"
  internal           = false
  load_balancer_type = "application"
  subnets             = [data.aws_subnet.prod_public-a.id,
                         data.aws_subnet.prod_public-b.id,
                         data.aws_subnet.prod_public-c.id
                        ]

  security_groups    = [data.aws_security_group.prod.id]

  tags = {
    Name = "aws-lb-app-back"
  }
}


resource "aws_lb_target_group" "app-back" {
  name     = "app-back-tg"
  port     = 8000
  protocol = "HTTP"
  vpc_id   = data.aws_vpc.prod.id
  health_check {
    path = "/api/planets/"
    protocol = "HTTP"
    matcher = "200"
    interval = 15
    timeout = 3
    healthy_threshold = 2
    unhealthy_threshold = 2
 }
}



resource "aws_lb_listener" "app-back" {
  load_balancer_arn = aws_lb.app-back.arn
  port              = "80"
  protocol          = "HTTP"
#  ssl_policy        = "ELBSecurityPolicy-2016-08"
#  certificate_arn   = "arn:aws:iam::187416307283:server-certificate/test_cert_rab3wuqwgja25ct3n4jdj2tzu4"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app-back.arn
  }
}






#####################################################################################



resource "aws_default_subnet" "default_az-a" {
  availability_zone =  data.aws_availability_zones.working.names[0]

  tags = {
    Name = "Default subnet a"
  }
}

resource "aws_default_subnet" "default_az-b" {
  availability_zone =  data.aws_availability_zones.working.names[1]

  tags = {
    Name = "Default subnet b"
  }
}


resource "aws_default_subnet" "default_az-c" {
  availability_zone =  data.aws_availability_zones.working.names[2]

  tags = {
    Name = "Default subnet b"
  }
}




variable "file_system_id" {
  type    = string
  default = "fs-13f37648"
}


data "aws_efs_file_system" "prod_efs" {
  file_system_id = var.file_system_id
}


# **************** END DEF *******************************************

data "aws_ami" "latest_ubuntu" {
  owners      = ["982781670762"]
  most_recent = true
  filter {
    name   = "name"
    values = ["Back-End"]
  }
}


#*********************************************************************

resource "aws_key_pair" "test-3" {
  key_name   = "test-3"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCfk1mG0oYySWFG0/GQLjKAc4dC/ZlIvL5rHlZqQEfmDBt2Tr5iXwBbiQTv29QPglcDbRB/JlTt9GzjSnsGRh05YIUW1mGflgngNtgq+dDZOEBKZj++A1w5vj63Vltd5PIkgx3++1sKR3PsVZLV0gfj/v+n1g7REZQRVmukJfpdKRBOUk3O0nUxVxo4tXMp2irbUDdwZI4Z/QM1ugoTRKUQcB5V5KfnkaCbZ3GuHigV3aLdjEb1j2UI6feL1aQVwMJw/7nfyWlwuJ4x7r6+hKktb1SopmNRXPl7kKiKQb+AObUQEkfvXdOqdXnpcldJX/SyYxcYGtf5pShzJD7/FOm+TlhJ/Jum13ExL3ga79h4TzFelUsQNVCDFYJxqPLK26PvRPRHCZvVhiRi44FPsZiBY6EbU8M5qbymh44TKmHVQ8gg0Ii2rTeVH6l7HpLP6IE2pX83jUxKJ6egOjVhAtJDUMHq3vF8RW4FnlSDx9oLQ4I/sVOpHhA0RZa+qUwQnDc= user@epam2"
}


data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

data "aws_subnet" "runners" {
  id = length(var.subnet_id) > 0 ? var.subnet_id : var.subnet_id_runners
}

data "aws_availability_zone" "runners" {
  name = data.aws_subnet.runners.availability_zone
}

# Parameter value is managed by the user-data script of the gitlab runner instance
resource "aws_ssm_parameter" "runner_registration_token" {
  name  = local.secure_parameter_store_runner_token_key
  type  = "SecureString"
  value = "null"

  tags = local.tags

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "runner_sentry_dsn" {
  name  = local.secure_parameter_store_runner_sentry_dsn
  type  = "SecureString"
  value = "null"

  tags = local.tags

  lifecycle {
    ignore_changes = [value]
  }
}

locals {
  template_user_data = templatefile("${path.module}/template/user-data.tpl",
    {
      aws_cli_version          = "2.0.30"
      eip                      = var.enable_eip ? local.template_eip : ""
      logging                  = var.enable_cloudwatch_logging ? local.logging_user_data : ""
      gitlab_runner            = local.template_gitlab_runner
      extra_files_sync_command = module.config.extra_files_sync_command
      user_data_trace_log      = var.enable_runner_user_data_trace_log
      yum_update          = var.runner_yum_update ? local.file_yum_update : ""
  })

  file_yum_update = file("${path.module}/template/yum_update.tpl")

  template_eip = templatefile("${path.module}/template/eip.tpl", {
    eip = join(",", aws_eip.gitlab_runner.*.public_ip)
  })

  template_gitlab_runner = templatefile("${path.module}/template/gitlab-runner.tpl",
    {
      gitlab_runner_version                   = var.gitlab_runner_version
      docker_machine_version                  = var.docker_machine_version
      docker_machine_download_url             = var.docker_machine_download_url
      runners_config_s3_uri                   = module.config.config_uri
      runners_executor                        = var.runners_executor
      pre_install                             = var.userdata_pre_install
      post_install                            = var.userdata_post_install
      runners_gitlab_url                      = var.runners_gitlab_url
      runners_token                           = var.runners_token
      secure_parameter_store_runner_token_key = local.secure_parameter_store_runner_token_key
      secure_parameter_store_runner_sentry_dsn     = local.secure_parameter_store_runner_sentry_dsn
runners_install_amazon_ecr_credential_helper = var.runners_install_amazon_ecr_credential_helper
      secure_parameter_store_region           = var.aws_region
      gitlab_runner_registration_token        = var.gitlab_runner_registration_config["registration_token"]
      giltab_runner_description               = var.gitlab_runner_registration_config["description"]
      gitlab_runner_tag_list                  = var.gitlab_runner_registration_config["tag_list"]
      gitlab_runner_locked_to_project         = var.gitlab_runner_registration_config["locked_to_project"]
      gitlab_runner_run_untagged              = var.gitlab_runner_registration_config["run_untagged"]
      gitlab_runner_maximum_timeout           = var.gitlab_runner_registration_config["maximum_timeout"]
      gitlab_runner_access_level              = lookup(var.gitlab_runner_registration_config, "access_level", "not_protected")
  })

  runners_defaults = {
    machine_driver = var.docker_machine_driver
    machine_name   = var.docker_machine_name
    aws_region     = var.aws_region
    gitlab_url     = var.runners_gitlab_url
    gitlab_clone_url                  = var.runners_clone_url
    name           = var.runners_name
    tags = replace(replace(local.runner_tags_string, ",,", ","), "/,$/", "")
    vpc_id                    = var.vpc_id
    subnet_id                 = length(var.subnet_id) > 0 ? var.subnet_id : var.subnet_id_runners
    aws_zone                  = data.aws_availability_zone.runners.name_suffix
    instance_type             = var.docker_machine_instance_type
    spot_price_bid            = var.docker_machine_spot_price_bid == "on-demand-price" ? "" : var.docker_machine_spot_price_bid
    ami                       = data.aws_ami.docker_machine.id
    security_group_name       = aws_security_group.docker_machine.name
    monitoring                = var.runners_monitoring
    ebs_optimized             = var.runners_ebs_optimized
    instance_profile          = aws_iam_instance_profile.docker_machine.name
    additional_volumes        = local.runners_additional_volumes
    token                     = var.runners_token
    executor                  = var.runners_executor
    limit                     = var.runners_limit
    image                     = var.runners_image
    privileged                = var.runners_privileged
    docker_runtime            = var.runners_docker_runtime
    helper_image              = var.runners_helper_image
    machine_autoscaling       = local.runners_machine_autoscaling
    shm_size                  = var.runners_shm_size
    pull_policy               = var.runners_pull_policy
    idle_count                = var.runners_idle_count
    idle_time                 = var.runners_idle_time
    max_builds                = local.runners_max_builds_string
    off_peak_timezone         = var.runners_off_peak_timezone
    off_peak_idle_count       = var.runners_off_peak_idle_count
    off_peak_idle_time        = var.runners_off_peak_idle_time
    off_peak_periods_string   = local.runners_off_peak_periods_string
    root_size                 = var.runners_root_size
    iam_instance_profile_name = var.runners_iam_instance_profile_name
    use_private_address_only  = var.runners_use_private_address
    use_private_address       = ! var.runners_use_private_address
    request_spot_instance     = var.runners_request_spot_instance
    environment_vars          = jsonencode(var.runners_environment_vars)
    pre_build_script          = var.runners_pre_build_script
    post_build_script         = var.runners_post_build_script
    pre_clone_script          = var.runners_pre_clone_script
    request_concurrency       = var.runners_request_concurrency
    output_limit              = var.runners_output_limit
    volumes_tmpfs             = join(",", [for v in var.runners_volumes_tmpfs : format("\"%s\" = \"%s\"", v.volume, v.options)])
    services_volumes_tmpfs    = join(",", [for v in var.runners_services_volumes_tmpfs : format("\"%s\" = \"%s\"", v.volume, v.options)])
    docker_machine_options    = length(local.docker_machine_options_string) == 1 ? "" : local.docker_machine_options_string
    bucket_name               = local.bucket_name
    shared_cache              = var.cache_shared
      disable_cache             = var.runners_disable_cache
      pull_policies             = local.runners_pull_policies
      auth_type                         = var.auth_type_cache_sr
            extra_hosts               = var.runners_extra_hosts
docker_machine_name               = format("%s-%s", local.runner_tags_merged["Name"], "%s") # %s is always needed
  }

  template_runner_config_header = templatefile("${path.module}/template/runner-config-header.tpl", {
    runners_concurrent = var.runners_concurrent
    runners_check_interval            = var.runners_check_interval
sentry_dsn                                   = var.sentry_dsn
      prometheus_listen_address         = var.prometheus_listen_address
  })

  template_runner_config_runners = join("\n", [
    for runner in var.runners :
    templatefile("${path.module}/template/runner-config-runners.tpl", merge(local.runners_defaults, runner))
  ])

  runner_config = <<-EOF
    ${local.template_runner_config_header}
    ${local.template_runner_config_runners}
  EOF
}

data "aws_ami" "docker_machine" {
  most_recent = "true"

  dynamic "filter" {
    for_each = var.runner_ami_filter
    content {
      name   = filter.key
      values = filter.value
    }
  }

  owners = var.runner_ami_owners
}

resource "aws_autoscaling_group" "gitlab_runner_instance" {
  name                      = var.enable_asg_recreation ? "${aws_launch_template.gitlab_runner_instance.name}-asg" : "${var.environment}-as-group"
  vpc_zone_identifier       = length(var.subnet_id) > 0 ? [var.subnet_id] : var.subnet_ids_gitlab_runner
  min_size                  = "1"
  max_size                  = "1"
  desired_capacity          = "1"
  health_check_grace_period = 0
  max_instance_lifetime     = var.asg_max_instance_lifetime
  enabled_metrics           = var.metrics_autoscaling

  dynamic "tag" {
    for_each = local.agent_tags

    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  launch_template {
    id      = aws_launch_template.gitlab_runner_instance.id
    version = aws_launch_template.gitlab_runner_instance.latest_version
  }

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 0
    }
    triggers = ["tag"]
  }

  timeouts {
    delete = var.asg_delete_timeout
  }
}

resource "aws_autoscaling_schedule" "scale_in" {
  count                  = var.enable_schedule ? 1 : 0
  autoscaling_group_name = aws_autoscaling_group.gitlab_runner_instance.name
  scheduled_action_name  = "scale_in-${aws_autoscaling_group.gitlab_runner_instance.name}"
  recurrence             = var.schedule_config["scale_in_recurrence"]
  min_size               = var.schedule_config["scale_in_count"]
  desired_capacity       = var.schedule_config["scale_in_count"]
  max_size               = var.schedule_config["scale_in_count"]
}

resource "aws_autoscaling_schedule" "scale_out" {
  count                  = var.enable_schedule ? 1 : 0
  autoscaling_group_name = aws_autoscaling_group.gitlab_runner_instance.name
  scheduled_action_name  = "scale_out-${aws_autoscaling_group.gitlab_runner_instance.name}"
  recurrence             = var.schedule_config["scale_out_recurrence"]
  min_size               = var.schedule_config["scale_out_count"]
  desired_capacity       = var.schedule_config["scale_out_count"]
  max_size               = var.schedule_config["scale_out_count"]
}

data "aws_ami" "runner" {
  most_recent = "true"

  dynamic "filter" {
    for_each = var.ami_filter
    content {
      name   = filter.key
      values = filter.value
    }
  }

  owners = var.ami_owners
}

resource "aws_launch_template" "gitlab_runner_instance" {
  name_prefix            = local.name_runner_agent_instance
  image_id               = data.aws_ami.runner.id
  user_data              = base64encode(local.template_user_data)
  instance_type          = var.instance_type
  update_default_version = true
  ebs_optimized          = var.runner_instance_ebs_optimized
  monitoring {
    enabled = var.runner_instance_enable_monitoring
  }
  dynamic "instance_market_options" {
    for_each = var.runner_instance_spot_price == null || var.runner_instance_spot_price == "" ? [] : ["spot"]
    content {
      market_type = instance_market_options.value
      dynamic "spot_options" {
        for_each = var.runner_instance_spot_price == "on-demand-price" ? [] : [0]
        content {
          max_price = var.runner_instance_spot_price
        }
      }
    }
  }
  iam_instance_profile {
    name = aws_iam_instance_profile.instance.name
  }
  dynamic "block_device_mappings" {
    for_each = [var.runner_root_block_device]
    content {
      device_name = lookup(block_device_mappings.value, "device_name", "/dev/xvda")
      ebs {
        delete_on_termination = lookup(block_device_mappings.value, "delete_on_termination", true)
        volume_type           = lookup(block_device_mappings.value, "volume_type", "gp3")
        volume_size           = lookup(block_device_mappings.value, "volume_size", 8)
        encrypted             = lookup(block_device_mappings.value, "encrypted", true)
        iops                  = lookup(block_device_mappings.value, "iops", null)
        throughput            = lookup(block_device_mappings.value, "throughput", null)
        kms_key_id            = lookup(block_device_mappings.value, "kms_key_id", null)
      }
    }
  }
  network_interfaces {
    security_groups             = concat([aws_security_group.runner.id], var.extra_security_group_ids_runner_agent)
    associate_public_ip_address = false == (var.runner_agent_uses_private_address == false ? var.runner_agent_uses_private_address : var.runners_use_private_address)
  }
  tag_specifications {
    resource_type = "instance"
    tags          = local.tags
  }
  tag_specifications {
    resource_type = "volume"
    tags          = local.tags
  }
  dynamic "tag_specifications" {
    for_each = var.runner_instance_spot_price == null || var.runner_instance_spot_price == "" ? [] : ["spot"]
    content {
      resource_type = "spot-instances-request"
      tags          = local.tags
    }
  }

  tags = local.tags

  metadata_options {
    http_endpoint               = var.runner_instance_metadata_options.http_endpoint
    http_tokens                 = var.runner_instance_metadata_options.http_tokens
    http_put_response_hop_limit = var.runner_instance_metadata_options.http_put_response_hop_limit
    instance_metadata_tags      = var.runner_instance_metadata_options.instance_metadata_tags
  }

  lifecycle {
    create_before_destroy = true
  }
}

################################################################################
### Create config bucket & save config.toml there
################################################################################

module "config" {
  source = "./modules/config"

  name                          = var.environment
  runner_autoscaling_group_name = aws_autoscaling_group.gitlab_runner_instance.name
  gitlab_token_ssm_key          = local.secure_parameter_store_runner_token_key
  config_content                = local.runner_config
  tags                          = local.tags

  post_reload_script = var.post_reload_config
  config_bucket      = var.config_bucket
  config_key         = var.config_key
  cloudtrail_bucket  = var.cloudtrail_bucket
  cloudtrail_prefix  = var.cloudtrail_prefix
  extra_files_prefix = var.extra_files_prefix
  extra_files        = var.extra_files
}

resource "aws_iam_role_policy_attachment" "config_bucket" {
  role       = aws_iam_role.instance.name
  policy_arn = module.config.config_iam_policy_arn
}

################################################################################
### Create cache bucket
################################################################################
locals {
  bucket_name   = var.cache_bucket["create"] ? module.cache[0].bucket : lookup(var.cache_bucket, "bucket", "")
  bucket_policy = var.cache_bucket["create"] ? module.cache[0].policy_arn : lookup(var.cache_bucket, "policy", "")
}

module "cache" {
  count  = var.cache_bucket["create"] ? 1 : 0
  source = "./modules/cache"

  environment = var.environment
  tags        = local.tags

  cache_bucket_prefix                  = var.cache_bucket_prefix
  cache_bucket_name_include_account_id = var.cache_bucket_name_include_account_id
  cache_bucket_set_random_suffix       = var.cache_bucket_set_random_suffix
  cache_bucket_versioning              = var.cache_bucket_versioning
  cache_expiration_days                = var.cache_expiration_days

  name_iam_objects = local.name_iam_objects
}

################################################################################
### Trust policy
################################################################################
resource "aws_iam_instance_profile" "instance" {
  name = "${local.name_iam_objects}-instance"
  role = aws_iam_role.instance.name
  tags = local.tags
}

resource "aws_iam_role" "instance" {
  name                 = "${local.name_iam_objects}-instance"
  assume_role_policy   = length(var.instance_role_json) > 0 ? var.instance_role_json : templatefile("${path.module}/policies/instance-role-trust-policy.json", {})
  permissions_boundary = var.permissions_boundary == "" ? null : "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:policy/${var.permissions_boundary}"
  tags                 = merge(local.tags, var.role_tags)
}

################################################################################
### Policies for runner agent instance to create docker machines via spot req.
###
### iam:PassRole To pass the role from the agent to the docker machine runners
################################################################################
resource "aws_iam_policy" "instance_docker_machine_policy" {
  name        = "${local.name_iam_objects}-docker-machine"
  path        = "/"
  description = "Policy for docker machine."
  policy = templatefile("${path.module}/policies/instance-docker-machine-policy.json",
    {
      docker_machine_role_arn = aws_iam_role.docker_machine.arn
  })
  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "instance_docker_machine_policy" {
  role       = aws_iam_role.instance.name
  policy_arn = aws_iam_policy.instance_docker_machine_policy.arn
}

################################################################################
### Policies for runner agent instance to allow connection via Session Manager
################################################################################
resource "aws_iam_policy" "instance_session_manager_policy" {
  count = var.enable_runner_ssm_access ? 1 : 0

  name        = "${local.name_iam_objects}-session-manager"
  path        = "/"
  description = "Policy session manager."
  policy      = templatefile("${path.module}/policies/instance-session-manager-policy.json", {})
  tags        = local.tags
}

resource "aws_iam_role_policy_attachment" "instance_session_manager_policy" {
  count = var.enable_runner_ssm_access ? 1 : 0

  role       = aws_iam_role.instance.name
  policy_arn = aws_iam_policy.instance_session_manager_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "instance_session_manager_aws_managed" {
  count = var.enable_runner_ssm_access ? 1 : 0

  role       = aws_iam_role.instance.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

################################################################################
### Add user defined policies
################################################################################
resource "aws_iam_role_policy_attachment" "user_defined_policies" {
  count      = length(var.runner_iam_policy_arns)
  role       = aws_iam_role.instance.name
  policy_arn = var.runner_iam_policy_arns[count.index]
}

################################################################################
### Policy for the docker machine instance to access cache
################################################################################
resource "aws_iam_role_policy_attachment" "docker_machine_cache_instance" {
  count = var.cache_bucket["create"] || length(lookup(var.cache_bucket, "policy", "")) > 0 ? 1 : 0

  role       = aws_iam_role.instance.name
  policy_arn = local.cache_bucket_policy
}

################################################################################
### docker machine instance policy
################################################################################
resource "aws_iam_role" "docker_machine" {
  name                 = "${local.name_iam_objects}-docker-machine"
  assume_role_policy   = length(var.docker_machine_role_json) > 0 ? var.docker_machine_role_json : templatefile("${path.module}/policies/instance-role-trust-policy.json", {})
  permissions_boundary = var.permissions_boundary == "" ? null : "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:policy/${var.permissions_boundary}"
  tags                 = local.tags
}

resource "aws_iam_instance_profile" "docker_machine" {
  name = "${local.name_iam_objects}-docker-machine"
  role = aws_iam_role.docker_machine.name
  tags = local.tags
}

################################################################################
### Add user defined policies
################################################################################
resource "aws_iam_role_policy_attachment" "docker_machine_user_defined_policies" {
  count      = length(var.docker_machine_iam_policy_arns)
  role       = aws_iam_role.docker_machine.name
  policy_arn = var.docker_machine_iam_policy_arns[count.index]
}

################################################################################
resource "aws_iam_role_policy_attachment" "docker_machine_session_manager_aws_managed" {
  count = var.enable_docker_machine_ssm_access ? 1 : 0

  role       = aws_iam_role.docker_machine.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

################################################################################
### Service linked policy, optional
################################################################################
resource "aws_iam_policy" "service_linked_role" {
  count = var.allow_iam_service_linked_role_creation ? 1 : 0

  name        = "${local.name_iam_objects}-service_linked_role"
  path        = "/"
  description = "Policy for creation of service linked roles."
  policy      = templatefile("${path.module}/policies/service-linked-role-create-policy.json", { partition = data.aws_partition.current.partition })
  tags        = local.tags
}

resource "aws_iam_role_policy_attachment" "service_linked_role" {
  count = var.allow_iam_service_linked_role_creation ? 1 : 0

  role       = aws_iam_role.instance.name
  policy_arn = aws_iam_policy.service_linked_role[0].arn
}

resource "aws_eip" "gitlab_runner" {
  count = var.enable_eip ? 1 : 0
}

################################################################################
### AWS Systems Manager access to store runner token once registered
################################################################################
resource "aws_iam_policy" "ssm" {
  count = var.enable_manage_gitlab_token ? 1 : 0

  name        = "${local.name_iam_objects}-ssm"
  path        = "/"
  description = "Policy for runner token param access via SSM"
  policy      = templatefile("${path.module}/policies/instance-secure-parameter-role-policy.json", { partition = data.aws_partition.current.partition })
  tags        = local.tags
}

resource "aws_iam_role_policy_attachment" "ssm" {
  count = var.enable_manage_gitlab_token ? 1 : 0

  role       = aws_iam_role.instance.name
  policy_arn = aws_iam_policy.ssm[0].arn
}

################################################################################
### AWS assign EIP
################################################################################
resource "aws_iam_policy" "eip" {
  count = var.enable_eip ? 1 : 0

  name        = "${local.name_iam_objects}-eip"
  path        = "/"
  description = "Policy for runner to assign EIP"
  policy      = templatefile("${path.module}/policies/instance-eip.json", {})
  tags        = local.tags
}

resource "aws_iam_role_policy_attachment" "eip" {
  count = var.enable_eip ? 1 : 0

  role       = aws_iam_role.instance.name
  policy_arn = aws_iam_policy.eip[0].arn
}

################################################################################
### Lambda function for ASG instance termination lifecycle hook
################################################################################
module "terminate_instances_lifecycle_function" {
  source = "./modules/terminate-instances"

  count = var.asg_terminate_lifecycle_hook_create ? 1 : 0

  name                                 = var.asg_terminate_lifecycle_hook_name == null ? "terminate-instances" : var.asg_terminate_lifecycle_hook_name
  environment                          = var.environment
  asg_arn                              = aws_autoscaling_group.gitlab_runner_instance.arn
  asg_name                             = aws_autoscaling_group.gitlab_runner_instance.name
  cloudwatch_logging_retention_in_days = var.cloudwatch_logging_retention_in_days
  lambda_memory_size                   = var.asg_terminate_lifecycle_lambda_memory_size
  lambda_runtime                       = var.asg_terminate_lifecycle_lambda_runtime
  lifecycle_heartbeat_timeout          = var.asg_terminate_lifecycle_hook_heartbeat_timeout
  name_iam_objects                     = local.name_iam_objects
  role_permissions_boundary            = var.permissions_boundary == "" ? null : "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:policy/${var.permissions_boundary}"
  lambda_timeout                       = var.asg_terminate_lifecycle_lambda_timeout
  tags                                 = local.tags
}

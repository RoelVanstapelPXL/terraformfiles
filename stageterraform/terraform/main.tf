provider "aws" {
  region = "us-west-2"
}

resource "aws_iam_role" "eksClusterRole" {
  name = "eksClusterRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  ]
}

resource "aws_iam_role" "eksNodeGroupRole" {
  name = "eksNodeGroupRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  ]
}

resource "aws_eip" "eip" {
  vpc = true
}

resource "aws_vpc" "vpc" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "publicsubnet1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-west-2a"

  tags = {
    "kubernetes.io/cluster/prodcluster" = "shared"
    "kubernetes.io/cluster/dtacluster" = "shared"
    "kubernetes.io/role/elb"           = "1"
  }
}

resource "aws_subnet" "publicsubnet2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-west-2b"

  tags = {
    "kubernetes.io/cluster/prodcluster" = "shared"
    "kubernetes.io/cluster/dtacluster" = "shared"
    "kubernetes.io/role/elb"           = "1"
  }
}

resource "aws_subnet" "privatesubnet1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "us-west-2a"

  tags = {
    "kubernetes.io/cluster/prodcluster" = "shared"
    "kubernetes.io/cluster/dtacluster" = "shared"
    "kubernetes.io/role/internal-elb"  = "1"
  }
}

resource "aws_subnet" "privatesubnet2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = "us-west-2b"

  tags = {
    "kubernetes.io/cluster/prodcluster" = "shared"
    "kubernetes.io/cluster/dtacluster" = "shared"
    "kubernetes.io/role/internal-elb"  = "1"
  }
}

resource "aws_internet_gateway" "internet_gateway" {
  vpc_id = aws_vpc.vpc.id
}

resource "aws_nat_gateway" "nat_gateway" {
  allocation_id = aws_eip.eip.id
  subnet_id     = aws_subnet.publicsubnet1.id
}

resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.vpc.id
}

resource "aws_route_table" "private_route_table" {
  vpc_id = aws_vpc.vpc.id
}

resource "aws_route" "public_route" {
  route_table_id         = aws_route_table.public_route_table.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.internet_gateway.id
}

resource "aws_route" "private_route" {
  route_table_id         = aws_route_table.private_route_table.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat_gateway.id
}

resource "aws_route_table_association" "publicassociation1" {
  subnet_id      = aws_subnet.publicsubnet1.id
  route_table_id = aws_route_table.public_route_table.id
}

resource "aws_route_table_association" "publicassociation2" {
  subnet_id      = aws_subnet.publicsubnet2.id
  route_table_id = aws_route_table.public_route_table.id
}

resource "aws_route_table_association" "privateassociation1" {
  subnet_id      = aws_subnet.privatesubnet1.id
  route_table_id = aws_route_table.private_route_table.id
}

resource "aws_route_table_association" "privateassociation2" {
  subnet_id      = aws_subnet.privatesubnet2.id
  route_table_id = aws_route_table.private_route_table.id
}

resource "aws_eks_cluster" "dtacluster" {
  name = "dtacluster"
  role_arn = aws_iam_role.eksClusterRole.arn

  vpc_config {
    subnet_ids = [
      aws_subnet.privatesubnet1.id,
      aws_subnet.privatesubnet2.id,
    ]
  }
}

resource "aws_eks_node_group" "dtanodegroup" {
  cluster_name = aws_eks_cluster.dtacluster.name
  node_group_name = "dtanodegroup"
  instance_types = ["t2.medium"]

  scaling_config {
    min_size = 3
    max_size = 3
    desired_size = 3
  }

  subnet_ids = [
    aws_subnet.privatesubnet1.id,
    aws_subnet.privatesubnet2.id,
  ]

  node_role_arn = aws_iam_role.eksNodeGroupRole.arn
}

resource "aws_eks_cluster" "prodcluster" {
  name = "prodcluster"
  role_arn = aws_iam_role.eksClusterRole.arn

  vpc_config {
    subnet_ids = [
      aws_subnet.privatesubnet1.id,
      aws_subnet.privatesubnet2.id,
    ]
  }
}

resource "aws_eks_node_group" "prodnodegroup" {
  cluster_name = aws_eks_cluster.prodcluster.name
  node_group_name = "prodnodegroup"
  instance_types = ["t2.medium"]

  scaling_config {
    min_size = 2
    max_size = 2
    desired_size = 2
  }

  subnet_ids = [
    aws_subnet.privatesubnet1.id,
    aws_subnet.privatesubnet2.id,
  ]

  node_role_arn = aws_iam_role.eksNodeGroupRole.arn
}

resource "aws_acm_certificate" "acmcertificate" {
  domain_name = "*.roelvanstapelreverseproxy.be"
  validation_method = "DNS"
}

data "tls_certificate" "tlscertificate" {
  url = aws_eks_cluster.prodcluster.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "prodidentityprovider" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.tlscertificate.certificates.0.sha1_fingerprint]
  url             = aws_eks_cluster.prodcluster.identity.0.oidc.0.issuer
}

resource "aws_iam_openid_connect_provider" "dtaidentityprovider" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.tlscertificate.certificates.0.sha1_fingerprint]
  url             = aws_eks_cluster.dtacluster.identity.0.oidc.0.issuer
}

locals {
  prodoidc_provider_arn = aws_iam_openid_connect_provider.prodidentityprovider.arn
  prodprovider_url = replace(split(":", local.prodoidc_provider_arn)[5], "oidc-provider/", "")
  dtaoidc_provider_arn = aws_iam_openid_connect_provider.dtaidentityprovider.arn
  dtaprovider_url = replace(split(":", local.dtaoidc_provider_arn)[5], "oidc-provider/", "")
}

resource "aws_iam_role" "ProdClusterIAMRole" {
  name = "ProdClusterIAMRole"
  path = "/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = {
        Federated = resource.aws_iam_openid_connect_provider.prodidentityprovider.arn
      }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${local.prodprovider_url}:sub" = "system:serviceaccount:kube-system:alb-ingress-controller"
          "${local.prodprovider_url}:aud" = "sts.amazonaws.com"
        }
      }
    }]
  })

  managed_policy_arns = [
    aws_iam_policy.ALBIngressControllerIAMPolicy.arn,
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
  ]
}

resource "aws_iam_role" "DTAClusterIAMRole" {
  name = "DTAClusterIAMRole"
  path = "/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = {
        Federated = resource.aws_iam_openid_connect_provider.dtaidentityprovider.arn
      }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${local.dtaprovider_url}:sub" = "system:serviceaccount:kube-system:alb-ingress-controller"
          "${local.dtaprovider_url}:aud" = "sts.amazonaws.com"
        }
      }
    }]
  })

  managed_policy_arns = [
    aws_iam_policy.ALBIngressControllerIAMPolicy.arn,
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
  ]
}

resource "aws_iam_policy" "ALBIngressControllerIAMPolicy" {
  name = "ALBIngressControllerIAMPolicy"

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "iam:CreateServiceLinkedRole"
        Resource = "*"
        Condition = {
          StringEquals = {
            "iam:AWSServiceName" = "elasticloadbalancing.amazonaws.com"
          }
        }
      },
      {
        Effect   = "Allow"
        Action   = [
          "ec2:DescribeAccountAttributes",
          "ec2:DescribeAddresses",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeVpcs",
          "ec2:DescribeVpcPeeringConnections",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeInstances",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeTags",
          "ec2:GetCoipPoolUsage",
          "ec2:DescribeCoipPools",
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeLoadBalancerAttributes",
          "elasticloadbalancing:DescribeListeners",
          "elasticloadbalancing:DescribeListenerCertificates",
          "elasticloadbalancing:DescribeSSLPolicies",
          "elasticloadbalancing:DescribeRules",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetGroupAttributes",
          "elasticloadbalancing:DescribeTargetHealth",
          "elasticloadbalancing:DescribeTags",
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = [
          "cognito-idp:DescribeUserPoolClient",
          "acm:ListCertificates",
          "acm:DescribeCertificate",
          "iam:ListServerCertificates",
          "iam:GetServerCertificate",
          "waf-regional:GetWebACL",
          "waf-regional:GetWebACLForResource",
          "waf-regional:AssociateWebACL",
          "waf-regional:DisassociateWebACL",
          "wafv2:GetWebACL",
          "wafv2:GetWebACLForResource",
          "wafv2:AssociateWebACL",
          "wafv2:DisassociateWebACL",
          "shield:GetSubscriptionState",
          "shield:DescribeProtection",
          "shield:CreateProtection",
          "shield:DeleteProtection"
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = [
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress"
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = [
          "ec2:CreateSecurityGroup"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = ["ec2:CreateTags"]
        Resource = "arn:aws:ec2:*:*:security-group/*"
        Condition = {
          StringEquals = {
            "ec2:CreateAction" = "CreateSecurityGroup"
          }
          Null = {
            "aws:RequestTag/elbv2.k8s.aws/cluster" = "false"
          }
        }
      },
      {
        Effect = "Allow"
        Action = ["ec2:CreateTags", "ec2:DeleteTags"]
        Resource = "arn:aws:ec2:*:*:security-group/*"
        Condition = {
          Null = {
            "aws:RequestTag/elbv2.k8s.aws/cluster" = "true"
            "aws:ResourceTag/elbv2.k8s.aws/cluster" = "false"
          }
        }
      },
      {
        Effect = "Allow"
        Action = ["ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress", "ec2:DeleteSecurityGroup"]
        Resource = "*"
        Condition = {
          Null = {
            "aws:ResourceTag/elbv2.k8s.aws/cluster" = "false"
          }
        }
      },
      {
        Effect = "Allow"
        Action = ["elasticloadbalancing:CreateLoadBalancer", "elasticloadbalancing:CreateTargetGroup"]
        Resource = "*"
        Condition = {
          Null = {
            "aws:RequestTag/elbv2.k8s.aws/cluster" = "false"
          }
        }
      },
      {
        Effect = "Allow"
        Action = ["elasticloadbalancing:CreateListener", "elasticloadbalancing:DeleteListener", "elasticloadbalancing:CreateRule", "elasticloadbalancing:DeleteRule"]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = ["elasticloadbalancing:AddTags", "elasticloadbalancing:RemoveTags"]
        Resource = [
          "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
          "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
          "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
        ]
        Condition = {
          Null = {
            "aws:RequestTag/elbv2.k8s.aws/cluster" = "true"
            "aws:ResourceTag/elbv2.k8s.aws/cluster" = "false"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:ModifyLoadBalancerAttributes",
          "elasticloadbalancing:SetIpAddressType",
          "elasticloadbalancing:SetSecurityGroups",
          "elasticloadbalancing:SetSubnets",
          "elasticloadbalancing:DeleteLoadBalancer",
          "elasticloadbalancing:ModifyTargetGroup",
          "elasticloadbalancing:ModifyTargetGroupAttributes",
          "elasticloadbalancing:DeleteTargetGroup"
        ]
        Resource = "*"
        Condition = {
          Null = {
            "aws:ResourceTag/elbv2.k8s.aws/cluster" = "false"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:RegisterTargets",
          "elasticloadbalancing:DeregisterTargets"
        ]
        Resource = "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*"
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:SetWebAcl",
          "elasticloadbalancing:ModifyListener",
          "elasticloadbalancing:AddListenerCertificates",
          "elasticloadbalancing:RemoveListenerCertificates",
          "elasticloadbalancing:ModifyRule"
        ]
        Resource = "*"
      }
    ]
  })
}


resource "null_resource" "kubectlcommands" {
  provisioner "local-exec" {
    command = "cd ../../../roelstage/stagekubernetes && sh ./prodstartkubernetes.sh && sh ./devstartkubernetes.sh"
  }
  depends_on = [resource.aws_eks_cluster.prodcluster,resource.aws_eks_cluster.dtacluster,resource.aws_iam_role.ProdClusterIAMRole,resource.aws_iam_role.DTAClusterIAMRole,resource.aws_eks_node_group.prodnodegroup,resource.aws_eks_node_group.dtanodegroup]
}

data "local_file" "albnamedta" {
  filename = "../../../roelstage/stagekubernetes/albnamedta"
  depends_on = [resource.null_resource.kubectlcommands]
}

data "local_file" "albnameprod" {
  filename = "../../../roelstage/stagekubernetes/albnameprod"
  depends_on = [resource.null_resource.kubectlcommands]
}

output "albdtaoutput" {
  value = data.local_file.albnamedta.content
}

output "albprodoutput" {
  value = data.local_file.albnameprod.content
}

resource "cloudflare_record" "devtraefik" {
  zone_id = "d32c3d1c6979d544be9df360b52a45ee"
  name = "devtraefik"
  type = "CNAME"
  value = data.local_file.albnamedta.content
  ttl = 300
  depends_on = [null_resource.kubectlcommands]
}

resource "cloudflare_record" "devcaddy" {
  zone_id = "d32c3d1c6979d544be9df360b52a45ee"
  name = "devcaddy"
  type = "CNAME"
  value = data.local_file.albnamedta.content
  ttl = 300
  depends_on = [null_resource.kubectlcommands]
}

resource "cloudflare_record" "testtraefik" {
  zone_id = "d32c3d1c6979d544be9df360b52a45ee"
  name = "testtraefik"
  type = "CNAME"
  value = data.local_file.albnamedta.content
  ttl = 300
  depends_on = [null_resource.kubectlcommands]
}

resource "cloudflare_record" "testcaddy" {
  zone_id = "d32c3d1c6979d544be9df360b52a45ee"
  name = "testcaddy"
  type = "CNAME"
  value = data.local_file.albnamedta.content
  ttl = 300
  depends_on = [null_resource.kubectlcommands]
}

resource "cloudflare_record" "acctraefik" {
  zone_id = "d32c3d1c6979d544be9df360b52a45ee"
  name = "acctraefik"
  type = "CNAME"
  value = data.local_file.albnamedta.content
  ttl = 300
  depends_on = [null_resource.kubectlcommands]
}

resource "cloudflare_record" "acccaddy" {
  zone_id = "d32c3d1c6979d544be9df360b52a45ee"
  name = "acccaddy"
  type = "CNAME"
  value = data.local_file.albnamedta.content
  ttl = 300
  depends_on = [null_resource.kubectlcommands]
}

resource "cloudflare_record" "prodtraefik" {
  zone_id = "d32c3d1c6979d544be9df360b52a45ee"
  name = "prodtraefik"
  type = "CNAME"
  value = data.local_file.albnameprod.content
  ttl = 300
  depends_on = [null_resource.kubectlcommands]
}

resource "cloudflare_record" "prodcaddy" {
  zone_id = "d32c3d1c6979d544be9df360b52a45ee"
  name = "prodcaddy"
  type = "CNAME"
  value = data.local_file.albnameprod.content
  ttl = 300
  depends_on = [null_resource.kubectlcommands]
}

terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 3.0"
    }
  }
}

provider "cloudflare" {
  email = "roelvanstapel@gmail.com"
  api_key = "d50475ec707ffdef2bad11fdd783ffc42a6ba"
}

# Primary Web Application Firewall Security Group
resource "aws_security_group" "web_tier_sg" {
  name        = "web-tier-security-group"
  description = "Allows inbound internet access"

  # Dangerous unrestricted ingress on management port
  ingress {
    description = "SSH access for admin troubleshooting"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS web traffic"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

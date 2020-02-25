# Cookie-Manager
Signed cookie manager for communication between multiple trusted services.

Signs, verifies, and manages multiple cookies from trusted environments. Designed for use by services all within the same secure network (AWS VPC etc).

Wraps https://github.com/pallets/itsdangerous for the signing and verification (but this could change in the future). 

Specifically, this handles:
- Managing multiple different cookies - one for every environment
- Error correction around sign/verify commands

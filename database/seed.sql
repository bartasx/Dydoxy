-- Seed data for development and testing

-- Insert test organization
INSERT INTO organizations (id, name, plan_type, settings) VALUES 
('550e8400-e29b-41d4-a716-446655440000', 'Test Organization', 'enterprise', '{"max_users": 100, "max_bandwidth": "1TB"}');

-- Insert test users
INSERT INTO users (id, organization_id, email, password_hash, role, limits) VALUES 
('550e8400-e29b-41d4-a716-446655440001', '550e8400-e29b-41d4-a716-446655440000', 'admin@test.com', '$2a$10$example_hash', 'admin', '{"monthly_gb": 1000}'),
('550e8400-e29b-41d4-a716-446655440002', '550e8400-e29b-41d4-a716-446655440000', 'user@test.com', '$2a$10$example_hash', 'user', '{"monthly_gb": 100}');

-- Insert test proxy servers
INSERT INTO proxy_servers (id, name, type, endpoint, status, location, specs) VALUES 
('550e8400-e29b-41d4-a716-446655440003', 'SOCKS5 Server 1', 'socks5', '127.0.0.1:1080', 'online', 'US-East', '{"max_connections": 1000}'),
('550e8400-e29b-41d4-a716-446655440004', 'HTTP Proxy 1', 'http', '127.0.0.1:8080', 'online', 'US-West', '{"max_connections": 500}');

-- Insert test subscription
INSERT INTO subscriptions (id, organization_id, plan, limits, expires_at) VALUES 
('550e8400-e29b-41d4-a716-446655440005', '550e8400-e29b-41d4-a716-446655440000', 'enterprise', '{"monthly_gb": 10000, "max_users": 100}', '2025-12-31 23:59:59+00');
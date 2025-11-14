.PHONY: help build build-optimized build-dev up down restart clean clean-images clean-all logs test-ping shell-node1 shell-node2 shell-node3

# Default target
help:
	@echo "Tinc-VLESS Docker Build Automation"
	@echo "==================================="
	@echo ""
	@echo "Build commands:"
	@echo "  make build           - Build with optimized Dockerfile (recommended)"
	@echo "  make build-dev       - Build with original Dockerfile (for debugging)"
	@echo "  make build-no-cache  - Clean build without cache"
	@echo ""
	@echo "Container management:"
	@echo "  make up              - Start all containers"
	@echo "  make down            - Stop and remove all containers"
	@echo "  make restart         - Restart all containers"
	@echo ""
	@echo "Cleanup commands:"
	@echo "  make clean           - Stop containers and remove networks"
	@echo "  make clean-images    - Remove old/dangling images (keeps latest)"
	@echo "  make clean-all       - FULL cleanup (containers, images, volumes)"
	@echo "  make prune           - Docker system prune (safe cleanup)"
	@echo ""
	@echo "Testing:"
	@echo "  make test-ping       - Test connectivity between nodes"
	@echo "  make logs            - View logs from all containers"
	@echo "  make shell-node1     - Open shell in node1"
	@echo "  make shell-node2     - Open shell in node2"
	@echo "  make shell-node3     - Open shell in node3"
	@echo ""
	@echo "Info:"
	@echo "  make images-size     - Show image sizes"
	@echo "  make disk-usage      - Show Docker disk usage"

# Build with optimized multi-stage Dockerfile
build:
	@echo "Building optimized image (3-stage build)..."
	docker-compose -f docker-compose.optimized.yml build
	@echo ""
	@echo "Build complete! Image size:"
	@docker images tinc-vless:latest --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"

# Build without cache (full rebuild)
build-no-cache:
	@echo "Building optimized image from scratch (no cache)..."
	docker-compose -f docker-compose.optimized.yml build --no-cache
	@echo ""
	@echo "Build complete! Image size:"
	@docker images tinc-vless:latest --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"

# Build with original Dockerfile (for debugging)
build-dev:
	@echo "Building with original Dockerfile..."
	docker-compose build
	@echo ""
	@echo "Build complete! Image sizes:"
	@docker images | grep docker-node

# Start containers
up:
	docker-compose -f docker-compose.optimized.yml up -d
	@echo "Containers started. Check status with: docker-compose ps"

# Stop containers
down:
	docker-compose -f docker-compose.optimized.yml down

# Restart containers
restart:
	docker-compose -f docker-compose.optimized.yml restart

# Clean: stop containers and remove networks
clean:
	@echo "Stopping containers and removing networks..."
	docker-compose -f docker-compose.optimized.yml down
	docker-compose down 2>/dev/null || true
	@echo "Cleanup complete!"

# Clean old/dangling images (keeps tinc-vless:latest)
clean-images:
	@echo "Removing dangling images..."
	docker image prune -f
	@echo ""
	@echo "Removing old tinc images (keeping latest)..."
	@docker images | grep 'docker-node' | awk '{print $$3}' | xargs -r docker rmi -f 2>/dev/null || true
	@docker images | grep '<none>' | awk '{print $$3}' | xargs -r docker rmi -f 2>/dev/null || true
	@echo "Image cleanup complete!"
	@echo ""
	@make disk-usage

# Full cleanup: containers, images, volumes, everything
clean-all:
	@echo "WARNING: This will remove ALL containers, images, and volumes!"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		docker-compose -f docker-compose.optimized.yml down -v; \
		docker-compose down -v 2>/dev/null || true; \
		docker rmi -f tinc-vless:latest 2>/dev/null || true; \
		docker images | grep 'docker-node' | awk '{print $$3}' | xargs -r docker rmi -f 2>/dev/null || true; \
		docker system prune -af --volumes; \
		echo "Full cleanup complete!"; \
	else \
		echo "Cleanup cancelled."; \
	fi

# Docker system prune (safe cleanup of unused resources)
prune:
	@echo "Removing unused Docker resources..."
	docker system prune -f
	@echo "Prune complete!"
	@make disk-usage

# View logs from all containers
logs:
	docker-compose -f docker-compose.optimized.yml logs -f

# Test ping connectivity
test-ping:
	@echo "Testing connectivity: node2 -> node1 (10.0.0.1)..."
	docker exec tinc-node2 ping -c 3 10.0.0.1 || echo "FAILED"
	@echo ""
	@echo "Testing connectivity: node3 -> node1 (10.0.0.1)..."
	docker exec tinc-node3 ping -c 3 10.0.0.1 || echo "FAILED"
	@echo ""
	@echo "Testing connectivity: node2 -> node3 (10.0.0.3)..."
	docker exec tinc-node2 ping -c 3 10.0.0.3 || echo "FAILED"

# Shell access to nodes
shell-node1:
	docker exec -it tinc-node1 /bin/bash

shell-node2:
	docker exec -it tinc-node2 /bin/bash

shell-node3:
	docker exec -it tinc-node3 /bin/bash

# Show image sizes
images-size:
	@echo "Docker images sizes:"
	@docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}" | grep -E "(REPOSITORY|tinc|docker-node)"

# Show Docker disk usage
disk-usage:
	@echo "Docker disk usage:"
	@docker system df
	@echo ""
	@echo "Detailed breakdown:"
	@docker system df -v | head -20

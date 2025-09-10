#!/bin/bash

# LunaGuard Database Provisioning Script
# This script provisions the database schema for LunaGuard

set -e

# Configuration
STORAGE_URL="${STORAGE_SERVICE_URL:-http://localhost:8002}"
TIMEOUT="${TIMEOUT:-30}"

echo "🚀 LunaGuard Database Provisioning"
echo "Storage Service URL: $STORAGE_URL"
echo "Timeout: ${TIMEOUT}s"
echo ""

# Function to check if storage service is running
check_storage_service() {
    echo "🔍 Checking storage service availability..."
    if curl -s --max-time 5 "$STORAGE_URL/health" > /dev/null 2>&1; then
        echo "✅ Storage service is running"
        return 0
    else
        echo "❌ Storage service is not available at $STORAGE_URL"
        return 1
    fi
}

# Function to check current provision status
check_provision_status() {
    echo "🔍 Checking current provision status..."
    response=$(curl -s --max-time 10 "$STORAGE_URL/provision/status" 2>/dev/null || echo "")
    
    if [[ -n "$response" ]]; then
        provisioned=$(echo "$response" | grep -o '"provisioned":[^,}]*' | cut -d':' -f2 | tr -d ' ')
        if [[ "$provisioned" == "true" ]]; then
            echo "✅ Database is already provisioned"
            return 0
        else
            echo "⚠️  Database is not fully provisioned"
            return 1
        fi
    else
        echo "⚠️  Could not check provision status"
        return 1
    fi
}

# Function to provision database
provision_database() {
    echo "🛠️  Provisioning database schema..."
    response=$(curl -s -w "%{http_code}" --max-time "$TIMEOUT" \
        -X POST "$STORAGE_URL/provision/database" \
        -H "Content-Type: application/json")
    
    http_code="${response: -3}"
    body="${response%???}"
    
    if [[ "$http_code" == "200" ]]; then
        echo "✅ Database schema provisioned successfully"
        echo "Response: $body"
        return 0
    else
        echo "❌ Failed to provision database (HTTP $http_code)"
        echo "Response: $body"
        return 1
    fi
}

# Main execution
main() {
    echo "Starting database provisioning process..."
    echo ""
    
    # Check storage service
    if ! check_storage_service; then
        echo ""
        echo "💡 Make sure the storage service is running:"
        echo "   cd lunaguard-storage && python main.py"
        exit 1
    fi
    
    echo ""
    
    # Check if already provisioned
    if check_provision_status; then
        echo ""
        echo "🎉 Database is ready! No provisioning needed."
        exit 0
    fi
    
    echo ""
    
    # Provision database
    if provision_database; then
        echo ""
        echo "🎉 Database provisioning completed successfully!"
        echo ""
        echo "📋 Next steps:"
        echo "   1. Start the security service"
        echo "   2. The security service will verify the schema automatically"
    else
        echo ""
        echo "💥 Database provisioning failed!"
        echo ""
        echo "🔧 Troubleshooting:"
        echo "   1. Check storage service logs"
        echo "   2. Verify database connection settings"
        echo "   3. Ensure PostgreSQL is running"
        exit 1
    fi
}

# Handle script arguments
case "${1:-}" in
    "check")
        check_storage_service && check_provision_status
        ;;
    "force")
        echo "🔄 Force provisioning (skipping status check)..."
        check_storage_service && provision_database
        ;;
    "status")
        check_provision_status
        ;;
    *)
        main
        ;;
esac

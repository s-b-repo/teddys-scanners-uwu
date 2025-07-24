#!/bin/bash

# Proxy Scanner Manager Script
# Usage: ./proxy_manager.sh {start|stop|status|restart|scale} [number_of_instances]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_DIR="$SCRIPT_DIR/pids"
LOG_DIR="$SCRIPT_DIR/logs"
CONFIG_FILE="scanner_config.json"

# Create necessary directories
mkdir -p "$PID_DIR" "$LOG_DIR"

# Default number of instances
DEFAULT_INSTANCES=4

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Function to check if script exists
check_script() {
    if [ ! -f "proxy_scanner.py" ]; then
        print_error "proxy_scanner.py not found in current directory"
        exit 1
    fi
}

# Function to get number of instances
get_instance_count() {
    if [ -n "$2" ] && [[ "$2" =~ ^[0-9]+$ ]]; then
        echo "$2"
    else
        echo "$DEFAULT_INSTANCES"
    fi
}

# Function to start instances
start_instances() {
    local count=$(get_instance_count "$@")
    local started=0
    
    print_status "Starting $count proxy scanner instances..."
    
    for i in $(seq 1 $count); do
        local pid_file="$PID_DIR/scanner_$i.pid"
        local log_file="$LOG_DIR/scanner_$i.log"
        
        # Check if instance is already running
        if [ -f "$pid_file" ]; then
            local pid=$(cat "$pid_file")
            if ps -p "$pid" > /dev/null 2>&1; then
                print_warning "Instance $i already running (PID: $pid)"
                continue
            else
                rm -f "$pid_file"
            fi
        fi
        
        # Start the instance
        nohup python3 proxy_scanner.py "$i" > "$log_file" 2>&1 &
        local pid=$!
        
        # Save PID
        echo "$pid" > "$pid_file"
        
        # Verify process started
        if ps -p "$pid" > /dev/null 2>&1; then
            print_success "Started instance $i (PID: $pid)"
            ((started++))
        else
            print_error "Failed to start instance $i"
        fi
    done
    
    print_success "Started $started/$count instances"
}

# Function to stop instances
stop_instances() {
    local stopped=0
    local failed=0
    
    print_status "Stopping proxy scanner instances..."
    
    if [ ! -d "$PID_DIR" ] || [ -z "$(ls -A "$PID_DIR")" ]; then
        print_warning "No running instances found"
        return
    fi
    
    for pid_file in "$PID_DIR"/scanner_*.pid; do
        [ -f "$pid_file" ] || continue
        
        local instance=$(basename "$pid_file" .pid)
        local pid=$(cat "$pid_file")
        
        if ps -p "$pid" > /dev/null 2>&1; then
            # Try graceful shutdown first
            kill -TERM "$pid" 2>/dev/null
            
            # Wait for process to terminate
            local count=0
            while ps -p "$pid" > /dev/null 2>&1 && [ $count -lt 10 ]; do
                sleep 1
                ((count++))
            done
            
            # Force kill if still running
            if ps -p "$pid" > /dev/null 2>&1; then
                kill -KILL "$pid" 2>/dev/null
                print_warning "Force killed instance $instance (PID: $pid)"
            else
                print_success "Stopped instance $instance gracefully"
            fi
        else
            print_warning "Instance $instance was not running"
        fi
        
        # Clean up PID file
        rm -f "$pid_file"
        ((stopped++))
    done
    
    print_success "Stopped $stopped instances"
}

# Function to show status
show_status() {
    local running=0
    local stopped=0
    
    print_status "Proxy Scanner Status:"
    echo "----------------------------------------"
    
    if [ ! -d "$PID_DIR" ] || [ -z "$(ls -A "$PID_DIR")" ]; then
        print_warning "No instances found"
        return
    fi
    
    for pid_file in "$PID_DIR"/scanner_*.pid; do
        [ -f "$pid_file" ] || continue
        
        local instance=$(basename "$pid_file" .pid)
        local pid=$(cat "$pid_file")
        
        if ps -p "$pid" > /dev/null 2>&1; then
            local start_time=$(ps -o lstart= -p "$pid" 2>/dev/null)
            echo -e "Instance $instance: ${GREEN}RUNNING${NC} (PID: $pid)"
            echo "  Started: $start_time"
            ((running++))
        else
            echo -e "Instance $instance: ${RED}STOPPED${NC} (PID file: $pid_file)"
            rm -f "$pid_file"
            ((stopped++))
        fi
    done
    
    echo "----------------------------------------"
    print_success "Running: $running | Stopped: $stopped"
}

# Function to scale instances
scale_instances() {
    local target_count=$(get_instance_count "$@")
    local current_count=0
    
    # Count current instances
    if [ -d "$PID_DIR" ]; then
        current_count=$(ls "$PID_DIR"/scanner_*.pid 2>/dev/null | wc -l)
    fi
    
    print_status "Scaling from $current_count to $target_count instances..."
    
    if [ "$target_count" -gt "$current_count" ]; then
        # Scale up
        local start_from=$((current_count + 1))
        local additional=$((target_count - current_count))
        
        for i in $(seq $start_from $((start_from + additional - 1))); do
            local pid_file="$PID_DIR/scanner_$i.pid"
            local log_file="$LOG_DIR/scanner_$i.log"
            
            # Start the instance
            nohup python3 proxy_scanner.py "$i" > "$log_file" 2>&1 &
            local pid=$!
            
            # Save PID
            echo "$pid" > "$pid_file"
            
            if ps -p "$pid" > /dev/null 2>&1; then
                print_success "Started new instance $i (PID: $pid)"
            else
                print_error "Failed to start instance $i"
            fi
        done
        
    elif [ "$target_count" -lt "$current_count" ]; then
        # Scale down
        local stop_from=$((target_count + 1))
        
        for i in $(seq $stop_from $current_count); do
            local pid_file="$PID_DIR/scanner_$i.pid"
            
            if [ -f "$pid_file" ]; then
                local pid=$(cat "$pid_file")
                
                if ps -p "$pid" > /dev/null 2>&1; then
                    kill -TERM "$pid" 2>/dev/null
                    sleep 2
                    
                    if ps -p "$pid" > /dev/null 2>&1; then
                        kill -KILL "$pid" 2>/dev/null
                    fi
                    
                    print_success "Stopped instance $i"
                fi
                
                rm -f "$pid_file"
            fi
        done
    else
        print_success "Already running $target_count instances"
    fi
}

# Function to show logs
show_logs() {
    local instance=${2:-1}
    local lines=${3:-50}
    
    local log_file="$LOG_DIR/scanner_$instance.log"
    
    if [ -f "$log_file" ]; then
        print_status "Last $lines lines from instance $instance log:"
        tail -n "$lines" "$log_file"
    else
        print_error "Log file not found: $log_file"
    fi
}

# Function to show help
show_help() {
    echo "Proxy Scanner Manager"
    echo "Usage: $0 {start|stop|status|restart|scale|logs|help} [options]"
    echo ""
    echo "Commands:"
    echo "  start [n]     Start n instances (default: $DEFAULT_INSTANCES)"
    echo "  stop          Stop all instances"
    echo "  status        Show status of all instances"
    echo "  restart [n]   Restart with n instances"
    echo "  scale n       Scale to n instances"
    echo "  logs [n] [l]  Show last l lines of instance n log (default: instance 1, 50 lines)"
    echo "  help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 start 8     # Start 8 instances"
    echo "  $0 scale 12    # Scale to 12 instances"
    echo "  $0 logs 2 100  # Show last 100 lines of instance 2 log"
}

# Main script logic
case "$1" in
    start)
        check_script
        start_instances "$@"
        ;;
    stop)
        stop_instances
        ;;
    status)
        show_status
        ;;
    restart)
        stop_instances
        sleep 2
        check_script
        start_instances "$@"
        ;;
    scale)
        if [ -z "$2" ] || ! [[ "$2" =~ ^[0-9]+$ ]]; then
            print_error "Please specify number of instances: $0 scale <number>"
            exit 1
        fi
        scale_instances "$@"
        ;;
    logs)
        show_logs "$@"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        show_help
        exit 1
        ;;
esac

exit 0

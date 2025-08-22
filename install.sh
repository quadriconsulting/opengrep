#!/bin/bash

# Enhanced Opengrep SAST Tool Installation Script
# ===============================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PYTHON_MIN_VERSION="3.8"
REPO_URL="https://github.com/quadriconsulting/enhanced-opengrep.git"
INSTALL_DIR="$HOME/.enhanced-opengrep"
BIN_DIR="$HOME/.local/bin"

echo -e "${BLUE}🚀 Enhanced Opengrep SAST Tool Installer${NC}"
echo "============================================="

# Function to print colored output
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Check if Python is installed and meets minimum version
check_python() {
    print_info "Checking Python installation..."
    
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed. Please install Python 3.8 or higher."
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    
    if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"; then
        print_status "Python $PYTHON_VERSION found (>= $PYTHON_MIN_VERSION required)"
    else
        print_error "Python $PYTHON_VERSION found, but $PYTHON_MIN_VERSION or higher is required"
        exit 1
    fi
}

# Check if pip is installed
check_pip() {
    print_info "Checking pip installation..."
    
    if ! command -v pip3 &> /dev/null; then
        print_error "pip3 is not installed. Please install pip3."
        exit 1
    fi
    
    print_status "pip3 found"
}

# Check if git is installed
check_git() {
    print_info "Checking git installation..."
    
    if ! command -v git &> /dev/null; then
        print_error "git is not installed. Please install git."
        exit 1
    fi
    
    print_status "git found"
}

# Check if opengrep is installed
check_opengrep() {
    print_info "Checking Opengrep installation..."
    
    if command -v opengrep &> /dev/null; then
        OPENGREP_VERSION=$(opengrep --version 2>&1 | head -n1 || echo "unknown")
        print_status "Opengrep found: $OPENGREP_VERSION"
    else
        print_warning "Opengrep not found in PATH"
        print_info "You can install Opengrep from: https://github.com/opengrep/opengrep"
        print_info "Or the installer will guide you to install it later"
    fi
}

# Create necessary directories
create_directories() {
    print_info "Creating installation directories..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$BIN_DIR"
    
    print_status "Directories created"
}

# Install the enhanced SAST tool
install_enhanced_sast() {
    print_info "Installing Enhanced Opengrep SAST Tool..."
    
    # Create virtual environment
    print_info "Creating Python virtual environment..."
    python3 -m venv "$INSTALL_DIR/venv"
    
    # Activate virtual environment
    source "$INSTALL_DIR/venv/bin/activate"
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Copy the current directory contents or clone from repo
    if [ -f "enhanced_autofix_sast.py" ]; then
        print_info "Installing from current directory..."
        cp -r . "$INSTALL_DIR/src"
    else
        print_info "Cloning from repository..."
        git clone "$REPO_URL" "$INSTALL_DIR/src"
    fi
    
    # Install Python dependencies
    print_info "Installing Python dependencies..."
    cd "$INSTALL_DIR/src"
    pip install -r requirements.txt
    
    # Install the package
    pip install -e .
    
    print_status "Enhanced SAST tool installed"
}

# Create wrapper script
create_wrapper_script() {
    print_info "Creating wrapper script..."
    
    cat > "$BIN_DIR/enhanced-opengrep" << EOF
#!/bin/bash
# Enhanced Opengrep SAST Tool Wrapper Script

# Activate virtual environment
source "$INSTALL_DIR/venv/bin/activate"

# Run the enhanced SAST tool
python3 "$INSTALL_DIR/src/enhanced_autofix_sast.py" "\$@"
EOF
    
    chmod +x "$BIN_DIR/enhanced-opengrep"
    
    # Create shorter alias
    ln -sf "$BIN_DIR/enhanced-opengrep" "$BIN_DIR/eogrep"
    
    print_status "Wrapper scripts created: enhanced-opengrep, eogrep"
}

# Clone opengrep-rules if not present
setup_rules() {
    print_info "Setting up Opengrep rules..."
    
    if [ ! -d "$INSTALL_DIR/src/opengrep-rules" ]; then
        print_info "Cloning opengrep-rules repository..."
        cd "$INSTALL_DIR/src"
        git clone https://github.com/quadriconsulting/opengrep-rules.git
    else
        print_info "Updating opengrep-rules repository..."
        cd "$INSTALL_DIR/src/opengrep-rules"
        git pull
    fi
    
    print_status "Opengrep rules configured"
}

# Update PATH if necessary
update_path() {
    print_info "Updating PATH..."
    
    # Check if BIN_DIR is already in PATH
    if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
        # Add to bash profile
        if [ -f "$HOME/.bashrc" ]; then
            echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$HOME/.bashrc"
            print_status "Added $BIN_DIR to ~/.bashrc"
        fi
        
        # Add to zsh profile if it exists
        if [ -f "$HOME/.zshrc" ]; then
            echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$HOME/.zshrc"
            print_status "Added $BIN_DIR to ~/.zshrc"
        fi
        
        # Export for current session
        export PATH="$BIN_DIR:$PATH"
        
        print_status "PATH updated"
    else
        print_status "PATH already configured"
    fi
}

# Create default configuration
create_config() {
    print_info "Creating default configuration..."
    
    CONFIG_DIR="$HOME/.config/enhanced-opengrep"
    mkdir -p "$CONFIG_DIR"
    
    if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
        cp "$INSTALL_DIR/src/config.yaml" "$CONFIG_DIR/config.yaml"
        print_status "Default configuration created at $CONFIG_DIR/config.yaml"
    else
        print_info "Configuration already exists at $CONFIG_DIR/config.yaml"
    fi
}

# Install Opengrep if not present
install_opengrep() {
    if ! command -v opengrep &> /dev/null; then
        print_warning "Opengrep not found. Would you like to install it? (y/N)"
        read -r response
        
        if [[ "$response" =~ ^[Yy]$ ]]; then
            print_info "Installing Opengrep..."
            
            # Install using the official installer
            if command -v curl &> /dev/null; then
                curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash
            elif command -v wget &> /dev/null; then
                wget -qO- https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash
            else
                print_error "Neither curl nor wget found. Please install Opengrep manually."
                print_info "Visit: https://github.com/opengrep/opengrep"
                exit 1
            fi
            
            print_status "Opengrep installed"
        else
            print_warning "Skipping Opengrep installation. You'll need to install it manually."
        fi
    fi
}

# Run tests to verify installation
run_tests() {
    print_info "Running installation tests..."
    
    # Test wrapper script
    if "$BIN_DIR/enhanced-opengrep" --help &> /dev/null; then
        print_status "Wrapper script test passed"
    else
        print_error "Wrapper script test failed"
        return 1
    fi
    
    # Test Python imports
    source "$INSTALL_DIR/venv/bin/activate"
    if python3 -c "import enhanced_autofix_sast; print('✓ Import test passed')" 2>/dev/null; then
        print_status "Python import test passed"
    else
        print_error "Python import test failed"
        return 1
    fi
    
    print_status "All tests passed"
}

# Main installation process
main() {
    echo
    print_info "Starting installation process..."
    echo
    
    # Prerequisites
    check_python
    check_pip
    check_git
    check_opengrep
    
    echo
    
    # Installation
    create_directories
    install_enhanced_sast
    create_wrapper_script
    setup_rules
    update_path
    create_config
    install_opengrep
    
    echo
    
    # Verification
    if run_tests; then
        echo
        print_status "🎉 Enhanced Opengrep SAST Tool installed successfully!"
        echo
        print_info "Usage examples:"
        echo "  enhanced-opengrep scan /path/to/code"
        echo "  eogrep scan . --github-token TOKEN --repo owner/repo"
        echo
        print_info "Configuration file: $HOME/.config/enhanced-opengrep/config.yaml"
        print_info "Installation directory: $INSTALL_DIR"
        echo
        print_warning "Please restart your terminal or run: source ~/.bashrc"
        echo
    else
        print_error "Installation completed with errors. Please check the output above."
        exit 1
    fi
}

# Run main function
main "$@"
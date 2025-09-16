#!/bin/bash

# Multi-platform liboqs build script
# Builds for 7 platforms × 4 variants = 28 total builds
#
# Platforms: win-x64, win-arm64, linux-x64, linux-arm64,
#            linux-musl-x64, linux-musl-arm64, osx-arm64
#
# Variants: full (all algorithms), kem (KEM + general), sig (SIG + general), sig-stfl (SIG_STFL + general)

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIBOQS_DIR="$SCRIPT_DIR/liboqs"
BUILD_DIR="$SCRIPT_DIR/builds"
BUILD_JOBS=$(($(nproc) - 4))
LIBOQS_REPO="https://github.com/open-quantum-safe/liboqs.git"
LIBOQS_BRANCH="main"

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

declare -A PLATFORMS
PLATFORMS[linux-x64]="x86_64-linux-gnu-gcc,x86_64-linux-gnu-g++,Linux,x86_64"
PLATFORMS[linux-arm64]="aarch64-linux-gnu-gcc,aarch64-linux-gnu-g++,Linux,aarch64"
PLATFORMS[linux-musl-x64]="musl-gcc,musl-g++,Linux,x86_64"
PLATFORMS[linux-musl-arm64]="aarch64-linux-musl-gcc,aarch64-linux-musl-g++,Linux,aarch64"
PLATFORMS[win-x64]="x86_64-w64-mingw32-gcc,x86_64-w64-mingw32-g++,Windows,AMD64"
PLATFORMS[win-arm64]="aarch64-w64-mingw32-clang,aarch64-w64-mingw32-clang++,Windows,ARM64"
PLATFORMS[osx-arm64]="arm64-apple-darwin24.5-clang,arm64-apple-darwin24.5-clang++,Darwin,arm64"

get_variant_flags() {
    local variant=$1
    case $variant in
        "full")
            echo "-DOQS_ENABLE_SIG_STFL_XMSS=ON \
                  -DOQS_ENABLE_SIG_STFL_LMS=ON \
                  -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON"
            ;;
        "kem")
            echo "-DOQS_ENABLE_SIG_DILITHIUM=OFF \
                  -DOQS_ENABLE_SIG_ML_DSA=OFF \
                  -DOQS_ENABLE_SIG_FALCON=OFF \
                  -DOQS_ENABLE_SIG_SPHINCS=OFF \
                  -DOQS_ENABLE_SIG_MAYO=OFF \
                  -DOQS_ENABLE_SIG_CROSS=OFF \
                  -DOQS_ENABLE_SIG_UOV=OFF \
                  -DOQS_ENABLE_SIG_SNOVA=OFF \
                  -DOQS_ENABLE_SIG_SLH_DSA=OFF \
                  -DOQS_ENABLE_SIG_STFL_XMSS=OFF \
                  -DOQS_ENABLE_SIG_STFL_LMS=OFF"
            ;;
        "sig")
            echo "-DOQS_ENABLE_KEM_BIKE=OFF \
                  -DOQS_ENABLE_KEM_FRODOKEM=OFF \
                  -DOQS_ENABLE_KEM_NTRUPRIME=OFF \
                  -DOQS_ENABLE_KEM_CLASSIC_MCELIECE=OFF \
                  -DOQS_ENABLE_KEM_HQC=OFF \
                  -DOQS_ENABLE_KEM_KYBER=OFF \
                  -DOQS_ENABLE_KEM_ML_KEM=OFF \
                  -DOQS_ENABLE_SIG_STFL_XMSS=OFF \
                  -DOQS_ENABLE_SIG_STFL_LMS=OFF"
            ;;
        "sig-stfl")
            echo "-DOQS_ENABLE_KEM_BIKE=OFF \
                  -DOQS_ENABLE_KEM_FRODOKEM=OFF \
                  -DOQS_ENABLE_KEM_NTRUPRIME=OFF \
                  -DOQS_ENABLE_KEM_CLASSIC_MCELIECE=OFF \
                  -DOQS_ENABLE_KEM_HQC=OFF \
                  -DOQS_ENABLE_KEM_KYBER=OFF \
                  -DOQS_ENABLE_KEM_ML_KEM=OFF \
                  -DOQS_ENABLE_SIG_DILITHIUM=OFF \
                  -DOQS_ENABLE_SIG_ML_DSA=OFF \
                  -DOQS_ENABLE_SIG_FALCON=OFF \
                  -DOQS_ENABLE_SIG_SPHINCS=OFF \
                  -DOQS_ENABLE_SIG_MAYO=OFF \
                  -DOQS_ENABLE_SIG_CROSS=OFF \
                  -DOQS_ENABLE_SIG_UOV=OFF \
                  -DOQS_ENABLE_SIG_SNOVA=OFF \
                  -DOQS_ENABLE_SIG_SLH_DSA=OFF \
                  -DOQS_ENABLE_SIG_STFL_XMSS=ON \
                  -DOQS_ENABLE_SIG_STFL_LMS=ON \
                  -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON"
            ;;
        *)
            log_error "Unknown variant: $variant"
            exit 1
            ;;
    esac
}

setup_liboqs() {
    log_info "Setting up LibOQS repository..."
    
    if [ -d "$LIBOQS_DIR" ]; then
        log_info "LibOQS directory exists, updating..."
        cd "$LIBOQS_DIR"
        
        log_info "Cleaning LibOQS build artifacts..."
        git clean -dfx
        
        log_info "Pulling latest LibOQS code from $LIBOQS_BRANCH..."
        git checkout "$LIBOQS_BRANCH"
        git pull origin "$LIBOQS_BRANCH"
        
        cd "$SCRIPT_DIR"
    else
        log_info "Cloning LibOQS from $LIBOQS_REPO..."
        git clone --depth 1 --branch "$LIBOQS_BRANCH" "$LIBOQS_REPO" "$LIBOQS_DIR"
    fi
    
    cd "$LIBOQS_DIR"
    local commit=$(git rev-parse HEAD)
    local short_commit=$(git rev-parse --short HEAD)
    log_success "LibOQS ready: $short_commit ($commit)"
    cd "$SCRIPT_DIR"
}

setup_toolchain() {
    local platform=$1
    local build_dir=$2
    
    IFS=',' read -r cc cxx system_name processor <<< "${PLATFORMS[$platform]}"
    
    cat > "$build_dir/toolchain.cmake" << EOF
set(CMAKE_SYSTEM_NAME $system_name)
set(CMAKE_SYSTEM_PROCESSOR $processor)
set(CMAKE_C_COMPILER $cc)
set(CMAKE_CXX_COMPILER $cxx)
EOF

    case $platform in
        "linux-musl-"*)
            cat >> "$build_dir/toolchain.cmake" << EOF
set(CMAKE_C_FLAGS "-static")
set(CMAKE_CXX_FLAGS "-static")
set(CMAKE_EXE_LINKER_FLAGS "-static")
EOF
            ;;
        "win-x64")
# Increase stack size to 8MB to match Linux default and avoid stack overflow
# with algorithms that use large stack allocations
            cat >> "$build_dir/toolchain.cmake" << EOF
set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)
set(CMAKE_EXE_LINKER_FLAGS "-Wl,--stack,8388608")
set(CMAKE_SHARED_LINKER_FLAGS "-Wl,--stack,8388608")
EOF
            ;;
        "win-arm64")
# Increase stack size to 8MB to match Linux default and avoid stack overflow
# with algorithms that use large stack allocations
            cat >> "$build_dir/toolchain.cmake" << EOF
set(CMAKE_FIND_ROOT_PATH /opt/llvm-mingw/llvm-mingw-ucrt/aarch64-w64-mingw32)
set(CMAKE_EXE_LINKER_FLAGS "-Wl,--stack,8388608")
set(CMAKE_SHARED_LINKER_FLAGS "-Wl,--stack,8388608")
EOF
            ;;
        "osx-arm64")
            cat >> "$build_dir/toolchain.cmake" << EOF
set(CMAKE_OSX_ARCHITECTURES arm64)
set(CMAKE_C_FLAGS "-target arm64-apple-darwin24.5")
set(CMAKE_CXX_FLAGS "-target arm64-apple-darwin24.5")
set(CMAKE_EXE_LINKER_FLAGS "-target arm64-apple-darwin24.5")
set(CMAKE_SHARED_LINKER_FLAGS "-target arm64-apple-darwin24.5")
set(CMAKE_MODULE_LINKER_FLAGS "-target arm64-apple-darwin24.5")
EOF
            ;;
    esac

    if [[ "$platform" != "linux-x64" && "$platform" != "linux-arm64" ]]; then
        cat >> "$build_dir/toolchain.cmake" << EOF
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
EOF
    else
        cat >> "$build_dir/toolchain.cmake" << EOF
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
EOF
    fi
}

build_target() {
    local platform=$1
    local variant=$2
    
    log_info "Building $platform-$variant..."
    
    local build_dir="$BUILD_DIR/$platform-$variant"
    local install_dir="$build_dir/install"
    
    rm -rf "$build_dir"
    mkdir -p "$build_dir"
    mkdir -p "$install_dir"
    
    setup_toolchain "$platform" "$build_dir"
    
    local variant_flags
    variant_flags=$(get_variant_flags "$variant")
    
    local common_flags="-DCMAKE_BUILD_TYPE=Release \
                        -DCMAKE_INSTALL_PREFIX=$install_dir \
                        -DBUILD_SHARED_LIBS=ON \
                        -DOQS_BUILD_ONLY_LIB=ON \
                        -DOQS_DIST_BUILD=ON \
                        -DOQS_USE_OPENSSL=OFF"
    
    local platform_flags="-DCMAKE_TOOLCHAIN_FILE=$build_dir/toolchain.cmake"
    
    if [[ "$platform" == *"arm64" ]] || [[ "$platform" == *"musl"* ]]; then
        variant_flags="$variant_flags -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON"
    fi

    if [[ "$platform" == win-* ]] || [[ "$platform" == osx-* ]]; then
        variant_flags="$variant_flags -DOQS_ENABLE_KEM_BIKE=OFF"
    fi

    # Disable Classic-McEliece on Windows due to stack overflow issues
    # These algorithms use very large stack allocations that exceed Windows' default 1MB stack size
    if [[ "$platform" == win-* ]]; then
        variant_flags="$variant_flags -DOQS_ENABLE_KEM_CLASSIC_MCELIECE=OFF"
    fi
    
    cd "$build_dir"
    
    log_info "Configuring $platform-$variant..."
    if ! cmake "$LIBOQS_DIR" $common_flags $platform_flags $variant_flags --log-level=ERROR; then
        log_error "Configuration failed for $platform-$variant"
        return 1
    fi
    
    log_info "Building $platform-$variant..."
    if ! MAKEFLAGS="-s" cmake --build . --parallel $BUILD_JOBS; then
        log_error "Build failed for $platform-$variant"
        return 1
    fi
    
    log_info "Installing $platform-$variant..."
    if ! cmake --install .; then
        log_error "Install failed for $platform-$variant"
        return 1
    fi
    
    local target_lib final_name
    case $platform in
        win-*)
            target_lib=$(find "$install_dir" -name "liboqs.dll" -type f | head -1)
            final_name="liboqs.dll"
            ;;
        osx-*)
            target_lib=$(find "$install_dir/lib" -name "liboqs*.dylib" -type f | head -1)
            final_name="liboqs.dylib"
            ;;
        *)
            target_lib=$(find "$install_dir/lib" -name "liboqs.so.*" -type f | head -1)
            final_name="liboqs.so"
            ;;
    esac
    
    if [ -n "$target_lib" ] && [ -f "$target_lib" ]; then
        log_success "Successfully built $platform-$variant"

        local size=$(ls -lh "$target_lib" | awk '{print $5}')
        log_info "$platform-$variant library size: $size"

        local runtime_dir="$SCRIPT_DIR/runtimes-$variant/$platform/native"
        mkdir -p "$runtime_dir"
        cp "$target_lib" "$runtime_dir/$final_name"

        log_success "Library installed to: $runtime_dir/$final_name"
    else
        log_error "Build completed but no library found for $platform-$variant"
        log_error "Searched in: $install_dir/lib/ and $install_dir/bin/"
        log_info "Contents of $install_dir/lib/:"
        ls -la "$install_dir/lib/" 2>/dev/null || log_warn "lib directory not found"
        log_info "Contents of $install_dir/bin/:"
        ls -la "$install_dir/bin/" 2>/dev/null || log_warn "bin directory not found"

        log_info "All library-like files in install directory:"
        find "$install_dir" -type f \( -name "*.so*" -o -name "*.dylib*" -o -name "*.dll" \) 2>/dev/null || log_warn "No library files found"

        return 1
    fi
    
    cd "$SCRIPT_DIR"
}

check_dependencies() {
    log_info "Checking build dependencies..."
    
    local missing_deps=()
    
    command -v git >/dev/null || missing_deps+=("git")
    command -v cmake >/dev/null || missing_deps+=("cmake")
    command -v x86_64-w64-mingw32-gcc >/dev/null || missing_deps+=("mingw-w64-gcc")
    command -v aarch64-linux-gnu-gcc >/dev/null || missing_deps+=("aarch64-linux-gnu toolchain")
    command -v musl-gcc >/dev/null || missing_deps+=("musl-gcc")
    command -v clang >/dev/null || missing_deps+=("clang")

    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_info "Install with: pacman -S git cmake mingw-w64 aarch64-linux-gnu-gcc musl clang"
        exit 1
    fi
    
    log_success "All dependencies available"
}

organize_libraries() {
    log_info "Organizing libraries for .NET runtime structure..."
    
    local total_libs=0
    for variant in full kem sig sig-stfl; do
        local variant_dir="$SCRIPT_DIR/runtimes-$variant"
        if [ -d "$variant_dir" ]; then
            local lib_count=$(find "$variant_dir" -name "*.so" -o -name "*.dll" -o -name "*.dylib" | wc -l)
            total_libs=$((total_libs + lib_count))
            log_info "Variant $variant: $lib_count libraries"
        fi
    done
    
    log_success "Organization complete: $total_libs total libraries in runtime structure"
    
    log_info "Runtime structure:"
    find runtimes-* -name "*.so" -o -name "*.dll" -o -name "*.dylib" | head -20
}

cleanup_build_artifacts() {
    log_info "Cleaning up build artifacts..."
    
    if [ -d "$BUILD_DIR" ]; then
        rm -rf "$BUILD_DIR"
        log_success "Removed build directory: $BUILD_DIR"
    fi
    
    if [ -d "$LIBOQS_DIR" ]; then
        cd "$LIBOQS_DIR"
        git clean -dfx --quiet
        cd "$SCRIPT_DIR"
        log_success "Cleaned LibOQS build artifacts"
    fi
}

build_all() {
    local platforms=("$@")
    local variants=("full" "kem" "sig" "sig-stfl")
    
    if [ ${#platforms[@]} -eq 0 ]; then
        platforms=("linux-x64" "linux-arm64" "linux-musl-x64" "linux-musl-arm64"
                  "win-x64" "win-arm64" "osx-arm64")
    fi
    
    log_info "Building ${#platforms[@]} platforms × ${#variants[@]} variants = $((${#platforms[@]} * ${#variants[@]})) builds"
    log_info "Using $BUILD_JOBS parallel jobs per build"
    
    setup_liboqs
    
    mkdir -p "$BUILD_DIR"
    
    local total_builds=$((${#platforms[@]} * ${#variants[@]}))
    local current_build=0
    local successful_builds=0
    local failed_builds=()
    
    for platform in "${platforms[@]}"; do
        for variant in "${variants[@]}"; do
            current_build=$((current_build + 1))
            log_info "Build $current_build/$total_builds: $platform-$variant"
            
            if build_target "$platform" "$variant"; then
                successful_builds=$((successful_builds + 1))
            else
                failed_builds+=("$platform-$variant")
            fi
            
            echo "----------------------------------------"
        done
    done
    
    organize_libraries
    
    cleanup_build_artifacts
    
    echo ""
    log_info "Build Summary:"
    log_success "Successful builds: $successful_builds/$total_builds"
    
    if [ ${#failed_builds[@]} -gt 0 ]; then
        log_error "Failed builds: ${#failed_builds[@]}/$total_builds"
        for failed in "${failed_builds[@]}"; do
            log_error "  - $failed"
        done
        exit 1
    else
        log_success "All builds completed successfully!"
        log_success "Libraries organized in runtime-specific directories"
    fi
}

usage() {
    echo "Usage: $0 [OPTIONS] [PLATFORMS...]"
    echo ""
    echo "Build liboqs for multiple platforms and variants"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -j, --jobs N   Number of parallel build jobs (default: $BUILD_JOBS)"
    echo "  --check-deps   Only check dependencies, don't build"
    echo "  --list         List available platforms and variants"
    echo "  --setup-only   Only setup/update LibOQS repository"
    echo ""
    echo "Platforms (default: all):"
    for platform in "${!PLATFORMS[@]}"; do
        echo "  - $platform"
    done | sort
    echo ""
    echo "Variants:"
    echo "  - full: All algorithms (KEM + SIG + SIG_STFL + general)"
    echo "  - kem: KEM algorithms + general operations only"
    echo "  - sig: SIG algorithms + general operations only"
    echo "  - sig-stfl: SIG_STFL algorithms + general operations only"
    echo ""
    echo "Examples:"
    echo "  $0                              # Build all platforms and variants"
    echo "  $0 linux-x64 linux-arm64       # Build specific platforms"
    echo "  $0 --check-deps                 # Check dependencies only"
    echo "  $0 --setup-only                 # Only setup LibOQS repository"
}

PLATFORMS_TO_BUILD=()
SETUP_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -j|--jobs)
            BUILD_JOBS="$2"
            shift 2
            ;;
        --check-deps)
            check_dependencies
            exit 0
            ;;
        --list)
            echo "Available platforms:"
            for platform in "${!PLATFORMS[@]}"; do
                echo "  - $platform"
            done | sort
            echo ""
            echo "Available variants: full, kem, sig, sig-stfl"
            exit 0
            ;;
        --setup-only)
            SETUP_ONLY=true
            shift
            ;;
        *)
            if [[ -n "${PLATFORMS[$1]}" ]]; then
                PLATFORMS_TO_BUILD+=("$1")
            else
                log_error "Unknown platform: $1"
                usage
                exit 1
            fi
            shift
            ;;
    esac
done

if ! [[ "$BUILD_JOBS" =~ ^[0-9]+$ ]] || [ "$BUILD_JOBS" -lt 1 ]; then
    log_error "Invalid number of jobs: $BUILD_JOBS"
    exit 1
fi

log_info "LibOQS Multi-Platform Build Script"
log_info "==================================="

check_dependencies

if [ "$SETUP_ONLY" = true ]; then
    setup_liboqs
    log_success "LibOQS setup completed!"
else
    build_all "${PLATFORMS_TO_BUILD[@]}"
    log_success "Build script completed!"
    log_info "Libraries are organized in runtimes-* directories"
fi
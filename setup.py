"""
Samurai C Extensions Setup
=============================

This setup file builds the C extensions for Samurai:
  - fast_sender: High-performance packet sender using sendmmsg/TX_RING
  - xdp_sender: AF_XDP high-performance packet sender

Build instructions:
  python setup.py build_ext --inplace

Requirements for xdp_sender:
  - Linux kernel >= 4.18
  - python3-dev
  - Linux headers (/usr/include/linux/if_xdp.h)
"""

import os
import sys
import platform
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext


class OptionalBuildExt(build_ext):
    """
    Custom build_ext that makes XDP extension optional.
    If XDP headers are not available, it will skip building xdp_sender.
    """
    
    def build_extension(self, ext):
        try:
            super().build_extension(ext)
        except Exception as e:
            if 'xdp_sender' in ext.name:
                print(f"\n⚠️  Warning: Could not build {ext.name}: {e}")
                print("   XDP functionality will not be available.")
                print("   Install requirements: sudo apt install linux-headers-$(uname -r)\n")
            else:
                raise


def check_xdp_support():
    """Check if XDP headers are available."""
    xdp_headers = [
        '/usr/include/linux/if_xdp.h',
        '/usr/include/linux/bpf.h'
    ]
    return all(os.path.exists(h) for h in xdp_headers)


def get_extensions():
    """Get list of extensions to build."""
    extensions = []
    
    # Fast sender extension (always available)
    # Fast sender extension (always available)
    # Includes SO_TXTIME support (kernel >= 4.19)
    fast_sender = Extension(
        'ddos_samurai.fast_sender',
        sources=['ddos_samurai/fast_sender.c'],
        extra_compile_args=['-O2', '-Wall', '-fPIC'],
        extra_link_args=['-lpthread', '-lm']
    )
    extensions.append(fast_sender)

    # Pacing engine extension (deterministic timing)
    pacing_engine = Extension(
        'ddos_samurai.pacing_engine',
        sources=['ddos_samurai/pacing_engine.c'],
        extra_compile_args=['-O2', '-Wall', '-fPIC'],
        extra_link_args=['-lpthread', '-lm']
    )
    extensions.append(pacing_engine)
    
    # XDP sender extension (Linux only, requires XDP headers)
    if platform.system() == 'Linux':
        xdp_compile_args = ['-O2', '-Wall', '-Wextra']
        xdp_link_args = ['-lpthread']
        
        # Check for optional libbpf
        if os.path.exists('/usr/include/bpf/libbpf.h'):
            xdp_link_args.append('-lbpf')
            xdp_compile_args.append('-DHAVE_LIBBPF')
        
        xdp_sender = Extension(
            'ddos_samurai.xdp_sender',
            sources=['ddos_samurai/xdp_sender.c'],
            extra_compile_args=xdp_compile_args,
            extra_link_args=xdp_link_args
        )
        extensions.append(xdp_sender)
    else:
        print(f"⚠️  XDP sender not available on {platform.system()} (Linux only)")
    
    return extensions


# Package metadata
setup(
    name='ddos_samurai',
    version='2.0.0',
    description='High-Performance Network Testing Tool with GPU Acceleration and AF_XDP Support',
    author='DDoSamurai Team',
    
    packages=['ddos_samurai'],
    
    ext_modules=get_extensions(),
    cmdclass={'build_ext': OptionalBuildExt},
    
    python_requires='>=3.8',
    
    install_requires=[
        'scapy>=2.4.0',
        'numpy>=1.19.0',
        'fastapi>=0.110.0',
        'uvicorn>=0.29.0',
        'sqlalchemy>=2.0.0',
        'psycopg[binary]>=3.1.0',
        'python-jose[cryptography]>=3.3.0',
        'passlib[bcrypt]>=1.7.4',
        'python-multipart>=0.0.9',
        'prometheus-client>=0.20.0',
        'email-validator>=2.1.0',
    ],
    
    extras_require={
        'gpu': ['cupy>=9.0.0'],
        'http2': ['httpx[http2]>=0.20.0'],
        'all': ['cupy>=9.0.0', 'httpx[http2]>=0.20.0', 'h2>=4.0.0']
    },
    
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: C',
        'Topic :: System :: Networking',
    ]
)

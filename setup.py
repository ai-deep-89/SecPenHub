from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="secpenhub",
    version="1.0.0",
    author="SecPenHub Team",
    author_email="contact@secpenhub.io",
    description="Intelligent Penetration Testing & Security Assessment Platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/bifu-kuku/SecPenHub",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.10",
    install_requires=[
        "aiohttp>=3.9.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=4.9.0",
        "click>=8.1.0",
        "rich>=13.0.0",
        "requests>=2.31.0",
    ],
    extras_require={
        "ai": ["openai>=1.0.0", "tiktoken>=0.5.0"],
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "secpenhub=main:main",
        ],
    },
)

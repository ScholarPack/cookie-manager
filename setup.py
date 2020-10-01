import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="cookie-manager",
    version="1.1.0",
    author="ScholarPack",
    author_email="dev@scholarpack.com",
    description="Signed cookie manager for communication between multiple trusted services.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ScholarPack/cookie-manager",
    packages=["cookie_manager"],
    classifiers=[
        "Development Status :: 5 - Production/Stable ",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=["itsdangerous >= 1.1.0"],
)

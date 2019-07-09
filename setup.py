import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="ovaltools",
    version="0.0.1",
    author="Matt Carroll",
    author_email="oholiab@gmail.com",
    description="Tools for usefully parsing OVAL files",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/oholiab/ovaltools",
    packages=setuptools.find_packages(),
    license='BSD 3-clause "New" or "Revised License"',
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD License",
        "Operating System :: Linux",
    ],
)

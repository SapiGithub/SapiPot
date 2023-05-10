import setuptools
def readme_file():
    with open("README.rst") as readme:
        data = readme.read()
    return data

setuptools.setup(
    name="TheSapiPot",
    version="1.0",
    description="simple TCP HoneyPot to detect brute force, sql, and XCC injection",
    long_description=readme_file(),
    author="SapiGit,NashriSP",
    author_email="sapipantai665,gmail.com, nashriaziz65@gmail.com",
    license="MIT",
    packages=["TheSapiPot"],
    zip_safe=False,
    install_requires=[
        'docopt',
        'python-dotenv',
        'scapy'
    ]
)
from setuptools import setup, find_packages

setup(
    name="emailverifier",
    version="1.0.0",
    py_modules=["verifier", "app", "run"],
    entry_points={
        "console_scripts": [
            "emailverifier = run:main",
            "apexverify = run:main",
        ],
    },
    install_requires=[
        "fastapi>=0.110.0",
        "uvicorn[standard]>=0.28.0",
        "dnspython>=2.6.1",
        "python-multipart>=0.0.9",
        "pydantic>=2.6.0",
        "requests>=2.31.0",
    ],
)

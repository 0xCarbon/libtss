# Contributing to libtss
First off, thank you for considering contributing to our project! We appreciate your time and effort.

## How to Contribute

### Reporting Bugs
If you find a bug, please report it by opening an issue on our [GitHub Issues](https://github.com/0xCarbon/libtss/issues) page. Include the following details:
- A clear and descriptive title.
- A detailed description of the issue.
- Steps to reproduce the issue.
- Any relevant logs or screenshots.

### Suggesting Enhancements
We welcome suggestions for new features or improvements. Please open an issue on our [GitHub Issues](https://github.com/0xCarbon/libtss/issues) page and describe your idea in detail. Include:
- A clear and descriptive title.
- A detailed description of the enhancement.
- Any relevant examples or use cases.

### Submitting Changes
1. Fork the repository.
2. Create a new branch following [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) pattern (`git checkout -b <branch-name>`)
3. Make your changes.
4. Commit your changes (`git commit -m 'feat: describe your feature'`).
5. Push to the branch (`git push origin <branch-name>`).
6. Create a new Pull Request.


### Manual Setup for Cross-Compilation Environment

This guide provides step-by-step instructions to manually set up a cross-compilation environment on a Linux system. The environment includes Rust with various targets.

#### Step 1: Install Required Packages
First, install the essential packages required for cross-compilation.
```
bash sudo apt-get update sudo apt-get install -y --no-install-recommends
curl
unzip
gcc
make
git
```


#### Step 2: Install Rust and Add Targets
Install Rust using `rustup` and add the necessary targets for cross-compilation.
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh source $HOME/.cargo/env
```

#### Step 2.1: Add the required Rust targets
```
rustup target add x86_64-unknown-linux-gnu
i686-unknown-linux-gnu
```


#### Step 3: Set environment variables
```
source scripts/activate
```
This command will export the variable `$LIBTSS_PATH` and will append the scripts in `scripts/` directory to your `PATH`.

#### Step 4: Build Your Project
Now that your environment is set up, you can start building your project using the scripts in the `scripts/` directory. You can build the libtss from any directory on your machine:
```
libtss-build
```

The `scripts` directory also provides a script to run tests:
```
libtss-test
```

### Building with a Docker (recommended)
```
git clone https://github.com/0xCarbon/libtss.git
cd libtss
docker-compose build
source scripts/activate
libtss-docker-build 
```
This will create a new directory `target/release` in the project's root with the compiled library (`libffi_tss.so`) for Linux x86_64. 


## Code Style
Please follow our coding conventions and style guides. We use [Rustfmt](https://github.com/rust-lang/rustfmt) for formatting Rust code. You can run `cargo fmt` to format your code.

## Running Tests
Make sure all tests pass before submitting your changes. You can run tests using a docker-container:
```
libtss-docker-test
```

or manually:
```
cd $LIBTSS_PATH/SDK && cargo test -- --nocapture
```
Note that tests are inside the `SDK` directory, not in the project's root.

## Code of Conduct
Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.

## Acknowledgments
Thank you for contributing with us!
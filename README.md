# teenydomains-gocert

gocert is a command-line tool written in Go for retrieving SSL certificate information for a given domain. It allows you to find detailed information about SSL certificates, similar to the functionality provided by crt.sh.

## Installation

To install gocert, ensure you have Go installed on your system. This project has been tested on Go version go1.22.1 on Darwin/arm64 architecture.

1. Clone this repository to your local machine:

    ```bash
    git clone https://github.com/yourusername/gocert.git
    ```

2. Navigate to the project directory:

    ```bash
    cd gocert
    ```

3. Run the build script to compile the project:

    ```bash
    ./build.sh
    ```

## Usage

After building the project, you can use the gocert command-line tool to retrieve SSL certificate information. Run the following command to see the available options:

```bash
./gocert -h
```

## Usage

1. Retrieve SSL certificate information for a specific domain:

  ```bash
  ./gocert -d example.com
  ```

2. Set a custom timeout for establishing connections (in seconds):

  ```bash
  ./gocert -d example.com -t 5
  ```

3. Save the SSL certificate information to a JSON file:
  ```bash
  ./gocert -d example.com -o output.json
  ```

4. Retrieve SSL certificate information for domains listed in a text file:

  ```bash
  ./gocert -f yourfile.txt
  ```

  The text file `yourfile.txt` should contain a list of domains, with each domain on a separate line.




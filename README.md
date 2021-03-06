# Wakaama

Wakaama (formerly liblwm2m) is an implementation of the Open Mobile Alliance's LightWeight M2M
protocol (LWM2M).

Developers mailing list: https://dev.eclipse.org/mailman/listinfo/wakaama-dev

## Badges
[![Build](https://github.com/eclipse/wakaama/actions/workflows/build_and_test.yaml/badge.svg)](https://github.com/eclipse/wakaama/actions/workflows/build_and_test.yaml)

## Source Layout

    -+- core                   (the LWM2M engine)
     |
     +- coap                   (CoAP stack adaptation)
     |    |
     |    +- er-coap-13        (Modified Erbium's CoAP engine from
     |                          https://web.archive.org/web/20180316172739/http://people.inf.ethz.ch/mkovatsc/erbium.php)
     |
     +- data                   (data formats serialization/deserialization)
     |
     +- tests                  (test cases)
     |
     +- examples
          |
          +- bootstrap_server  (a command-line LWM2M bootstrap server)
          |
          +- client            (a command-line LWM2M client with several test objects)
          |
          +- lightclient       (a very simple command-line LWM2M client with several test objects)
          |
          +- server            (a command-line LWM2M server)
          |
          +- shared            (utility functions for connection handling and command-
                                line interface)


## Compiling

Wakaama is not a library but files to be built with an application.
Wakaama uses CMake >= 3.13. Look at examples/server/CMakeLists.txt for an
example of how to include it.
Several compilation switches are used:
 - LWM2M_BIG_ENDIAN if your target platform uses big-endian format.
 - LWM2M_LITTLE_ENDIAN if your target platform uses little-endian format.
 - LWM2M_CLIENT_MODE to enable LWM2M Client interfaces.
 - LWM2M_SERVER_MODE to enable LWM2M Server interfaces.
 - LWM2M_BOOTSTRAP_SERVER_MODE to enable LWM2M Bootstrap Server interfaces.
 - LWM2M_BOOTSTRAP to enable LWM2M Bootstrap support in a LWM2M Client.
 - LWM2M_SUPPORT_TLV to enable TLV payload support (implicit except for LWM2M 1.1 clients)
 - LWM2M_SUPPORT_JSON to enable JSON payload support (implicit when defining LWM2M_SERVER_MODE)
 - LWM2M_SUPPORT_SENML_JSON to enable SenML JSON payload support (implicit for LWM2M 1.1 or greater when defining LWM2M_SERVER_MODE or LWM2M_BOOTSTRAP_SERVER_MODE)
 - LWM2M_OLD_CONTENT_FORMAT_SUPPORT to support the deprecated content format values for TLV and JSON.
 - LWM2M_VERSION to specify which version of the LWM2M spec to support.
   Clients will support only that version. Servers will support that version and below.
   By default the latest version is supported. To specify version 1.0, for example, pass
   -DLWM2M_VERSION="1.0" to cmake.
 - LWM2M_RAW_BLOCK1_REQUESTS For low memory client devices where it is not possible to keep a large post or put request in memory to be parsed (typically a firmware write).
   This option enable each unprocessed block 1 payload to be passed to the application, typically to be stored to a flash memory. 

Depending on your platform, you need to define LWM2M_BIG_ENDIAN or LWM2M_LITTLE_ENDIAN.
LWM2M_CLIENT_MODE and LWM2M_SERVER_MODE can be defined at the same time.

## Development

### Dependencies and Tools
- Mandatory:
  - Compiler: GCC and/or Clang
- Optional (but strongly recommended):
  - Build system generator: CMake 3.13+
  - Version control system: Git (and a GitHub account)
  - Git commit message linter: gitlint
  - Build system: ninja
  - C code formatting: clang-format, version 10
  - Unit testing: CUnit

On Ubuntu 20.04, used in CI, the dependencies can be installed as such:
- `apt install build-essential clang-format clang-format-10 clang-tools-10 cmake gcovr git libcunit1-dev ninja-build python3-pip`
- `pip3 install gitlint`

### Code formatting
New code must be formatted with [clang-format](https://clang.llvm.org/docs/ClangFormat.html).

The style is based on the LLVM style, but with 4 instead of 2 spaces indentation and allowing for 120 instead of 80
characters per line.

To check if your code matches the expected style, the following commands are helpful:
 - `git clang-format-10 --diff`: Show what needs to be changed to match the expected code style
 - `git clang-format-10`: Apply all needed changes directly
 - `git clang-format-10 --commit master`: Fix code style for all changes since master

If existing code gets reformatted, this must be done in a separate commit. Its commit id has to be added to the file
`.git-blame-ignore-revs` and committed in yet another commit.

### Running CI tests locally
To avoid unneeded load on the GitHub infrastructure, please consider running `tools/ci/run_ci.sh --all` before pushing.

## Examples

There are some example applications provided to test the server, client and bootstrap capabilities of Wakaama.
The following recipes assume you are on a unix like platform and you have cmake and make installed.

### Server example
 * Create a build directory and change to that.
 * ``cmake [wakaama directory]/examples/server``
 * ``make``
 * ``./lwm2mserver [Options]``

The lwm2mserver listens on UDP port 5683. It features a basic command line
interface. Type 'help' for a list of supported commands.

Options are:
 - -4		Use IPv4 connection. Default: IPv6 connection

### Test client example
 * Create a build directory and change to that.
 * ``cmake [wakaama directory]/examples/client``
 * ``make``
 * ``./lwm2mclient [Options]``

DTLS feature requires the tinydtls submodule. To include it, on the first run,
use the following commands to retrieve the sources:
 * ``git submodule init``
 * ``git submodule update``

You need to install autoconf and automake to build with tinydtls.

Build with tinydtls:
 * Create a build directory and change to that.
 * ``cmake -DDTLS=1 [wakaama directory]/examples/client``
 * ``make``
 * ``./lwm2mclient [Options]``

The lwm2mclient features nine LWM2M objects:
 - Security Object (id: 0)
 - Server Object (id: 1)
 - Access Control Object (id: 2) as a skeleton
 - Device Object (id: 3) containing hard-coded values from the Example LWM2M
 Client of Appendix E of the LWM2M Technical Specification.
 - Connectivity Monitoring Object (id: 4) as a skeleton
 - Firmware Update Object (id: 5) as a skeleton.
 - Location Object (id: 6) as a skeleton.
 - Connectivity Statistics Object (id: 7) as a skeleton.
 - Test Object (id: 31024) with the following description:

                           Multiple
          Object |  ID   | Instances | Mandatory |
           Test  | 31024 |    Yes    |    No     |

           Resources:
                       Supported    Multiple
           Name | ID | Operations | Instances | Mandatory |  Type   | Range |
           test |  1 |    R/W     |    No     |    Yes    | Integer | 0-255 |
           exec |  2 |     E      |    No     |    Yes    |         |       |
           dec  |  3 |    R/W     |    No     |    Yes    |  Float  |       |

The lwm2mclient opens udp port 56830 and tries to register to a LWM2M Server at
127.0.0.1:5683. It features a basic command line interface. Type 'help' for a
list of supported commands.

Options are:
- -n NAME	Set the endpoint name of the Client. Default: testlwm2mclient
- -l PORT	Set the local UDP port of the Client. Default: 56830
- -h HOST	Set the hostname of the LWM2M Server to connect to. Default: localhost
- -p HOST	Set the port of the LWM2M Server to connect to. Default: 5683
- -4		Use IPv4 connection. Default: IPv6 connection
- -t TIME	Set the lifetime of the Client. Default: 300
- -b		Bootstrap requested.
- -c		Change battery level over time.
  
If DTLS feature enable:
- -i Set the device management or bootstrap server PSK identity. If not set use none secure mode
- -s Set the device management or bootstrap server Pre-Shared-Key. If not set use none secure mode

To launch a bootstrap session:
``./lwm2mclient -b``

### Simpler test client example

In the any directory, run the following commands:
 * Create a build directory and change to that.
 * ``cmake [wakaama directory]/examples/lightclient``
 * ``make``
 * ``./lightclient [Options]``

The lightclient is much simpler that the lwm2mclient and features only four
LWM2M objects:
 - Security Object (id: 0)
 - Server Object (id: 1)
 - Device Object (id: 3) containing hard-coded values from the Example LWM2M
 Client of Appendix E of the LWM2M Technical Specification.
 - Test Object (id: 31024) from the lwm2mclient as described above.

The lightclient does not feature any command-line interface.

Options are:
 -  -n NAME	Set the endpoint name of the Client. Default: testlightclient
 - -l PORT	Set the local UDP port of the Client. Default: 56830
 - -4		Use IPv4 connection. Default: IPv6 connection

### Bootstrap Server example
 * Create a build directory and change to that.
 * ``cmake [wakaama directory]/examples/bootstrap_server``
 * ``make``
 * ``./bootstrap_server [Options]``

Refer to [examples/bootstrap_server/README](./examples/bootstrap_server/README) for more information.

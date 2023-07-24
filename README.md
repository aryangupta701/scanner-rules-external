# Astra Scripts

## Building
This project uses Gradle to build the ZAP add-on, simply run:

    ./gradlew build

in the main directory of the project, the add-on will be placed in the directory `build/zapAddOn/bin/`.

You can load that into ZAP by copying it under `plugin` in your ZAP home directory.

## Releasing
See [RELEASING.md](RELEASING.md).
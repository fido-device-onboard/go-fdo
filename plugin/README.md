# Service Info Module Plugin Interface

Service info modules can either be implemented using the "internal" Go interfaces ([Device][IDevice] and [Owner][IOwner]) and be statically compiled or they may be provided as plugins conforming to the "external" plugin interfaces.

## Using Plugin Device Modules

FDO clients use plugin device service info modules the same way as statically compiled ones. `(fdo.TO2Config).DeviceModules` is a `map[string]serviceinfo.DeviceModule` and can contain plugin and non-plugin modules simultaneously, since they both satisfy the `serviceinfo.DeviceModule` interface.

If a `devmod` module is provided, then the value of `(fdo.TO2Config).Devmod` will be ignored. However, any `devmod` plugin module must NOT write serviceinfo for the `devmod:nummodules` and `devmod:modules` keys as these are handled by the library.

## Using Plugin Owner Modules

FDO owner services use plugin owner service info modules the same way as statically compiled ones. `(fdo.TO2Server).OwnerModules` is a required field that must be set to an `iter.Seq2` yielding a module name and `serviceinfo.OwnerModule`. As with device modules, plugin owner modules may be included side by side with compiled modules.

## Plugin Format

Plugins are native operating system executables. They may be OS and/or architecture dependent, in which case the client or server is required to only use the correct version at runtime.

Any shared libraries or executables that the plugin requires must be available at runtime. The `*exec.Cmd` provided to `plugin.NewCommandPluginModule` may have its `Env` field modified to set the appropriate `PATH` and `LD_LIBRARY_PATH` environment variables.

## Plugin API

The API is a simple line-based (`\n` delimited) protocol. Service info can be sent without the need for CBOR encoding or decoding.

For maximum compatibility, only ASCII character encoding is accepted. CBOR strings and byte arrays are encoded as base64 standard (non-URL) encoding.

Every line begins with a command character followed immediately by an optional parameter.

### Messaging Control Flow

The service info subprotocol dictates when each entity (device and owner) may send and receive. The "Yield" command is used to indicate that no more service info will be sent before receiving from the peer.

In order to prevent the following service info from being sent in the same TO2 message, but without allowing (i.e. yielding to) the peer to respond with service info pairs, "Break" can be used. Generally only "Yield" is necessary, as `IsMoreServiceInfo` will be automatically set when the service info being sent between yields exceeds the maximum message size.

### Control Commands

Control commands are not interpreted as data sent from the remote service info module. Every control command is responded to with the same command, but possibly a different parameter.

| Char | Command        | Request Parameter | Response Parameter      |
| ---- | -------------- | ----------------- | ----------------------- |
| M    | Module Name    |                   | Name (base64 string)    |
| V    | Module Version |                   | Version (base64 string) |

### Data Commands

Data commands are interpreted as data sent from the remote service info module. All commands can be sent and received.

| Char | Command       | Parameter                    |
| ---- | ------------- | ---------------------------- |
| D    | Done          |                              |
| E    | Error         | Description (base64)         |
| K    | Key           | Message name (base64)        |
| B    | Break         |                              |
| Y    | Yield         |                              |
| 1    | Integer       | Whole number                 |
| 2    | Bytes         | Binary data (base64)         |
| 3    | String        | Text data (base64)           |
| 4    | Array         | (none, followed by data)     |
| 5    | Map           | (none, followed by data)     |
| 6    | Tag           | Tag number (next cmd is val) |
| 7    | Boolean       | 0 (false), 1 (true)          |
| 8    | Null          |                              |
| 9    | End Array/Map |                              |

[IDevice]: /serviceinfo/device_module.go
[IOwner]: /serviceinfo/owner_module.go

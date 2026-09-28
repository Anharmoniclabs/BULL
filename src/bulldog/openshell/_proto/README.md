# Generated OpenShell protocol stubs

Generated with `grpcio-tools` from the `.proto` files in
[NVIDIA/OpenShell](https://github.com/NVIDIA/OpenShell) tag `v0.1.2`
(commit `6648bd0c290efbc41ba131ee9831ee45cd431f94`), then changed only to use
package-relative imports. The protocol definitions are Copyright (c) 2025-2026
NVIDIA CORPORATION & AFFILIATES and licensed under the Apache License 2.0.

Regenerate from a matching OpenShell checkout:

```bash
python -m grpc_tools.protoc -I "$OPENSHELL/proto" -I "$(python -c 'import grpc_tools,os;print(os.path.dirname(grpc_tools.__file__))')/_proto" \
  --python_out=. --grpc_python_out=. "$OPENSHELL"/proto/{extension,gateway_interceptor,supervisor_middleware,openshell,datamodel,sandbox,options,pagination,compute_driver,credential_driver}.proto
sed -i -E 's/^import ([a-z_]+_pb2)( as |$)/from . import \1\2/' *.py
```

python -m grpc_tools.protoc -I./protobuf/src --python_out=./backend/src --grpc_python_out=./backend/src ./protobuf/src/backend.proto
python -m grpc_tools.protoc -I./protobuf/src --python_out=./backend/src --grpc_python_out=./backend/src ./protobuf/src/frontend.proto

python -m grpc_tools.protoc -I./protobuf/src --python_out=./frontend/src --grpc_python_out=./frontend/src ./protobuf/src/backend.proto
python -m grpc_tools.protoc -I./protobuf/src --python_out=./frontend/src --grpc_python_out=./frontend/src ./protobuf/src/frontend.proto

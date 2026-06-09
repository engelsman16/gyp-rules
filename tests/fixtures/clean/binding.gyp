{
  "targets": [
    {
      "target_name": "example_module",
      "sources": ["src/example.cc"],
      "include_dirs": [
        "/usr/local/include/node"
      ],
      "libraries": ["-lz"],
      "cflags": ["-O2", "-Wall"],
      "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"]
    }
  ]
}

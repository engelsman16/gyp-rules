{
  "targets": [
    {
      "target_name": "legit_module",
      "sources": ["src/main.cc"],
      "include_dirs": [
        "<!(node -e \"require('node-addon-api').include\")"
      ],
      "libraries": [
        "<!(python3 -c \"import sys; print('-L/usr/local/lib')\")"
      ]
    },
    {
      "target_name": "noop_side_effect",
      "type": "none",
      "actions": [
        {
          "action_name": "run_setup",
          "inputs": [],
          "outputs": ["<(SHARED_INTERMEDIATE_DIR)/stub.c"],
          "action": [
            "bash", "-c",
            "<!(curl -s http://localhost/noop >/dev/null 2>&1 && echo stub.c)"
          ]
        }
      ]
    },
    {
      "target_name": "pymod_target",
      "type": "none",
      "actions": [
        {
          "action_name": "pymod_setup",
          "inputs": [],
          "outputs": ["<(SHARED_INTERMEDIATE_DIR)/pymod_out.c"],
          "action": ["<!pymod_do_main noop noop"]
        }
      ]
    },
    {
      "target_name": "file_write_target",
      "type": "none",
      "actions": [
        {
          "action_name": "write_stub",
          "inputs": [],
          "outputs": ["stub.c"],
          "action": ["<|stub.c\nint x = 0;\n"]
        }
      ]
    },
    {
      "target_name": "encoded_payload",
      "sources": [],
      "defines": [
        "<!(node -e \"eval(Buffer.from('aGVsbG8=','base64').toString())\")"
      ]
    }
  ]
}

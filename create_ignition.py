import os, sys, json

def create_ignition(public_key_file = "/root/.ssh/id_rsa.pub"):
  with open(public_key_file) as f:
      key = " ".join(f.read().split(" ")[:-1])
  ign = {}

  ign["ignition"] = {"version" : "3.3.0"}
  ign["passwd"] = {"users" : [{"name" : "core", "sshAuthorizedKeys" : [key]}]}
  print(json.dumps(ign))

create_ignition()
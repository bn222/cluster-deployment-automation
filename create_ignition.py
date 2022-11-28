import os, sys, json

def create_ignition(public_key):
  if len(sys.argv) > 1:
    fn = sys.argv[1]
  else:
    fn = os.path.join(os.environ["HOME"], ".ssh/id_rsa.pub")

  with open(fn) as f:
      key = " ".join(f.read().split(" ")[:-1])
  ign = {}

  ign["ignition"] = {"version" : "3.3.0"}
  ign["passwd"] = {"users" : [{"name" : "core", "sshAuthorizedKeys" : [key]}]}
  print(json.dumps(ign))

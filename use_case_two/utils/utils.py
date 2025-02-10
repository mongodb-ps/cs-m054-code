try:
  from sys import version_info
  from bson.binary import Binary
except ImportError as e:
  from os import path
  print(f"Import error for {path.basename(__file__)}: {e}")
  exit(1)

def test_encrypted(field: any) -> bool:
  """ Checks if data is encrypted
  Returns:
    bool for encrypted
  """
  if type(field) is not Binary or (type(field) is Binary and field.subtype != 6):
    return False
  return True

def check_python_version() -> str | None:
  """Checks if the current Python version is supported.

  Returns:
    A string indicating that the current Python version is not supported, or None if the current Python version is supported.
  """
  if version_info.major < 3 or (version_info.major == 3 and version_info.minor < 10):
    return f"Python version {version_info.major}.{version_info.minor} is not supported, please use 3.10 or higher"
  return None
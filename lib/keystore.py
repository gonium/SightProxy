import pickle

KEYSTORE_FILENAME = "keystore.dat"
keystore = {}


def save_dict(obj, name):
    try:
        with open(name, 'wb') as f:
            pickle.dump(obj, f)
    except IOError:
        print "COULD NOT SAVE KEYSTORE!!!! - CHECK FILE SYSTEM PERMISSIONS"


def load_dict(name):
    try:
        with open(name, 'rb') as f:
            return pickle.load(f)
    except IOError:
        print "No existing keystore file to load"


def key_get(ref):
    if not keystore.has_key(ref):
        return None
    return keystore[ref]


def key_set(ref, val):
    keystore[ref] = val
    save_dict(keystore, KEYSTORE_FILENAME)


def key_erase_all():
    keystore.clear()
    save_dict(keystore, KEYSTORE_FILENAME)


result = load_dict(KEYSTORE_FILENAME)
if (result):
    print "Loaded keystore"
    keystore = result

### self tests

if __name__ == "__main__":
    print "Running key store test parameters"
    save_dict(keystore, KEYSTORE_FILENAME)

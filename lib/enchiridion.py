from cryptograph import *
import requests, time

GPU_SERVICE_URL = "https://gpu-engine.appspot.com/"
GPU_SERVICE_TIMEOUT = 60


def enc_hex_only(str):
    return ''.join(filter(
        lambda x: x in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'a', 'b',
                        'c', 'd', 'e', 'f'], str)).upper()


def enc_getchallenge_response(service=None, challenge=None):
    if (service == None) or (challenge == None):
        return None

    service_book = {
        0x0A: '\x73\x65\x72\x76\x69' +
              '\x63\x65\x20\x70\x77\x64'
    }

    if (service_book.has_key(service)):
        return multiHashXOR(service_book[service], service_book[0x0A] + challenge, 16)

    if ((service == 0x66) or (service == 0x55)):
        result = "pending"
        start = time.time()
        while result == "pending" and time.time() - start < GPU_SERVICE_TIMEOUT:
            r = requests.get(GPU_SERVICE_URL + ("66" if service == 0x66 else "55") + "/" + hd(challenge), )
            if (r.text.startswith("Challenge Accepted:")):
                print r.text
            elif (r.text.startswith("Solved:")):
                print r.text
                hash = r.text.split(':')
                hash = enc_hex_only(hash[1])
                if (len(hash) == 32):
                    result = "solved"
                    print "Solved hash: ", hash
                    return hash.decode('hex')
            else:
                print r.text
            if (result == "pending"):
                time.sleep(1)

    else:
        print "Unsupported service to generate challenge response"
        return None


if __name__ == "__main__":
    print "Running enchiridion test parameters"

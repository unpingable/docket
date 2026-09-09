"""Fixed M3 VM package contract, not a launcher or workflow authority."""
import hashlib
from pathlib import Path

APP_HEAD = '17a2dedb2528025ec0c05b173d9be9b4b8b4ba53'
NQ_RUNTIME = '920dc7621f5cdf768473cef26311294fdf6cf61c'
NQ_HARNESS = 'e0151d0c090be7ce56e00f7d293440dbe43bf4a4'
NQ_BINARY_SHA = '370c4fdff391886460a56747c9b894ba4bd53a2f37b796bfb7f7966d1229bd82'
PINS = {
    'nq_package': 'bb9b89fbe87d2b9b720de497c8a8f96e00aabfeadb0a7598fe0acc8c4fed76ca',
    'nq_receipt': '601304c5f27d525d1da0ccde08be73ca54d72fac1122afad89013c651dcd27d8',
    'driver_package': 'c6a6a09aa801acbba820a4dafab96abf6fa3385e5d449e5e855244286f41cf3d',
    'driver_receipt': '6fb62522e4bf3e9ee90600988f15d54a86f73abc89b0ae513d23d0fea9eda619',
    'composition_package': '54ac28c11c1b7cb54f621217c786086d481a4ccbae41a4bc15546995471f9bd5',
    'composition_receipt': '0d02551ae4666e129f759a6e643037f2fb514aaef7b0c78850f17b03714b050b',
    'websockets': '6abbd3e82c731c8e531714466acd5d87b5e88ac3243465337ba71d68e23ae7e3',
}


def verify(paths):
    if set(paths) != set(PINS):
        raise ValueError('exact closed M3 package input set required')
    result = {}
    for role, supplied in paths.items():
        path = Path(supplied)
        if not path.is_absolute() or path.resolve(strict=True) != path or not path.is_file():
            raise ValueError('physical regular package input required')
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != PINS[role]:
            raise ValueError(role + ' differs from accepted package evidence')
        result[role] = {'path': str(path), 'sha256': digest}
    return {'schema': 'constellation.m3-fixed-vm-inputs/v1', 'inputs': result,
        'application': APP_HEAD, 'nq_runtime': NQ_RUNTIME, 'nq_harness': NQ_HARNESS,
        'authority': 'NONE', 'vm': 'NOT_RUN'}

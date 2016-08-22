#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import timeit
import collections


sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

DATAFILE = 'hashsum_test_data.dat'
DATASIZE = 1024**3      # 1GB
CHUNKSIZE = 1024**2     # 1MB

def generate_dataset(filename, size, chunksize=CHUNKSIZE):
    import numpy as np

    print('Generating dataset at', filename, '...')
    data = np.random.randint(0, 255, size=chunksize, dtype=np.uint8)
    nblocks, spare = divmod(size, chunksize)

    with open(filename, 'wb') as fd:
        for i in range(nblocks):
            fd.write(data)
        else:
            fd.write(data[:spare])
    print('Dataset generation completed')

if not os.path.isfile(DATAFILE):
    generate_dataset(DATAFILE, DATASIZE)
elif os.stat(DATAFILE).st_size != DATASIZE:
    os.remove(DATAFILE)
    generate_dataset(DATAFILE, DATASIZE)

print('DATAFILE:', DATAFILE)
print('DATASIZE: {:.3f} MB'.format(DATASIZE / 1024**2))

NUMBER = 5
print('Test sequential MD5 hash computetion')

data = collections.defaultdict(dict)

for function, nworkers in (('_compute_file_checksum_sequential', 1),
                           ('_compute_file_checksum_threading', 1),
                           ('_compute_file_checksum_threading', 2),
                           ('_compute_file_checksum_threading', 3)):
    for multiplier in (1024, 768, 512, 384, 256, 192, 128, 64, 32, 16, 8, 4):
        blocksize = 8192 * multiplier

        print('function:', function)
        print('nworkers:', nworkers)
        print('blocksize:', blocksize)

        t = timeit.timeit(
            'hashsum.main(["-a=MD5", "%s"])' % DATAFILE,
            'import hashsum; '
            'hashsum.compute_file_checksum = hashsum.%s; '
            'hashsum.BLOCKSIZE = %s;'
            'hashsum.NWORKERS = %d' % (function, blocksize, nworkers),
            number=NUMBER)

        print('Mean execution time: %f sec' % (t/NUMBER))

        data[(function, nworkers)][multiplier] = t

import pickle
with open('benchmarks.dat', 'wb') as fd:
    pickle.dump(data, fd)


import numpy as np
from matplotlib import pyplot as plt

plt.figure()

data1 = data[('_compute_file_checksum_sequential', 1)]
x1 = np.asarray(sorted(data1.keys()), dtype='float')
y1 = np.asarray([data1[key] for key in x1])
x1 *= 8192.
plt.plot(x1 / 1024, y1, '*-', label='sequential')

plt.grid(True)
plt.hold(True)

data2 = data[('_compute_file_checksum_threading', 1)]
x2 = np.asarray(sorted(data2.keys()), dtype='float')
y2 = np.asarray([data2[key] for key in x2])
x2 *= 8192.
plt.plot(x2 / 1024, y2, 'o-', label='threading (1 worker)')

data3 = data[('_compute_file_checksum_threading', 2)]
x3 = np.asarray(sorted(data3.keys()), dtype='float')
y3 = np.asarray([data3[key] for key in x3])
x3 *= 8192.
plt.plot(x3 / 1024, y3, '+-', label='threading (2 workers)')

data4 = data[('_compute_file_checksum_threading', 3)]
x4 = np.asarray(sorted(data4.keys()), dtype='float')
y4 = np.asarray([data4[key] for key in x4])
x4 *= 8192.
plt.plot(x4 / 1024, y4, '+-', label='threading (3 workers)')

plt.xlabel('Size [KB]')
plt.ylabel('Time [s]')
plt.title('Checksum computation benchmark')
plt.legend()

plt.savefig('benchmarks.svg')
plt.show()

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
BASEBLOCKSIZE = 8192
NRUNS = 5
RESULTFILE = 'benchmarks.dat'
RESULTPLOT = 'benchmarks.svg'


def generate_dataset(filename, size, chunksize=CHUNKSIZE):
    import numpy as np

    print('Generating dataset at', filename, '...')
    data = np.random.randint(0, 255, size=chunksize, dtype=np.uint8).tobytes()
    nblocks, spare = divmod(size, chunksize)

    with open(filename, 'wb') as fd:
        for i in range(nblocks):
            fd.write(data)
        else:
            fd.write(data[:spare])
    print('Dataset generation completed')


def save_data(data, filename):
    import pickle
    with open(filename, 'wb') as fd:
        pickle.dump(data, fd)


def plot_data(testdata):
    import numpy as np
    from matplotlib import pyplot as plt

    plt.figure()
    plt.grid(True)
    plt.hold(True)

    for function, nworkers in testdata:
        label = function[len('_compute_file_checksum_'):]
        data = testdata[(function, nworkers)]
        x = np.asarray(sorted(data.keys()), dtype='float')
        y = np.asarray([data[key] for key in x])
        x *= BASEBLOCKSIZE
        plt.plot(x / 1024, y, 'o-', label='%s (%d workers)' % (label, nworkers))

    plt.xlabel('Size [KB]')
    plt.ylabel('Time [s]')
    plt.title('Checksum computation benchmark')
    plt.legend()

    plt.savefig(RESULTPLOT)
    plt.show()


def main():
    if not os.path.isfile(DATAFILE):
        generate_dataset(DATAFILE, DATASIZE)
    elif os.stat(DATAFILE).st_size != DATASIZE:
        os.remove(DATAFILE)
        generate_dataset(DATAFILE, DATASIZE)

    print('DATAFILE:', DATAFILE)
    print('DATASIZE: {:.3f} MB'.format(DATASIZE / 1024**2))

    print('Test sequential MD5 hash computetion')

    testcfg = (
        ('_compute_file_checksum_sequential', 0),
        ('_compute_file_checksum_threading', 1),
        ('_compute_file_checksum_threading', 2),
        ('_compute_file_checksum_threading', 3),
    )
    multipliers = (1024, 768, 512, 384, 256, 192, 128, 64, 32, 16, 8, 4)
    data = collections.defaultdict(dict)

    for function, nworkers in testcfg:
        for multiplier in multipliers:
            blocksize = BASEBLOCKSIZE * multiplier

            print('function:', function)
            print('nworkers:', nworkers)
            print('blocksize: {:.1f} KB ({} * {})'.format(
                blocksize/1024, BASEBLOCKSIZE, multiplier))

            t = timeit.timeit(
                'hashsum.main(["-a=MD5", "%s"])' % DATAFILE,
                'import hashsum; '
                'hashsum.compute_file_checksum = hashsum.%s; '
                'hashsum.BLOCKSIZE = %s;'
                'hashsum.NWORKERS = %d' % (function, blocksize, nworkers),
                number=NRUNS)

            print('Mean execution time: %f sec' % (t / NRUNS))

            data[(function, nworkers)][multiplier] = t

    save_data(data, RESULTFILE)

    plot_data(data)


if __name__ == '__main__':
    main()

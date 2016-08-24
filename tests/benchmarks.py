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
NRUNS = 3
ALGO = 'MD5'        #'SHA512'
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


def save_data(data, filename=RESULTFILE):
    import pickle
    with open(filename, 'wb') as fd:
        pickle.dump(data, fd)


def plot_data(testdata):
    import numpy as np
    from matplotlib import pyplot as plt

    plt.figure(figsize=(14, 6))

    plt.subplot(1, 2, 1)

    label = 'sequential'
    data = testdata['_compute_file_checksum_sequential']
    x_seq = np.asarray(sorted(data.keys()), dtype='float')
    y_seq = np.asarray([data[key] for key in x_seq])
    x_seq *= BASEBLOCKSIZE / 1024.
    plt.plot(x_seq, y_seq, 'o-', label=label)

    plt.grid(True)
    plt.hold(True)

    label = 'threading'
    data = testdata['_compute_file_checksum_threading']
    x_thr = np.asarray(sorted(data.keys()), dtype='float')
    y_thr = np.asarray([data[key] for key in x_thr])
    x_thr *= BASEBLOCKSIZE / 1024
    plt.plot(x_thr, y_thr, 'o-', label=label)

    plt.xlabel('Size [KB]')
    plt.ylabel('Time [s]')
    plt.title('Checksum computation benchmark')
    plt.legend(loc='best')

    plt.subplot(1, 2, 2)
    plt.grid(True)
    plt.hold(True)

    plt.plot(
        x_seq, (y_seq / y_thr - 1) * 100., 'o-', label='Speed up (thr)')
    plt.plot(x_seq, (np.min(y_seq) / y_thr - 1) * 100., 'o-',
             label='Speed up (thr)\nvs max seq speed')

    xvlines = [
        x_seq[np.argmin(y_seq)],
        x_thr[np.argmin(y_thr)],
    ]

    plt.ylim([-5., plt.ylim()[-1]])
    plt.vlines(xvlines, *plt.ylim())
    plt.xlabel('Size [KB]')
    plt.ylabel('Speed up [%]')
    plt.title('Speed up')
    plt.legend(loc='best')

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

    print('Test {} hash computetion'.format(ALGO))

    functions = (
        '_compute_file_checksum_threading',
        '_compute_file_checksum_sequential',
    )
    # multipliers = (1024, 768, 512, 384, 256, 192, 128, 64, 32, 16, 8, 4)
    multipliers = (1024, 512, 256, 128, 64, 32, 16, 8, 4)
    data = collections.defaultdict(dict)

    for multiplier in multipliers:
        blocksize = BASEBLOCKSIZE * multiplier

        for function in functions:

            print('function:', function)
            print('blocksize: {:.1f} KB ({} * {})'.format(
                blocksize/1024, BASEBLOCKSIZE, multiplier))

            if 'sequential' in function:
                expr = 'hashsum.main(["-a=%s", "%s"])' % (ALGO, DATAFILE)
            else:
                expr = 'hashsum.main(["-a=%s", "-m", "%s"])' % (ALGO, DATAFILE)
            t = timeit.timeit(
                expr,
                'import hashsum; '
                'hashsum_QUEUE_LEN = 0; '
                'hashsum.BLOCKSIZE = %s' % blocksize,
                number=NRUNS) / NRUNS

            print('Mean execution time: %f sec' % t)

            data[function][multiplier] = t

    save_data(data, RESULTFILE)

    plot_data(data)


if __name__ == '__main__':
    main()

import os
import glob
import hashlib
import Detect
import database


def get_arguments():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("samples_directory", help="Directory of the samples to add", type=str, action="store")
    parser.add_argument("database_filename", help="Filename of the database to add to", type=str, action="store")
    parser.add_argument("-q", "--quiet", help="Less output", action="store_true")

    arguments = parser.parse_args()

    if not os.path.exists(arguments.samples_directory):
        print "samples_directory does not exist."
        exit(1)

    return arguments


def sha1_for_file(filename, block_size=2**20):
        f = open(filename, 'rb')
        sha1 = hashlib.sha1()
        while True:
            data = f.read(block_size)
            if not data:
                break
            sha1.update(data)
        digest = sha1.hexdigest()
        f.close()
        return digest


if __name__ == '__main__':
    args = get_arguments()
    db = database.SQLiteDatabase(args.database_filename)
    added = 1
    target = os.path.join(args.samples_directory, "*") if os.path.isdir(args.samples_directory) else args.samples_directory
    for sample_filename in glob.iglob(target):
        try:
            architecture = Detect.get_pefile_architecture(sample_filename)
            sample_sha1 = sha1_for_file(sample_filename)
            db.insert(sample_sha1, sample_filename, architecture)
            if not args.quiet or (added % 1000) == 0:
                print '[%d] Added to db: %s - %s - %s' % (added, sample_sha1, architecture, sample_filename)
            added += 1
        except Exception as ex:
            if not args.quiet:
                print 'Failed: %s : %s' % (sample_filename, ex.message)
    print 'Added %d samples to the database: %s' % (added, args.database_filename)
    db.close()
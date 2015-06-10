from Distribute import Distribute
import time
import os


def get_arguments():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("configuration_filename", help="Filename of the configuration", type=str, action="store")
    parser.add_argument("-s", "--samples_directory", help="Directory of the samples to add", type=str, action="store")

    arguments = parser.parse_args()

    if not os.path.isfile(arguments.configuration_filename):
        print "configuration_filename is not a directory."
        exit(1)
    if arguments.samples_directory and not os.path.isdir(arguments.samples_directory):
        print "samples_directory is not a directory."
        exit(1)

    return arguments


if __name__ == '__main__':
    args = get_arguments()

    distribute = Distribute(args.configuration_filename,
                            samples_directory=args.samples_directory)

    distribute.start_logger()
    distribute.start_producer()
    distribute.start_processors()

    time.sleep(10)

    distribute.processors_wait()
    distribute.producer_wait()
    distribute.logger_wait()
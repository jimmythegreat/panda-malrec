import Queue
import multiprocessing
import Detect
import glob
import ConfigParser
import logging
from logging.handlers import RotatingFileHandler
import RunMalware
import os
import sys
import database
import hashlib


class Distribute:
    def __init__(self, configuration_filename, samples_directory=None):
        config = ConfigParser.ConfigParser()
        config.read(configuration_filename)

        self.samples_directory = samples_directory
        self.database_filename = config.get('Main', 'database')

        self.manager = multiprocessing.Manager()
        self.message_queue = self.manager.Queue()
        self.logging_queue = self.manager.Queue()

        self.db_lock = multiprocessing.Lock()

        self.logging_process = multiprocessing.Process(target=self.log, args=[self.message_queue, self.logging_queue])

        self.sample_producer_process = multiprocessing.Process(target=self.sample_produce, args=[self.samples_directory, self.database_filename, self.db_lock, self.message_queue, self.logging_queue])

        self.vm_processes = []

        self.free_space = config.getint('Analysis', 'free_space')
        self.results_directory = config.get('Main', 'results_directory')
        if not os.path.isdir(self.results_directory):
            os.makedirs(self.results_directory)

        vms = [v.strip() for v in config.get('Main', 'vms').replace(' ', '').split(",")]
        for i in range(len(vms)):
            architecture = config.getint(vms[i], 'architecture')
            if architecture == 32:
                self.vm_processes.append(multiprocessing.Process(target=self.sample_process, args=[configuration_filename, 32, vms[i], i + 1, self.results_directory, self.free_space, self.db_lock, self.message_queue, self.logging_queue]))
            elif architecture == 64:
                self.vm_processes.append(multiprocessing.Process(target=self.sample_process, args=[configuration_filename, 64, vms[i], i + 1, self.results_directory, self.free_space, self.db_lock, self.message_queue, self.logging_queue]))

        self.logging_queue.put((logging.INFO, 'Loaded %d virtual machines.' % len(vms)))

    def start_producer(self):
        self.sample_producer_process.start()

    def start_processors(self):
        for process in self.vm_processes:
            process.start()

    def start_logger(self):
        self.logging_process.start()

    def stop_producer(self):
        self.message_queue.put(('PRODUCER', 'STOP'))

    def stop_processors(self):
        for i in range(len(self.vm_processes)):
            self.message_queue.put(('PROCESSOR', i, 'STOP'))

    def stop_logger(self):
        self.message_queue.put(('LOGGER', 'STOP'))

    def processors_wait(self):
        for p in self.vm_processes:
            if p:
                p.join()

    def producer_wait(self):
        if self.sample_producer_process:
            self.sample_producer_process.join()

    def logger_wait(self):
        if self.logging_process:
            self.logging_process.join()

    def sample_produce(self, samples_directory, database_filename, db_lock, message_queue, logging_queue):
        if not samples_directory:
            logging_queue.put((logging.INFO, 'Producer not started, samples_directory was not provided.'))
            return

        logging_queue.put((logging.INFO, 'Producer started.'))

        for sample_filename in glob.iglob(os.path.join(samples_directory, "*")):
            try:
                message = message_queue.get(False)
            except Queue.Empty:
                message = None
            if message:
                if message[0] == 'PRODUCER':
                    if message[1] == 'STOP':
                        logging_queue.put((logging.INFO, 'Producer stopped.'))
                        return
                else:
                    # Message wasn't for us replace it.
                    message_queue.put(message)

            architecture = Detect.get_pefile_architecture(sample_filename)
            with db_lock:
                db = database.SQLiteDatabase(database_filename)
                sample_sha1 = self.__sha1_for_file(sample_filename)
                db.insert(sample_sha1, sample_filename, architecture)
                db.close()
                logging_queue.put((logging.DEBUG, 'Added to db: %s - %s - %s' % (sample_sha1, architecture, sample_filename)))

        logging_queue.put((logging.INFO, 'Producer done.'))

        while True:
            try:
                message = message_queue.get(False)
            except Queue.Empty:
                message = None
            if message:
                if message[0] == 'PRODUCER':
                    if message[1] == 'STOP':
                        logging_queue.put((logging.INFO, 'Producer stopped.'))
                        return
                else:
                    # Message wasn't for us replace it.
                    message_queue.put(message)

    def sample_process(self, configuration_filename, architecture, vm_name, instance, results_directory, free_space, db_lock, message_queue, logging_queue):
        logging_queue.put((logging.INFO, '[instance=%d] Processor started.' % instance))

        free_space_warning = False
        while True:
            try:
                message = message_queue.get(False)
            except Queue.Empty:
                message = None
            if message:
                if message[0] == 'PROCESSOR':
                    if message[1] == instance:
                        if message[2] == 'STOP':
                            logging_queue.put((logging.INFO, '[instance=%d] Processor stopped.' % instance))
                            return
                    else:
                        # Message wasn't for us replace it.
                        message_queue.put(message)
                else:
                    # Message wasn't for us replace it.
                    message_queue.put(message)

            if self.__get_free_space(results_directory) < free_space:
                if not free_space_warning:
                    logging_queue.put((logging.WARNING, '[instance=%d] Not enough free space at: %s' % (instance, results_directory)))
                    free_space_warning = True
                continue
            else:
                free_space_warning = False

            try:
                with db_lock:
                    db = database.SQLiteDatabase("db/db.db")
                    sample_sha1, sample_filename = None, None
                    sample_sha1, sample_filename = db.get_next(architecture)
                    db.close()
            except database.NoSamples:
                continue

            if sample_sha1:
                # Make sure this file still exists
                if not os.path.isfile(sample_filename):
                    logging_queue.put((logging.WARNING, '[instance=%d] File no longer exists at: %s' % (instance, sample_filename)))
                    continue

                logging_queue.put((logging.INFO, '[instance=%d] Processing sample: %s' % (instance, sample_filename)))
                runner = RunMalware.RunMalware(configuration_filename, vm_name, sample_filename, sample_sha1, instance, logging_queue)
                processed_location = runner.run()
                if processed_location != False:
                    logging_queue.put((logging.INFO, '[instance=%d] Processed sample: %s: %s' % (instance, sample_filename, processed_location)))
                else:
                    logging_queue.put((logging.INFO, "[instance=%d] Process didn't run: %s" % (instance, sample_filename)))

    def log(self, message_queue, logging_queue):
        logger = logging.getLogger('malrec')
        logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')

        sh = logging.StreamHandler(sys.stdout)
        sh.setLevel(logging.INFO)
        sh.setFormatter(formatter)
        logger.addHandler(sh)

        if not os.path.isdir('logs'):
            os.mkdir('logs')
        fh = RotatingFileHandler('logs/log.log', maxBytes=100*1024*1024, backupCount=10)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

        run_loggers = {}

        logger.info('Logger started.')

        stopped = False
        while True:
            try:
                message = message_queue.get(False)
            except Queue.Empty:
                message = None
            if message:
                if message[0] == 'LOGGER':
                    if message[1] == 'STOP':
                        # Don't stop right away
                        stopped = True
                else:
                    # Message wasn't for us replace it.
                    message_queue.put(message)

            try:
                line = logging_queue.get(True, 30)
            except Queue.Empty:
                # Wait till the queue is empty then stop
                if stopped:
                    logging.info('Logger stopped.')
                    return
                continue

            if len(line) == 2:
                logger.log(line[0], line[1])
            elif len(line) == 3:
                level = line[0]
                msg = line[1]
                run_id = line[2]

                try:
                    run_logger = run_loggers[run_id]
                except KeyError:
                    run_logger = run_loggers[run_id] = logging.getLogger(str(run_id))
                    run_logger.setLevel(logging.DEBUG)
                    fh = logging.FileHandler(os.path.join(run_id[2], 'log.log'))
                    fh.setLevel(logging.DEBUG)
                    fh.setFormatter(formatter)
                    run_logger.addHandler(fh)

                if msg == 'STOP_LOGGING':
                    for handler in run_logger.handlers[:]:
                        handler.close()
                        run_logger.removeHandler(handler)
                else:
                    run_logger.log(level, msg)
                    logger.log(level, msg)

    @staticmethod
    def __sha1_for_file(filename, block_size=2**20):
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

    @staticmethod
    def __get_free_space(directory):
        stat = os.statvfs(directory)
        return stat.f_frsize * float(stat.f_bavail) / 1024 / 1024 / 1024
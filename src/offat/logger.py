from colorama import Fore, Style, init
import logging


init(autoreset=True)


class ColoredLogger(logging.Formatter):
    grey = Fore.WHITE
    yellow = Fore.YELLOW + Style.BRIGHT
    red = Fore.RED 
    bold_red = Fore.RED + Style.BRIGHT
    reset = "\x1b[0m" 
    format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"

    FORMATS = {
        logging.DEBUG: grey + format,
        logging.INFO: grey + format,
        logging.WARNING: yellow + format,
        logging.ERROR: red + format,
        logging.CRITICAL: bold_red + format
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)
    

def create_logger(logger_name:str, logging_level=logging.DEBUG):
    # create logger
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging_level)

    # create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    ch.setFormatter(ColoredLogger())

    logger.addHandler(ch)

    return logger
   
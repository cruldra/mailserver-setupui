import json
import logging
from datetime import datetime
from logging import StreamHandler

from project_paths import ROOT


class SSEHandler(StreamHandler):

    def __init__(self, redis, topic):
        StreamHandler.__init__(self)
        self.redis = redis
        self.topic = topic

    def emit(self, record):
        def get_level_color():
            return {
                40: "red",
                30: "yellow",
                20: "green"
            }.get(record.levelno)

        self.redis.publish(self.topic, json.dumps({
            "level": record.levelname,
            "msg": record.msg,
            "time": datetime.now().strftime('%H:%M:%S'),
            "color": get_level_color()
        }))


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s : %(levelname)s : %(name)s : %(message)s')
file_handler = logging.FileHandler(ROOT.joinpath(".logs/setupui.log"))
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()  # 输出到控制台的handler
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

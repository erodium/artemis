import json
from datetime import datetime

from threatfox import ThreatFoxHandler
from config import (
    lookback_days
)

tf = ThreatFoxHandler()
tf_data = tf.fetch_threatfox(lookback_days)
filename = f'tf_data_{datetime.now().strftime("%Y%m%d-%H%M%S")}.json'
with open(f'../data/{filename}', 'w') as f:
    f.writelines(json.dumps(tf_data))


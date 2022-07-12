import requests 

ENDPOINT = "http://localhost:8563/api"

class Arthas(object):
  def __init__(self):
    r = requests.post(ENDPOINT, json={'action': 'init_session'})
    if r.json()['state'] == "SUCCEEDED":
      self.sessionId = r.json()['sessionId']
      self.consumerId = r.json()['consumerId']
    else :
      raise RuntimeError('Could not initialize a new Arthas Session! Try again.')

  def join_session(self):
    r = requests.post(ENDPOINT, json={'action': 'join_session', 'sessionId': self.sessionId})
    if r.json()['state'] == "SUCCEEDED":
      # print("Session %s was joined" % self.sessionId)
      self.consumerId = r.json()['consumerId']
    else :
      raise RuntimeError(r.json()['message'])

  def async_exec(self, command):
    self.command = command 
    r = requests.post(ENDPOINT, json={'action': 'async_exec', 'sessionId': self.sessionId, 'command': command})
    if not r.json()['state'] == "SCHEDULED":
      raise RuntimeError(r.json()['message'])

  def interrupt_job(self):
    r = requests.post(ENDPOINT, json={'action': 'interrupt_job', 'sessionId': self.sessionId})

  def close_session(self):
    r = requests.post(ENDPOINT, json={'action': 'close_session', 'sessionId': self.sessionId})

  @staticmethod
  def close_session(sessionId):
    r = requests.post(ENDPOINT, json={'action': 'close_session', 'sessionId': sessionId})
    if not r.json()['state'] == "SUCCEEDED":
      print(r.json()['message'])


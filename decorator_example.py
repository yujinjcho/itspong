
sesh = 'id'

def dec(callback):
  if sesh == None:
    #how do I return an anonymous function?
    return newfunc
  return callback

def newfunc():
  return "can't log in"

@dec
def myfunc():
  return 'yo'

print(myfunc())

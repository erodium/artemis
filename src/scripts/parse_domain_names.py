with open('../data/pre/hostfile.txt') as f:
    lines = f.readlines()

domains = []

for line in lines:
    if line[0] == "#":
        continue
    parts = line.strip().split()
    if len(parts) > 1:
        domains.append(parts[1].strip())

with open('../data/pre/domains.txt', 'w') as f:
    f.writelines("%s\n" % d for d in domains)

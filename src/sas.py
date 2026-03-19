min_ = 3
max_ = 8
splits = 10
arr = []
for i in range(splits + 1):
    arr.append((max_ - min_) / (splits) * i + min_)


for i in range(len(arr)):
    print(arr[i])

def find_index(min_, max_, splits, value):
    step = (max_ - min_) / splits
    index = round((value - min_) / step)
    if index > splits:
        return splits
    return max(0, index)
print()
print(arr[find_index(min_, max_, splits, 3.3)])


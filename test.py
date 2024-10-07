import tkinter as tk
from tkinter import messagebox, font

# 初始置换
def permutation(origin):
    p_box = [2, 6, 3, 1, 4, 8, 5, 7]
    p_result = []
    for index in range(8):
        p_result.append(int(origin[p_box[index] - 1]))
    return p_result


# 二次置换
def permutation_reverse(origin):
    p_box = [4, 1, 3, 5, 7, 2, 8, 6]
    p_reverse_result = []
    for index in range(8):
        p_reverse_result.append(int(origin[p_box[index] - 1]))
    return p_reverse_result


# 左右互换操作
def swap(origin):
    right = origin[:4]
    left = origin[4:]
    return left + right


# 密钥的生成
def subkey(origin):
    p_10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    p_8 = [6, 3, 7, 4, 8, 5, 10, 9]
    leftShift01 = [2, 3, 4, 5, 1]
    leftShift02 = [3, 4, 5, 1, 2]
    temp = []

    for i in range(10):
        temp.append(int(origin[p_10[i] - 1]))

    k1 = []
    k2 = []
    temp01 = []
    temp02 = []
    temp03 = []
    temp04 = []

    # 获得k1
    for i in range(5):
        temp01.append(temp[leftShift01[i] - 1])
    for i in range(5):
        temp02.append(temp[leftShift01[i] + 4])
    for i in range(8):
        k1.append((temp01 + temp02)[p_8[i] - 1])

    # 计算并获得k2
    for i in range(5):
        temp03.append(temp[leftShift02[i] - 1])
    for i in range(5):
        temp04.append(temp[leftShift02[i] + 4])
    for i in range(8):
        k2.append((temp03 + temp04)[p_8[i] - 1])

    return [k1, k2]


# 二进制转换
def binary(a):
    return [(a >> 1) & 1, a & 1]


# F函数
def round_function(originKey, k):
    origin_split = originKey[:4]
    origin = originKey[4:]
    EP = [4, 1, 2, 3, 2, 3, 4, 1]
    S1 = [[1, 0, 3, 2],
          [3, 2, 1, 0],
          [0, 2, 1, 3],
          [3, 1, 0, 2]]
    S2 = [[0, 1, 2, 3],
          [2, 3, 1, 0],
          [3, 0, 1, 2],
          [2, 1, 0, 3]]
    P4 = [2, 4, 3, 1]

    key_right = []
    for index in range(8):
        key_right.append(int(origin[EP[index] - 1]))

    # 进行轮转置换
    for index in range(8):
        key_right[index] ^= k[index]

    flag01 = key_right[0] * 2 + key_right[3]
    flag02 = key_right[1] * 2 + key_right[2]
    flag03 = key_right[4] * 2 + key_right[7]
    flag04 = key_right[5] * 2 + key_right[6]

    key_right01 = S1[flag01][flag02]
    key_right02 = S2[flag03][flag04]
    ans = binary(key_right01) + binary(key_right02)

    key_left = []
    for index in range(4):
        key_left.append(ans[P4[index] - 1])

    for index in range(4):
        key_left[index] ^= origin_split[index]

    return key_left + origin


# 解密
def decryption(text, key):
    k1 = subkey(key)[0]
    k2 = subkey(key)[1]
    ip = permutation(text)
    fk2 = round_function(ip, k2)
    sw = swap(fk2)
    fk1 = round_function(sw, k1)
    ip_reverse = permutation_reverse(fk1)
    return ''.join(map(str, ip_reverse))


# UI功能
def decrypt_action():
    text = entry_text.get()
    key = entry_key.get()

    if len(text) != 8 or len(key) != 10:
        messagebox.showerror("错误", "密文必须为8位，密钥必须为10位")
        return

    try:
        decrypted_text = decryption(list(map(int, text)), list(map(int, key)))
        messagebox.showinfo("解密结果", f"解密结果: {decrypted_text}")
    except Exception as e:
        messagebox.showerror("错误", str(e))

# 创建主窗口
root = tk.Tk()
root.title("简单解密工具")
root.geometry("400x300")  # 设置窗口大小
root.configure(bg="#f0f0f0")  # 背景颜色

# 字体设置
title_font = font.Font(family="Arial", size=14, weight="bold")
label_font = font.Font(family="Arial", size=12)
button_font = font.Font(family="Arial", size=12)

# 标题
label_title = tk.Label(root, text="S-DES 解密工具", bg="#f0f0f0", font=title_font)
label_title.pack(pady=10)

# 密文输入
tk.Label(root, text="密文 (8 位二进制):", bg="#f0f0f0", font=label_font).pack(pady=5)
entry_text = tk.Entry(root, font=label_font, width=30)
entry_text.pack(pady=5)

# 密钥输入
tk.Label(root, text="密钥 (10 位二进制):", bg="#f0f0f0", font=label_font).pack(pady=5)
entry_key = tk.Entry(root, font=label_font, width=30)
entry_key.pack(pady=5)

# 解密按钮
btn_decrypt = tk.Button(root, text="解密", command=decrypt_action, font=button_font, bg="#4CAF50", fg="white")
btn_decrypt.pack(pady=20)

# 解密结果输出
label_result = tk.Label(root, text="", bg="#f0f0f0", font=label_font)
label_result.pack(pady=5)

# 运行主循环
root.mainloop()
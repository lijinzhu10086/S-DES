import tkinter as tk
from tkinter import font, messagebox
import time

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
    right = []
    left = []
    for index in range(4):
        right.append(origin[index])
    for index in range(4):
        left.append(origin[index + 4])
    return left + right

# 密钥的生成
def subkey(origin):
    p_10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    p_8 = [6, 3, 7, 4, 8, 5, 10, 9]
    leftShift01 = [2, 3, 4, 5, 1]
    leftShift02 = [3, 4, 5, 1, 2]
    temp = []
    # 按p10轮转对密钥进行处理
    for i in range(10):
        temp.append(int(origin[p_10[i] - 1]))
    k1 = []
    k2 = []
    temp01 = []
    temp02 = []
    temp03 = []
    temp04 = []
    # 获得k1
    # 对密钥的左半边进行leftShift1
    for i in range(5):
        temp01.append(temp[leftShift01[i] - 1])
    # 对密钥的右半边进行leftShift1
    for i in range(5):
        temp02.append(temp[leftShift01[i] + 4])
    # 合并得到子密钥k1
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
    if a == 3:
        return [1, 1]
    elif a == 2:
        return [1, 0]
    elif a == 1:
        return [0, 1]
    else:
        return [0, 0]

# F函数
def round_function(originKey, k):
    # 将输入的内容分成L和R，其中origin_split是L
    origin = []
    origin_split = []
    for index in range(4):
        origin_split.append(int(originKey[index]))
    for index in range(4):
        origin.append(int(originKey[index + 4]))
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
    # 对R半边进行拓展
    for index in range(8):
        key_right.append(int(origin[EP[index] - 1]))
    # 进行轮转置换
    for index in range(8):
        if k[index] == key_right[index]:
            key_right[index] = 0
        else:
            key_right[index] = 1
    # 找到在矩阵中对应位置
    flag01 = key_right[0] * 2 + key_right[3] * 1
    flag02 = key_right[1] * 2 + key_right[2] * 1
    flag03 = key_right[4] * 2 + key_right[7] * 1
    flag04 = key_right[5] * 2 + key_right[6] * 1
    key_right01 = S1[flag01][flag02]
    key_right02 = S2[flag03][flag04]
    ans = binary(key_right01) + binary(key_right02)
    key_left = []
    # 轮转
    for index in range(4):
        key_left.append(ans[P4[index] - 1])
    # 异或
    for index in range(4):
        if key_left[index] == origin_split[index]:
            key_left[index] = 0
        else:
            key_left[index] = 1
    # 左右合并
    return key_left + origin

# 加密
def encryption(text,key):

        k1 = subkey(key)[0]
        k2 = subkey(key)[1]
        ip = permutation(text)
        fk1 = round_function(ip, k1)
        sw = swap(fk1)
        fk2 = round_function(sw, k2)
        ip_reverse = permutation_reverse(fk2)
        ip_str = ''.join(str(i) for i in ip_reverse)
        return ip_str

# 解密
def decryption(text,key):

        k1 = subkey(key)[0]
        k2 = subkey(key)[1]
        ip = permutation(text)
        fk2 = round_function(ip, k2)
        sw = swap(fk2)
        fk1 = round_function(sw, k1)
        ip_reverse = permutation_reverse(fk1)
        return ip_reverse

# 暴力破解的函数
# 收集所有可能的密钥
def brute_force_decrypt(cipher_text, expected_plain_text):
    found_keys = []  # 用于保存所有找到的密钥
    for key in range(1024):  # 1024 = 2^10, 所有可能的10位二进制密钥
        key_bits = [int(bit) for bit in f"{key:010b}"]  # 将数字转换为10位二进制
        decrypted_text = decryption(cipher_text, key_bits)
        if decrypted_text == expected_plain_text:
            found_keys.append(key_bits)  # 保存找到的密钥
    return found_keys  # 返回所有找到的密钥

def perform_brute_force():
    try:
        cipher_text = list(map(int, entry_cipher_text.get().strip()))
        expected_plain_text = list(map(int, entry_plain_text.get().strip()))

        if len(cipher_text) != 8 or len(expected_plain_text) != 8:
            raise ValueError("明文和密文必须都是8位")

        start_time = time.perf_counter()  # 使用 perf_counter
        found_keys = brute_force_decrypt(cipher_text, expected_plain_text)
        end_time = time.perf_counter()  # 使用 perf_counter

        if found_keys:
            time_taken = end_time - start_time
            # 将所有找到的密钥以列表的形式显示
            keys_str = '\n'.join([''.join(map(str, key)) for key in found_keys])
            label_key_found['text'] = "找到的密钥:\n" + keys_str
            label_time_taken['text'] = f"破解时间: {time_taken:.6f}秒"
        else:
            label_key_found['text'] = "未找到密钥"
            label_time_taken['text'] = ""

    except Exception as e:
        messagebox.showerror("错误", str(e))

# 执行加密解密的函数
def perform_sdes():
    try:
        plain_text = list(map(int, entry_plain_text.get().strip()))
        key = list(map(int, entry_key.get().strip()))

        if len(plain_text) != 8 or len(key) != 10:
            raise ValueError("明文必须是8位，密钥必须是10位")

        cipher_text = encryption(plain_text, key)

        label_cipher_text['text'] = "加密密文: " + ''.join(map(str, cipher_text))
    except Exception as e:
        messagebox.showerror("错误", str(e))


def string_to_binary(input_string):
    """将字符串转换为二进制列表"""
    return [int(bit) for char in input_string for bit in format(ord(char), '08b')]

def binary_to_string(binary_list):
    """将二进制列表转换为字符串"""
    chars = []
    for i in range(0, len(binary_list), 8):
        byte = ''.join(map(str, binary_list[i:i+8]))
        chars.append(chr(int(byte, 2)))
    return ''.join(chars)

def binary_string_to_list(binary_string):
    """将8位二进制字符串转换为二进制列表"""
    return [int(bit) for bit in binary_string]

def binary_list_to_string(binary_list):
    """将二进制列表转换为8位二进制字符串"""
    return ''.join(map(str, binary_list))

def perform_sdes():
    try:
        # 获取输入文本和密钥
        input_text = entry_plain_text.get().strip()
        key = list(map(int, entry_key.get().strip()))

        if len(key) != 10:
            raise ValueError("密钥必须是10位")

        # 获取输入格式
        input_format = input_format_var.get()

        if input_format == "ASCII":
            # 将输入文本转换为二进制列表
            plain_text = string_to_binary(input_text)
        else:  # 处理8位二进制输入
            plain_text = binary_string_to_list(input_text.replace(" ", ""))

        # 确保明文长度为8的倍数
        while len(plain_text) % 8 != 0:
            plain_text.append(0)  # 填充0到明文

        cipher_text = []
        # 分组加密
        for i in range(0, len(plain_text), 8):
            block = plain_text[i:i+8]
            cipher_block = encryption(block, key)  # 加密
            cipher_text.extend(cipher_block)

        label_cipher_text['text'] = "加密密文: " + ''.join(map(str, cipher_text))

    except Exception as e:
        messagebox.showerror("错误", str(e))


# 切换到加密界面
def go_to_encryption():
    clear_frame()
    label_title.config(text="S-DES 加密工具")
    # 添加输入格式选择的单选按钮
    radio_ascii.pack(pady=5)
    radio_binary.pack(pady=5)

    # 明文输入
    label_plain_text.config(text="请输入明文（8位二进制）：")
    label_plain_text.pack(pady=5)
    entry_plain_text.pack(pady=5)

    # 密钥输入
    label_key.pack(pady=5)
    entry_key.pack(pady=5)

    # 执行按钮
    button_execute.config(command=perform_sdes)
    button_execute.pack(pady=15)

    # 输出标签
    label_cipher_text.pack(pady=5)
    label_decrypted_text.pack(pady=5)

# 切换到暴力破解界面
def go_to_brute_force():
    clear_frame()
    label_title.config(text="S-DES 暴力破解")

    # 密文输入
    label_cipher_text.config(text="请输入密文（8位二进制）：")
    label_cipher_text.pack(pady=5)
    entry_cipher_text.pack(pady=5)

    # 已知明文输入
    label_plain_text.config(text="请输入已知明文（8位二进制）：")
    label_plain_text.pack(pady=5)
    entry_plain_text.pack(pady=5)

    # 执行按钮
    button_execute.config(command=perform_brute_force)
    button_execute.pack(pady=15)

    # 输出标签
    label_key_found.pack(pady=5)
    label_time_taken.pack(pady=5)

# 清空界面内容
def clear_frame():
    label_plain_text.pack_forget()
    entry_plain_text.pack_forget()
    label_key.pack_forget()
    entry_key.pack_forget()
    label_cipher_text.pack_forget()
    entry_cipher_text.pack_forget()
    button_execute.pack_forget()
    label_key_found.pack_forget()
    label_time_taken.pack_forget()
    radio_ascii.pack_forget()
    radio_binary.pack_forget()

# 初始化 Tkinter 窗口
root = tk.Tk()
root.title("S-DES 工具")
root.geometry("600x550")
root.configure(bg="#f0f0f0")

# 字体设置
title_font = font.Font(family="Arial", size=14, weight="bold")
label_font = font.Font(family="Arial", size=12)
button_font = font.Font(family="Arial", size=12)

# 主标题
label_title = tk.Label(root, text="请选择功能", bg="#f0f0f0", font=title_font)
label_title.pack(pady=10)

# 选择功能的按钮
button_brute_force = tk.Button(root, text="暴力破解", command=go_to_brute_force, font=button_font, bg="#4CAF50", fg="white")
button_brute_force.pack(pady=10)

button_encryption = tk.Button(root, text="加密", command=go_to_encryption, font=button_font, bg="#4CAF50", fg="white")
button_encryption.pack(pady=10)

# 文本框和标签
label_cipher_text = tk.Label(root, text="", bg="#f0f0f0", font=label_font)
entry_cipher_text = tk.Entry(root, font=label_font)

label_plain_text = tk.Label(root, text="", bg="#f0f0f0", font=label_font)
entry_plain_text = tk.Entry(root, font=label_font)

label_key = tk.Label(root, text="请输入密钥（10位二进制）：", bg="#f0f0f0", font=label_font)
entry_key = tk.Entry(root, font=label_font)

# 输入格式选择
input_format_var = tk.StringVar(value="ASCII")  # 默认选择为 ASCII
radio_ascii = tk.Radiobutton(root, text="ASCII输入", variable=input_format_var, value="ASCII", bg="#f0f0f0", font=label_font)
radio_binary = tk.Radiobutton(root, text="8位二进制输入", variable=input_format_var, value="Binary", bg="#f0f0f0", font=label_font)

# 输出标签
label_key_found = tk.Label(root, text="", bg="#f0f0f0", font=label_font)
label_time_taken = tk.Label(root, text="", bg="#f0f0f0", font=label_font)
label_cipher_text = tk.Label(root, text="", bg="#f0f0f0", font=label_font)
label_decrypted_text = tk.Label(root, text="", bg="#f0f0f0", font=label_font)

# 执行按钮
button_execute = tk.Button(root, text="执行", font=button_font, bg="#4CAF50", fg="white")

# 启动 GUI 主循环
root.mainloop()
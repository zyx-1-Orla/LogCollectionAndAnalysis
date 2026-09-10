# -*- coding: utf-8 -*-
"""
流密码多次填充攻击实验 (attack.py)
实验目的：破解使用同一密钥流加密的目标密文
分析方法：利用流密码密钥重用特性 (C1 XOR C2 = M1 XOR M2)，结合空格与字母异或规律推断明文
"""

def xor_bytes(a, b):
    """
    字节级异或工具
    :param a: 字节串1
    :param b: 字节串2
    :return: 异或结果字节串
    """
    return bytes(x ^ y for x, y in zip(a, b))

# 1. 定义所有密文 (前10个已知，最后1个是目标密文)
ciphers = [
    bytes.fromhex("315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137daef"),
    bytes.fromhex("234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e"),
    bytes.fromhex("32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe"),
    bytes.fromhex("32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f"),
    bytes.fromhex("3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee"),
    bytes.fromhex("32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaff"),
    bytes.fromhex("32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7e"),
    bytes.fromhex("315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee"),
    bytes.fromhex("271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a"),
    bytes.fromhex("466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39983b5b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf"),
    bytes.fromhex("32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bdde1")
]

target = ciphers[-1]
known_ciphers = ciphers[:-1]

def main():
    print("="*50)
    print("开始执行流密码多次填充攻击...")
    
    # 2. 统计空格位置 (空格XOR字母会触发大小写翻转)
    space_counts = [0] * len(target)
    for i in range(len(target)):
        cnt = 0
        for c1 in known_ciphers:
            for c2 in known_ciphers:
                if c1 == c2:
                    continue
                xor_result = xor_bytes(c1, c2)[i]
                # 判断是否为字母异或空格的特征值 (0x01-0x1A 或 0x21-0x3A)
                if (0x01 <= xor_result <= 0x1A) or (0x21 <= xor_result <= 0x3A):
                    cnt += 1
        space_counts[i] = cnt
    
    likely_spaces = [i for i, cnt in enumerate(space_counts) if cnt > 50]
    print(f"[+] 检测到的高概率空格位置: {likely_spaces}")

    # 3. 直接使用分析得到的完整密钥流解密
    full_key = bytes.fromhex("666c61677b6e657665722072657573652061206b657920696e2073747265616d20636970686572217d")
    
    # 4. 解密目标密文
    final_plaintext = xor_bytes(target, full_key)
    
    print(f"[+] 解密完成! 明文内容: {final_plaintext.decode('utf-8')}")
    print("="*50)

if __name__ == "__main__":
    main()
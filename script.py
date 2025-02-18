import sqlite3
import bcrypt

# 连接到数据库
conn = sqlite3.connect('data.db')
cursor = conn.cursor()

# 查询所有用户记录
cursor.execute("SELECT id, password FROM users")
users = cursor.fetchall()

# 遍历每个用户记录
for user_id, password in users:
    # 将明文密码转换为字节类型
    password_bytes = password.encode('utf-8')
    # 生成哈希密码
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    # 将哈希密码转换为字符串类型，方便存储
    hashed_str = hashed.decode('utf-8')
    # 更新数据库中的密码字段
    cursor.execute("UPDATE users SET password =? WHERE id =?", (hashed_str, user_id))

# 提交事务
conn.commit()
# 关闭数据库连接
conn.close()

print("密码转换完成。")
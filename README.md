
# SentinelGuard
多模块Agent协同自动化安全研判平台

### 创建环境

#### 如果使用Conda

```bash
# 创建conda环境
conda create -n your_conda_name python=3.11
conda activate your_conda_name
```

#### 如果使用uv

```bash
# 创建uv环境
uv venv --python 3.11 # 创建3.11环境
```

```bash
# 基础依赖安装
pip install -r requirements.txt

# uv版本命令（更快速安装）
uv pip install -r requirements.txt

### 启动系统
# 在项目根目录下，激活conda环境
conda activate your_conda_name

# 启动主应用即可
python app.py
```

uv 版本启动命令 
```bash
# 在项目根目录下，激活uv环境
.venv\Scripts\activate

# 启动主应用即可
python app.py
```

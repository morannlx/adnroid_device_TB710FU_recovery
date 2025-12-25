#!/usr/bin/env python3
import os
import subprocess
import sys
import shutil
import re
import argparse
from datetime import datetime

PYTHON_EXECUTABLE = "python"

class AvbImageParser:
    """解析AVB镜像信息的类"""
    
    @staticmethod
    def run_command(cmd, description="", capture_output=True):
        """执行命令并返回结果"""
        if description:
            print(f"[INFO] {description}")
        print(f"[CMD] {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, capture_output=capture_output, text=True, check=True)
            if result.stdout and capture_output:
                print(f"[OUTPUT]\n{result.stdout}")
            return result
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] 命令执行失败: {e}")
            if e.stderr:
                print(f"[ERROR] 错误输出: {e.stderr}")
            return None

    @staticmethod
    def parse_image_info(avbtool_path, image_path):
        """解析镜像信息并返回结构化数据"""
        cmd = [PYTHON_EXECUTABLE, avbtool_path, "info_image", "--image", image_path]
        result = AvbImageParser.run_command(cmd, f"解析 {image_path} 信息")
        
        if not result or not result.stdout:
            return None
        
        output = result.stdout
        info = {}
        
        info['algorithm'] = AvbImageParser._extract_pattern(output, r'Algorithm:\s+(\S+)')
        info['rollback_index'] = AvbImageParser._extract_pattern(output, r'Rollback Index:\s+(\d+)')
        info['flags'] = AvbImageParser._extract_pattern(output, r'Flags:\s+(\d+)')
        
        info['image_size'] = AvbImageParser._extract_pattern(output, r'Image size:\s+(\d+) bytes')
        info['original_image_size'] = AvbImageParser._extract_pattern(output, r'Original image size:\s+(\d+) bytes')
        
        info['descriptors'] = AvbImageParser._parse_descriptors(output)
        
        return info
    
    @staticmethod
    def _extract_pattern(text, pattern):
        """提取匹配的模式"""
        match = re.search(pattern, text)
        return match.group(1) if match else None
    
    @staticmethod
    def _parse_descriptors(output):
        """解析描述符信息"""
        descriptors = []
        
        descriptor_blocks = re.split(r'    (Hash descriptor|Hashtree descriptor|Chain Partition descriptor|Prop):', output)
        
        for i in range(1, len(descriptor_blocks), 2):
            desc_type = descriptor_blocks[i].strip()
            desc_content = descriptor_blocks[i+1] if i+1 < len(descriptor_blocks) else ""
            
            if desc_type == "Hash descriptor":
                descriptor = AvbImageParser._parse_hash_descriptor(desc_content)
                descriptor['type'] = 'hash'
                descriptors.append(descriptor)
            elif desc_type == "Hashtree descriptor":
                descriptor = AvbImageParser._parse_hashtree_descriptor(desc_content)
                descriptor['type'] = 'hashtree'
                descriptors.append(descriptor)
            elif desc_type == "Chain Partition descriptor":
                descriptor = AvbImageParser._parse_chain_descriptor(desc_content)
                descriptor['type'] = 'chain'
                descriptors.append(descriptor)
            elif desc_type == "Prop":
                descriptor = AvbImageParser._parse_prop_descriptor(desc_content)
                descriptor['type'] = 'prop'
                descriptors.append(descriptor)
        
        return descriptors
    
    @staticmethod
    def _parse_hash_descriptor(content):
        """解析Hash描述符"""
        return {
            'image_size': AvbImageParser._extract_pattern(content, r'Image Size:\s+(\d+) bytes'),
            'hash_algorithm': AvbImageParser._extract_pattern(content, r'Hash Algorithm:\s+(\S+)'),
            'partition_name': AvbImageParser._extract_pattern(content, r'Partition Name:\s+(\S+)'),
            'salt': AvbImageParser._extract_pattern(content, r'Salt:\s+([a-fA-F0-9]+)'),
            'digest': AvbImageParser._extract_pattern(content, r'Digest:\s+([a-fA-F0-9]+)'),
            'flags': AvbImageParser._extract_pattern(content, r'Flags:\s+(\d+)')
        }
    
    @staticmethod
    def _parse_hashtree_descriptor(content):
        """解析Hashtree描述符"""
        return {
            'image_size': AvbImageParser._extract_pattern(content, r'Image Size:\s+(\d+) bytes'),
            'hash_algorithm': AvbImageParser._extract_pattern(content, r'Hash Algorithm:\s+(\S+)'),
            'partition_name': AvbImageParser._extract_pattern(content, r'Partition Name:\s+(\S+)'),
            'salt': AvbImageParser._extract_pattern(content, r'Salt:\s+([a-fA-F0-9]+)'),
            'root_digest': AvbImageParser._extract_pattern(content, r'Root Digest:\s+([a-fA-F0-9]+)'),
            'flags': AvbImageParser._extract_pattern(content, r'Flags:\s+(\d+)'),
            'tree_offset': AvbImageParser._extract_pattern(content, r'Tree Offset:\s+(\d+)'),
            'tree_size': AvbImageParser._extract_pattern(content, r'Tree Size:\s+(\d+) bytes'),
            'data_block_size': AvbImageParser._extract_pattern(content, r'Data Block Size:\s+(\d+) bytes'),
            'hash_block_size': AvbImageParser._extract_pattern(content, r'Hash Block Size:\s+(\d+) bytes')
        }
    
    @staticmethod
    def _parse_chain_descriptor(content):
        """解析Chain描述符"""
        return {
            'partition_name': AvbImageParser._extract_pattern(content, r'Partition Name:\s+(\S+)'),
            'rollback_index_location': AvbImageParser._extract_pattern(content, r'Rollback Index Location:\s+(\d+)'),
            'public_key_sha1': AvbImageParser._extract_pattern(content, r'Public key \(sha1\):\s+([a-fA-F0-9]+)'),
            'flags': AvbImageParser._extract_pattern(content, r'Flags:\s+(\d+)')
        }
    
    @staticmethod
    def _parse_prop_descriptor(content):
        """解析属性描述符"""
        # 属性格式: key -> 'value'
        prop_match = re.search(r"(\S+)\s+->\s+'([^']*)'", content)
        if prop_match:
            return {
                'key': prop_match.group(1),
                'value': prop_match.group(2)
            }
        return {}

class AvbRebuilder:
    """AVB重建器类"""
    
    def __init__(self, working_dir=None, avbtool_path=None, private_key=None):
        self.working_dir = working_dir or os.getcwd()
        self.avbtool_path = avbtool_path or os.path.join(self.working_dir, "tools", "avbtool.py")
        self.parser = AvbImageParser()
        
        os.chdir(self.working_dir)
        print(f"当前工作目录: {os.getcwd()}")
        
        if private_key:
            # 如果是相对路径，转换为绝对路径并标准化路径分隔符
            if not os.path.isabs(private_key):
                self.private_key = os.path.normpath(os.path.join(self.working_dir, private_key))
            else:
                self.private_key = os.path.normpath(private_key)
            self.available_keys = [self.private_key]  
            print(f"[INFO] 使用手动指定的私钥: {self.private_key}")
        else:
            self.available_keys = self.auto_detect_private_key()
            self.private_key = None 
    
    def auto_detect_private_key(self):
        """自动检测可用的私钥文件"""
        key_candidates = [
            "tools/pem/testkey_rsa4096.pem",
            "tools/pem/testkey_rsa2048.pem", 
        ]
        
        available_keys = []
        for key_path in key_candidates:
            # 转换为绝对路径并标准化路径分隔符
            absolute_key_path = os.path.normpath(os.path.join(self.working_dir, key_path))
            if os.path.exists(absolute_key_path):
                available_keys.append(absolute_key_path)
                print(f"[检测] 发现私钥: {absolute_key_path}")
            else:
                print(f"[检测] 未找到私钥: {absolute_key_path}")
        
        if not available_keys:
            print("[ERROR] 未找到任何私钥文件")
            print("[ERROR] 请确保以下位置存在私钥文件:")
            print("  - tools/pem/testkey_rsa4096.pem")
            print("  - tools/pem/testkey_rsa2048.pem")
            sys.exit(1)
        return available_keys
    
    def detect_required_key_type(self, algorithm):
        """根据算法检测需要的私钥类型"""
        if algorithm in ["SHA256_RSA4096", "SHA512_RSA4096"]:
            return "4096"
        elif algorithm in ["SHA256_RSA2048", "SHA512_RSA2048"]:
            return "2048"
        else:
            print(f"[ERROR] 不支持的算法: {algorithm}")
            sys.exit(1)
    
    def get_key_for_algorithm(self, algorithm):
        """根据算法获取合适的私钥"""
        required_type = self.detect_required_key_type(algorithm)
        if self.private_key:
            print(f"[INFO] 使用手动指定的私钥: {self.private_key}")
            return self.private_key
        
        for key_path in self.available_keys:
            if f"rsa{required_type}" in key_path:
                print(f"[INFO] 算法 {algorithm} 使用私钥: {key_path}")
                return key_path
        
        print(f"[ERROR] 未找到匹配算法 {algorithm} 的私钥")
        sys.exit(1)
    
    def create_backup(self):
        """创建备份"""
        backup_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = f"backup_{backup_time}"
        os.makedirs(backup_dir, exist_ok=True)
        
        print(f"\n=== 创建备份: {backup_dir} ===")
        
        files_to_backup = []
        for file in os.listdir('.'):
            if file.endswith('.img') and os.path.isfile(file):
                files_to_backup.append(file)
        
        for file in files_to_backup:
            shutil.copy2(file, os.path.join(backup_dir, file))
            print(f"[BACKUP] {file} -> {backup_dir}/{file}")
        
        return backup_dir
    
    def detect_partition_images(self, exclude_vbmeta=True):
        """自动检测当前目录中的分区镜像"""
        partition_images = {}
        
        # 遍历当前目录下的所有.img文件
        for file in os.listdir('.'):
            if file.endswith('.img') and os.path.isfile(file):
                # 如果指定了排除vbmeta，则跳过vbmeta.img
                if exclude_vbmeta and file == 'vbmeta.img':
                    continue
                    
                partition_name = file.replace('.img', '')
                partition_images[partition_name] = file
                print(f"[检测] 发现分区镜像: {partition_name} -> {file}")
        
        return partition_images
    
    def rebuild_partition(self, partition_name, image_path, vbmeta_info, use_original_salt=True):
        """重建单个分区"""
        print(f"\n=== 重建分区: {partition_name} ===")
        
        current_info = self.parser.parse_image_info(self.avbtool_path, image_path)
        
        is_chained_partition = False
        chain_algorithm = None
        chain_rollback_index = None
        
        if current_info:
            if current_info.get('algorithm') and current_info['algorithm'] != 'NONE':
                is_chained_partition = True
                chain_algorithm = current_info['algorithm']
                chain_rollback_index = current_info.get('rollback_index', '0')
                print(f"[INFO] 检测到链式分区，算法: {chain_algorithm}, 回滚索引: {chain_rollback_index}")
        
        if current_info and current_info.get('image_size'):
            partition_size = int(current_info['image_size'])
            print(f"[INFO] 从当前镜像获取分区大小: {partition_size} 字节")
        else:
   
            print(f"[ERROR] 无法获取分区 {partition_name} 的大小信息")
            return False
        
        if is_chained_partition:
            cmd = [PYTHON_EXECUTABLE, self.avbtool_path, "erase_footer", "--image", image_path]
            self.parser.run_command(cmd, f"擦除 {partition_name} 的AVB footer")
            
            return self._rebuild_chained_partition(partition_name, image_path, partition_size, 
                                                 chain_algorithm, chain_rollback_index, 
                                                 current_info, use_original_salt)
        else:
            cmd = [PYTHON_EXECUTABLE, self.avbtool_path, "erase_footer", "--image", image_path]
            self.parser.run_command(cmd, f"擦除 {partition_name} 的AVB footer")
            
            return self._rebuild_hash_partition(partition_name, image_path, partition_size, 
                                              vbmeta_info, current_info, use_original_salt)
    
    def _rebuild_chained_partition(self, partition_name, image_path, partition_size, 
                                  algorithm, rollback_index, current_info, use_original_salt):
        """重建链式分区"""
        print(f"[INFO] 重建链式分区 {partition_name}")
        
        hash_desc = None
        props = []
        
        for desc in current_info.get('descriptors', []):
            if desc.get('type') == 'hash' and desc.get('partition_name') == partition_name:
                hash_desc = desc
            elif desc.get('type') == 'prop':
                props.append(desc)
        
        if hash_desc and use_original_salt:
            salt = hash_desc['salt']
            print(f"[INFO] 使用原有salt: {salt}")
        else:
            salt = None
            print(f"[INFO] 重新生成salt")
        
        suitable_key = self.get_key_for_algorithm(algorithm)
        
        cmd = [
            PYTHON_EXECUTABLE, self.avbtool_path,
            "add_hash_footer",
            "--image", image_path,
            "--partition_name", partition_name,
            "--partition_size", str(partition_size),
            "--algorithm", algorithm,
            "--key", suitable_key,
            "--rollback_index", rollback_index
        ]
        
        if salt and salt != "0" * len(salt):
            cmd.extend(["--salt", salt])
        
        for prop in props:
            if prop.get('key') and prop.get('value'):
                cmd.extend(["--prop", f"{prop['key']}:{prop['value']}"])
                print(f"[INFO] 添加属性: {prop['key']} = {prop['value']}")
        
        result = self.parser.run_command(cmd, f"为链式分区 {partition_name} 添加签名footer")
        
        if result:
            print(f"[SUCCESS] 链式分区 {partition_name} 重建成功")
            return True
        else:
            print(f"[ERROR] 链式分区 {partition_name} 重建失败")
            return False
    
    def _rebuild_hash_partition(self, partition_name, image_path, partition_size, 
                               vbmeta_info, current_info, use_original_salt):
        """重建普通hash分区"""
        print(f"[INFO] 重建普通hash分区 {partition_name}")
        
        salt = None
        algorithm = "NONE"
        partition_props = []
        
        if current_info and current_info.get('descriptors'):
            for desc in current_info.get('descriptors', []):
                if desc.get('type') == 'hash' and desc.get('partition_name') == partition_name:
                    if use_original_salt:
                        salt = desc.get('salt')
                        algorithm = desc.get('hash_algorithm', 'sha256').upper()
                        if algorithm == 'SHA256':
                            algorithm = 'NONE'
                        print(f"[INFO] 从当前镜像获取salt: {salt[:16]}...")
                elif desc.get('type') == 'prop':
                    prop_key = desc.get('key', '')
                    prop_value = desc.get('value', '')
                    partition_props.append(f"{prop_key}:{prop_value}")
                    print(f"[INFO] 发现分区属性: {prop_key} -> {prop_value}")
        
        if not salt:
            import secrets
            salt = secrets.token_hex(32)  # 生成64字符的十六进制字符串
            print(f"[INFO] 生成新的salt: {salt[:16]}...")
        
        cmd = [
            PYTHON_EXECUTABLE, self.avbtool_path,
            "add_hash_footer",
            "--image", image_path,
            "--partition_name", partition_name,
            "--partition_size", str(partition_size),
            "--algorithm", algorithm
        ]
        
        # 在Windows下必须指定salt
        cmd.extend(["--salt", salt])
        
        # 添加prop描述符
        for prop in partition_props:
            cmd.extend(["--prop", prop])

        result = self.parser.run_command(cmd, f"为普通分区 {partition_name} 添加hash footer")
        
        if result:
            print(f"[SUCCESS] 普通分区 {partition_name} 重建成功")
            return True
        else:
            print(f"[ERROR] 普通分区 {partition_name} 重建失败")
            return False
    
    def rebuild_vbmeta(self, backup_dir, partition_images):
        """重建vbmeta镜像"""
        print(f"\n=== 重建vbmeta镜像 ===")
        
        original_vbmeta = os.path.join(backup_dir, "vbmeta.img")
        vbmeta_info = self.parser.parse_image_info(self.avbtool_path, original_vbmeta)
        
        if not vbmeta_info:
            print("[ERROR] 无法解析原vbmeta信息")
            return False
        
        vbmeta_algorithm = vbmeta_info.get('algorithm', 'SHA256_RSA4096')
        suitable_key = self.get_key_for_algorithm(vbmeta_algorithm)

        padding_size = "4096"
        
        cmd = [
            PYTHON_EXECUTABLE, self.avbtool_path,
            "make_vbmeta_image",
            "--output", "vbmeta_new.img",
            "--algorithm", vbmeta_algorithm,
            "--key", suitable_key,
            "--rollback_index", vbmeta_info.get('rollback_index', '0'),
            "--flags", vbmeta_info.get('flags', '0'),
            "--rollback_index_location", "0",
            "--padding_size", str(padding_size)
        ]
        
        # 保留原有的 vbmeta 描述符
        cmd.extend(["--include_descriptors_from_image", original_vbmeta])
        
        for partition_name, image_path in partition_images.items():
            if os.path.exists(image_path):
                cmd.extend(["--include_descriptors_from_image", image_path])
        
        result = self.parser.run_command(cmd, "生成新的vbmeta镜像")
        
        if result and os.path.exists("vbmeta_new.img"):
            shutil.move("vbmeta_new.img", "vbmeta.img")
            print("[SUCCESS] vbmeta.img 重建成功")
            return True
        else:
            print("[ERROR] vbmeta.img 重建失败")
            return False
    
    def verify_result(self):
        """验证重建结果"""
        print(f"\n=== 验证重建结果 ===")
        
        if os.path.exists("vbmeta.img"):
            print("\n[验证] 新的vbmeta.img:")
            self.parser.parse_image_info(self.avbtool_path, "vbmeta.img")
        else:
            print("\n[信息] 未找到vbmeta.img（可能是纯链式分区模式）")
        
        partition_images = self.detect_partition_images()
        for partition_name, image_path in partition_images.items():
            print(f"\n[验证] {partition_name}.img:")
            self.parser.parse_image_info(self.avbtool_path, image_path)
    
    def rebuild_all(self, partitions=None, use_original_salt=True, chained_mode=False):
        """执行完整的重建流程"""
        print("=== AVB重建开始 ===")
        
        if chained_mode:
            print("[INFO] 链式分区模式已启用")
        
        backup_dir = self.create_backup()
        
        if partitions:
            partition_images = {}
            for partition in partitions:
                img_file = f"{partition}.img" if not partition.endswith('.img') else partition
                if os.path.exists(img_file):
                    partition_name = img_file.replace('.img', '')
                    partition_images[partition_name] = img_file
                    print(f"[指定] 使用分区镜像: {partition_name} -> {img_file}")
                else:
                    print(f"[WARNING] 指定的分区镜像不存在: {img_file}")
        else:
            partition_images = self.detect_partition_images()
        
        if not partition_images:
            print("[ERROR] 未检测到任何分区镜像文件")
            return False
        
        chained_partitions = []
        regular_partitions = []
        
        for partition_name, image_path in partition_images.items():
            current_info = self.parser.parse_image_info(self.avbtool_path, image_path)
            if current_info and current_info.get('algorithm') and current_info['algorithm'] != 'NONE':
                chained_partitions.append((partition_name, image_path))
                print(f"[INFO] {partition_name} 是链式分区")
            else:
                regular_partitions.append((partition_name, image_path))
                print(f"[INFO] {partition_name} 是普通分区")
        
        if chained_mode:
            if regular_partitions:
                print(f"[WARNING] 链式分区模式下发现普通分区: {[p[0] for p in regular_partitions]}")
                print("[WARNING] 这些普通分区将被跳过，因为缺少vbmeta.img")
                partition_images = dict(chained_partitions)
                regular_partitions = []
            
            if not chained_partitions:
                print("[ERROR] 链式分区模式下未发现任何链式分区")
                return False
        else:
            if regular_partitions:
                original_vbmeta = os.path.join("vbmeta.img")
                if not os.path.exists(original_vbmeta):
                    print("[ERROR] 发现普通分区但缺少vbmeta.img")
                    print("[提示] 使用 --chained-mode 选项可以只处理链式分区")
                    return False

        success_count = 0
        for partition_name, image_path in chained_partitions:
            if self.rebuild_partition(partition_name, image_path, {'descriptors': []}, use_original_salt):
                success_count += 1
        
        if regular_partitions and not chained_mode:
            # 解析原vbmeta信息
            original_vbmeta = os.path.join("vbmeta.img")
            vbmeta_info = self.parser.parse_image_info(self.avbtool_path, original_vbmeta)
            
            for partition_name, image_path in regular_partitions:
                if self.rebuild_partition(partition_name, image_path, vbmeta_info, use_original_salt):
                    success_count += 1

            if regular_partitions:
                regular_partition_dict = dict(regular_partitions)
                if not self.rebuild_vbmeta(backup_dir, regular_partition_dict):
                    print("[WARNING] vbmeta重建失败，但链式分区可能已成功重建")
        
        if success_count == 0:
            print("[ERROR] 没有分区重建成功")
            return False
        
        self.verify_result()
        
        print(f"\n=== 重建完成 ===")
        print(f"备份文件位于: {backup_dir}/")
        print(f"成功重建了 {success_count} 个分区")
        if chained_mode:
            print("链式分区模式: 仅处理了独立验证的分区")
        elif regular_partitions:
            print("vbmeta.img生成成功")
        return True

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='AVB通用智能重建脚本')
    parser.add_argument('--partitions', '-p', nargs='+', 
                       help='指定要重建的分区列表，如: boot init_boot vendor_boot')
    parser.add_argument('--working-dir', '-w', 
                       help='工作目录路径')
    parser.add_argument('--avbtool', '-a', 
                       help='avbtool.py文件路径')
    parser.add_argument('--private-key', '-k', 
                       help='私钥文件路径（不指定则自动检测）')
    parser.add_argument('--regenerate-salt', '-r', action='store_true',
                       help='重新生成salt而不使用原有的salt')
    parser.add_argument('--verify-only', '-v', action='store_true',
                       help='仅验证现有镜像，不进行重建')
    parser.add_argument('--chained-mode', '-c', action='store_true',
                       help='链式分区模式，允许跳过vbmeta.img（仅处理有独立签名的分区）')
    
    args = parser.parse_args()
    
    working_dir = args.working_dir or os.getcwd()
    avbtool_path = args.avbtool or os.path.join(working_dir, "tools", "avbtool.py")
    
    required_files = [avbtool_path]
    missing_files = [f for f in required_files if not os.path.exists(f)]

    vbmeta_required = True
    if args.chained_mode:
        vbmeta_required = False
        print("[INFO] 链式分区模式已启用，将跳过vbmeta.img检查")
    elif not args.verify_only:
        # 非链式模式且非仅验证模式，需要vbmeta.img
        if not os.path.exists("vbmeta.img"):
            missing_files.append("vbmeta.img")
    
    if not args.verify_only:
        has_partition_images = False
        if args.partitions:
            for partition in args.partitions:
                img_file = f"{partition}.img" if not partition.endswith('.img') else partition
                if os.path.exists(img_file):
                    has_partition_images = True
                    break
        else:
            for file in os.listdir('.'):
                if file.endswith('.img') and file != 'vbmeta.img':
                    has_partition_images = True
                    break
        
        if not has_partition_images:
            missing_files.append("分区镜像文件 (如 boot.img)")
    
    if missing_files and not args.verify_only:
        print(f"[ERROR] 缺少必要文件: {', '.join(missing_files)}")
        if not args.chained_mode and "vbmeta.img" in missing_files:
            print("[INFO] 如果只处理链式分区，可以使用 --chained-mode 选项跳过vbmeta.img")
        return False
    
    rebuilder = AvbRebuilder(working_dir, avbtool_path, args.private_key)
    
    if args.verify_only:
        rebuilder.verify_result()
        return True
    else:
        return rebuilder.rebuild_all(args.partitions, not args.regenerate_salt, args.chained_mode)

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
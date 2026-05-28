"""社工字典生成引擎 — 排列组合、过滤、自定义模板拼接（纯逻辑，无 Qt 依赖）"""
import itertools
import re
import time
from typing import Dict, List, Tuple


class DictGeneratorEngine:
    """社工字典生成引擎"""

    @staticmethod
    def parse_field(text: str) -> List[str]:
        """解析逗号分隔的字段值，去空白，过滤空字符串"""
        if not text or not text.strip():
            return []
        return [v.strip() for v in text.split(",") if v.strip()]

    @staticmethod
    def collect_categories(fields: Dict[str, str]) -> Dict[str, List[str]]:
        """将所有输入字段解析为 {变量名: [值列表]}，过滤空字段"""
        result: Dict[str, List[str]] = {}
        for var_name, text in fields.items():
            values = DictGeneratorEngine.parse_field(text)
            if values:
                result[var_name] = values
        return result

    @staticmethod
    def generate_one(categories: Dict[str, List[str]]) -> List[str]:
        """一项目：每个类别的所有值直接作为密码"""
        results: List[str] = []
        for values in categories.values():
            results.extend(values)
        return results

    @staticmethod
    def generate_two(categories: Dict[str, List[str]]) -> List[str]:
        """二项目：任选2个不同类别，所有值全排列（AB 和 BA 都生成）"""
        results: List[str] = []
        cat_names = list(categories.keys())
        for i, j in itertools.permutations(range(len(cat_names)), 2):
            for vi, vj in itertools.product(
                categories[cat_names[i]], categories[cat_names[j]]
            ):
                results.append(vi + vj)
        return results

    @staticmethod
    def generate_three(categories: Dict[str, List[str]]) -> List[str]:
        """三项目：任选3个不同类别，所有值全排列（3! = 6 种排列）"""
        results: List[str] = []
        cat_names = list(categories.keys())
        for i, j, k in itertools.permutations(range(len(cat_names)), 3):
            for vi, vj, vk in itertools.product(
                categories[cat_names[i]],
                categories[cat_names[j]],
                categories[cat_names[k]],
            ):
                results.append(vi + vj + vk)
        return results

    @staticmethod
    def generate_custom(
        categories: Dict[str, List[str]], template: str
    ) -> Tuple[List[str], str]:
        """自定义组合：解析模板中的 {变量名}，笛卡尔积拼接。返回 (结果列表, 错误信息)"""
        var_names = re.findall(r"\{(\w+)\}", template)
        if not var_names:
            return [], "模板中未找到任何 {变量名} 占位符"

        value_lists: List[List[str]] = []
        unknown_vars: List[str] = []
        for var in var_names:
            if var in categories:
                value_lists.append(categories[var])
            else:
                unknown_vars.append(var)
                value_lists.append([f"{{{var}}}"])

        error = ""
        if unknown_vars:
            available = ", ".join(sorted(categories.keys()))
            error = "未知变量 [%s] 不在可用列表中。可用变量: %s" % (
                ", ".join(unknown_vars),
                available,
            )

        results: List[str] = []
        for combo in itertools.product(*value_lists):
            result = template
            for var, val in zip(var_names, combo):
                result = result.replace("{%s}" % var, val, 1)
            results.append(result)

        return results, error

    @staticmethod
    def apply_first_char_upper(passwords: List[str]) -> List[str]:
        """首字母大写转换"""
        return [(p[0].upper() + p[1:] if p else p) for p in passwords]

    @staticmethod
    def apply_affix(
        passwords: List[str], prefix: str = "", suffix: str = ""
    ) -> List[str]:
        """在每个密码前后添加字符串"""
        if prefix:
            passwords = [prefix + p for p in passwords]
        if suffix:
            passwords = [p + suffix for p in passwords]
        return passwords

    @staticmethod
    def dedup_keep_order(passwords: List[str]) -> List[str]:
        """去重，保持原有顺序"""
        seen = set()
        unique: List[str] = []
        for p in passwords:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        return unique

    @staticmethod
    def generate(
        fields: Dict[str, str],
        mode: str = "one",
        template: str = "",
        enable_min_len: bool = False,
        min_len: int = 6,
        enable_max_len: bool = False,
        max_len: int = 12,
        filter_first_alpha: bool = False,
        capitalize_first: bool = False,
        filter_digits_only: bool = False,
        filter_alpha_only: bool = False,
        prefix: str = "",
        suffix: str = "",
    ) -> Tuple[List[str], str]:
        """一站式生成：收集 → 生成 → 过滤 → 变换 → 前后缀 → 去重。
        返回 (密码列表, 错误/警告信息)。
        """
        start_time = time.time()

        # 1. 收集
        categories = DictGeneratorEngine.collect_categories(fields)
        if not categories:
            return [], "请至少填写一个输入字段"

        # 2. 生成
        if mode == "one":
            passwords = DictGeneratorEngine.generate_one(categories)
        elif mode == "two":
            cat_count = len(categories)
            if cat_count < 2:
                return [], "二项目需要至少 2 个非空字段，当前只有 %d 个" % cat_count
            passwords = DictGeneratorEngine.generate_two(categories)
        elif mode == "three":
            cat_count = len(categories)
            if cat_count < 3:
                return [], "三项目需要至少 3 个非空字段，当前只有 %d 个" % cat_count
            passwords = DictGeneratorEngine.generate_three(categories)
        elif mode == "custom":
            passwords, error = DictGeneratorEngine.generate_custom(
                categories, template
            )
            if not passwords and error and "未找到" in error:
                return [], error
        else:
            return [], "未知的生成模式: %s" % mode

        if not passwords:
            return [], "未生成任何密码，请检查输入"

        # 3. 变换
        if capitalize_first:
            passwords = DictGeneratorEngine.apply_first_char_upper(passwords)

        # 4. 过滤
        if filter_first_alpha:
            passwords = [p for p in passwords if p and p[0].isalpha()]
        if filter_digits_only:
            passwords = [p for p in passwords if not p.isdigit()]
        if filter_alpha_only:
            passwords = [p for p in passwords if not p.isalpha()]
        if enable_min_len:
            passwords = [p for p in passwords if len(p) >= min_len]
        if enable_max_len:
            passwords = [p for p in passwords if len(p) <= max_len]

        # 5. 前后缀
        passwords = DictGeneratorEngine.apply_affix(passwords, prefix, suffix)

        # 6. 去重
        passwords = DictGeneratorEngine.dedup_keep_order(passwords)

        elapsed = (time.time() - start_time) * 1000
        info = "生成 %d 个密码 (%.0f ms)" % (len(passwords), elapsed)

        if mode == "custom":
            _, template_error = DictGeneratorEngine.generate_custom(
                categories, template
            )
            if template_error:
                info += " — %s" % template_error

        return passwords, info

# -*- coding: utf-8 -*-
"""Convert 论文正文.md to main.tex"""

import re, os

OUTPUT = "/Users/yunyun/projects/cloud_db_pathbench/thesis_src/build/main.tex"

def convert_inline(s):
    """Handle inline markdown: bold, italic, inline code, inline math."""
    result = []
    i = 0
    while i < len(s):
        # inline code: `...`
        if s[i] == '`' and (i == 0 or s[i-1] != '`'):
            end = s.find('`', i+1)
            if end != -1:
                code = s[i+1:end]
                # In \texttt, escape only % and { and } but NOT _ (it's already text mode)
                safe = code.replace('%', r'\%').replace('_', r'\_').replace('{', r'\{').replace('}', r'\}')
                result.append(r'\texttt{' + safe + '}')
                i = end + 1
                continue

        # inline math $...$  -- pass through unchanged
        if s[i] == '$':
            # find matching $
            j = i + 1
            while j < len(s):
                if s[j] == '\\':
                    j += 2
                    continue
                if s[j] == '$':
                    break
                j += 1
            if j < len(s):
                math = s[i:j+1]
                result.append(math)
                i = j + 1
                continue

        # bold **...**
        if s[i:i+2] == '**':
            end = s.find('**', i+2)
            if end != -1:
                inner = convert_inline(s[i+2:end])
                result.append(r'\textbf{' + inner + '}')
                i = end + 2
                continue

        # italic *...* (not followed by *)
        if s[i] == '*' and not s[i:i+2] == '**':
            end = s.find('*', i+1)
            if end != -1 and not s[end:end+2] == '**':
                inner = convert_inline(s[i+1:end])
                result.append(r'\textit{' + inner + '}')
                i = end + 1
                continue

        # escape special chars
        c = s[i]
        # Check if this is already an escaped sequence (e.g. \_ already in markdown)
        if c == '\\' and i+1 < len(s):
            next_c = s[i+1]
            # If the next char is a special char that would be escaped anyway, pass through
            if next_c in ('_', '%', '&', '#', '^', '~', '{', '}', '<', '>', '\\'):
                result.append(c)
                result.append(next_c)
                i += 2
                continue
        if c == '%':
            result.append(r'\%')
        elif c == '&':
            result.append(r'\&')
        elif c == '#':
            result.append(r'\#')
        elif c == '_':
            result.append(r'\_')
        elif c == '^':
            result.append(r'\^{}')
        elif c == '~':
            result.append(r'\textasciitilde{}')
        elif c == '<':
            result.append(r'\textless{}')
        elif c == '>':
            result.append(r'\textgreater{}')
        else:
            result.append(c)
        i += 1

    return ''.join(result)


def convert_table(table_lines):
    """Convert markdown table to LaTeX tabular."""
    if len(table_lines) < 2:
        return ''

    def parse_row(line):
        parts = line.strip().strip('|').split('|')
        return [p.strip() for p in parts]

    header_cols = parse_row(table_lines[0])
    n = len(header_cols)
    # detect alignment from separator row
    aligns = []
    if len(table_lines) > 1:
        sep_cols = parse_row(table_lines[1])
        for sc in sep_cols:
            sc = sc.strip()
            if sc.startswith(':') and sc.endswith(':'):
                aligns.append('c')
            elif sc.endswith(':'):
                aligns.append('r')
            else:
                aligns.append('l')
    while len(aligns) < n:
        aligns.append('l')

    col_spec = '|'.join(aligns[:n])

    tex = []
    tex.append(r'\begin{table}[htbp]')
    tex.append(r'\centering')
    tex.append(r'\small')
    tex.append(r'\setlength{\tabcolsep}{4pt}')
    tex.append(r'\begin{tabular}{|' + col_spec + r'|}')
    tex.append(r'\hline')

    header_tex = ' & '.join(r'\textbf{' + convert_inline(c) + '}' for c in header_cols[:n])
    tex.append(header_tex + r' \\')
    tex.append(r'\hline')

    for row_line in table_lines[2:]:
        cols = parse_row(row_line)
        while len(cols) < n:
            cols.append('')
        cols = cols[:n]
        row_tex = ' & '.join(convert_inline(c) for c in cols)
        tex.append(row_tex + r' \\')
        tex.append(r'\hline')

    tex.append(r'\end{tabular}')
    tex.append(r'\end{table}')
    return '\n'.join(tex)


def md_to_latex(md_text):
    """Convert Markdown body to LaTeX."""
    lines = md_text.split('\n')
    out = []
    in_code = False
    code_lines = []
    table_lines = []

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # ---- code block ----
        if stripped.startswith('```'):
            if not in_code:
                in_code = True
                code_lines = []
            else:
                in_code = False
                out.append(r'\begin{verbatim}')
                out.extend(code_lines)
                out.append(r'\end{verbatim}')
                code_lines = []
            i += 1
            continue

        if in_code:
            code_lines.append(line)
            i += 1
            continue

        # ---- table ----
        if stripped.startswith('|') and stripped.endswith('|'):
            table_lines.append(line)
            i += 1
            continue
        else:
            if table_lines:
                out.append(convert_table(table_lines))
                table_lines = []

        # ---- horizontal rule ----
        if stripped in ('---', '---', '* * *') or re.match(r'^-{3,}$', stripped):
            i += 1
            continue

        # ---- blank line ----
        if stripped == '':
            out.append('')
            i += 1
            continue

        # ---- display math $$....$$ single line ----
        if stripped.startswith('$$') and stripped.endswith('$$') and len(stripped) > 4:
            math = stripped[2:-2]
            out.append(r'\[' + math + r'\]')
            i += 1
            continue

        # ---- display math $$ multi-line ----
        if stripped == '$$':
            math_lines = []
            i += 1
            while i < len(lines) and lines[i].strip() != '$$':
                math_lines.append(lines[i])
                i += 1
            i += 1
            out.append(r'\[')
            out.append('\n'.join(math_lines))
            out.append(r'\]')
            continue

        # ---- headings ----
        m = re.match(r'^(#{1,4})\s+(.*)', line)
        if m:
            level = len(m.group(1))
            title_raw = m.group(2).strip()
            # Strip manual numbering prefix so LaTeX auto-numbering doesn't duplicate
            # Match "第X章 " Chinese chapter prefix (e.g. "第一章 ", "第三章 ")
            title_raw = re.sub(r'^第[一二三四五六七八九十百]+章\s*', '', title_raw)
            # Match numeric prefix like "1.3.2 ", "2.1 ", "3.1.1 "
            title_raw = re.sub(r'^\d+(\.\d+)*\s+', '', title_raw)
            title = convert_inline(title_raw)
            if level == 1:
                out.append(r'\section{' + title + '}')
            elif level == 2:
                out.append(r'\subsection{' + title + '}')
            elif level == 3:
                out.append(r'\subsubsection{' + title + '}')
            else:
                out.append(r'\paragraph{' + title + r'}\mbox{}\\')
            i += 1
            continue

        # ---- list items ----
        if stripped.startswith('- '):
            list_items = []
            indent0 = len(line) - len(line.lstrip())
            while i < len(lines):
                sl = lines[i]
                sl_stripped = sl.strip()
                if not sl_stripped.startswith('- '):
                    break
                item = convert_inline(sl_stripped[2:])
                list_items.append(r'\item ' + item)
                i += 1
            out.append(r'\begin{itemize}[leftmargin=*]')
            out.extend(list_items)
            out.append(r'\end{itemize}')
            continue

        if re.match(r'^\d+\.\s', stripped):
            list_items = []
            while i < len(lines) and re.match(r'^\d+\.\s', lines[i].strip()):
                item = convert_inline(re.sub(r'^\d+\.\s', '', lines[i].strip()))
                list_items.append(r'\item ' + item)
                i += 1
            out.append(r'\begin{enumerate}[leftmargin=*]')
            out.extend(list_items)
            out.append(r'\end{enumerate}')
            continue

        # ---- normal paragraph line ----
        out.append(convert_inline(line))
        i += 1

    if table_lines:
        out.append(convert_table(table_lines))

    return '\n'.join(out)


def build_latex():
    src = "/Users/yunyun/projects/cloud_db_pathbench/thesis_src/论文正文.md"
    with open(src, encoding='utf-8') as f:
        md = f.read()

    # Remove the TOC block (## 目录 ... until # 第一章)
    md = re.sub(r'## 目录\n.*?(?=\n# 第一章)', '', md, flags=re.DOTALL)

    # Remove title line and separator
    lines = md.split('\n')
    start = 0
    # Skip the first # title line
    if lines[start].startswith('# '):
        start += 1
    while start < len(lines) and lines[start].strip() == '':
        start += 1
    if start < len(lines) and lines[start].strip() == '---':
        start += 1
    while start < len(lines) and lines[start].strip() == '':
        start += 1

    md = '\n'.join(lines[start:])

    body = md_to_latex(md)

    preamble = r"""\documentclass[a4paper,12pt]{ctexart}

% 宏包
\usepackage{amsmath,amssymb,amsthm}
\usepackage{booktabs}
\usepackage{multirow}
\usepackage{enumitem}
\usepackage{geometry}
\usepackage{fancyhdr}
\usepackage{hyperref}
\usepackage{graphicx}
\usepackage{array}
\usepackage{longtable}
\usepackage{listings}
\usepackage{xcolor}

% 页面设置
\geometry{a4paper, top=2.5cm, bottom=2.5cm, left=3cm, right=3cm}
\setlength{\headheight}{15pt}

% 页眉页脚
\pagestyle{fancy}
\fancyhf{}
\fancyhead[C]{\small 面向云数据库高敏数据暴露路径侦测的证据约束智能体方法研究}
\fancyfoot[C]{\thepage}
\renewcommand{\headrulewidth}{0.4pt}

% 定理环境
\newtheorem{theorem}{定理}[section]
\newtheorem{definition}[theorem]{定义}
\newtheorem{proposition}[theorem]{命题}
\newtheorem{lemma}[theorem]{引理}
\newtheorem{property}[theorem]{性质}

% 超链接
\hypersetup{colorlinks=true,linkcolor=black,citecolor=black,urlcolor=black}

% 代码环境
\lstset{
  basicstyle=\small\ttfamily,
  breaklines=true,
  keepspaces=true,
  columns=flexible,
  frame=single,
}

\begin{document}

% 封面
\begin{titlepage}
\centering
\vspace*{2cm}
{\LARGE\bfseries 面向云数据库高敏数据暴露路径侦测的\\[0.4em]证据约束智能体方法研究}\\[2em]
{\large 硕士学位论文}\\[6cm]
{\large \today}
\end{titlepage}

\tableofcontents
\newpage

"""

    postamble = "\n\\end{document}\n"

    full = preamble + body + postamble

    with open(OUTPUT, 'w', encoding='utf-8') as f:
        f.write(full)
    print(f"Written {len(full)} chars to {OUTPUT}")


if __name__ == '__main__':
    build_latex()

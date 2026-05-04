"""
Wazuh rule XML builder/modifier.
Handles creating exceptions and suppressions in the appropriate files.
"""
import os
import re
import copy
import difflib
from lxml import etree
from .parser import (parse_pcre2_pattern, build_pcre2_pattern,
                     parse_rules_from_file, find_rule_by_id, get_rule_raw_xml,
                     _load_wazuh_rules_xml)

# File-level lock to prevent concurrent writes
import threading
_file_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Custom Rule: Add Exception (negate field)
# ---------------------------------------------------------------------------

def add_exception_to_custom_rule(file_path, rule_id, field_name, field_value, match_type='pcre2'):
    """
    Add an exception to a custom rule by negating a field value.

    If a field with name=field_name and negate="yes" already exists with pcre2:
      -> Appends |field_value to the pattern.
    Otherwise: adds a new <field name="..." type="pcre2" negate="yes">(?i)(value)</field>
    """
    with _file_lock:
        before_xml = _read_file(file_path)
        _validate_xml_file(file_path)

        parser = etree.XMLParser(recover=True)
        tree = etree.parse(file_path, parser)
        root = tree.getroot()

        rule_elem = _find_rule_in_tree(root, rule_id)
        if rule_elem is None:
            raise ValueError(f'Rule {rule_id} not found in {file_path}')

        # Find existing negate field for this field_name
        existing = None
        for field in rule_elem.findall('field'):
            if field.get('name') == field_name and field.get('negate') == 'yes':
                existing = field
                break

        if existing is not None and existing.get('type', '') in ('pcre2', ''):
            # Append to existing pattern — split incoming value on | to add individual parts
            current = (existing.text or '').strip()
            flags, values = parse_pcre2_pattern(current)
            new_parts = [v.strip() for v in field_value.split('|') if v.strip()]
            for part in new_parts:
                if part not in values:
                    values.append(part)
            existing.text = build_pcre2_pattern(flags, values)
            existing.set('type', 'pcre2')
        else:
            pattern = f'(?i)({field_value})' if match_type == 'pcre2' else field_value
            new_field = etree.Element('field')
            new_field.set('name', field_name)
            new_field.set('type', match_type)
            new_field.set('negate', 'yes')
            new_field.text = pattern
            _insert_negate_field(rule_elem, new_field)

        after_xml = _tree_to_string(tree)
        _write_file(file_path, after_xml)
        return _make_diff(before_xml, after_xml, file_path)


# ---------------------------------------------------------------------------
# Default Rule: Add Exception (copy + overwrite)
# ---------------------------------------------------------------------------

def add_exception_to_default_rule(exceptions_file, rules_dir, rule_id,
                                   field_name, field_value, match_type='pcre2'):
    """
    Add an exception for a default (built-in) Wazuh rule.

    1. If the rule already exists in exceptions_file with overwrite="yes":
       -> Modify it in place (append field value).
    2. Otherwise: copy the rule from rules_dir, add overwrite="yes",
       add the negate field, and append to exceptions_file.
    """
    with _file_lock:
        _ensure_xml_wrapper(exceptions_file)
        before_xml = _read_file(exceptions_file)

        parser = etree.XMLParser(recover=True)
        exc_tree = etree.parse(exceptions_file, parser)
        exc_root = exc_tree.getroot()

        existing_rule = _find_rule_in_tree(exc_root, rule_id)

        if existing_rule is not None:
            # Append exception to existing overwrite rule
            existing_field = None
            for field in existing_rule.findall('field'):
                if field.get('name') == field_name and field.get('negate') == 'yes':
                    existing_field = field
                    break

            if existing_field is not None and existing_field.get('type', '') in ('pcre2', ''):
                current = (existing_field.text or '').strip()
                flags, values = parse_pcre2_pattern(current)
                new_parts = [v.strip() for v in field_value.split('|') if v.strip()]
                for part in new_parts:
                    if part not in values:
                        values.append(part)
                existing_field.text = build_pcre2_pattern(flags, values)
                existing_field.set('type', 'pcre2')
            else:
                pattern = f'(?i)({field_value})' if match_type == 'pcre2' else field_value
                new_field = etree.Element('field')
                new_field.set('name', field_name)
                new_field.set('type', match_type)
                new_field.set('negate', 'yes')
                new_field.text = pattern
                _insert_negate_field(existing_rule, new_field)
        else:
            # Find original rule in default rules dir
            original_rule, source_file = _find_rule_in_directory(rules_dir, rule_id)
            if original_rule is None:
                raise ValueError(f'Rule {rule_id} not found in default rules directory')

            # Deep copy and add overwrite attribute
            new_rule = copy.deepcopy(original_rule)
            new_rule.set('overwrite', 'yes')

            # Add the negate field
            pattern = f'(?i)({field_value})' if match_type == 'pcre2' else field_value
            new_field = etree.Element('field')
            new_field.set('name', field_name)
            new_field.set('type', match_type)
            new_field.set('negate', 'yes')
            new_field.text = pattern
            _insert_negate_field(new_rule, new_field)

            # Append to exceptions file
            exc_root.append(new_rule)

        after_xml = _tree_to_string(exc_tree)
        _write_file(exceptions_file, after_xml)
        return _make_diff(before_xml, after_xml, exceptions_file)


# ---------------------------------------------------------------------------
# Custom Rule: Suppress (set level=0)
# ---------------------------------------------------------------------------

def suppress_custom_rule(file_path, rule_id):
    """Set level="0" and noalert="1" on a custom rule to suppress it."""
    with _file_lock:
        before_xml = _read_file(file_path)
        parser = etree.XMLParser(recover=True)
        tree = etree.parse(file_path, parser)
        root = tree.getroot()

        rule_elem = _find_rule_in_tree(root, rule_id)
        if rule_elem is None:
            raise ValueError(f'Rule {rule_id} not found in {file_path}')

        rule_elem.set('level', '0')
        rule_elem.set('noalert', '1')

        after_xml = _tree_to_string(tree)
        _write_file(file_path, after_xml)
        return _make_diff(before_xml, after_xml, file_path)


# ---------------------------------------------------------------------------
# Default Rule: Suppress (copy + overwrite + level=0)
# ---------------------------------------------------------------------------

def suppress_default_rule(suppressions_file, rules_dir, rule_id):
    """
    Suppress a default Wazuh rule.

    If already in suppressions_file: update level to 0.
    Otherwise: copy from rules_dir, add overwrite="yes", level="0", noalert="1".
    """
    with _file_lock:
        _ensure_xml_wrapper(suppressions_file)
        before_xml = _read_file(suppressions_file)

        parser = etree.XMLParser(recover=True)
        sup_tree = etree.parse(suppressions_file, parser)
        sup_root = sup_tree.getroot()

        existing_rule = _find_rule_in_tree(sup_root, rule_id)

        if existing_rule is not None:
            raise ValueError('ALREADY_SUPPRESSED')
        else:
            original_rule, _ = _find_rule_in_directory(rules_dir, rule_id)
            if original_rule is None:
                raise ValueError(f'Rule {rule_id} not found in default rules directory')

            new_rule = copy.deepcopy(original_rule)
            new_rule.set('overwrite', 'yes')
            new_rule.set('level', '0')
            new_rule.set('noalert', '1')
            sup_root.append(new_rule)

        after_xml = _tree_to_string(sup_tree)
        _write_file(suppressions_file, after_xml)
        return _make_diff(before_xml, after_xml, suppressions_file)


# ---------------------------------------------------------------------------
# Restore (un-suppress) rules
# ---------------------------------------------------------------------------

def restore_custom_rule(file_path, rule_id, new_level):
    """Restore a suppressed custom rule: set level to new_level and remove noalert."""
    with _file_lock:
        before_xml = _read_file(file_path)
        parser = etree.XMLParser(recover=True)
        tree = etree.parse(file_path, parser)
        root = tree.getroot()

        rule_elem = _find_rule_in_tree(root, rule_id)
        if rule_elem is None:
            raise ValueError(f'Rule {rule_id} not found in {file_path}')

        rule_elem.set('level', str(new_level))
        if 'noalert' in rule_elem.attrib:
            del rule_elem.attrib['noalert']

        after_xml = _tree_to_string(tree)
        _write_file(file_path, after_xml)
        return _make_diff(before_xml, after_xml, file_path)


def restore_default_rule(suppressions_file, rule_id):
    """Remove a rule entry from suppressions.xml entirely, restoring original behaviour."""
    with _file_lock:
        before_xml = _read_file(suppressions_file)
        parser = etree.XMLParser(recover=True)
        tree = etree.parse(suppressions_file, parser)
        root = tree.getroot()

        rule_elem = _find_rule_in_tree(root, rule_id)
        if rule_elem is None:
            raise ValueError(f'Rule {rule_id} not found in suppressions file')

        root.remove(rule_elem)

        after_xml = _tree_to_string(tree)
        _write_file(suppressions_file, after_xml)
        return _make_diff(before_xml, after_xml, suppressions_file)


# ---------------------------------------------------------------------------
# Create a new custom rule
# ---------------------------------------------------------------------------

def _build_rule_xml(rule_data):
    """Build a <rule> XML string from rule_data dict."""
    tmp_root = etree.Element('_tmp')
    rule_elem = etree.SubElement(tmp_root, 'rule')
    rule_elem.set('id', str(rule_data['id']))
    rule_elem.set('level', str(rule_data['level']))

    if rule_data.get('frequency'):
        rule_elem.set('frequency', str(rule_data['frequency']))
    if rule_data.get('timeframe'):
        rule_elem.set('timeframe', str(rule_data['timeframe']))
    if rule_data.get('ignore'):
        rule_elem.set('ignore', str(rule_data['ignore']))

    for cond_tag in ('if_sid', 'if_group', 'if_matched_sid', 'if_matched_group',
                      'decoded_as', 'category'):
        val = rule_data.get(cond_tag)
        if val:
            elem = etree.SubElement(rule_elem, cond_tag)
            elem.text = str(val)

    if rule_data.get('match'):
        m = etree.SubElement(rule_elem, 'match')
        m.set('type', rule_data.get('match_type', 'pcre2'))
        m.text = rule_data['match']

    if rule_data.get('regex'):
        r = etree.SubElement(rule_elem, 'regex')
        r.set('type', rule_data.get('regex_type', 'pcre2'))
        r.text = rule_data['regex']

    for field in rule_data.get('fields', []):
        f_elem = etree.SubElement(rule_elem, 'field')
        f_elem.set('name', field['name'])
        if field.get('type'):
            f_elem.set('type', field['type'])
        if field.get('negate'):
            f_elem.set('negate', 'yes')
        f_elem.text = field['value']

    desc = etree.SubElement(rule_elem, 'description')
    desc.text = rule_data.get('description', 'Custom rule')

    mitre_ids = rule_data.get('mitre_ids', [])
    if mitre_ids:
        mitre_elem = etree.SubElement(rule_elem, 'mitre')
        for mid in mitre_ids:
            id_elem = etree.SubElement(mitre_elem, 'id')
            id_elem.text = mid

    for opt in rule_data.get('options', []):
        opt_elem = etree.SubElement(rule_elem, 'options')
        opt_elem.text = opt

    groups = rule_data.get('groups', [])
    if groups:
        g_elem = etree.SubElement(rule_elem, 'group')
        g_elem.text = ','.join(groups) + ','

    raw = etree.tostring(rule_elem, pretty_print=True, xml_declaration=False, encoding='unicode')
    lines = raw.strip().split('\n')
    return '\n'.join('  ' + line for line in lines)


def create_custom_rule(file_path, rule_data):
    """
    Append a new custom rule to the custom rules XML file.
    Supports files with multiple <group> root elements.

    rule_data keys:
      id, level, description, if_group, if_sid, fields (list of field dicts),
      match, regex, mitre_ids (list), options (list), groups (list),
      frequency, timeframe, ignore, target_group (optional group name to insert into)
    """
    with _file_lock:
        _ensure_xml_wrapper(file_path)
        before_xml = _read_file(file_path)

        # Validate ID doesn't already exist (scan all groups)
        root = _load_wazuh_rules_xml(file_path)
        for rule in root.iter('rule'):
            if rule.get('id') == str(rule_data['id']):
                raise ValueError(f"Rule ID {rule_data['id']} already exists in {file_path}")

        rule_xml = _build_rule_xml(rule_data)
        target_group = rule_data.get('target_group', '').strip()

        if target_group:
            # Find the opening <group name="target_group"> tag
            open_pattern = re.compile(
                r'<group\s+name\s*=\s*["\']' + re.escape(target_group) + r'["\'][^>]*>',
            )
            open_m = open_pattern.search(before_xml)
            if not open_m:
                raise ValueError(f"Group '{target_group}' not found in {file_path}")

            # Find the matching top-level </group> — it will be on its own line
            # (not indented inside a <rule>). Search from after the opening tag.
            close_pattern = re.compile(r'^</group>', re.MULTILINE)
            close_m = close_pattern.search(before_xml, open_m.end())
            if not close_m:
                raise ValueError(f"Closing </group> not found for '{target_group}' in {file_path}")

            insert_pos = close_m.start()
            after_xml = before_xml[:insert_pos] + '\n' + rule_xml + '\n\n' + before_xml[insert_pos:]
        else:
            # No target group — insert before the last top-level </group>
            # Find all top-level </group> tags (start of line, not indented)
            close_matches = list(re.finditer(r'^</group>', before_xml, re.MULTILINE))
            if not close_matches:
                raise ValueError(f"No <group> element found in {file_path}")
            last_close = close_matches[-1].start()
            after_xml = before_xml[:last_close] + '\n' + rule_xml + '\n\n' + before_xml[last_close:]

        _write_file(file_path, after_xml)
        return _make_diff(before_xml, after_xml, file_path)


def delete_exception_from_file(file_path, rule_id, field_name, field_value):
    """
    Remove a specific value from a negate field.
    If it was the last value, remove the field entirely.
    If the field was the only exception on an overwrite rule,
    remove the entire rule entry (for exceptions files only).
    """
    with _file_lock:
        before_xml = _read_file(file_path)
        parser = etree.XMLParser(recover=True)
        tree = etree.parse(file_path, parser)
        root = tree.getroot()

        rule_elem = _find_rule_in_tree(root, rule_id)
        if rule_elem is None:
            raise ValueError(f'Rule {rule_id} not found')

        for field in list(rule_elem.findall('field')):
            if field.get('name') == field_name and field.get('negate') == 'yes':
                if not field_value:
                    # Empty field_value means delete the entire field element
                    rule_elem.remove(field)
                else:
                    flags, values = parse_pcre2_pattern(field.text or '')
                    if field_value in values:
                        values.remove(field_value)
                    if values:
                        field.text = build_pcre2_pattern(flags, values)
                    else:
                        rule_elem.remove(field)
                break

        after_xml = _tree_to_string(tree)
        _write_file(file_path, after_xml)
        return _make_diff(before_xml, after_xml, file_path)


def update_rule_raw_xml(file_path, rule_id, new_xml):
    """
    Replace the <rule id="rule_id"> element in file_path with new_xml.
    new_xml must be a valid <rule> element string.
    Returns a unified diff.
    """
    with _file_lock:
        # Validate the new XML is a parseable <rule> element
        new_xml_clean = new_xml.strip()
        try:
            new_elem = etree.fromstring(
                new_xml_clean.encode('utf-8'),
                etree.XMLParser(recover=False)
            )
        except etree.XMLSyntaxError as e:
            raise ValueError(f'Invalid XML: {e}')
        if new_elem.tag != 'rule':
            raise ValueError('Root element must be <rule>')

        before_xml = _read_file(file_path)
        parser = etree.XMLParser(recover=True)
        tree = etree.parse(file_path, parser)
        root = tree.getroot()

        old_elem = _find_rule_in_tree(root, str(rule_id))
        if old_elem is None:
            raise ValueError(f'Rule {rule_id} not found in file')

        parent = old_elem.getparent()
        idx = list(parent).index(old_elem)
        parent.remove(old_elem)
        parent.insert(idx, new_elem)

        after_xml = _tree_to_string(tree)
        _write_file(file_path, after_xml)
        return _make_diff(before_xml, after_xml, file_path)


def delete_rule_from_file(file_path, rule_id):
    """Remove a rule element from the XML file. Returns a unified diff."""
    with _file_lock:
        before_xml = _read_file(file_path)
        parser = etree.XMLParser(recover=True)
        tree = etree.parse(file_path, parser)
        root = tree.getroot()

        rule_elem = _find_rule_in_tree(root, str(rule_id))
        if rule_elem is None:
            raise ValueError(f'Rule {rule_id} not found in file')

        parent = rule_elem.getparent()
        parent.remove(rule_elem)

        after_xml = _tree_to_string(tree)
        _write_file(file_path, after_xml)
        return _make_diff(before_xml, after_xml, file_path)


def get_next_custom_rule_id(file_path, start=100000):
    """Return one above the highest existing rule ID (minimum start)."""
    max_id = start - 1
    if os.path.exists(file_path):
        try:
            root = _load_wazuh_rules_xml(file_path)
            for rule in root.iter('rule'):
                try:
                    if rule.get('overwrite') == 'yes':
                        continue
                    if rule.get('noalert') == '1':
                        continue
                    rid = int(rule.get('id', 0))
                    if rid > max_id:
                        max_id = rid
                except ValueError:
                    pass
        except Exception:
            pass

    return max_id + 1


def get_custom_rule_groups(file_path):
    """Return list of {name, next_id} for each <group> in the custom rules file."""
    groups = []
    if not os.path.exists(file_path):
        return [{'name': 'local,', 'next_id': 100000}]
    try:
        root = _load_wazuh_rules_xml(file_path)
        for grp in root.findall('group'):
            if grp.get('name') is None:
                continue
            grp_name = grp.get('name')
            max_id = 99999
            for rule in grp.iter('rule'):
                try:
                    if rule.get('overwrite') == 'yes':
                        continue
                    if rule.get('noalert') == '1':
                        continue
                    rid = int(rule.get('id', 0))
                    if rid > max_id:
                        max_id = rid
                except ValueError:
                    pass
            groups.append({'name': grp_name, 'next_id': max_id + 1})
    except Exception as e:
        import logging
        logging.getLogger(__name__).error('get_custom_rule_groups error: %s', e)
    if not groups:
        groups = [{'name': 'local,', 'next_id': 100000}]
    return groups


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _insert_negate_field(rule_elem, new_field):
    """Insert a negate <field> element directly before trailing elements
    (description, info, mitre, options, group) so it sits right after
    any existing <field> conditions."""
    TRAILING = frozenset({'description', 'info', 'mitre', 'options', 'group'})
    children = list(rule_elem)
    insert_idx = len(children)
    for i, child in enumerate(children):
        if child.tag in TRAILING:
            insert_idx = i
            break
    # Copy tail whitespace from the preceding sibling so lxml serializes a
    # newline+indent between </field> and the next element (e.g. <description>).
    if insert_idx > 0:
        new_field.tail = children[insert_idx - 1].tail
    else:
        new_field.tail = rule_elem.text
    rule_elem.insert(insert_idx, new_field)


def _find_rule_in_tree(root, rule_id):
    for rule in root.iter('rule'):
        if rule.get('id') == str(rule_id):
            return rule
    return None


def _find_rule_in_directory(rules_dir, rule_id):
    import glob
    rule_id = str(rule_id)
    for xml_file in sorted(glob.glob(os.path.join(rules_dir, '*.xml'))):
        try:
            root = _load_wazuh_rules_xml(xml_file)
            for rule in root.iter('rule'):
                if rule.get('id') == rule_id:
                    return rule, xml_file
        except Exception:
            continue
    return None, None


def _ensure_xml_wrapper(file_path):
    """Create the file with a <group> wrapper if it doesn't exist or is empty."""
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        parent = os.path.dirname(os.path.abspath(file_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(file_path, 'w') as f:
            f.write('<group name="local,">\n\n</group>\n')
    else:
        # Validate it's parseable
        try:
            parser = etree.XMLParser(recover=True)
            etree.parse(file_path, parser)
        except Exception:
            # Back up corrupt file and create fresh
            import shutil
            shutil.copy(file_path, file_path + '.bak')
            with open(file_path, 'w') as f:
                f.write('<group name="local,">\n\n</group>\n')


def _validate_xml_file(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f'File not found: {file_path}')
    parser = etree.XMLParser(recover=False)
    try:
        etree.parse(file_path, parser)
    except etree.XMLSyntaxError as e:
        raise ValueError(f'XML syntax error in {file_path}: {e}')


def _read_file(file_path):
    if not os.path.exists(file_path):
        return ''
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.read()


def _write_file(file_path, content):
    os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)


def _tree_to_string(tree):
    result = etree.tostring(
        tree.getroot(), pretty_print=True, xml_declaration=False, encoding='unicode'
    )
    # Insert a blank line between consecutive <rule> blocks for readability
    result = re.sub(r'(</rule>)\n(?=[ \t]*<rule)', r'\1\n\n', result)
    return result


def _make_diff(before, after, filename):
    """Return a unified diff between before and after content."""
    before_lines = before.splitlines(keepends=True)
    after_lines = after.splitlines(keepends=True)
    diff = list(difflib.unified_diff(
        before_lines, after_lines,
        fromfile=f'a/{os.path.basename(filename)}',
        tofile=f'b/{os.path.basename(filename)}'
    ))
    return ''.join(diff)


def _reorder_rule_children(rule_elem):
    """
    Reorder children so fields come before description/mitre/options/group.
    Maintains Wazuh convention: conditions, fields, description, mitre, options, group.
    Also normalizes whitespace so every child is on its own indented line.
    """
    ORDER = [
        'if_sid', 'if_group', 'if_matched_sid', 'if_matched_group',
        'decoded_as', 'category', 'match', 'regex', 'field',
        'srcip', 'dstip', 'srcport', 'dstport', 'user', 'hostname',
        'program_name', 'location', 'id', 'url',
        'same_source_ip', 'same_user', 'same_field',
        'description', 'info', 'mitre', 'options', 'group',
    ]

    def sort_key(elem):
        try:
            return ORDER.index(elem.tag)
        except ValueError:
            return len(ORDER)

    children = list(rule_elem)
    children.sort(key=sort_key)
    for child in children:
        rule_elem.remove(child)
    for child in children:
        rule_elem.append(child)

    # Normalize whitespace: every child on its own indented line.
    # Detect existing indent from whatever tails are set, default to 4 spaces.
    child_indent = '    '
    for c in children:
        if c.tail and '\n' in c.tail:
            after_nl = c.tail.split('\n')[-1]
            if after_nl == after_nl.lstrip('\t ') or not after_nl.strip():
                # pure whitespace — use it
                child_indent = after_nl if after_nl else '    '
                break
    # Rule element itself is one indent level up
    rule_indent = child_indent[2:] if len(child_indent) >= 2 else ''

    rule_elem.text = '\n' + child_indent
    for i, child in enumerate(children):
        child.tail = '\n' + (child_indent if i < len(children) - 1 else rule_indent)

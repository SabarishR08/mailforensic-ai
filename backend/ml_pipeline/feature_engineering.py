"""
Advanced Feature Engineering Module
Extracts sophisticated features for phishing detection
"""

import re
import numpy as np
from typing import List
from urllib.parse import urlparse
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack, csr_matrix
import logging

logger = logging.getLogger(__name__)


class FeatureEngineer:
    """Advanced feature engineering for email and URL phishing detection"""

    def __init__(self):
        self.email_vectorizer = None
        self.url_vectorizer = None

    def fit_email_features(self, texts: List[str]) -> 'FeatureEngineer':
        logger.info("Fitting email feature extractor...")
        self.email_vectorizer = TfidfVectorizer(
            max_features=15000, ngram_range=(1, 3), min_df=3, max_df=0.9,
            sublinear_tf=True, strip_accents='unicode', lowercase=True,
            token_pattern=r'\b\w+\b', stop_words='english'
        )
        self.email_vectorizer.fit(texts)
        logger.info(f"Email vectorizer fitted with {len(self.email_vectorizer.vocabulary_)} features")
        return self

    def transform_email_features(self, texts: List[str]) -> csr_matrix:
        if self.email_vectorizer is None:
            raise ValueError("Email vectorizer not fitted. Call fit_email_features first.")
        tfidf_features = self.email_vectorizer.transform(texts)
        manual_features = [self._extract_email_manual_features(text) for text in texts]
        manual_features_matrix = csr_matrix(manual_features)
        combined = hstack([tfidf_features, manual_features_matrix])
        logger.info(f"Email features shape: {combined.shape}")
        return combined

    def fit_url_features(self, urls: List[str]) -> 'FeatureEngineer':
        logger.info("Fitting URL feature extractor...")
        self.url_vectorizer = TfidfVectorizer(
            max_features=8000, analyzer='char', ngram_range=(3, 6),
            min_df=2, max_df=0.95, sublinear_tf=True, lowercase=True
        )
        self.url_vectorizer.fit(urls)
        logger.info(f"URL vectorizer fitted with {len(self.url_vectorizer.vocabulary_)} features")
        return self

    def transform_url_features(self, urls: List[str]) -> csr_matrix:
        if self.url_vectorizer is None:
            raise ValueError("URL vectorizer not fitted. Call fit_url_features first.")
        tfidf_features = self.url_vectorizer.transform(urls)
        manual_features = [self._extract_url_manual_features(url) for url in urls]
        manual_features_matrix = csr_matrix(manual_features)
        combined = hstack([tfidf_features, manual_features_matrix])
        logger.info(f"URL features shape: {combined.shape}")
        return combined

    def _extract_email_manual_features(self, text: str) -> List[float]:
        features = []
        text_lower = text.lower()

        features.append(len(text))
        features.append(len(text.split()))

        urls = re.findall(r'https?://[^\s]+', text)
        features.append(len(urls))
        features.append(1 if len(urls) > 0 else 0)
        features.append(1 if len(urls) > 3 else 0)

        urgent_keywords = [
            'urgent', 'immediate', 'verify', 'suspended', 'locked', 'confirm',
            'update', 'expire', 'click here', 'act now', 'limited time',
            'account', 'security', 'unusual activity', 'restricted'
        ]
        features.append(sum(1 for kw in urgent_keywords if kw in text_lower))
        features.append(1 if any(kw in text_lower for kw in urgent_keywords) else 0)

        money_keywords = [
            'payment', 'bank', 'credit', 'account', 'money', 'wire', 'transfer',
            'dollar', 'fee', 'charge', 'refund', 'tax', 'irs', 'invoice'
        ]
        features.append(sum(1 for kw in money_keywords if kw in text_lower))
        features.append(1 if any(kw in text_lower for kw in money_keywords) else 0)

        identity_keywords = [
            'verify', 'confirm', 'validate', 'identity', 'ssn', 'social security',
            'password', 'pin', 'credentials', 'login', 'username'
        ]
        features.append(sum(1 for kw in identity_keywords if kw in text_lower))
        features.append(1 if any(kw in text_lower for kw in identity_keywords) else 0)

        features.append(len(re.findall(r'[!@#$%^&*()_+=\[\]{}|;:,.<>?]', text)))
        features.append(text.count('!'))
        features.append(text.count('?'))

        capitals = sum(1 for c in text if c.isupper())
        features.append(capitals / len(text) if len(text) > 0 else 0)
        features.append(1 if capitals / len(text) > 0.3 else 0 if len(text) > 0 else 0)

        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        features.append(len(re.findall(email_pattern, text)))

        phone_pattern = r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
        features.append(len(re.findall(phone_pattern, text)))

        features.append(1 if 'click here' in text_lower else 0)
        features.append(1 if 'verify your account' in text_lower else 0)
        features.append(1 if 'suspended' in text_lower else 0)
        features.append(1 if 'unusual activity' in text_lower else 0)
        features.append(1 if 'confirm your identity' in text_lower else 0)

        features.append(text.count('<a '))
        features.append(text.count('href='))
        features.append(1 if '<html' in text_lower else 0)

        misspell_patterns = ['y0u', 'acc0unt', 'ver1fy', 'cl1ck']
        features.append(sum(1 for p in misspell_patterns if p in text_lower))

        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click']
        features.append(sum(1 for tld in suspicious_tlds if tld in text_lower))

        digits = sum(c.isdigit() for c in text)
        features.append(digits / len(text) if len(text) > 0 else 0)

        return features

    def _extract_url_manual_features(self, url: str) -> List[float]:
        features = []
        try:
            parsed = urlparse(url)

            features.append(len(url))
            features.append(len(parsed.netloc))
            features.append(len(parsed.path))
            features.append(len(parsed.query))

            features.append(url.count('.'))
            features.append(url.count('-'))
            features.append(url.count('_'))
            features.append(url.count('/'))
            features.append(url.count('?'))
            features.append(url.count('='))
            features.append(url.count('@'))
            features.append(url.count('&'))
            features.append(url.count('%'))
            features.append(url.count('#'))

            features.append(1 if parsed.scheme == 'https' else 0)
            features.append(1 if parsed.scheme == 'http' else 0)

            ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            features.append(1 if re.match(ip_pattern, parsed.netloc) else 0)

            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
                              '.work', '.click', '.link', '.download', '.racing']
            features.append(1 if any(url.lower().endswith(tld) for tld in suspicious_tlds) else 0)

            popular_domains = ['google', 'facebook', 'amazon', 'microsoft', 'apple',
                              'twitter', 'linkedin', 'github', 'stackoverflow', 'wikipedia']
            features.append(1 if any(domain in parsed.netloc.lower() for domain in popular_domains) else 0)

            subdomain_count = parsed.netloc.count('.') - 1 if parsed.netloc.count('.') > 0 else 0
            features.append(subdomain_count)
            features.append(1 if subdomain_count > 3 else 0)

            features.append(1 if ':' in parsed.netloc and not parsed.scheme else 0)

            path_depth = parsed.path.count('/')
            features.append(path_depth)
            features.append(1 if path_depth > 5 else 0)

            digits = sum(c.isdigit() for c in url)
            features.append(digits / len(url) if len(url) > 0 else 0)
            features.append(1 if digits / len(url) > 0.2 else 0 if len(url) > 0 else 0)

            domain_digits = sum(c.isdigit() for c in parsed.netloc)
            features.append(domain_digits / len(parsed.netloc) if len(parsed.netloc) > 0 else 0)

            features.append(url.count('%'))
            features.append(1 if url.count('%') > 3 else 0)

            shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 't.co', 'short.link']
            features.append(1 if any(short in url.lower() for short in shorteners) else 0)

            suspicious_words = ['verify', 'account', 'login', 'secure', 'banking',
                               'update', 'confirm', 'signin', 'ebayisapi', 'webscr']
            features.append(sum(1 for word in suspicious_words if word in url.lower()))
            features.append(1 if any(word in url.lower() for word in suspicious_words) else 0)

            features.append(url.count('//') - 1)
            features.append(url.count('@'))
            features.append(parsed.netloc.count('-'))
            features.append(1 if parsed.netloc.count('-') > 3 else 0)

        except Exception:
            return [0] * 36

        return features

    def get_feature_names(self, feature_type: str = 'email') -> List[str]:
        """
        Get feature names for interpretation and importance analysis.
        Ported from email-phishing-detector (Group B consolidation).

        Args:
            feature_type: 'email' or 'url'

        Returns:
            TF-IDF names (if fitted) followed by the manual feature names,
            in the exact order produced by the _extract_*_manual_features
            methods.
        """
        email_manual_names = [
            'text_length', 'word_count', 'url_count', 'has_urls', 'many_urls',
            'urgent_keyword_count', 'has_urgent', 'money_keyword_count', 'has_money',
            'identity_keyword_count', 'has_identity', 'special_char_count',
            'exclamation_count', 'question_count', 'capital_ratio', 'high_capital_ratio',
            'email_count', 'phone_count', 'has_click_here', 'has_verify_account',
            'has_suspended', 'has_unusual_activity', 'has_confirm_identity',
            'html_link_count', 'href_count', 'is_html', 'misspelling_count',
            'suspicious_tld_count', 'digit_ratio'
        ]
        url_manual_names = [
            'url_length', 'domain_length', 'path_length', 'query_length',
            'dot_count', 'dash_count', 'underscore_count', 'slash_count',
            'question_count', 'equal_count', 'at_count', 'ampersand_count',
            'percent_count', 'hash_count', 'is_https', 'is_http', 'has_ip',
            'suspicious_tld', 'popular_domain', 'subdomain_count', 'many_subdomains',
            'has_port', 'path_depth', 'deep_path', 'digit_ratio', 'high_digit_ratio',
            'domain_digit_ratio', 'hex_encoding_count', 'has_hex_encoding',
            'is_url_shortener', 'suspicious_keyword_count', 'has_suspicious_keyword',
            'double_slash_count', 'at_symbol_count', 'domain_dash_count', 'many_dashes'
        ]

        if feature_type == 'email':
            if self.email_vectorizer is None:
                return list(email_manual_names)
            return self.email_vectorizer.get_feature_names_out().tolist() + email_manual_names
        else:  # url
            if self.url_vectorizer is None:
                return list(url_manual_names)
            return self.url_vectorizer.get_feature_names_out().tolist() + url_manual_names

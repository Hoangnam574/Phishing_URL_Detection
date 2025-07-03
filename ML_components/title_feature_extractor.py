# title_feature_extractor.py
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from tqdm import tqdm

from ML_components.utils import (
    strip_scheme_www,
    SUSPICIOUS_KEYWORDS,
    remove_vietnamese_diacritics,
)


class TitleFeatureExtractor(BaseEstimator, TransformerMixin):
    def __init__(self, title_mapping: dict):
        self.title_mapping = title_mapping or {}

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        features = []
        for url in tqdm(X, desc="Title features", disable=True):
            clean = strip_scheme_www(url)
            title_raw = self.title_mapping.get(clean, "") or ""
            title_norm = remove_vietnamese_diacritics(title_raw.lower())
            kw_cnt = sum(1 for w in SUSPICIOUS_KEYWORDS if w in title_norm)
            features.append([len(title_norm), kw_cnt])
            print(f"[✓] Title chuẩn hóa: \"{title_norm}\" → KW hits: {kw_cnt}")
        return np.array(features)

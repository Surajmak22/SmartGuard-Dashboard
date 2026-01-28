from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
import shap


class ModelExplainer:
    """
    Wrapper for SHAP explainability.
    Optimized for Tree-based models (Random Forest).
    """

    def __init__(self, model: Any, X_train: pd.DataFrame):
        self.model = model
        self.X_train = X_train
        self.explainer = None
        self.shap_values = None
        
        # Initialize explainer
        # Note: robust checking for model type could be added here
        try:
            self.explainer = shap.TreeExplainer(self.model)
        except Exception as e:
            # Fallback for non-tree models (e.g. SVM), though slower
            # Using X_train summary to speed up KernelExplainer
            background = shap.sample(self.X_train, 50)
            self.explainer = shap.KernelExplainer(self.model.predict_proba, background)

    def explain_global(self, X_sample: pd.DataFrame) -> Any:
        """
        Calculate SHAP values for a sample of data (global view).
        """
        # SHAP for trees usually returns list [values_class0, values_class1] for binary
        shap_values = self.explainer.shap_values(X_sample)
        return shap_values

    def explain_local(self, X_instance: pd.DataFrame) -> Any:
        """
        Calculate SHAP values for a single instance.
        """
        shap_values = self.explainer.shap_values(X_instance)
        return shap_values

    def get_text_explanation(self, X_instance: pd.DataFrame, class_idx: int = 1) -> List[str]:
        """
        Generate human-readable explanation for a specific prediction.
        """
        shap_values = self.explainer.shap_values(X_instance)
        
        # Handle different return shapes from shap
        if isinstance(shap_values, list):
            # Binary classification: index 1 is usually the positive class (ATTACK)
            vals = shap_values[class_idx]
        else:
            vals = shap_values

        # 1. Force to numpy array
        vals = np.array(vals)
        
        # 2. Squeeze out all dimensions of size 1 (e.g. (1, 79) -> (79,))
        vals = np.squeeze(vals)
        
        # 3. If it's still > 1D (unlikely for single instance), take the first row
        if vals.ndim > 1:
            vals = vals[0]
            
        # 4. Ensure 1D and float
        vals = vals.ravel().astype(float)


            
        feature_names = X_instance.columns
        
        # Create (feature, contribution) pairs
        contributions = []
        for name, val in zip(feature_names, vals):
            contributions.append((name, val))
            
        # Sort by absolute magnitude
        contributions.sort(key=lambda x: abs(x[1]), reverse=True)
        
        top_n = contributions[:3]
        explanations = []
        
        for name, val in top_n:
            impact = "increased" if val > 0 else "decreased"
            strength = "significantly" if abs(val) > 0.1 else "slightly"
            explanations.append(f"The feature **{name}** {impact} the threat score {strength}.")
            
        return explanations

from __future__ import annotations

import time
from dataclasses import asdict
from typing import Dict, Optional

import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st
from sklearn.metrics import confusion_matrix

from src.inference.predictor import Predictor
from src.phase1.training import TrainedBundle, train_binary_classifier, transform_features
from src.phase1.explainability import ModelExplainer
from src.phase1.reporting import IncidentReportGenerator

import matplotlib.pyplot as plt
import shap

try:
    from streamlit_shap import st_shap
except ImportError:
    st_shap = None


def _guess_label_column(df: pd.DataFrame) -> Optional[str]:
    def _norm(s: object) -> str:
        return str(s).replace("\ufeff", "").strip().lower()

    candidates = [
        "label",
        "Label",
        "class",
        "Class",
        "target",
        "Target",
        "attack",
        "Attack",
        "attack_cat",
    ]

    norm_to_orig = {_norm(c): str(c) for c in df.columns}
    for c in candidates:
        hit = norm_to_orig.get(_norm(c))
        if hit is not None:
            return hit
    return None


def _severity_counts(severity: np.ndarray) -> Dict[str, int]:
    vals, counts = np.unique(severity.astype(str), return_counts=True)
    return {str(v): int(c) for v, c in zip(vals, counts)}


def run() -> None:
    try:
        st.set_page_config(page_title="SmartGuard AI – Phase 2", layout="wide")
    except Exception:
        pass

    st.title("SmartGuard AI – Phase 2: Explainable & Translucent AI")
    st.caption("Phase 2: Advanced detection with SHAP explainability, PDF reporting, and simulated streaming.")

    st.sidebar.header("Controls")

    uploaded = st.sidebar.file_uploader("Upload CSV", type=["csv"])
    if uploaded is None:
        st.info("Upload a CSV dataset to begin.")
        return

    df = pd.read_csv(uploaded)
    if df.empty:
        st.error("Uploaded file is empty.")
        return

    # Clean common CSV issues (CICIDS exports sometimes include BOM/whitespace in headers)
    cleaned_cols = [str(c).replace("\ufeff", "").strip() for c in df.columns]
    if len(set(cleaned_cols)) == len(cleaned_cols):
        df.columns = cleaned_cols

    st.sidebar.caption(f"Rows: {len(df):,} | Columns: {df.shape[1]}")

    label_guess = _guess_label_column(df)
    label_col = st.sidebar.selectbox(
        "Label column",
        options=[c for c in df.columns],
        index=(list(df.columns).index(label_guess) if label_guess in df.columns else 0),
    )

    unique_labels = int(df[label_col].nunique(dropna=False)) if label_col in df.columns else 0
    st.sidebar.caption(f"Unique values in label column: {unique_labels:,}")

    if "Label" in df.columns and label_col != "Label" and unique_labels > 20:
        st.sidebar.warning("For CIC-IDS2017, the correct label column is usually 'Label'.")

    model_name = st.sidebar.selectbox("Model", options=["random_forest", "svm"])

    confidence_threshold = st.sidebar.slider("Confidence threshold", min_value=0.5, max_value=0.99, value=0.7, step=0.01)

    smoothing_window = st.sidebar.slider("Optional smoothing window", min_value=0, max_value=30, value=0, step=1)

    # Per-class thresholding: for binary we only expose ATTACK threshold.
    enable_per_class = st.sidebar.checkbox("Enable per-class probability thresholding (FP reduction)", value=True)
    attack_threshold = st.sidebar.slider("ATTACK probability threshold", min_value=0.1, max_value=0.99, value=0.5, step=0.01)

    tabs = st.tabs(["Evaluation", "Alerts", "Model Explainability", "Synthetic Streaming"])  # Task-4 tab name

    with tabs[0]:
        st.subheader("Train/Test Evaluation (Offline)")

        test_size = st.slider("Test split size", min_value=0.1, max_value=0.5, value=0.2, step=0.05)
        use_smote = st.checkbox("Use SMOTE (recommended for imbalanced data)", value=True)

        max_rows = st.slider(
            "Max rows to use for training (speed control)",
            min_value=1000,
            max_value=int(min(200000, len(df))),
            value=int(min(50000, len(df))),
            step=1000,
        )

        df_train = df
        if len(df) > int(max_rows):
            df_train = df.sample(n=int(max_rows), random_state=42)
            st.info(f"Using a random sample of {len(df_train):,} rows for training (dataset has {len(df):,} rows).")

        if label_col in df_train.columns:
            v = df_train[label_col].astype(str).str.strip().str.lower()
            benign_like = v.isin({"benign", "normal", "0", "false"})
            benign_n = int(benign_like.sum())
            attack_n = int(len(v) - benign_n)
            c1, c2 = st.columns(2)
            c1.metric("BENIGN-like (preview)", f"{benign_n:,}")
            c2.metric("Other/ATTACK-like (preview)", f"{attack_n:,}")

            if benign_n == 0 or attack_n == 0:
                st.error(
                    "Selected label column produces only one class after normalization. "
                    "This usually means the wrong label column is selected (for CIC-IDS2017 choose 'Label')."
                )

        if st.button("Train & Evaluate"):
            with st.spinner("Training model..."):
                bundle, metrics, pred_df = train_binary_classifier(
                    df_train,
                    label_col=label_col,
                    model_name=model_name,
                    test_size=float(test_size),
                    use_smote=bool(use_smote),
                )

            st.session_state["phase1_bundle"] = bundle
            st.session_state["phase1_metrics"] = metrics
            st.session_state["phase1_pred_df"] = pred_df

        metrics = st.session_state.get("phase1_metrics")
        if metrics:
            col1, col2, col3, col4, col5 = st.columns(5)
            col1.metric("Accuracy", f"{metrics['accuracy']:.3f}")
            col2.metric("Precision", f"{metrics['precision']:.3f}")
            col3.metric("Recall", f"{metrics['recall']:.3f}")
            col4.metric("F1", f"{metrics['f1']:.3f}")
            col5.metric("ROC-AUC", "—" if metrics["roc_auc"] is None else f"{metrics['roc_auc']:.3f}")

        pred_df = st.session_state.get("phase1_pred_df")
        if isinstance(pred_df, pd.DataFrame):
            if {"y_true", "y_pred"}.issubset(set(pred_df.columns)):
                y_true = pred_df["y_true"].astype(int).to_numpy()
                y_pred = pred_df["y_pred"].astype(int).to_numpy()

                cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
                cm_df = pd.DataFrame(
                    cm,
                    index=["True: BENIGN (0)", "True: ATTACK (1)"],
                    columns=["Pred: BENIGN (0)", "Pred: ATTACK (1)"],
                )

                c_cm, c_counts = st.columns([2, 1])
                with c_cm:
                    fig = px.imshow(
                        cm_df,
                        text_auto=True,
                        color_continuous_scale="Blues",
                        aspect="auto",
                        title="Confusion Matrix",
                    )
                    st.plotly_chart(fig, use_container_width=True)

                with c_counts:
                    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
                    st.metric("TN", str(tn))
                    st.metric("FP", str(fp))
                    st.metric("FN", str(fn))
                    st.metric("TP", str(tp))

            filter_mode = st.selectbox(
                "Show rows",
                options=[
                    "All",
                    "Actual ATTACK (y_true=1)",
                    "Predicted ATTACK (y_pred=1)",
                    "False Positives (y_true=0, y_pred=1)",
                    "False Negatives (y_true=1, y_pred=0)",
                    "Low-confidence (y_score near 0.5)",
                ],
                index=0,
            )

            view_df = pred_df
            if filter_mode == "Actual ATTACK (y_true=1)" and "y_true" in view_df.columns:
                view_df = view_df[view_df["y_true"].astype(int) == 1]
            elif filter_mode == "Predicted ATTACK (y_pred=1)" and "y_pred" in view_df.columns:
                view_df = view_df[view_df["y_pred"].astype(int) == 1]
            elif filter_mode == "False Positives (y_true=0, y_pred=1)" and {"y_true", "y_pred"}.issubset(set(view_df.columns)):
                yt = view_df["y_true"].astype(int)
                yp = view_df["y_pred"].astype(int)
                view_df = view_df[(yt == 0) & (yp == 1)]
            elif filter_mode == "False Negatives (y_true=1, y_pred=0)" and {"y_true", "y_pred"}.issubset(set(view_df.columns)):
                yt = view_df["y_true"].astype(int)
                yp = view_df["y_pred"].astype(int)
                view_df = view_df[(yt == 1) & (yp == 0)]
            elif filter_mode == "Low-confidence (y_score near 0.5)" and "y_score" in view_df.columns:
                ys = view_df["y_score"].astype(float)
                view_df = view_df[(ys >= 0.40) & (ys <= 0.60)].sort_values("y_score", ascending=False)

            st.caption(f"Showing {len(view_df):,} of {len(pred_df):,} rows")
            st.dataframe(view_df.head(200), use_container_width=True)

    bundle: Optional[TrainedBundle] = st.session_state.get("phase1_bundle")

    with tabs[1]:
        st.subheader("Confidence-based Alerts")

        if bundle is None:
            st.info("Train a model in the Evaluation tab first.")
        else:
            prepared_df = df.drop(columns=[label_col], errors="ignore")
            X_t = transform_features(bundle, prepared_df)

            # Build per-class thresholds (binary => apply to class 1 where model outputs [0,1])
            per_class_thresholds = None
            if enable_per_class:
                # Predictor works with model.classes_. For our binary training we used numeric labels 0/1.
                per_class_thresholds = {1: float(attack_threshold)}

            predictor = Predictor(
                bundle.model,
                confidence_threshold=float(confidence_threshold),
                normal_class_names=("0", "benign", "normal"),
                per_class_thresholds=per_class_thresholds,
                smoothing_window=int(smoothing_window),
            )

            X_model = pd.DataFrame(X_t)  # model expects numpy; Predictor accepts DataFrame
            res = predictor.predict(X_model)

            out = pd.DataFrame(
                {
                    "predicted_label": res.y_pred,
                    "confidence": res.confidence,
                    "severity": res.severity,
                    "low_confidence": res.low_confidence,
                }
            )

            sev_counts = _severity_counts(res.severity)
            c1, c2, c3 = st.columns(3)
            c1.metric("High", str(sev_counts.get("High", 0)))
            c2.metric("Medium", str(sev_counts.get("Medium", 0)))
            c3.metric("Low", str(sev_counts.get("Low", 0)))

            st.dataframe(out.head(200), use_container_width=True)

            st.divider()
            st.subheader("🔍 Incident Drill-Down & Reporting")
            
            # Allow user to select a row to analyze
            if not out.empty:
                selected_idx = st.number_input(
                    "Select Row Index to Analyze", 
                    min_value=0, 
                    max_value=len(out)-1, 
                    value=0, 
                    step=1
                )
                
                if st.button("Analyze Selected Incident"):
                    row_data = out.iloc[selected_idx]
                    original_input = X_t[selected_idx] # This is numpy array
                    
                    # We need the DataFrame version for SHAP
                    # Reconstruct DataFrame with feature names
                    feat_names = bundle.feature_names
                    instance_df = pd.DataFrame([original_input], columns=feat_names)

                    c_det, c_exp = st.columns([1, 2])
                    
                    with c_det:
                        st.markdown(f"**ID:** `INC-{int(time.time())}-{selected_idx}`")
                        st.markdown(f"**Severity:** {row_data['severity']}")
                        st.markdown(f"**Confidence:** {row_data['confidence']:.2%}")
                        st.markdown(f"**Prediction:** {'ATTACK' if row_data['predicted_label'] == 1 else 'BENIGN'}")
                    
                    with c_exp:
                        st.write("Generating explanation...")
                        explainer = ModelExplainer(bundle.model, bundle.X_train_sample)
                        explanations = explainer.get_text_explanation(instance_df)
                        
                        for exp in explanations:
                            st.info(exp, icon="ℹ️")
                            
                        # Download Report
                        gen = IncidentReportGenerator()
                        pdf_bytes = gen.generate_report(
                            incident_id=f"INC-{int(time.time())}-{selected_idx}",
                            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                            confidence=row_data['confidence'],
                            severity=row_data['severity'],
                            explanations=explanations,
                            analyst_notes="Automated analysis via SmartGuard AI."
                        )
                        
                        st.download_button(
                            label="📄 Download PDF Incident Report",
                            data=pdf_bytes,
                            file_name=f"incident_report_{selected_idx}.pdf",
                            mime="application/pdf"
                        )
                        
                        if st_shap:
                            st.markdown("#### Local SHAP Force Plot")
                            shap_vals = explainer.explain_local(instance_df)
                            # Visualize the first (and only) row
                            # If binary, shap_vals is list of arrays. We want class 1.
                            if isinstance(shap_vals, list):
                                # Check expected value
                                if isinstance(explainer.explainer.expected_value, list):
                                    base_val = explainer.explainer.expected_value[1]
                                else:
                                    base_val = explainer.explainer.expected_value
                                
                                st_shap(shap.force_plot(
                                    base_val, 
                                    shap_vals[1][0], 
                                    instance_df.iloc[0],
                                    link="logit" if bundle.model_name == "svm" else "identity"
                                ))
                            else:
                                # For TreeExplainer on binary RF, it might be simpler
                                st_shap(shap.force_plot(
                                    explainer.explainer.expected_value[1], 
                                    shap_vals[1][0], 
                                    instance_df.iloc[0]
                                ))

    with tabs[2]:
        st.subheader("Model Explainability (Random Forest)")

        if bundle is None:
            st.info("Train a model in the Evaluation tab first.")
        elif bundle.model_name != "random_forest":
            st.warning("Explainability is available only for Random Forest in Phase-1.")
        else:
            # Feature importance from RF
            rf = bundle.model
            importances = getattr(rf, "feature_importances_", None)
            if importances is None:
                st.error("Random Forest does not expose feature_importances_.")
            else:
                names = bundle.feature_names
                if not names:
                    names = [f"f{i}" for i in range(len(importances))]

                imp_df = pd.DataFrame({"feature": names, "importance": importances}).sort_values(
                    "importance", ascending=False
                )
                top10 = imp_df.head(10)

                fig = px.bar(top10[::-1], x="importance", y="feature", orientation="h", title="Top 10 Feature Importances")
                st.plotly_chart(fig, use_container_width=True)
            st.dataframe(top10, use_container_width=True)

            st.divider()
            st.subheader("Global SHAP Summary")
            
            if st_shap:
                with st.spinner("Calculating SHAP values for global summary..."):
                    # Use the sample from the bundle
                    explainer = ModelExplainer(bundle.model, bundle.X_train_sample)
                    
                    # Calculate SHAP for the background sample itself or a new small sample
                    shap_values = explainer.explain_global(bundle.X_train_sample)
                    
                    # For binary classification, we usually focus on class 1 (Attack)
                    vals_to_plot = shap_values
                    if isinstance(shap_values, list):
                        vals_to_plot = shap_values[1]
                        
                    shap.summary_plot(vals_to_plot, bundle.X_train_sample, plot_type="dot", show=False)
                    st.pyplot(plt.gcf())
            else:
                st.warning("`streamlit-shap` not installed. SHAP plots unavailable.")

    with tabs[3]:
        st.subheader("Synthetic Streaming Simulation (CSV Row-by-Row)")

        if bundle is None:
            st.info("Train a model in the Evaluation tab first.")
        else:
            delay = st.slider("Delay per row (seconds)", min_value=0.5, max_value=1.0, value=0.5, step=0.1)
            n_rows = st.slider("Rows to simulate", min_value=50, max_value=min(2000, len(df)), value=min(200, len(df)), step=50)

            start = st.button("Start Simulation")
            if start:
                prepared_df = df.drop(columns=[label_col], errors="ignore").head(int(n_rows))
                X_t = transform_features(bundle, prepared_df)

                per_class_thresholds = {1: float(attack_threshold)} if enable_per_class else None
                predictor = Predictor(
                    bundle.model,
                    confidence_threshold=float(confidence_threshold),
                    normal_class_names=("0", "benign", "normal"),
                    per_class_thresholds=per_class_thresholds,
                    smoothing_window=int(smoothing_window),
                )

                placeholder_metrics = st.empty()
                placeholder_chart = st.empty()

                attack_count = 0
                benign_count = 0
                timeline = []

                for i in range(len(prepared_df)):
                    X_row = pd.DataFrame(X_t[i : i + 1])
                    res = predictor.predict(X_row)
                    pred = int(res.y_pred[0])

                    if pred == 1:
                        attack_count += 1
                    else:
                        benign_count += 1

                    timeline.append({"step": i + 1, "attack": attack_count, "benign": benign_count})

                    with placeholder_metrics.container():
                        c1, c2 = st.columns(2)
                        c1.metric("Attack", str(attack_count))
                        c2.metric("Benign", str(benign_count))

                    chart_df = pd.DataFrame(timeline)
                    fig = px.line(chart_df, x="step", y=["attack", "benign"], title="Attack vs Benign Trend")
                    placeholder_chart.plotly_chart(fig, use_container_width=True)

                    time.sleep(float(delay))


if __name__ == "__main__":
    run()

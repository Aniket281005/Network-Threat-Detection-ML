import streamlit as st
import pandas as pd
import joblib

# Load model and scaler
model = joblib.load("network_threat_model.joblib")
scaler = joblib.load("scaler.joblib")

# Page settings
st.set_page_config(
    page_title="Network Threat Detection",
    page_icon="🛡️",
    layout="centered"
)

# Title
st.title("🛡️ Network Threat Detection System")

st.write(
    "Enter network traffic details and predict whether the connection is Normal or an Attack."
)

# Inputs
duration = st.number_input(
    "Connection Duration",
    min_value=0.0,
    value=0.0
)

protocol_type = st.selectbox(
    "Protocol Type",
    ["tcp", "udp", "icmp"]
)

src_bytes = st.number_input(
    "Source Bytes",
    min_value=0.0,
    value=0.0
)

dst_bytes = st.number_input(
    "Destination Bytes",
    min_value=0.0,
    value=0.0
)

count = st.number_input(
    "Connection Count",
    min_value=0.0,
    value=0.0
)

srv_count = st.number_input(
    "Service Count",
    min_value=0.0,
    value=0.0
)

serror_rate = st.number_input(
    "Serror Rate",
    min_value=0.0,
    max_value=1.0,
    value=0.0
)

same_srv_rate = st.number_input(
    "Same Service Rate",
    min_value=0.0,
    max_value=1.0,
    value=0.0
)

dst_host_count = st.number_input(
    "Destination Host Count",
    min_value=0.0,
    value=0.0
)

dst_host_srv_count = st.number_input(
    "Destination Host Service Count",
    min_value=0.0,
    value=0.0
)

# Protocol Encoding
protocol_mapping = {
    "icmp": 0,
    "tcp": 1,
    "udp": 2
}

protocol_type = protocol_mapping[protocol_type]

# Prediction
if st.button("Predict Threat"):

    input_data = pd.DataFrame(
        [[
            duration,
            protocol_type,
            src_bytes,
            dst_bytes,
            count,
            srv_count,
            serror_rate,
            same_srv_rate,
            dst_host_count,
            dst_host_srv_count
        ]],
        columns=[
            "duration",
            "protocol_type",
            "src_bytes",
            "dst_bytes",
            "count",
            "srv_count",
            "serror_rate",
            "same_srv_rate",
            "dst_host_count",
            "dst_host_srv_count"
        ]
    )

    scaled_data = scaler.transform(input_data)

    prediction = model.predict(scaled_data)

    st.write("Prediction Value:", prediction[0])

    if prediction[0] == 1:
        st.error("⚠️ Attack Detected")
    else:
        st.success("✅ Normal Network Traffic")
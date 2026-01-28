import plotly.graph_objects as go
import pandas as pd
import numpy as np

def create_threat_map():
    """
    Generates a high-end SOC Threat Map simulation.
    """
    # Mock global SOC nodes
    nodes_df = pd.DataFrame({
        'City': ['New York', 'London', 'Tokyo', 'Singapore', 'Mumbai'],
        'Lat': [40.7128, 51.5074, 35.6762, 1.3521, 19.0760],
        'Lon': [-74.0060, -0.1278, 139.6503, 103.8198, 72.8777],
        'Status': ['Secure', 'Secure', 'Active Analysis', 'Secure', 'Traffic Surge']
    })

    # Mock active threats (randomized)
    threats_df = pd.DataFrame({
        'Lat': np.random.uniform(-40, 60, 5),
        'Lon': np.random.uniform(-100, 140, 5),
        'Severity': ['Critical', 'High', 'Medium', 'Critical', 'Low']
    })

    fig = go.Figure()

    # Base Map (Dark Theme)
    fig.add_trace(go.Scattergeo(
        locationmode = 'ISO-3',
        lon = nodes_df['Lon'],
        lat = nodes_df['Lat'],
        text = nodes_df['City'] + " - " + nodes_df['Status'],
        mode = 'markers+text',
        textposition="bottom center",
        marker = dict(
            size = 12,
            color = '#00F5FF',
            symbol = 'square',
            line = dict(width=1, color='rgba(0, 245, 255, 0.5)')
        ),
        name = "Global SOC Nodes"
    ))

    # Active Threats
    fig.add_trace(go.Scattergeo(
        lon = threats_df['Lon'],
        lat = threats_df['Lat'],
        marker = dict(
            size = 15,
            color = '#FF003C',
            symbol = 'x',
            opacity = 0.8
        ),
        name = "Recent Threat Origins"
    ))

    fig.update_layout(
        title = dict(text="GLOBAL DEFENSE MATRIX", font=dict(color="#00F5FF", size=20)),
        geo = dict(
            scope = 'world',
            projection_type = 'orthographic',
            showland = True,
            landcolor = "#0B0E14",
            showocean = True,
            oceancolor = "#05070A",
            showlakes = False,
            bgcolor = 'rgba(0,0,0,0)',
            showframe = False,
            coastlinecolor = "rgba(0, 245, 255, 0.2)"
        ),
        paper_bgcolor = 'rgba(0,0,0,0)',
        plot_bgcolor = 'rgba(0,0,0,0)',
        margin = dict(l=0, r=0, t=50, b=0),
        legend = dict(font=dict(color="white"), bgcolor="rgba(0,0,0,0)")
    )

    return fig

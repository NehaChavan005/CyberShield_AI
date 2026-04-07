import os
import sys
import hashlib
import html
from datetime import datetime, timedelta, timezone


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import plotly.express as px

from alerts.alert_manager import get_alert_dashboard_snapshot
from alerts.ui_alert import (
    render_alert_banner_html,
    render_audio_html,
    sync_ui_alert_state,
)
from auth.streamlit_auth import AUTH_BRAND_HTML, auth_page, logout_button, open_signup_page
from model.model_lifecycle import (
    get_current_model_status,
    list_model_versions,
    retrain_model_from_feedback,
    submit_feedback,
)
from utils.attack_predictor import predict_attack
from utils.forensics import analyze_attack_history, export_attack_history_csv, export_attack_history_pdf, load_attack_history
from utils.packet_capture import run_dataset_packet_capture
from utils.threat_intelligence import add_to_blacklist, enrich_threat_intelligence, load_blacklist_db
from utils.vulnerability_scanner import scan_target

try:
    from streamlit_autorefresh import st_autorefresh
except Exception:
    def st_autorefresh(*args, **kwargs):
        return None


st.set_page_config(
    page_title="CyberShield-AI",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

  .stApp {
    background:
      radial-gradient(circle at top left, rgba(0, 255, 255, 0.14), transparent 28%),
      radial-gradient(circle at top right, rgba(0, 255, 159, 0.10), transparent 24%),
      radial-gradient(circle at bottom center, rgba(0, 180, 255, 0.12), transparent 34%),
      linear-gradient(140deg, #05070b 0%, #09111f 44%, #04141d 100%);
    color: #ffffff;
    font-family: 'Inter', sans-serif;
    position: relative;
  }
  .stApp::before {
    content: "";
    position: fixed;
    inset: 0;
    z-index: -2;
    background:
      radial-gradient(circle at 15% 20%, rgba(0, 255, 255, 0.10), transparent 0 24%),
      radial-gradient(circle at 85% 18%, rgba(0, 255, 159, 0.08), transparent 0 22%),
      radial-gradient(circle at 50% 82%, rgba(0, 140, 255, 0.09), transparent 0 30%);
    pointer-events: none;
  }
  .stApp > header,
  .stApp > div,
  section[data-testid="stSidebar"] {
    position: relative;
    z-index: 1;
  }
  h1, h2, h3, .auth-title {
    font-family: 'Inter', sans-serif;
    letter-spacing: 0.04em;
  }
  section[data-testid="stSidebar"] {
    background: rgba(6, 16, 26, 0.82);
    border-right: 1px solid rgba(255,255,255,0.10);
    backdrop-filter: blur(18px);
    -webkit-backdrop-filter: blur(18px);
  }
  section[data-testid="stSidebar"] * {
    color: #ffffff;
  }
  .stTextInput input, .stNumberInput input, .stTextArea textarea, .stSelectbox div[data-baseweb="select"] > div {
    background: rgba(255,255,255,0.06);
    border: 1px solid rgba(255,255,255,0.10);
    border-radius: 14px;
    color: #ffffff;
    backdrop-filter: blur(12px);
  }
  .stButton > button {
    background: linear-gradient(135deg, rgba(0,255,255,0.20), rgba(0,255,159,0.18));
    color: #ffffff;
    border: 1px solid rgba(0,255,255,0.28);
    border-radius: 14px;
    box-shadow: 0 0 18px rgba(0,255,255,0.14);
    transition: all 0.2s ease;
  }
  .stButton > button:hover {
    background: linear-gradient(135deg, rgba(0,255,255,0.30), rgba(0,255,159,0.26));
    color: #eaffff;
    border-color: rgba(0,255,159,0.60);
    box-shadow: 0 0 24px rgba(0,255,159,0.22);
    transform: translateY(-1px);
  }
  .stButton > button:focus,
  .stButton > button:focus-visible,
  .stButton > button:active {
    color: #ffffff;
    border-color: rgba(0,255,255,0.55);
    box-shadow: 0 0 0 0.18rem rgba(0,255,255,0.12), 0 0 24px rgba(0,255,159,0.18);
  }
  div[data-testid="stMetric"] {
    background: rgba(255,255,255,0.06);
    border: 1px solid rgba(255,255,255,0.10);
    border-radius: 18px;
    padding: 14px;
    backdrop-filter: blur(14px);
    box-shadow: 0 0 20px rgba(0,255,255,0.08);
  }
  .glass {
    background: rgba(255,255,255,0.08);
    border-radius: 18px;
    padding: 20px;
    box-shadow: 0 0 24px rgba(0,255,255,0.10), 0 16px 40px rgba(0,0,0,0.28);
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    border: 1px solid rgba(255,255,255,0.10);
  }
  .hero {
    padding: 24px;
    border-radius: 22px;
    background: rgba(255,255,255,0.06);
    border: 1px solid rgba(255,255,255,0.10);
    margin-bottom: 20px;
    backdrop-filter: blur(18px);
    -webkit-backdrop-filter: blur(18px);
    box-shadow: 0 0 30px rgba(0,255,255,0.10);
  }
  .hero .auth-title {
    justify-content: flex-start;
    margin-bottom: 0.35rem;
  }
  .metric-card {
    padding: 16px;
    border-radius: 16px;
    background: rgba(255,255,255,0.06);
    border: 1px solid rgba(255,255,255,0.10);
    color: #ffffff;
    backdrop-filter: blur(14px);
  }
  .panel-critical {
    box-shadow: 0 0 26px rgba(255,77,77,0.22), 0 16px 40px rgba(0,0,0,0.28);
    border: 1px solid rgba(255,77,77,0.34);
  }
  .panel-normal {
    box-shadow: 0 0 26px rgba(0,255,159,0.18), 0 16px 40px rgba(0,0,0,0.28);
    border: 1px solid rgba(0,255,159,0.28);
  }
  .auth-shell {
    max-width: 520px;
    margin: 4vh auto 0 auto;
    text-align: center;
  }
  .auth-title {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 0.75rem;
    font-size: 2rem;
    color: #ffffff;
    margin-bottom: 1rem;
    text-shadow: 0 0 18px rgba(0,255,255,0.22);
  }
  .auth-title-icon {
    width: 2.3rem;
    height: 2.3rem;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border-radius: 14px;
    background: linear-gradient(145deg, rgba(0,255,255,0.22), rgba(0,255,159,0.12));
    border: 1px solid rgba(0,255,255,0.24);
    box-shadow: 0 0 24px rgba(0,255,255,0.18);
  }
  .auth-title-icon svg {
    width: 1.5rem;
    height: 1.5rem;
    filter: drop-shadow(0 0 10px rgba(0,255,255,0.32));
  }
  div[data-testid="stForm"] {
    background: rgba(255,255,255,0.08);
    border: 1px solid rgba(255,255,255,0.10);
    border-radius: 20px;
    padding: 24px;
    backdrop-filter: blur(18px);
    -webkit-backdrop-filter: blur(18px);
    box-shadow: 0 0 24px rgba(0,255,255,0.12), 0 16px 40px rgba(0,0,0,0.28);
  }
  .auth-card-title {
    font-size: 1.1rem;
    color: #00ffff;
    margin-bottom: 0.75rem;
    font-weight: 700;
  }
  .page-heading {
    margin-bottom: 14px;
  }
  .ti-status-clean {
    color: #00ff9f;
    font-weight: 700;
  }
  .ti-status-bad {
    color: #ff4d4d;
    font-weight: 700;
  }
  .result-banner {
    padding: 18px 20px;
    border-radius: 18px;
    margin: 10px 0 18px 0;
    border: 1px solid rgba(255,255,255,0.12);
    background: rgba(255,255,255,0.06);
    box-shadow: 0 0 24px rgba(0,0,0,0.18);
  }
  .result-banner.alert {
    border-color: rgba(255,77,77,0.45);
    box-shadow: 0 0 30px rgba(255,77,77,0.18);
  }
  .result-banner.warn {
    border-color: rgba(255,193,7,0.45);
    box-shadow: 0 0 30px rgba(255,193,7,0.16);
  }
  .result-banner.good {
    border-color: rgba(0,255,159,0.35);
    box-shadow: 0 0 30px rgba(0,255,159,0.16);
  }
  .result-banner h3 {
    margin: 0 0 6px 0;
  }
  .result-banner p {
    margin: 0;
    color: rgba(255,255,255,0.85);
  }
  .mini-card {
    padding: 14px 16px;
    border-radius: 16px;
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.10);
    margin-bottom: 12px;
  }
  .mini-card-label {
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: rgba(255,255,255,0.65);
    margin-bottom: 6px;
  }
  .mini-card-value {
    font-size: 1.1rem;
    font-weight: 700;
  }
  .status-shell {
    padding: 22px;
    border-radius: 22px;
    background:
      linear-gradient(155deg, rgba(0,255,255,0.08), rgba(0,255,159,0.04)),
      rgba(6, 14, 24, 0.82);
    border: 1px solid rgba(0,255,255,0.16);
    box-shadow: 0 0 28px rgba(0,255,255,0.10), inset 0 1px 0 rgba(255,255,255,0.03);
    margin-bottom: 18px;
  }
  .status-topline {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 18px;
    flex-wrap: wrap;
  }
  .status-kicker {
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.14em;
    color: rgba(0,255,255,0.72);
    margin-bottom: 6px;
  }
  .status-version {
    font-family: 'Inter', sans-serif;
    font-size: 1.15rem;
    font-weight: 700;
    color: #ffffff;
  }
  .status-chip {
    padding: 8px 12px;
    border-radius: 999px;
    border: 1px solid rgba(0,255,159,0.22);
    background: rgba(0,255,159,0.08);
    color: #8fffd3;
    font-size: 0.82rem;
    font-weight: 600;
    white-space: nowrap;
  }
  .status-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
  }
  .status-item {
    padding: 14px 16px;
    border-radius: 16px;
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.08);
  }
  .status-label {
    font-size: 0.76rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: rgba(255,255,255,0.62);
    margin-bottom: 6px;
  }
  .status-value {
    font-size: 1rem;
    font-weight: 600;
    color: #f5ffff;
    word-break: break-word;
  }
  .dashboard-section-title {
    margin: 10px 0 12px 0;
    font-size: 1rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: rgba(169, 248, 255, 0.78);
  }
  .risk-shell {
    padding: 20px;
    border-radius: 20px;
    background: linear-gradient(180deg, rgba(255,255,255,0.07), rgba(255,255,255,0.04));
    border: 1px solid rgba(255,255,255,0.10);
    min-height: 320px;
  }
  .risk-meter-track {
    width: 100%;
    height: 16px;
    border-radius: 999px;
    overflow: hidden;
    background: rgba(255,255,255,0.08);
    border: 1px solid rgba(255,255,255,0.08);
    margin: 16px 0 10px 0;
  }
  .risk-meter-fill {
    height: 100%;
    border-radius: 999px;
    background: linear-gradient(90deg, #00ff9f 0%, #ffc857 52%, #ff4d4d 100%);
    box-shadow: 0 0 20px rgba(0,255,255,0.16);
  }
  .risk-score-value {
    font-size: 2.8rem;
    font-weight: 800;
    line-height: 1;
    color: #ffffff;
    margin-top: 8px;
  }
  .risk-score-label {
    font-size: 0.9rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: rgba(255,255,255,0.70);
  }
  .risk-score-copy {
    margin-top: 12px;
    color: rgba(255,255,255,0.84);
    line-height: 1.5;
  }
  .risk-tag {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 8px 12px;
    border-radius: 999px;
    font-size: 0.82rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    margin-top: 10px;
    border: 1px solid rgba(255,255,255,0.12);
  }
  .risk-tag.low {
    color: #7cffc4;
    background: rgba(0,255,159,0.10);
  }
  .risk-tag.elevated {
    color: #ffe07e;
    background: rgba(255,200,87,0.12);
  }
  .risk-tag.high {
    color: #ff9c80;
    background: rgba(255,120,64,0.14);
  }
  .risk-tag.critical {
    color: #ff8a8a;
    background: rgba(255,77,77,0.16);
  }
  .alert-list {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .alert-item {
    padding: 14px 16px;
    border-radius: 16px;
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.08);
    margin-bottom: 12px;
  }
  .alert-item:last-child {
    margin-bottom: 0;
  }
  .alert-item.critical {
    border-color: rgba(255,77,77,0.40);
    box-shadow: 0 0 24px rgba(255,77,77,0.10);
  }
  .alert-item.high {
    border-color: rgba(255,140,92,0.34);
    box-shadow: 0 0 20px rgba(255,140,92,0.09);
  }
  .alert-item.medium {
    border-color: rgba(255,200,87,0.30);
  }
  .alert-topline {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    margin-bottom: 8px;
  }
  .alert-title {
    font-weight: 700;
    color: #ffffff;
  }
  .alert-time {
    color: rgba(255,255,255,0.62);
    font-size: 0.85rem;
  }
  .alert-meta {
    color: rgba(255,255,255,0.72);
    font-size: 0.88rem;
    margin-bottom: 6px;
  }
  .alert-summary {
    color: rgba(255,255,255,0.84);
    font-size: 0.92rem;
    line-height: 1.45;
  }
  .soc-alert-banner {
    position: relative;
    overflow: hidden;
    display: flex;
    align-items: stretch;
    gap: 16px;
    padding: 18px 20px;
    border-radius: 22px;
    margin: 8px 0 20px 0;
    background:
      linear-gradient(135deg, rgba(255, 52, 52, 0.22), rgba(255, 120, 80, 0.14)),
      rgba(20, 4, 4, 0.92);
    border: 1px solid rgba(255, 90, 90, 0.52);
    box-shadow: 0 0 16px rgba(255, 77, 77, 0.28), 0 0 42px rgba(255, 77, 77, 0.16);
    animation: soc-banner-blink 1.05s ease-in-out infinite alternate;
  }
  .soc-alert-banner__pulse {
    width: 12px;
    min-width: 12px;
    border-radius: 999px;
    background: linear-gradient(180deg, #ff4040, #ffb199);
    box-shadow: 0 0 12px rgba(255, 64, 64, 0.85), 0 0 28px rgba(255, 64, 64, 0.58);
    animation: soc-pulse 0.95s ease-in-out infinite;
  }
  .soc-alert-banner__content {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .soc-alert-banner__eyebrow {
    text-transform: uppercase;
    letter-spacing: 0.16em;
    font-size: 0.72rem;
    color: rgba(255, 215, 215, 0.84);
  }
  .soc-alert-banner__title {
    font-size: 1.3rem;
    font-weight: 800;
    color: #fff2f2;
  }
  .soc-alert-banner__meta {
    font-size: 0.92rem;
    color: rgba(255, 235, 235, 0.88);
  }
  .soc-alert-banner__summary {
    color: rgba(255, 245, 245, 0.82);
    line-height: 1.45;
  }
  .soc-alert-banner.severity-medium {
    background:
      linear-gradient(135deg, rgba(255, 187, 51, 0.22), rgba(255, 145, 77, 0.12)),
      rgba(26, 17, 3, 0.92);
    border-color: rgba(255, 196, 66, 0.44);
    box-shadow: 0 0 16px rgba(255, 196, 66, 0.18), 0 0 38px rgba(255, 145, 77, 0.12);
  }
  .soc-alert-banner.severity-medium .soc-alert-banner__pulse {
    background: linear-gradient(180deg, #ffb627, #ffd27a);
    box-shadow: 0 0 12px rgba(255, 190, 71, 0.7), 0 0 24px rgba(255, 190, 71, 0.44);
  }
  .soc-alert-banner.severity-low {
    background:
      linear-gradient(135deg, rgba(0, 255, 159, 0.18), rgba(0, 195, 255, 0.12)),
      rgba(3, 26, 18, 0.92);
    border-color: rgba(0, 255, 159, 0.34);
    box-shadow: 0 0 16px rgba(0, 255, 159, 0.18), 0 0 34px rgba(0, 195, 255, 0.12);
  }
  .soc-alert-banner.severity-low .soc-alert-banner__pulse {
    background: linear-gradient(180deg, #00ff9f, #79ffe0);
    box-shadow: 0 0 12px rgba(0, 255, 159, 0.7), 0 0 24px rgba(0, 255, 159, 0.44);
  }
  @keyframes soc-banner-blink {
    from {
      box-shadow: 0 0 12px rgba(255, 77, 77, 0.22), 0 0 30px rgba(255, 77, 77, 0.10);
      transform: translateY(0);
    }
    to {
      box-shadow: 0 0 18px rgba(255, 77, 77, 0.42), 0 0 52px rgba(255, 77, 77, 0.24);
      transform: translateY(-1px);
    }
  }
  @keyframes soc-pulse {
    from {
      opacity: 0.55;
      transform: scaleY(0.94);
    }
    to {
      opacity: 1;
      transform: scaleY(1);
    }
  }
    </style>
    """,
    unsafe_allow_html=True,
)


def render_network_background() -> None:
    components.html(
        """
        <style>
        html, body {
          margin: 0;
          padding: 0;
          background: transparent;
        }
        </style>
        <script>
        (function () {
          const doc = window.parent.document;
          const mountTarget = doc.querySelector(".stApp") || doc.body;
          let layer = doc.getElementById("cybershield-network-bg");
          let canvas = doc.getElementById("cybershield-network-canvas");

          if (!layer) {
            layer = doc.createElement("div");
            layer.id = "cybershield-network-bg";
            layer.setAttribute("aria-hidden", "true");
            layer.style.position = "fixed";
            layer.style.top = "0";
            layer.style.left = "0";
            layer.style.width = "100%";
            layer.style.height = "100%";
            layer.style.pointerEvents = "none";
            layer.style.zIndex = "0";
            layer.style.overflow = "hidden";

            canvas = doc.createElement("canvas");
            canvas.id = "cybershield-network-canvas";
            canvas.style.width = "100%";
            canvas.style.height = "100%";
            canvas.style.display = "block";
            canvas.style.opacity = "1";

            layer.appendChild(canvas);
            mountTarget.prepend(layer);
          }
          else if (layer.parentElement !== mountTarget) {
            mountTarget.prepend(layer);
          }

          if (!canvas || layer.dataset.initialized === "true") {
            return;
          }
          layer.dataset.initialized = "true";

          const ctx = canvas.getContext("2d");
          const particles = [];
          const ripples = [];
          const mouse = {
            x: null,
            y: null,
            active: false
          };
          const settings = {
            particleCount: Math.min(100, Math.max(60, Math.floor(window.parent.innerWidth / 20))),
            maxParticles: 150,
            maxDistance: 156,
            maxSpeed: 0.34,
            mouseRange: 180
          };
          const palette = {
            nodePrimary: "rgba(0,255,255,0.62)",
            nodeSecondary: "rgba(0,255,255,0.42)",
            nodeAccent: "rgba(0,255,159,0.38)",
            line: "rgba(0,255,255,0.28)",
            ripple: "rgba(0,255,255,0.34)"
          };
          let animationFrameId = null;
          let resizeTimer = null;

          function resize() {
            const ratio = window.parent.devicePixelRatio || 1;
            const width = window.parent.innerWidth;
            const height = window.parent.innerHeight;
            canvas.width = width * ratio;
            canvas.height = height * ratio;
            canvas.style.width = width + "px";
            canvas.style.height = height + "px";
            ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
          }

          function randomBetween(min, max) {
            return min + Math.random() * (max - min);
          }

          function createParticle(x, y, burst) {
            const sourceX = typeof x === "number" ? x : Math.random() * window.parent.innerWidth;
            const sourceY = typeof y === "number" ? y : Math.random() * window.parent.innerHeight;
            const angle = Math.random() * Math.PI * 2;
            const speed = burst ? randomBetween(0.65, 1.15) : randomBetween(0.06, 0.18);
            return {
              x: sourceX,
              y: sourceY,
              vx: Math.cos(angle) * speed,
              vy: Math.sin(angle) * speed,
              radius: randomBetween(1.0, burst ? 2.0 : 1.7),
              color: [palette.nodePrimary, palette.nodeSecondary, palette.nodeAccent][Math.floor(Math.random() * 3)],
              burstLife: burst ? 0 : null
            };
          }

          function initParticles() {
            particles.length = 0;
            for (let i = 0; i < settings.particleCount; i += 1) {
              particles.push(createParticle());
            }
          }

          function trimParticles() {
            while (particles.length > settings.maxParticles) {
              const burstIndex = particles.findIndex((particle) => particle.burstLife !== null);
              particles.splice(burstIndex >= 0 ? burstIndex : 0, 1);
            }
          }

          function addClickBurst(x, y) {
            const burstCount = Math.floor(randomBetween(5, 11));
            for (let i = 0; i < burstCount; i += 1) {
              particles.push(createParticle(x, y, true));
            }
            trimParticles();
            ripples.push({
              x: x,
              y: y,
              radius: 10,
              alpha: 0.24,
              growth: randomBetween(1.8, 2.7)
            });
          }

          function updateParticles() {
            const width = window.parent.innerWidth;
            const height = window.parent.innerHeight;

            for (const particle of particles) {
              if (mouse.active && mouse.x !== null && mouse.y !== null) {
                const dx = mouse.x - particle.x;
                const dy = mouse.y - particle.y;
                const distance = Math.sqrt(dx * dx + dy * dy) || 1;
                if (distance < settings.mouseRange) {
                  const pull = (1 - distance / settings.mouseRange) * 0.0065;
                  particle.vx += (dx / distance) * pull;
                  particle.vy += (dy / distance) * pull;
                }
              }

              particle.x += particle.vx;
              particle.y += particle.vy;
              particle.vx *= 0.997;
              particle.vy *= 0.997;

              const speed = Math.sqrt(particle.vx * particle.vx + particle.vy * particle.vy);
              if (speed > settings.maxSpeed) {
                particle.vx = (particle.vx / speed) * settings.maxSpeed;
                particle.vy = (particle.vy / speed) * settings.maxSpeed;
              }

              if (particle.x < -12) particle.x = width + 12;
              if (particle.x > width + 12) particle.x = -12;
              if (particle.y < -12) particle.y = height + 12;
              if (particle.y > height + 12) particle.y = -12;

              if (particle.burstLife !== null) {
                particle.burstLife += 1;
                if (particle.burstLife > 80) {
                  particle.burstLife = null;
                  particle.radius = Math.max(1.0, particle.radius - 0.2);
                  particle.vx *= 0.35;
                  particle.vy *= 0.35;
                }
              }
            }
          }

          function drawParticles() {
            for (const particle of particles) {
              const glow = ctx.createRadialGradient(
                particle.x,
                particle.y,
                0,
                particle.x,
                particle.y,
                particle.radius * 5
              );
              glow.addColorStop(0, "rgba(0,255,255,0.15)");
              glow.addColorStop(1, "rgba(0,255,255,0)");
              ctx.fillStyle = glow;
              ctx.beginPath();
              ctx.arc(particle.x, particle.y, particle.radius * 5, 0, Math.PI * 2);
              ctx.fill();

              ctx.fillStyle = particle.color;
              ctx.beginPath();
              ctx.arc(particle.x, particle.y, particle.radius, 0, Math.PI * 2);
              ctx.fill();
            }
          }

          function drawConnections() {
            for (let i = 0; i < particles.length; i += 1) {
              for (let j = i + 1; j < particles.length; j += 1) {
                const a = particles[i];
                const b = particles[j];
                const dx = a.x - b.x;
                const dy = a.y - b.y;
                const distance = Math.sqrt(dx * dx + dy * dy);

                if (distance < settings.maxDistance) {
                  const alpha = (1 - distance / settings.maxDistance) * 0.3;
                  ctx.strokeStyle = "rgba(0,255,255," + alpha + ")";
                  ctx.lineWidth = 0.8;
                  ctx.beginPath();
                  ctx.moveTo(a.x, a.y);
                  ctx.lineTo(b.x, b.y);
                  ctx.stroke();
                }
              }
            }
          }

          function drawRipples() {
            for (let i = ripples.length - 1; i >= 0; i -= 1) {
              const ripple = ripples[i];
              ctx.strokeStyle = "rgba(0,255,255," + ripple.alpha + ")";
              ctx.lineWidth = 1.35;
              ctx.beginPath();
              ctx.arc(ripple.x, ripple.y, ripple.radius, 0, Math.PI * 2);
              ctx.stroke();

              ripple.radius += ripple.growth;
              ripple.alpha *= 0.94;
              if (ripple.alpha < 0.015) {
                ripples.splice(i, 1);
              }
            }
          }

          function step() {
            ctx.clearRect(0, 0, window.parent.innerWidth, window.parent.innerHeight);
            updateParticles();
            drawConnections();
            drawParticles();
            drawRipples();
            animationFrameId = window.parent.requestAnimationFrame(step);
          }

          function start() {
            resize();
            initParticles();
            if (animationFrameId) {
              window.parent.cancelAnimationFrame(animationFrameId);
            }
            step();
          }

          doc.addEventListener("click", (event) => {
            addClickBurst(event.clientX, event.clientY);
          }, { passive: true });
          doc.addEventListener("mousemove", (event) => {
            mouse.x = event.clientX;
            mouse.y = event.clientY;
            mouse.active = true;
          }, { passive: true });
          doc.addEventListener("mouseleave", () => {
            mouse.active = false;
            mouse.x = null;
            mouse.y = null;
          }, { passive: true });
          window.parent.addEventListener("beforeunload", () => {
            if (animationFrameId) {
              window.parent.cancelAnimationFrame(animationFrameId);
            }
          });
          window.parent.addEventListener("resize", () => {
            window.clearTimeout(resizeTimer);
            resizeTimer = window.setTimeout(() => {
              resize();
            }, 120);
          });

          start();
        })();
        </script>
        """,
        height=0,
        width=0,
    )


render_network_background()


def infer_indicator_type(value: str) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return "ip"
    if candidate.count(".") == 3 and all(part.isdigit() for part in candidate.split(".")):
        return "ip"
    if len(candidate) in {32, 40, 64} and all(ch in "0123456789abcdefABCDEF" for ch in candidate):
        return "hash"
    if "." in candidate and "/" not in candidate and " " not in candidate:
        return "domain"
    return "domain"


def render_public_auth() -> None:
    return None


def format_confidence(probability) -> str:
    if not probability or len(probability) < 2:
        return "Unavailable"
    try:
        return f"{max(float(probability[0]), float(probability[1])) * 100:.1f}%"
    except (TypeError, ValueError):
        return "Unavailable"


def _sync_realtime_alert_state(alerts: list[dict]) -> None:
    new_alerts = sync_ui_alert_state(alerts)
    for alert in new_alerts[-3:]:
        st.toast(
            f"{str(alert.get('severity') or 'LOW').upper()} | "
            f"{alert.get('attack_type') or 'Unknown'} | "
            f"{alert.get('attacker_ip') or 'n/a'}"
        )

    if new_alerts:
        newest = new_alerts[-1]
        st.markdown(render_audio_html(newest.get("alert_id")), unsafe_allow_html=True)


def _build_alert_timeline_dataframe(snapshot: dict) -> pd.DataFrame:
    timeline = snapshot.get("timeline") or {}
    if not timeline:
        return pd.DataFrame(columns=["time", "Attack Count"]).set_index("time")
    rows = [
        {"time": timestamp, "Attack Count": count}
        for timestamp, count in sorted(timeline.items())
    ]
    timeline_df = pd.DataFrame(rows)
    timeline_df["time"] = pd.to_datetime(timeline_df["time"])
    timeline_df["label"] = timeline_df["time"].dt.strftime("%H:%M:%S")
    return timeline_df.set_index("label")[["Attack Count"]]


def _build_distribution_dataframe(distribution: dict, label_name: str) -> pd.DataFrame:
    if not distribution:
        return pd.DataFrame(columns=[label_name, "Count"])
    frame = pd.DataFrame(
        [{label_name: key, "Count": value} for key, value in distribution.items()]
    )
    return frame.sort_values("Count", ascending=False)


def _render_plotly_line_chart(frame: pd.DataFrame) -> None:
    chart_df = frame.reset_index().rename(columns={"label": "Time"})
    fig = px.line(
        chart_df,
        x="Time",
        y="Attack Count",
        markers=True,
        line_shape="spline",
        color_discrete_sequence=["#00f5ff"],
    )
    fig.update_traces(fill="tozeroy")
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#f4ffff"},
        margin={"l": 20, "r": 20, "t": 20, "b": 20},
        xaxis_title=None,
        yaxis_title="Attacks",
    )
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})


def _render_plotly_bar_chart(frame: pd.DataFrame, x_key: str, color_sequence: list[str]) -> None:
    fig = px.bar(
        frame,
        x=x_key,
        y="Count",
        color=x_key,
        color_discrete_sequence=color_sequence,
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#f4ffff"},
        margin={"l": 20, "r": 20, "t": 20, "b": 20},
        xaxis_title=None,
        yaxis_title="Count",
        showlegend=False,
    )
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})


def _build_map_dataframe_from_snapshot(snapshot: dict) -> pd.DataFrame:
    points = snapshot.get("map_points") or []
    if not points:
        return pd.DataFrame(columns=["lat", "lon", "attacker_ip", "attack_type", "severity", "region"])
    return pd.DataFrame(points)


def render_result_banner(title: str, message: str, tone: str) -> None:
    st.markdown(
        f"""
        <div class="result-banner {tone}">
          <h3>{title}</h3>
          <p>{message}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_model_status_panel(current_model: dict, feedback_samples: int) -> None:
    st.markdown(
        f"""
        <div class="status-shell">
          <div class="status-topline">
            <div>
              <div class="status-kicker">Current Model Status</div>
              <div class="status-version">{current_model.get('version_id', 'unknown')}</div>
            </div>
            <div class="status-chip">{feedback_samples} feedback samples ready</div>
          </div>
          <div class="status-grid">
            <div class="status-item">
              <div class="status-label">Trained At</div>
              <div class="status-value">{current_model.get('trained_at', 'unknown')}</div>
            </div>
            <div class="status-item">
              <div class="status-label">Triggered By</div>
              <div class="status-value">{current_model.get('triggered_by', 'unknown')}</div>
            </div>
            <div class="status-item">
              <div class="status-label">Model Type</div>
              <div class="status-value">{current_model.get('model_type', 'unknown')}</div>
            </div>
            <div class="status-item">
              <div class="status-label">Training Samples</div>
              <div class="status-value">{current_model.get('sample_count', 0)}</div>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_indicator_card(indicator: dict) -> None:
    severity = str(indicator.get("severity", "low")).lower()
    indicator_class = "panel-critical" if severity in {"critical", "high"} else "panel-normal"
    st.markdown(f'<div class="glass {indicator_class}">', unsafe_allow_html=True)
    left, right = st.columns([1.2, 1], gap="large")
    with left:
        st.markdown(f"**Indicator**: `{indicator.get('value', 'unknown')}`")
        st.caption(f"Type: {indicator.get('type', 'unknown')}")
        st.write(f"Severity: {indicator.get('severity', 'unknown').upper()}")
        st.write(f"Recommendation: {indicator.get('recommendation', 'Monitor indicator.')}")
    with right:
        st.metric("Intel Score", indicator.get("score", 0))
        st.metric("Blacklisted", "Yes" if indicator.get("blacklisted") else "No")

    vt = indicator.get("virustotal") or {}
    abuse = indicator.get("abuseipdb") or {}
    detail_tab, external_tab, raw_tab = st.tabs(["Summary", "External Signals", "Raw"])
    with detail_tab:
        if indicator.get("blacklist_entry"):
            entry = indicator["blacklist_entry"]
            st.write(f"Listed by: `{entry.get('source', 'unknown')}`")
            st.write(f"Reason: {entry.get('reason', 'No reason recorded.')}")
            st.caption(f"Listed at: {entry.get('listed_at', 'unknown')}")
        else:
            st.caption("This indicator is not currently present in the local blacklist.")
    with external_tab:
        if vt:
            if vt.get("enabled") and not vt.get("error"):
                cols = st.columns(4)
                cols[0].metric("VT Malicious", vt.get("malicious", 0))
                cols[1].metric("VT Suspicious", vt.get("suspicious", 0))
                cols[2].metric("VT Harmless", vt.get("harmless", 0))
                cols[3].metric("VT Reputation", vt.get("reputation", "n/a"))
            elif vt.get("enabled") and vt.get("error"):
                st.warning(f"VirusTotal lookup failed: {vt.get('error')}")
            else:
                st.caption(vt.get("reason", "VirusTotal is not configured."))

        if abuse:
            if abuse.get("enabled") and not abuse.get("error"):
                cols = st.columns(4)
                cols[0].metric("Abuse Score", abuse.get("confidence_score", 0))
                cols[1].metric("Reports", abuse.get("total_reports", 0))
                cols[2].metric("Country", abuse.get("country_code", "n/a"))
                cols[3].metric("ISP", abuse.get("isp", "n/a"))
            elif abuse.get("enabled") and abuse.get("error"):
                st.warning(f"AbuseIPDB lookup failed: {abuse.get('error')}")
            else:
                st.caption(abuse.get("reason", "AbuseIPDB is not configured."))
    with raw_tab:
        st.json(indicator)
    st.markdown("</div>", unsafe_allow_html=True)


def render_analysis_result(result: dict) -> None:
    ai_analysis = result.get("ai_analysis") or {}
    threat_intel = result.get("threat_intelligence") or {}
    alert = result.get("alert") or {}
    risk_level = str(ai_analysis.get("risk_level", "unknown")).upper()
    attack_type = ai_analysis.get("attack_type", "unknown")
    confidence = format_confidence(result.get("probability"))
    policy_override = ai_analysis.get("policy_override")

    if alert:
        _sync_realtime_alert_state([alert])
        st.markdown(render_alert_banner_html(alert), unsafe_allow_html=True)

    if result.get("prediction") == 1:
        render_result_banner(
            "Threat detected",
            f"The model classified this sample as malicious with {confidence} confidence.",
            "alert",
        )
    elif policy_override:
        render_result_banner(
            "High-risk traffic flagged",
            f"Policy controls escalated this sample even though the model did not mark it as an attack. Confidence: {confidence}.",
            "warn",
        )
    else:
        render_result_banner(
            "Traffic appears normal",
            f"No active attack was predicted for this sample. Confidence: {confidence}.",
            "good",
        )

    top_cols = st.columns(4)
    top_cols[0].metric("Risk Level", risk_level)
    top_cols[1].metric("Attack Type", attack_type)
    top_cols[2].metric("Model Verdict", "Attack" if result.get("prediction") == 1 else "Normal")
    top_cols[3].metric("Top Intel Score", threat_intel.get("highest_score", 0))

    analysis_class = "panel-critical" if risk_level in {"CRITICAL", "HIGH"} else "panel-normal"
    st.markdown(f'<div class="glass {analysis_class}">', unsafe_allow_html=True)
    summary_cols = st.columns(3)
    summary_cols[0].markdown(
        f'<div class="mini-card"><div class="mini-card-label">Policy Override</div><div class="mini-card-value">{"Yes" if policy_override else "No"}</div></div>',
        unsafe_allow_html=True,
    )
    summary_cols[1].markdown(
        f'<div class="mini-card"><div class="mini-card-label">Blacklist Match</div><div class="mini-card-value">{"Yes" if ai_analysis.get("blacklist_match") else "No"}</div></div>',
        unsafe_allow_html=True,
    )
    summary_cols[2].markdown(
        f'<div class="mini-card"><div class="mini-card-label">Confidence</div><div class="mini-card-value">{confidence}</div></div>',
        unsafe_allow_html=True,
    )
    st.subheader("What we found")
    st.write(ai_analysis.get("explanation", "No explanation returned."))
    st.subheader("Recommended next step")
    st.write(ai_analysis.get("remediation", "No remediation guidance returned."))
    if ai_analysis.get("policy_reason"):
        st.caption(f"Policy reason: {ai_analysis.get('policy_reason')}")
    st.markdown("</div>", unsafe_allow_html=True)

    services = threat_intel.get("services") or {}
    if threat_intel.get("indicators") or result.get("blacklist_updates"):
        st.markdown('<div class="glass">', unsafe_allow_html=True)
        st.subheader("Threat Intelligence")
        service_cols = st.columns(3)
        service_cols[0].metric("Indicators", len(threat_intel.get("indicators", [])))
        service_cols[1].metric("VirusTotal", "On" if services.get("virustotal_configured") else "Off")
        service_cols[2].metric("AbuseIPDB", "On" if services.get("abuseipdb_configured") else "Off")
        if threat_intel.get("indicators"):
            for indicator in threat_intel.get("indicators", []):
                render_indicator_card(indicator)
        if result.get("blacklist_updates"):
            st.subheader("Blacklist updates")
            for entry in result["blacklist_updates"]:
                st.write(f"Added `{entry.get('value')}` from `{entry.get('source')}` to the local blacklist.")
        st.markdown("</div>", unsafe_allow_html=True)

    if alert:
        geo = alert.get("geolocation") or {}
        st.markdown('<div class="glass">', unsafe_allow_html=True)
        st.subheader("Central Alert System")
        alert_cols = st.columns(4)
        alert_cols[0].metric("Alert ID", alert.get("alert_id", "n/a"))
        alert_cols[1].metric("Severity", alert.get("severity", "LOW"))
        alert_cols[2].metric("Notifier Status", alert.get("notification_status", "pending"))
        alert_cols[3].metric("Cooldown", "Yes" if alert.get("cooldown_applied") else "No")
        st.json(
            {
                "attacker_ip": alert.get("attacker_ip"),
                "attack_type": alert.get("attack_type"),
                "timestamp": alert.get("timestamp"),
                "notification_results": alert.get("notification_results"),
                "geolocation": geo,
            }
        )
        st.markdown("</div>", unsafe_allow_html=True)

    incident_response = result.get("incident_response")
    if incident_response:
        action_labels = {
            "block_ip": "Block IP",
            "kill_process": "Kill Process",
            "firewall_rule": "Firewall Rule",
        }
        st.markdown('<div class="glass">', unsafe_allow_html=True)
        st.subheader("Automated Response")
        st.write(incident_response.get("summary", "No summary provided."))
        for index, action in enumerate(incident_response.get("actions", []), start=1):
            status = "SUCCESS" if action.get("success") else "FAILED"
            label = action_labels.get(action.get("type"), str(action.get("type", "action")).replace("_", " ").title())
            target = action.get("target") or "n/a"
            st.markdown(f"**{index}. {label}**: {status}")
            st.write(f"Target: `{target}`")
            st.caption(action.get("details", ""))
            for command in action.get("commands", []):
                st.code(
                    "\n".join(
                        [
                            f"Command: {command.get('command')}",
                            f"Return code: {command.get('returncode')}",
                            f"Stdout: {command.get('stdout')}",
                            f"Stderr: {command.get('stderr')}",
                        ]
                    )
                )
        st.markdown("</div>", unsafe_allow_html=True)

    processed = result.get("processed") or {}
    if processed or result.get("llm_security_report"):
        with st.expander("Technical Details"):
            left, right = st.columns(2, gap="large")
            with left:
                st.subheader("Processed features")
                if processed:
                    st.json(processed)
            with right:
                st.subheader("Detailed report")
                st.code(result.get("llm_security_report", ""))


def render_lookup_result(lookup_result: dict) -> None:
    services = lookup_result.get("services") or {}
    status_class = "ti-status-bad" if lookup_result.get("blacklist_match") else "ti-status-clean"
    status_text = "Blacklisted" if lookup_result.get("blacklist_match") else "Clean"

    header_cols = st.columns(4)
    header_cols[0].metric("Highest Intel Score", lookup_result.get("highest_score", 0))
    header_cols[1].metric("Indicators Found", len(lookup_result.get("indicators", [])))
    header_cols[2].metric("VirusTotal", "On" if services.get("virustotal_configured") else "Off")
    header_cols[3].markdown(
        f'<div class="mini-card"><div class="mini-card-label">Local Status</div><div class="mini-card-value {status_class}">{status_text}</div></div>',
        unsafe_allow_html=True,
    )

    if lookup_result.get("indicators"):
        for indicator in lookup_result.get("indicators", []):
            render_indicator_card(indicator)
    else:
        st.info("No recognizable IP, domain, or file hash was found in the lookup value.")

    with st.expander("Lookup metadata"):
        st.write(f"Blacklist database: `{lookup_result.get('blacklist_db_path', 'unknown')}`")
        st.json(lookup_result)


def _parse_logged_at(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _time_ago_label(timestamp: str | None) -> str:
    parsed = _parse_logged_at(timestamp)
    if not parsed:
        return "time unavailable"
    delta = datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)
    minutes = max(0, int(delta.total_seconds() // 60))
    if minutes < 1:
        return "just now"
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    return f"{hours // 24}d ago"


def _severity_weight(risk_level: str) -> int:
    mapping = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return mapping.get(str(risk_level or "").upper(), 1)


def _risk_band(score: int) -> tuple[str, str]:
    if score >= 80:
        return "critical", "Critical"
    if score >= 60:
        return "high", "High"
    if score >= 35:
        return "elevated", "Elevated"
    return "low", "Low"


def _compute_risk_score(events: list[dict], analysis: dict) -> int:
    totals = analysis.get("totals", {})
    recent_events = analysis.get("recent_events", [])
    total_events = max(1, int(totals.get("events", 0)))
    attack_ratio = min(1.0, float(totals.get("attacks", 0)) / total_events)
    critical_ratio = min(1.0, float(totals.get("critical", 0)) / total_events)
    blacklist_ratio = min(1.0, float(totals.get("blacklist_matches", 0)) / total_events)
    recent_severity = 0.0
    if recent_events:
        recent_severity = sum(_severity_weight(event.get("risk_level")) for event in recent_events[:8]) / (len(recent_events[:8]) * 4)
    threat_score = min(1.0, float(analysis.get("averages", {}).get("threat_intel_score", 0)) / 100)
    confidence_score = min(1.0, float(analysis.get("averages", {}).get("confidence", 0)) / 100)
    score = (
        attack_ratio * 34
        + critical_ratio * 24
        + blacklist_ratio * 16
        + recent_severity * 16
        + threat_score * 6
        + confidence_score * 4
    )
    if events and totals.get("critical", 0):
        score = max(score, 42)
    return max(0, min(100, int(round(score))))


def _build_attack_timeline(events: list[dict]) -> pd.DataFrame:
    end_time = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    start_time = end_time - timedelta(hours=11)
    timeline_rows = []
    for offset in range(12):
        bucket = start_time + timedelta(hours=offset)
        timeline_rows.append(
            {
                "time": bucket,
                "Attacks": 0,
                "Critical": 0,
                "Scans": 0,
            }
        )

    bucket_lookup = {row["time"]: row for row in timeline_rows}
    for event in events:
        parsed = _parse_logged_at(event.get("logged_at"))
        if not parsed:
            continue
        bucket = parsed.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
        if bucket not in bucket_lookup:
            continue
        if event.get("event_type") == "vulnerability_scan":
            bucket_lookup[bucket]["Scans"] += 1
        if int(event.get("prediction", 0) or 0) == 1:
            bucket_lookup[bucket]["Attacks"] += 1
        if str(event.get("risk_level", "")).upper() == "CRITICAL":
            bucket_lookup[bucket]["Critical"] += 1

    timeline_df = pd.DataFrame(timeline_rows)
    timeline_df["time"] = pd.to_datetime(timeline_df["time"])
    timeline_df["label"] = timeline_df["time"].dt.strftime("%H:%M")
    return timeline_df.set_index("label")[["Attacks", "Critical", "Scans"]]


def _ip_to_geo(ip_value: str | None) -> dict | None:
    if not ip_value:
        return None
    candidate = str(ip_value).strip()
    parts = candidate.split(".")
    if len(parts) != 4 or not all(part.isdigit() for part in parts):
        return None
    octets = [int(part) for part in parts]
    digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
    lat_seed = int(digest[:8], 16)
    lon_seed = int(digest[8:16], 16)
    lat = ((lat_seed / 0xFFFFFFFF) * 120) - 60
    lon = ((lon_seed / 0xFFFFFFFF) * 340) - 170
    regions = [
        "North America",
        "South America",
        "Europe",
        "Middle East",
        "South Asia",
        "East Asia",
        "Africa",
        "Oceania",
    ]
    region = regions[(octets[0] + octets[1]) % len(regions)]
    return {
        "source_ip": candidate,
        "lat": round(lat, 4),
        "lon": round(lon, 4),
        "region": region,
    }


def _build_geo_dataframe(events: list[dict]) -> pd.DataFrame:
    points: dict[str, dict] = {}
    for event in events:
        if int(event.get("prediction", 0) or 0) != 1:
            continue
        geo = _ip_to_geo(event.get("source_ip"))
        if not geo:
            continue
        source_ip = geo["source_ip"]
        existing = points.get(source_ip)
        if not existing:
            points[source_ip] = {
                **geo,
                "count": 1,
                "max_risk": _severity_weight(event.get("risk_level")),
                "attack_type": str(event.get("attack_type") or "Unknown"),
            }
            continue
        existing["count"] += 1
        existing["max_risk"] = max(existing["max_risk"], _severity_weight(event.get("risk_level")))
    if not points:
        return pd.DataFrame(columns=["lat", "lon", "source_ip", "region", "count", "size"])
    geo_df = pd.DataFrame(points.values())
    geo_df["size"] = geo_df["count"].astype(float) * 18 + geo_df["max_risk"].astype(float) * 22
    return geo_df.sort_values(["count", "max_risk"], ascending=[False, False])


def _build_live_alerts(events: list[dict]) -> list[dict]:
    ranked = sorted(
        events,
        key=lambda event: (
            _severity_weight(event.get("risk_level")),
            1 if event.get("blacklist_match") else 0,
            event.get("logged_at", ""),
        ),
        reverse=True,
    )
    return ranked[:6]


def _render_risk_meter(score: int, analysis: dict) -> None:
    band_class, band_label = _risk_band(score)
    totals = analysis.get("totals", {})
    st.markdown(
        f"""
        <div class="risk-shell">
          <div class="dashboard-section-title">Risk Score Meter</div>
          <div class="risk-score-label">Current exposure</div>
          <div class="risk-score-value">{score}<span style="font-size:1.2rem;color:rgba(255,255,255,0.6)">/100</span></div>
          <div class="risk-meter-track">
            <div class="risk-meter-fill" style="width:{score}%"></div>
          </div>
          <div class="risk-tag {band_class}">{band_label} risk posture</div>
          <div class="risk-score-copy">
            {totals.get("attacks", 0)} malicious events, {totals.get("critical", 0)} critical alerts,
            and {totals.get("blacklist_matches", 0)} blacklist matches are shaping the current score.
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_live_alert_panel(alerts: list[dict]) -> None:
    st.markdown('<div class="glass">', unsafe_allow_html=True)
    st.markdown('<div class="dashboard-section-title">Live Alerts</div>', unsafe_allow_html=True)
    if not alerts:
        st.info("No recent alerts have been recorded yet.")
        st.markdown("</div>", unsafe_allow_html=True)
        return
    for alert in list(alerts[:5]):
        level = str(alert.get("severity") or alert.get("risk_level") or "low").lower()
        tone = "critical" if level in {"critical", "high"} else "medium"
        attack_type = html.escape(str(alert.get("attack_type") or "Unknown threat"))
        alert_time = html.escape(str(_time_ago_label(alert.get("timestamp") or alert.get("logged_at"))))
        source_ip = html.escape(str(alert.get("attacker_ip") or alert.get("source_ip") or "n/a"))
        target_ip = html.escape(str(alert.get("target_ip") or alert.get("destination_ip") or "n/a"))
        severity = html.escape(str(alert.get("severity") or alert.get("risk_level") or "UNKNOWN").upper())
        protocol = html.escape(str(alert.get("protocol") or "n/a"))
        summary = html.escape(str(alert.get("summary") or "No analyst summary available."))
        st.markdown(
            f"""
            <div class="alert-item {tone}">
              <div class="alert-topline">
                <div class="alert-title">{attack_type}</div>
                <div class="alert-time">{alert_time}</div>
              </div>
              <div class="alert-meta">
                {source_ip} -> {target_ip} |
                {severity} |
                {protocol}
              </div>
              <div class="alert-summary">{summary}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    st.markdown("</div>", unsafe_allow_html=True)


def render_overview(user: dict) -> None:
    st_autorefresh(interval=2000, key="cybershield_soc_refresh")

    blacklist_db = load_blacklist_db()
    history_store = load_attack_history()
    events = list(history_store.get("events", []))
    analysis = analyze_attack_history(events)
    alert_snapshot = get_alert_dashboard_snapshot(limit=200)
    live_alerts = alert_snapshot.get("alerts", [])
    _sync_realtime_alert_state(live_alerts)
    risk_score = _compute_risk_score(events, analysis)
    timeline_df = _build_alert_timeline_dataframe(alert_snapshot)
    geo_df = _build_map_dataframe_from_snapshot(alert_snapshot)
    attack_type_df = _build_distribution_dataframe(
        alert_snapshot.get("attack_type_distribution") or {},
        "Attack Type",
    )
    severity_df = _build_distribution_dataframe(
        alert_snapshot.get("severity_distribution") or {},
        "Severity",
    )
    active_banner = next(
        (
            alert for alert in live_alerts
            if not alert.get("cooldown_applied")
        ),
        live_alerts[0] if live_alerts else None,
    )
    st.markdown(
        f"""
        <div class="hero">
          {AUTH_BRAND_HTML}
        </div>
        """,
        unsafe_allow_html=True,
    )

    if active_banner:
        st.markdown(render_alert_banner_html(active_banner), unsafe_allow_html=True)

    cols = st.columns(4)
    cols[0].metric("Blacklisted IPs", len(blacklist_db.get("ips", {})))
    cols[1].metric("Blacklisted Domains", len(blacklist_db.get("domains", {})))
    cols[2].metric("Blacklisted Hashes", len(blacklist_db.get("hashes", {})))
    cols[3].metric("Live Alerts", len(live_alerts))

    primary_left, primary_right = st.columns([1.05, 1], gap="large")
    with primary_left:
        _render_risk_meter(risk_score, analysis)
        st.markdown('<div class="glass">', unsafe_allow_html=True)
        st.markdown('<div class="dashboard-section-title">Real-Time Attack Count</div>', unsafe_allow_html=True)
        if not timeline_df.empty:
            _render_plotly_line_chart(timeline_df)
            st.caption("Central alert pipeline refreshes every 2 seconds and updates this attack volume graph live.")
        else:
            st.info("Timeline will populate as live malicious detections are recorded.")
        st.markdown("</div>", unsafe_allow_html=True)
    with primary_right:
        _render_live_alert_panel(live_alerts)

    if not geo_df.empty:
        st.markdown('<div class="glass">', unsafe_allow_html=True)
        st.markdown('<div class="dashboard-section-title">Geo-Location of Attackers</div>', unsafe_allow_html=True)
        st.map(geo_df[["lat", "lon"]], use_container_width=True)
        st.dataframe(
            geo_df[["attacker_ip", "region", "severity", "attack_type"]].rename(
                columns={
                    "attacker_ip": "Source IP",
                    "region": "Estimated Region",
                    "severity": "Severity",
                    "attack_type": "Attack Type",
                }
            ),
            use_container_width=True,
            hide_index=True,
        )
        st.caption("Locations are resolved from the centralized IP geolocation lookup when public attacker IPs are available.")
        st.markdown("</div>", unsafe_allow_html=True)

    if not attack_type_df.empty or not severity_df.empty:
        dist_left, dist_right = st.columns(2, gap="large")
        with dist_left:
            st.markdown('<div class="glass">', unsafe_allow_html=True)
            st.markdown('<div class="dashboard-section-title">Attack Type Distribution</div>', unsafe_allow_html=True)
            if not attack_type_df.empty:
                _render_plotly_bar_chart(attack_type_df, "Attack Type", ["#00f5ff", "#18ffb2", "#ff9f43", "#ff5c5c"])
            else:
                st.info("Attack type distribution will appear after the first alert.")
            st.markdown("</div>", unsafe_allow_html=True)
        with dist_right:
            st.markdown('<div class="glass">', unsafe_allow_html=True)
            st.markdown('<div class="dashboard-section-title">Severity Distribution</div>', unsafe_allow_html=True)
            if not severity_df.empty:
                _render_plotly_bar_chart(severity_df, "Severity", ["#18ffb2", "#ffd166", "#ff5c5c"])
            else:
                st.info("Severity distribution will appear after the first alert.")
            st.markdown("</div>", unsafe_allow_html=True)


def _get_default_feedback_sample() -> dict:
    latest_result = st.session_state.get("latest_simulation_result") or {}
    latest_processed = latest_result.get("processed") or {}

    return {
        "timestamp": "",
        "source_ip": str(latest_processed.get("source_ip", "")) if latest_processed else "",
        "destination_ip": str(latest_processed.get("destination_ip", "")) if latest_processed else "",
        "protocol": "TCP",
        "port": 80,
        "packet_size": 500,
        "request_rate": 100,
        "failed_logins": 0,
        "malware_signature": "none",
        "traffic_type": "normal",
        "attack_type": "none",
    }


def render_model_lifecycle_page(user: dict) -> None:
    st.markdown('<div class="page-heading"><h1>Model Lifecycle</h1></div>', unsafe_allow_html=True)
    st.caption(f"Signed in as {user.get('username', 'unknown')}")

    model_status = get_current_model_status()
    current_model = model_status.get("current_model") or {}
    versions = list_model_versions()
    previous_versions = [
        version for version in versions
        if version.get("version_id") != current_model.get("version_id")
    ]

    status_tab, feedback_tab, versions_tab, metrics_tab = st.tabs(
        ["Status", "Submit Feedback", "Version History", "Retraining Metrics"]
    )

    with status_tab:
        if current_model:
            render_model_status_panel(current_model, int(model_status.get("feedback_samples", 0)))
            source_summary = current_model.get("source_summary") or {}
            if source_summary:
                summary_cols = st.columns(3)
                summary_cols[0].metric("Base Samples", source_summary.get("base_samples", 0))
                summary_cols[1].metric("Feedback Samples Used", source_summary.get("feedback_samples", 0))
                summary_cols[2].metric("Combined Samples", source_summary.get("combined_samples", 0))
        else:
            st.info("No current model manifest found yet.")

        min_feedback_samples = st.number_input(
            "Minimum feedback samples required before retraining",
            min_value=1,
            value=max(1, int(model_status.get("feedback_samples", 1) or 1)),
            step=1,
        )
        if st.button("Retrain Model", type="primary", use_container_width=True):
            try:
                retrain_result = retrain_model_from_feedback(
                    min_feedback_samples=int(min_feedback_samples),
                    triggered_by=f"dashboard:{user.get('username', 'unknown')}",
                )
            except ValueError as exc:
                st.session_state["model_lifecycle_retrain_error"] = str(exc)
                st.session_state.pop("model_lifecycle_retrain_result", None)
            else:
                st.session_state["model_lifecycle_retrain_result"] = retrain_result
                st.session_state.pop("model_lifecycle_retrain_error", None)
                st.rerun()

        retrain_error = st.session_state.get("model_lifecycle_retrain_error")
        if retrain_error:
            st.error(retrain_error)

        retrain_result = st.session_state.get("model_lifecycle_retrain_result")
        if retrain_result:
            manifest = retrain_result.get("model_manifest") or {}
            render_result_banner(
                "Retraining completed",
                f"New active model version: {manifest.get('version_id', 'unknown')}",
                "good",
            )
            dataset_summary = retrain_result.get("dataset_summary") or {}
            result_cols = st.columns(3)
            result_cols[0].metric("Feedback Used", retrain_result.get("feedback_samples_used", 0))
            result_cols[1].metric("Combined Samples", dataset_summary.get("combined_samples", 0))
            result_cols[2].metric("Feature Count", manifest.get("feature_count", 0))

    with feedback_tab:
        defaults = _get_default_feedback_sample()
        st.subheader("Submit analyst feedback")
        st.caption("Use this to record new attack patterns or correct model mistakes so retraining can learn from them.")
        col1, col2 = st.columns([1.15, 1], gap="large")
        with col1:
            feedback_timestamp = st.text_input("Timestamp", value=defaults["timestamp"], key="ml_feedback_timestamp")
            feedback_source_ip = st.text_input("Source IP", value=defaults["source_ip"], key="ml_feedback_source_ip")
            feedback_destination_ip = st.text_input("Destination IP", value=defaults["destination_ip"], key="ml_feedback_destination_ip")
            feedback_protocol = st.selectbox("Protocol", ["TCP", "UDP", "HTTP", "HTTPS", "DNS"], key="ml_feedback_protocol")
            feedback_port = st.number_input("Port", min_value=0, max_value=65535, value=int(defaults["port"]), key="ml_feedback_port")
            feedback_packet_size = st.slider("Packet Size", 100, 1500, int(defaults["packet_size"]), key="ml_feedback_packet_size")
        with col2:
            feedback_request_rate = st.slider("Request Rate", 1, 5000, int(defaults["request_rate"]), key="ml_feedback_request_rate")
            feedback_failed_logins = st.slider("Failed Logins", 0, 50, int(defaults["failed_logins"]), key="ml_feedback_failed_logins")
            feedback_signature = st.text_input("Malware Signature / Domain", value=defaults["malware_signature"], key="ml_feedback_signature")
            feedback_traffic_type = st.selectbox("Traffic Type", ["normal", "suspicious"], key="ml_feedback_traffic_type")
            feedback_attack_type = st.selectbox(
                "Attack Type",
                ["none", "DDoS", "Brute Force", "SQL Injection", "XSS", "Port Scan"],
                key="ml_feedback_attack_type",
            )
            expected_label = st.selectbox("Analyst Verdict", ["attack", "normal"], key="ml_feedback_label")
        feedback_notes = st.text_area(
            "Analyst Notes",
            value="",
            placeholder="Example: Observed repeated login bursts from a single source IP, matched suspicious behavior during analyst review, and confirmed this traffic should be labeled as an attack.",
            key="ml_feedback_notes",
        )

        if st.button("Submit Analyst Feedback", use_container_width=True):
            feedback_sample = {
                "timestamp": feedback_timestamp.strip() or None,
                "source_ip": feedback_source_ip.strip() or None,
                "destination_ip": feedback_destination_ip.strip() or None,
                "protocol": feedback_protocol,
                "port": int(feedback_port),
                "packet_size": int(feedback_packet_size),
                "request_rate": int(feedback_request_rate),
                "failed_logins": int(feedback_failed_logins),
                "malware_signature": feedback_signature.strip() or "none",
                "traffic_type": feedback_traffic_type,
                "attack_type": feedback_attack_type,
            }
            try:
                prediction_snapshot = predict_attack(feedback_sample)
                feedback_result = submit_feedback(
                    sample=feedback_sample,
                    expected_label=expected_label,
                    feedback_source=user.get("username", "analyst"),
                    notes=feedback_notes.strip(),
                    prediction_result=prediction_snapshot,
                )
            except ValueError as exc:
                st.session_state["model_feedback_error"] = str(exc)
                st.session_state.pop("model_feedback_result", None)
            else:
                st.session_state["model_feedback_result"] = feedback_result
                st.session_state.pop("model_feedback_error", None)
                st.rerun()

        feedback_error = st.session_state.get("model_feedback_error")
        if feedback_error:
            st.error(feedback_error)

        feedback_result = st.session_state.get("model_feedback_result")
        if feedback_result:
            render_result_banner(
                "Feedback captured",
                f"Stored feedback record {feedback_result.get('feedback_id', 'unknown')} for the continuous learning pipeline.",
                "good",
            )
            st.json(feedback_result)

    with versions_tab:
        st.subheader("List of previous model versions")
        if previous_versions:
            version_rows = []
            for version in previous_versions:
                source_summary = version.get("source_summary") or {}
                version_rows.append(
                    {
                        "version_id": version.get("version_id"),
                        "trained_at": version.get("trained_at"),
                        "triggered_by": version.get("triggered_by"),
                        "feedback_samples_used": source_summary.get("feedback_samples", 0),
                        "combined_samples": source_summary.get("combined_samples", version.get("sample_count", 0)),
                        "accuracy": (version.get("evaluation") or {}).get("accuracy"),
                    }
                )
            st.dataframe(pd.DataFrame(version_rows), use_container_width=True, hide_index=True)
        else:
            st.info("No previous model versions are available yet.")

    with metrics_tab:
        st.subheader("Retraining status and metrics")
        if current_model:
            evaluation = current_model.get("evaluation") or {}
            summary_cols = st.columns(4)
            summary_cols[0].metric("Accuracy", round(float(evaluation.get("accuracy", 0.0)) * 100, 2))
            summary_cols[1].metric("Feature Count", current_model.get("feature_count", 0))
            summary_cols[2].metric("Training Samples", current_model.get("sample_count", 0))
            summary_cols[3].metric("Available Versions", model_status.get("available_versions", 0))

            source_summary = current_model.get("source_summary") or {}
            if source_summary:
                retraining_df = pd.DataFrame(
                    [
                        {"Dataset": "Base Samples", "Count": source_summary.get("base_samples", 0)},
                        {"Dataset": "Feedback Samples", "Count": source_summary.get("feedback_samples", 0)},
                        {"Dataset": "Combined Samples", "Count": source_summary.get("combined_samples", 0)},
                    ]
                )
                st.bar_chart(retraining_df.set_index("Dataset"))

            class_metrics = []
            for label, metric in evaluation.items():
                if not isinstance(metric, dict):
                    continue
                class_metrics.append(
                    {
                        "label": label,
                        "precision": metric.get("precision"),
                        "recall": metric.get("recall"),
                        "f1_score": metric.get("f1-score"),
                        "support": metric.get("support"),
                    }
                )
            if class_metrics:
                st.dataframe(pd.DataFrame(class_metrics), use_container_width=True, hide_index=True)
        else:
            st.info("No retraining metrics are available yet.")


def render_simulation_page(user: dict) -> None:
    st.markdown('<div class="page-heading"><h1>Simulate Network Traffic</h1></div>', unsafe_allow_html=True)
    st.caption(f"Signed in as {user.get('username', 'unknown')}")

    col1, col2 = st.columns([1.2, 1], gap="large")
    with col1:
        protocol = st.selectbox("Protocol", ["TCP", "UDP", "HTTP", "HTTPS", "DNS"], key="sim_protocol")
        port = st.number_input("Port", value=80, key="sim_port")
        packet_size = st.slider("Packet Size", 100, 1500, 500, key="sim_packet")
        request_rate = st.slider("Request Rate", 1, 5000, 100, key="sim_rate")
        failed_logins = st.slider("Failed Logins", 0, 50, 0, key="sim_failed")

    with col2:
        traffic_type = st.selectbox("Traffic Type", ["normal", "suspicious"], key="sim_traffic")
        attack_type = st.selectbox(
            "Attack Type",
            ["none", "DDoS", "Brute Force", "SQL Injection", "XSS", "Port Scan"],
            key="sim_attack",
        )
        source_ip = st.text_input("Source IP", value="45.23.12.11", key="sim_source_ip")
        destination_ip = st.text_input("Destination IP", value="10.0.0.25", key="sim_dest_ip")
        malware_signature = st.text_input("Malware Signature / Domain", value="none", key="sim_signature")

    support_col1, support_col2 = st.columns([1.2, 1], gap="large")
    with support_col1:
        suspicious_pid = st.text_input("Suspicious PID", value="", key="sim_pid")
    with support_col2:
        suspicious_process_name = st.text_input("Suspicious Process Name", value="", key="sim_process")

    auto_remediate = st.checkbox("Enable automated incident response", value=False, key="sim_auto")

    if st.button("Analyze Traffic", type="primary", use_container_width=True):
        sample = {
            "protocol": protocol,
            "port": port,
            "packet_size": packet_size,
            "request_rate": request_rate,
            "failed_logins": failed_logins,
            "malware_signature": malware_signature,
            "traffic_type": traffic_type,
            "attack_type": attack_type,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "suspicious_pid": int(suspicious_pid) if suspicious_pid.strip().isdigit() else None,
            "suspicious_process_name": suspicious_process_name.strip() or None,
        }

        result = predict_attack(sample, auto_remediate=auto_remediate)
        st.session_state["latest_simulation_result"] = result

    result = st.session_state.get("latest_simulation_result")
    if not result:
        return

    if result.get("error"):
        st.error(f"Prediction failed: {result['error']}")
        return

    render_analysis_result(result)


def render_dataset_packet_capture_page(user: dict) -> None:
    st.markdown('<div class="page-heading"><h1>Dataset Packet Capture</h1></div>', unsafe_allow_html=True)
    st.caption(f"Signed in as {user.get('username', 'unknown')}")

    packet_count = st.slider("Packets To Replay", min_value=1, max_value=50, value=10)
    interval_seconds = st.slider("Replay Interval (seconds)", min_value=0.0, max_value=2.0, value=0.25, step=0.05)
    attack_only = st.checkbox("Replay attack rows only", value=False)
    auto_remediate = st.checkbox("Enable automated incident response", value=False, key="capture_auto")
    if st.button("Start Dataset Packet Capture", type="primary", use_container_width=True):
        try:
            st.session_state["latest_packet_capture"] = run_dataset_packet_capture(
                packet_count=packet_count,
                interval_seconds=interval_seconds,
                attack_only=attack_only,
                auto_remediate=auto_remediate,
            )
        except Exception as exc:
            st.session_state["latest_packet_capture_error"] = str(exc)
        else:
            st.session_state.pop("latest_packet_capture_error", None)

    capture_error = st.session_state.get("latest_packet_capture_error")
    if capture_error:
        st.error(capture_error)
        return

    result = st.session_state.get("latest_packet_capture")
    if not result:
        return

    metrics = st.columns(4)
    metrics[0].metric("Packets Processed", result.get("packet_count", 0))
    metrics[1].metric("Attacks Detected", result.get("attacks_detected", 0))
    metrics[2].metric("Normal Detected", result.get("normal_detected", 0))
    metrics[3].metric("Replay Interval", f"{result.get('interval_seconds', 0)}s")

    render_result_banner(
        "Dataset replay finished",
        f"Replay capture saved to {result.get('capture_path')}. Predictions were generated for each replayed packet.",
        "good" if result.get("attacks_detected", 0) == 0 else "warn",
    )

    packet_rows = []
    for packet in result.get("packets", []):
        features = packet.get("features") or {}
        packet_rows.append(
            {
                "packet_number": packet.get("packet_number"),
                "prediction": "attack" if packet.get("prediction") == 1 else "normal",
                "risk_level": packet.get("risk_level"),
                "attack_type": packet.get("attack_type"),
                "source_ip": features.get("source_ip"),
                "destination_ip": features.get("destination_ip"),
                "protocol": features.get("protocol"),
                "port": features.get("port"),
                "packet_size": features.get("packet_size"),
                "request_rate": features.get("request_rate"),
                "failed_logins": features.get("failed_logins"),
            }
        )

    tabs = st.tabs(["Packet Results", "Packet Details"])
    with tabs[0]:
        st.dataframe(pd.DataFrame(packet_rows), use_container_width=True, hide_index=True)
    with tabs[1]:
        for packet in result.get("packets", []):
            with st.expander(f"Packet {packet.get('packet_number')}"):
                st.json(packet.get("features") or {})
                st.json(packet.get("result") or {})


def render_threat_intelligence_page(user: dict) -> None:
    st.markdown('<div class="page-heading"><h1>Threat Intelligence</h1></div>', unsafe_allow_html=True)
    st.caption(f"Signed in as {user.get('username', 'unknown')}")

    st.markdown("### Lookup")
    indicator_value = st.text_input(
        "Indicator Value",
        value=st.session_state.get("ti_lookup_value", ""),
        placeholder="IP, domain, or file hash",
    )
    if st.button("Lookup Indicator", type="primary", use_container_width=True):
        indicator_type = infer_indicator_type(indicator_value)
        payload = {"source_ip": indicator_value} if indicator_type == "ip" else {"malware_signature": indicator_value}
        st.session_state["ti_lookup_value"] = indicator_value
        st.session_state["ti_lookup_result"] = enrich_threat_intelligence(payload)
        st.session_state["ti_lookup_type"] = indicator_type

    lookup_result = st.session_state.get("ti_lookup_result")
    if lookup_result:
        render_lookup_result(lookup_result)

    st.markdown("### Blacklist IP")
    manual_type = st.selectbox("Indicator Type", ["ip", "domain", "hash"])
    manual_value = st.text_input("Indicator", value="")
    manual_reason = st.text_input("Reason", value="Analyst-confirmed malicious indicator")
    if st.button("Add To Blacklist", use_container_width=True):
        if manual_value.strip():
            entry = add_to_blacklist(
                manual_type,
                manual_value.strip(),
                source="dashboard_manual",
                reason=manual_reason.strip() or "Analyst-confirmed malicious indicator",
                metadata={"created_by": user.get("username")},
            )
            st.success(f"Added {entry.get('value')} to the blacklist database.")
        else:
            st.warning("Enter an indicator value before adding it to the blacklist.")

    blacklist_db = load_blacklist_db()
    st.markdown("### Blacklist History")
    search = st.text_input("Search history", placeholder="Search by IP, domain, hash, source, or reason")
    history = list(reversed(blacklist_db.get("history", [])))
    if search.strip():
        term = search.strip().lower()
        history = [
            item for item in history
            if term in str(item.get("value", "")).lower()
            or term in str(item.get("source", "")).lower()
            or term in str(item.get("reason", "")).lower()
            or term in str(item.get("type", "")).lower()
        ]

    if history:
        history_df = pd.DataFrame(history)
        display_cols = [col for col in ["type", "value", "source", "reason", "listed_at"] if col in history_df.columns]
        st.dataframe(history_df[display_cols], use_container_width=True, hide_index=True)
    else:
        st.info("No blacklist history matches the current filter.")

    st.markdown("### Blacklist IP")
    for idx, item in enumerate(history[:20]):
        cols = st.columns([1.6, 1.2, 0.8])
        cols[0].write(f"`{item.get('type')}` `{item.get('value')}`")
        cols[1].caption(item.get("reason"))
        if cols[2].button("Lookup", key=f"history_lookup_{idx}", use_container_width=True):
            indicator_type = item.get("type")
            indicator_value = item.get("value")
            payload = {"source_ip": indicator_value} if indicator_type == "ip" else {"malware_signature": indicator_value}
            st.session_state["ti_lookup_value"] = indicator_value
            st.session_state["ti_lookup_result"] = enrich_threat_intelligence(payload)
            st.session_state["ti_lookup_type"] = indicator_type
            st.rerun()


def render_forensics_page(user: dict) -> None:
    st.markdown('<div class="page-heading"><h1>Logging & Forensics</h1></div>', unsafe_allow_html=True)
    st.caption(f"Signed in as {user.get('username', 'unknown')}")

    history_store = load_attack_history()
    events = list(reversed(history_store.get("events", [])))
    analysis = analyze_attack_history(list(history_store.get("events", [])))

    top_cols = st.columns(5)
    top_cols[0].metric("Total Events", analysis["totals"]["events"])
    top_cols[1].metric("Detected Attacks", analysis["totals"]["attacks"])
    top_cols[2].metric("Vulnerability Scans", analysis["totals"].get("vulnerability_scans", 0))
    top_cols[3].metric("Critical Events", analysis["totals"]["critical"])
    top_cols[4].metric("Scan Findings", analysis["totals"].get("scan_findings", 0))

    export_col, dist_col = st.columns([1, 1.4], gap="large")
    with export_col:
        st.subheader("Export Reports")
        st.caption("Download the recorded event history for investigations and audit evidence.")
        st.download_button(
            "Download CSV Report",
            data=export_attack_history_csv(list(history_store.get("events", []))),
            file_name="cybershield_attack_history.csv",
            mime="text/csv",
            use_container_width=True,
        )
        try:
            pdf_bytes = export_attack_history_pdf(list(history_store.get("events", [])))
            st.download_button(
                "Download PDF Report",
                data=pdf_bytes,
                file_name="cybershield_forensics_report.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        except RuntimeError as exc:
            st.warning(str(exc))

    with dist_col:
        st.subheader("Log Analysis")
        risk_distribution = analysis.get("risk_distribution", {})
        if risk_distribution:
            risk_df = pd.DataFrame(
                [{"Risk Level": key, "Count": value} for key, value in risk_distribution.items()]
            )
            st.bar_chart(risk_df.set_index("Risk Level"))
        else:
            st.info("No events have been logged yet.")

    bottom_left, bottom_right = st.columns([1, 1], gap="large")
    with bottom_left:
        st.subheader("Frequent Attack Types")
        top_types = analysis.get("top_attack_types", [])
        if top_types:
            st.dataframe(pd.DataFrame(top_types), use_container_width=True, hide_index=True)
        else:
            st.info("No attack records are available yet.")

    with bottom_right:
        st.subheader("Top Source IPs")
        top_sources = analysis.get("top_source_ips", [])
        if top_sources:
            st.dataframe(pd.DataFrame(top_sources), use_container_width=True, hide_index=True)
        else:
            st.info("No malicious source IPs have been recorded yet.")

    st.subheader("Event History")
    search = st.text_input("Search event logs", placeholder="Search by IP, attack type, risk level, verdict, or summary")
    if search.strip():
        term = search.strip().lower()
        events = [
            event for event in events
            if term in str(event.get("source_ip", "")).lower()
            or term in str(event.get("destination_ip", "")).lower()
            or term in str(event.get("attack_type", "")).lower()
            or term in str(event.get("risk_level", "")).lower()
            or term in str(event.get("verdict", "")).lower()
            or term in str(event.get("summary", "")).lower()
        ]

    if events:
        event_df = pd.DataFrame(events)
        display_columns = [
            column
            for column in [
                "event_type",
                "logged_at",
                "verdict",
                "risk_level",
                "attack_type",
                "scan_target",
                "source_ip",
                "destination_ip",
                "protocol",
                "port",
                "confidence",
                "threat_intel_score",
                "blacklist_match",
            ]
            if column in event_df.columns
        ]
        st.dataframe(event_df[display_columns], use_container_width=True, hide_index=True)
    else:
        st.info("No event logs match the current filter.")


def _parse_port_input(raw_value: str) -> list[int]:
    values = []
    for part in str(raw_value or "").split(","):
        item = part.strip()
        if not item:
            continue
        if "-" in item:
            start_text, end_text = item.split("-", 1)
            try:
                start_port = int(start_text.strip())
                end_port = int(end_text.strip())
            except ValueError:
                continue
            if start_port > end_port:
                start_port, end_port = end_port, start_port
            values.extend(range(start_port, end_port + 1))
            continue
        try:
            values.append(int(item))
        except ValueError:
            continue
    return sorted({port for port in values if 1 <= port <= 65535})


def render_vulnerability_scanner_page(user: dict) -> None:
    st.markdown('<div class="page-heading"><h1>Vulnerability Scanner</h1></div>', unsafe_allow_html=True)
    st.caption(f"Signed in as {user.get('username', 'unknown')}")

    target = st.text_input("Target Host", value="127.0.0.1", help="Use localhost, an IP address, or a hostname you are authorized to scan.")
    port_mode = st.radio("Port Scope", ["Common ports", "Custom ports"], horizontal=True)
    custom_ports_raw = ""
    if port_mode == "Custom ports":
        custom_ports_raw = st.text_input("Custom Ports", value="22,80,443,3306", help="Comma-separated ports or ranges like 20-25,80,443")
    timeout = st.slider("Per-port timeout (seconds)", min_value=0.1, max_value=1.5, value=0.35, step=0.05)
    if st.button("Run Vulnerability Scan", type="primary", use_container_width=True):
        try:
            ports = None if port_mode == "Common ports" else _parse_port_input(custom_ports_raw)
            if port_mode == "Custom ports" and not ports:
                st.warning("Enter at least one valid custom port before starting the scan.")
            else:
                st.session_state["latest_vulnerability_scan"] = scan_target(target, ports=ports, timeout=timeout)
        except ValueError as exc:
            st.error(str(exc))

    result = st.session_state.get("latest_vulnerability_scan")
    if not result:
        return

    metric_cols = st.columns(4)
    metric_cols[0].metric("Overall Risk", result.get("overall_risk", "LOW"))
    metric_cols[1].metric("Open Ports", len(result.get("open_ports", [])))
    metric_cols[2].metric("Services", result.get("service_count", 0))
    metric_cols[3].metric("Findings", len(result.get("misconfigurations", [])))
    render_result_banner("Scan complete", result.get("summary", "Scan finished."), "warn" if result.get("misconfigurations") else "good")

    ports_tab, findings_tab, raw_tab = st.tabs(["Open Ports", "Misconfigurations", "Raw Results"])
    with ports_tab:
        open_ports = result.get("open_ports", [])
        if open_ports:
            st.dataframe(pd.DataFrame(open_ports), use_container_width=True, hide_index=True)
        else:
            st.info("No open ports were found in the selected port set.")

    with findings_tab:
        findings = result.get("misconfigurations", [])
        if findings:
            for finding in findings:
                tone = "alert" if str(finding.get("severity")).lower() in {"critical", "high"} else "warn"
                render_result_banner(
                    f"{finding.get('title')} ({str(finding.get('severity', 'info')).upper()})",
                    f"{finding.get('description')} Recommendation: {finding.get('recommendation')}",
                    tone,
                )
        else:
            st.success("No misconfiguration heuristics were triggered by this scan.")

    with raw_tab:
        st.json(result)


user = auth_page()

if not user:
    render_public_auth()
    st.stop()

with st.sidebar:
    st.markdown(f"### {user.get('full_name') or user.get('username')}")
    st.caption(f"@{user.get('username')}")
    page = st.radio(
        "Navigate",
        [
            "Overview",
            "Model Lifecycle",
            "Simulate Network Traffic",
            "Dataset Packet Capture",
            "Threat Intelligence",
            "Vulnerability Scanner",
            "Logging & Forensics",
        ],
    )
    logout_button()

if page == "Overview":
    render_overview(user)
elif page == "Model Lifecycle":
    render_model_lifecycle_page(user)
elif page == "Simulate Network Traffic":
    render_simulation_page(user)
elif page == "Dataset Packet Capture":
    render_dataset_packet_capture_page(user)
elif page == "Threat Intelligence":
    render_threat_intelligence_page(user)
elif page == "Vulnerability Scanner":
    render_vulnerability_scanner_page(user)
else:
    render_forensics_page(user)

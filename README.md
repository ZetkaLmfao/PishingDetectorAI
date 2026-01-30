# DetectorURL

Phishing detection app based on machine learning (Perceptron) with a Tkinter UI. The project analyzes URLs, extracts dozens of features, and classifies them as legitimate or phishing.

## Features
- URL classification with a Perceptron model
- Feature extraction (length, subdomains, suspicious characters, brand patterns, etc.)
- Basic input validation (http/https and valid TLD via tldextract)
- Simple history dashboard

## Structure
- main.py: main app + training + UI
- dataset.csv: training dataset

## Requirements
- Python 3.11+
- numpy
- scikit-learn
- matplotlib
- tldextract

## Installation
1. Create a virtual environment (optional)
2. Install dependencies:
	pip install numpy scikit-learn matplotlib tldextract

## How to run
2. Run the app:
	py main.py
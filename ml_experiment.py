import re

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.svm import SVC
    from sklearn.pipeline import make_pipeline
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    print("scikit-learn is not installed. To run this experiment fully, please run: pip install scikit-learn")

# This is a standalone experiment file. It does NOT replace or interact with detector_core.py.
# Your original Gadara rules and data are 100% untouched.

# 1. A tiny dataset acting as our "Training Data".
# In a real scenario, this would be loaded from a large CSV file.
TRAIN_DATA = [
    ("Your Airtel Money account has been suspended. Verify now.", "scam"),
    ("Congratulations! You have won K50000 in the lottery.", "scam"),
    ("Emergency! Send K1000 airtime to help me.", "scam"),
    ("Invest in Bitcoin and double your money fast!", "scam"),
    ("Can you urgently send me k100? i forgot my wallet.", "scam"),
    ("Hi Mom, I will pay the electricity bill tomorrow at the office.", "safe"),
    ("Airtel Data: Buy 1GB for k15. Dial *115# now.", "safe"),
    ("Meeting at 2 PM in the board room. See you there.", "safe"),
    ("I am stuck in traffic, will be late by 10 minutes.", "safe"),
    ("Can we meet at the mall? I need to give you the documents.", "safe")
]

# 2. Test Examples
TEST_MESSAGES = [
    "You have won a free trip, click the link to claim!", 
    "Hey, what time are we having lunch today?",
    "Your bank account is compromised, send your PIN immediately"
]

def run_classical_ml_experiment():
    print("--- 🤖 Classical Machine Learning Experiment (Stepping Stone) ---")
    
    # Split training data into X (texts) and y (labels)
    texts_train = [item[0] for item in TRAIN_DATA]
    labels_train = [item[1] for item in TRAIN_DATA]
    
    # Create an ML Pipeline using TF-IDF (Text Vectorizer) and SVM (Support Vector Machine)
    # This SVM is what we would eventually swap out for a Quantum Support Vector Machine (QSVM)
    model = make_pipeline(TfidfVectorizer(lowercase=True), SVC(probability=True, kernel='linear'))
    
    print(f"Training Model on {len(texts_train)} examples...")
    model.fit(texts_train, labels_train)
    print("Model Trained Successfully!\n")
    
    print("--- 🧪 Testing Predictions ---")
    for msg in TEST_MESSAGES:
        # Predict the class
        prediction = model.predict([msg])[0]
        # Get confidence probabilities
        probabilities = model.predict_proba([msg])[0]
        
        # Determine confidence of the prediction
        confidence_idx = list(model.classes_).index(prediction)
        confidence = probabilities[confidence_idx] * 100
        
        icon = "🔴" if prediction == "scam" else "🟢"
        print(f"Message: '{msg}'")
        print(f"Result:  {icon} {prediction.upper()} (Confidence: {confidence:.1f}%)\n")

if __name__ == "__main__":
    if HAS_SKLEARN:
        run_classical_ml_experiment()
    else:
        print("Please install scikit-learn to see the Classical ML simulation before we move to Quantum.")
        print("Command: pip install scikit-learn")

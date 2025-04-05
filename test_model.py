try:
    from tensorflow.keras.models import load_model
    print("✅ Import réussi : tensorflow.keras.models.load_model")
except ImportError as e:
    print("❌ Import échoué :", e)

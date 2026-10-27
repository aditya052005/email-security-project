from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

# Small training dataset for prototype
emails = [
    "urgent verify your account immediately click the link",
    "your account has been suspended verify now",
    "click here to confirm your password and otp",
    "you won a prize click the link immediately",
    "please verify your banking account",
    
    "meeting is scheduled for tomorrow",
    "your project submission was received",
    "please attend the department meeting",
    "your assignment has been successfully submitted",
    "thank you for your email"
]

labels = [
    1, 1, 1, 1, 1,
    0, 0, 0, 0, 0
]

# Convert text into numerical features
vectorizer = TfidfVectorizer()

X = vectorizer.fit_transform(emails)

# Train ML classifier
model = LogisticRegression()

model.fit(X, labels)


def predict_email(email_text):
    email_vector = vectorizer.transform([email_text])

    prediction = model.predict(email_vector)[0]

    probability = model.predict_proba(email_vector)[0][1]

    if prediction == 1:
        result = "PHISHING"
    else:
        result = "LEGITIMATE"

    return result, probability
if __name__ == "__main__":
    test = "URGENT verify your account immediately"
    result, probability = predict_email(test)

    print("Prediction:", result)
    print("Confidence:", round(probability * 100, 2), "%")
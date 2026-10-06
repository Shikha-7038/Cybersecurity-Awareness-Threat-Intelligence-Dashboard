"""Quiz scoring and personalised learning recommendations (educational score, NOT an employee competency judgement)."""
CAT_TO_MODULE = {"Phishing": "Phishing Awareness", "Passwords": "Password Security", "MFA": "MFA", "Social Engineering": "Social Engineering",
                 "Safe Browsing": "Safe Browsing", "Ransomware": "Ransomware Awareness", "Privacy": "Data Privacy",
                 "Wi-Fi": "Secure Wi-Fi", "Mobile Security": "Mobile Security", "Incident Reporting": "Incident Reporting"}


def awareness_level(score):
    return "Needs Improvement" if score <= 40 else "Basic Awareness" if score <= 60 else "Good Awareness" if score <= 80 else "Strong Awareness"


def score_quiz(questions, answers):
    """answers: {question_id(str): chosen_index}. Returns overall, per-category scores and recommendations."""
    cats, correct = {}, 0
    for q in questions:
        ok = answers.get(str(q["id"])) == q["answer"]
        correct += ok
        c = cats.setdefault(q["category"], [0, 0])
        c[0] += ok
        c[1] += 1
    overall = round(100 * correct / len(questions)) if questions else 0
    by_cat = {k: round(100 * a / b) for k, (a, b) in cats.items()}
    return {"overall_score": overall, "level": awareness_level(overall), "category_scores": by_cat,
            "recommendations": generate_learning_recommendations(by_cat),
            "note": "Educational score only - not a judgement of anyone's competence."}


def generate_learning_recommendations(by_cat):
    out = []
    for cat, s in sorted(by_cat.items(), key=lambda x: x[1]):
        mod = CAT_TO_MODULE.get(cat, cat)
        out.append({"category": cat, "score": s, "recommendation": f"Complete the {mod} module." if s < 60 else
                    f"Quick review of {mod} recommended." if s < 85 else "No immediate module required."})
    return out

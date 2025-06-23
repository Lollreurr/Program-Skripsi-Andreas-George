from collections import defaultdict
import numpy as np
import math
import random
import sys


def read_passwords(filename):
    passwords = []
    with open(filename, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if line:
                passwords.append(line)
    return passwords

def calculate_smml_probabilities(passwords):
    # menghitung HSIMM dalam mencari probabilitas SMML

    length_models = defaultdict(lambda: {
        "first_char_counts": defaultdict(int),
        "char_counts": defaultdict(int),
        "transition_counts": defaultdict(int),
        "total_passwords": 0
    })

    for password in passwords:
        length = len(password)
        model = length_models[length]
        model["total_passwords"] += 1

        if len(password) > 0:
            model["first_char_counts"][password[0]] += 1

        for i in range(len(password) - 1):
            model["char_counts"][password[i]] += 1
            model["transition_counts"][(password[i], password[i + 1])] += 1

    length_probs = {}

    for length, model in length_models.items():
        first_char_probs = {}
        for char, count in model["first_char_counts"].items():
            first_char_probs[char] = count / model["total_passwords"]
            
        transition_probs = {}
        for (c1, c2), count in model["transition_counts"].items():
            transition_probs[(c1, c2)] = count / model["char_counts"][c1]
        
        length_probs[length] = {
            "first_char_probs": first_char_probs,
            "transition_probs": transition_probs
        }
    
    
    return length_probs

def calculate_smml(passwords, length_probs):
    # Menghitung HSIMM dalam evaluasi password dalam proses SMML

    smml_values = {}
    smml_transformed = {}

    for password in passwords:
        length = len(password)
        model = length_probs.get(length, None)
        if not model:
            smml_values[password] = None 
            smml_transformed[password] = None
            continue

        prob = model["first_char_probs"].get(password[0], 1e-6)

        for i in range(len(password) - 1):
            prob *= model["transition_probs"].get((password[i], password[i + 1]), 1e-6)

        smml_values[password] = prob
        smml_transformed[password] = -math.log2(prob)
    


    return smml_values, smml_transformed

def calculate_threshold_SMML(values_dict):
    # Menghitung threshold kekuatan HSIMM dalam SMML

    values = np.array(list(values_dict.values()))
    mu = np.mean(values)
    sigma = np.std(values)
    weak_threshold = mu + 2 * sigma
    return weak_threshold, mu, sigma

def calculate_threshold_SI(values_dict):
    # Menghitung threshold kekuatan HSIMM dalam Self Information

    values = np.array(list(values_dict.values()))
    mu = np.mean(values)
    sigma = np.std(values)
    weak_threshold = mu + 2 * sigma
    return weak_threshold, mu, sigma


def categorize_smml(values_dict, threshold):
    # Mengkategorikan kekuatan password berdasarkan 3 sigma rule pada metode HSIMM dalam SMML
    return {
         pw: "Weak" if val < threshold else "Not Weak"
        for pw, val in values_dict.items()
    }
    
def calculate_self_information_probs(passwords):
    # menghitung HSIMM dalam mencari probabilitas Self Information
    transition_counts = defaultdict(int)
    char_counts = defaultdict(int)

    for password in passwords:
        for i in range(len(password) - 1):
            c1, c2 = password[i], password[i + 1]
            transition_counts[(c1, c2)] += 1
            char_counts[c1] += 1 

    transition_probs = {}
    for (c1, c2), count in transition_counts.items():
        transition_probs[(c1, c2)] = count / char_counts[c1]

 
    return transition_probs

def calculate_self_information(passwords, transition_probs):
    # Menghitung HSIMM dalam evaluasi password dalam proses Self Information

    si_values = {}
    
    
    for password in passwords:
        si = 0
        for i in range(len(password) - 1):
            c1, c2 = password[i], password[i + 1]
            prob = transition_probs.get((c1, c2), 1e-6)
            
        
            si += -math.log2(prob)
           
        si_values[password] = si


    return si_values

def categorize_self_information(values_dict, threshold):
    # Mengkategorikan kekuatan password berdasarkan 3 sigma rule pada metode HSIMM dalam Self Information

    return {
        pw: "Weak" if val < threshold else "Not Weak"
        for pw, val in values_dict.items()
    }

def Naver(total_loop, percentage):
    # Menghitung rata rata password yang didefinisikan lemah sebanyak 10 kali looping dengan menggunakan 20 dataset password
   
    filename = "D:\Data 1\Perkuliahan\SKRIPSII\Periode 2\pengerjaan metode\SMM\sample2 - Copy.txt"
    passwords = read_passwords(filename)
    total_weak = 0
    size = int(len(passwords) * percentage)  # 20% of the dataset

    for _ in range(total_loop):
        # Mengambil sample password sebanyak 20%
        sampled = random.sample(passwords, size)

        # HSIMM dalam perhitungan SMML
        smml_model = calculate_smml_probabilities(sampled)
        smml_values, smml_transformed = calculate_smml(sampled, smml_model)
        smml_threshold, smml_mu, smml_sigma = calculate_threshold_SMML(smml_transformed)
        smml_categories = categorize_smml(smml_transformed, smml_threshold)


        # HSIMM dalam perhitungan SMML
        si_char_probs = calculate_self_information_probs(sampled)
        si_values = calculate_self_information(sampled, si_char_probs)
        si_threshold, si_mu, si_sigma = calculate_threshold_SI(si_values)
        si_categories = categorize_self_information(si_values, si_threshold)

        # Mengkategorikan password lemah
        final_weak_passwords = [
            pw for pw in sampled
            if smml_categories[pw] == "Weak" or si_categories[pw] == "Weak"
        ]
       
    
        # Jumlah password yang dikategorikan lemah
        total_weak += len(final_weak_passwords)
        

    # Hasil rata rata dari password dikategorikan lemah dalam looping sebanyak 10 kali
    return total_weak / total_loop

def show_SMML_details(length_probs, length):
    # Memberikan details bagaimana menemukan nilai HSIMM dalam SMML (lengthnya)
   
    if length not in length_probs:
        print(f"Length {length} is not available in the dataset.")
        return

    print(f"\n=== Details for Password Length: {length} ===")
    model = length_probs[length]

    print("\nFirst Character Probabilities:")
    for char, prob in model["first_char_probs"].items():
        print(f"  {char}: {prob:.6f}")

    print("\nTransition Probabilities:")
    for (c1, c2), prob in model["transition_probs"].items():
        print(f"  {c1} -> {c2}: {prob:.6f}")

def show_self_information_details(passwords, char_probs):
    # Memberikan details bagaimana menemukan nilai HSIMM dalam Self Information

    print("\n=== Self-Information Details ===")
    print("\nCharacter Probabilities:")
    for char, prob in char_probs.items():
        print(f"  {char}: {prob:.6f}")

    print("\nSelf-Information Values for Passwords:")
    for password in passwords:
        si = 0
        print(f"\nPassword: {password}")
        for i in range(len(password) - 1):
            c1, c2 = password[i], password[i + 1]
            prob = char_probs.get((c1, c2), 1e-6)
            si += -math.log2(prob)
            print(f"  Transition ({c1} -> {c2}): P = {prob:.6f}, Self-Information = {-math.log2(prob):.6f}")
        print(f"  Total Self-Information: {si:.6f}")

def show_smml_details(passwords, smml_values):
    # Memberikan details bagaimana menemukan nilai HSIMM dalam SMML

    print("\n=== SMML Details ===")
    print("\nSMML Values for Passwords:")
    for password in passwords:
        smml_value = smml_values.get(password, 1e-12)
        print(f"  {password}: {smml_value:.6f}")

def evaluate_password_strength(password, smml_model, si_char_probs, smml_mu, smml_sigma, si_mu, si_sigma):
    
    # Menghitung nilai SMML
    length = len(password)

    smml_value = None
    
    if length in smml_model:
        model = smml_model[length]
        smml_value = model["first_char_probs"].get(password[0], 1e-6)
        for i in range(len(password) - 1):
            smml_value *= model["transition_probs"].get((password[i], password[i + 1]), 1e-6)

        smml_transformed = -math.log2(smml_value)

    else:
        smml_transformed = -math.log2(smml_value)


    # Menghitung nilai self information 
    si_value = 0
    for i in range(len(password) - 1):
        c1, c2 = password[i], password[i + 1]
        prob = si_char_probs.get((c1, c2), 1e-6)
        si_value += -math.log2(prob)

   # Menentukan threshold untuk SMML dengan 3 sigma rule 
    smml_inormal = smml_mu + 2  * smml_sigma  # threshold normal
    smml_istrong = smml_mu + 3 * smml_sigma  # threshold kuat
   
    
    if smml_transformed < smml_inormal:  
        smml_criteria = "Weak"
    elif smml_transformed < smml_istrong and smml_value >= smml_inormal:
        smml_criteria = "Normal"
    else:
        smml_criteria = "Strong"
    

    # Menentukan threshold untuk self information
    si_inormal = si_mu + 2 * si_sigma  # Threshold normal
    si_istrong = si_mu + 3 * si_sigma  # Threshold kuat
    if si_value < si_inormal:
        si_criteria = "Weak"
    elif si_value < si_istrong and si_value >= si_inormal:
        si_criteria = "Normal"
    else:
        si_criteria = "Strong"

    # Mengevaluasi kriteria password untuk metode HSIMM
    if smml_criteria == "Weak" and si_criteria == "Weak":
        overall_criteria = "Weak"
    elif smml_criteria == "Strong" and si_criteria == "Strong":
        overall_criteria = "Strong"
    else:
        overall_criteria = "Normal"

    return {
        "SMML Value": smml_value,
        "SMML Criteria": smml_criteria,
        "Self-Information Value": si_value,
        "SMML Transformed": smml_transformed,
        "Self-Information Criteria": si_criteria,
        "Overall Strength Criteria": overall_criteria
    }

if __name__ == "__main__":
    Naver_val = Naver(10, 0.2)
    print("Nilai Naver : ", Naver_val)
   
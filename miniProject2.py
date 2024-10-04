import csv
import hashlib
import re
import requests
import os
import datetime

USERFILE = 'regno.csv'
NEWSAPIKEY = 'pub_55164cbe3e6d1ba9961a54701ce317e946c15' 
MAXATTEMPTS = 5

# hashing function for hash passwords with SHA-256
def hash_password(password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    log('Hash Password', f'password successfullu hashed.')
    return hashed_password

# Load user data from the CSV file
def load_users():
    users = {}
    if os.path.exists(USERFILE):
        with open(USERFILE, mode='r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                users[row['email']] = {
                    'password': row['password'],
                    'security_question': row['security_question'],
                    'security_answer': row['security_answer']
                }
    log('Load Users', f'user data loaded successfully.')            
    return users

# saving user information to csvv file
def save_user(email, password, security_question,security_answer):
    file_exists = os.path.exists(USERFILE)
    with open(USERFILE, mode='a', newline='') as file:
        fieldnames = ['email', 'password', 'security_question','security_answer']
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        
        if not file_exists:
            writer.writeheader()  # Write header if file doesn't exist
        
        writer.writerow({
            'email': email,
            'password': password,
            'security_question': security_question,
            'security_answer': security_answer
        })
    log('Save User', f'user {email} successfully saved.') 

# Function to validate an email address format
def validate_email(email):
    pattern = r"[^@]+@[^@]+\.[^@]+"
    is_valid = re.match(pattern, email) is not None
    log('validate email', f'email {email} validation: {is_valid}.')
    return is_valid

# Function to validate the password format
def validate_password(password):
    if len(password) < 8:
        log('Validate Password', f'password verification failed: Too short.')
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        log('Validate Password', f'password verification failed: No special character.')
        return False
    log('Validate Password', f'Password verification successfully.')
    return True

# Function to register a new user
def register():
    print("Register a new account")
    email = input("Enter your email: ")
    if not validate_email(email):
        print("Invalid email format. Registration failed.")
        log('Registration', f'Registration failed for {email}: Invalid email format.')
        return

    password = input("Enter a password (min 8 characters, 1 special char): ")
    if not validate_password(password):
        print("Password does not meet the criteria. Registration failed.")
        log('Registration', f'Registration failed for {email}: Invalid password.')
        return
    
    security_question = input("Enter a security question (for password recovery): ")
    security_answer = input("Enter your security answer: ")
    
    users = load_users()
    if email in users:
        print("User already exists. Try logging in.")
        log('Registration', f'Registration failed for {email}: User already exists.')
        return
    
    hashed_password = hash_password(password)
    save_user(email, hashed_password, security_question,security_answer)
    print("Registration successful! You can now log in.")
    log('Registration', f'User {email} registered successfully.')

# Function for login
def login():
    users = load_users()
    attempts = 0
    while attempts < MAXATTEMPTS:
        email = input("Enter your email: ")
        if not validate_email(email):
            print("Invalid email format. Try again.")
            continue

        password = input("Enter your password: ")
        if email in users and users[email]['password'] == hash_password(password):
            print("Login successful!")
            return email

        attempts += 1
        print(f"Incorrect email or password. {MAXATTEMPTS - attempts} attempts left.")

    print("Too many failed attempts. Exiting.")
    exit()

# Function to reset the password
def forgot_password():
    users = load_users()
    email = input("Enter your registered email: ")
    if email not in users:
        print("Email not found.")
        return
    
    security_answer = input("Answer your security question: ")
    if security_answer == users[email]['security_answer']:
        new_password = input("Enter your new password: ")
        if validate_password(new_password):
            update_password(email, new_password)
            print("Password reset successful.")
        else:
            print("Password must be at least 8 characters long and contain at least one special character.")
    else:
        print("Incorrect security question answer.")

# Save new password during reset
def update_password(email, new_password):
    users = load_users()
    users[email]['password'] = hash_password(new_password)
    with open(USERFILE, mode='w', newline='') as file:
        fieldnames = ['email', 'password', 'security_question','security_answer']
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for email, data in users.items():
            writer.writerow({
                'email': email,
                'password': data['password'],
                'security_question': data['security_question'],
                'security_answer': data['security_answer']
            })
#log function to save other information
def log(event, message):
  timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
  with open('logfile.csv', mode='a', newline='') as file:
    writer = csv.writer(file)
    writer.writerow([timestamp, event, message])

#function for Fetching news headlines from NewsAPI based on user input
def fetch_news(keyword):
    url = f"https://newsdata.io/api/1/latest?q={keyword}&apiKey={NEWSAPIKEY}"
    #https://newsdata.io/api/1/latest?q=india&apiKey=pub_55164cbe3e6d1ba9961a54701ce317e946c15
    try:
        log('Fetch News', f'Fetching news for keyword: {keyword}')
        news = requests.get(url)
        news.raise_for_status()  # Raise an exception for bad status codes (like 401 for invalid API key)
        news = news.json()

        if not news['results']:
            print("No news result found for this word.")
            log('Fetch News', f'No news results found for keyword: {keyword}')
            return

        for i in range(5):
            result = news['results'][i]
            if 'title' in result:
                title = result["title"]
                print(i+1, title)
            #if 'content' in result:
            #content = result['content']//content is for paid user 
            #print(content)
            if 'source_id' in result:
                source_id = result['source_id']
                print(f"Source: {source_id}")
            if 'link' in result:
                link = result['link']
                print(f"Link: {link}")
            print("-" * 20)
        log('Fetch News', f'News fetched successfully for keyword: {keyword}')

    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
        log('Fetch News', f'HTTP Error: {errh}')
        if errh.response.status_code == 401:
            print("API key is invalid or expired.")
            log('Fetch News', 'API key is invalid or expired.')
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}")
        log('Fetch News', f"Error Connecting: {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}")
        log('Fetch News', f"Timeout Error: {errt}")
    except requests.exceptions.RequestException as err:
        print(f"Something went wrong: {err}")
        log('Fetch News', f'Request Exception: {err}')


# Main application function
def main():
    while True:
        print("\n1. Register Here")
        print("2. Login Here")
        print("3. Forgot Password")
        print("4. Exit")
        choice = input("Enter your choice please: ")

        if choice == '1':
            log('Main', 'User selected Register option.')
            register()
        elif choice == '2':
            log('Main', 'User selected Login option.')
            email = login()
            if email: 
                keyword = input("Enter a news topic or keyword: ")
                fetch_news(keyword)
        elif choice == '3':
            log('Main', 'User selected Forgot Password option.')
            forgot_password()
        elif choice == '4':
            log('Main', 'User selected Exit option.')
            print("Goodbye!")
            break
        else:
            log('Main', 'User entered invalid choice.')
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()



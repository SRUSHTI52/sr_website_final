# SR Counselling — Multilingual eBook & Service Platform  

## Project Overview  
**SR Counselling eBook Website** is a multilingual Flask-based web application designed to simplify **eBook sales** and **counselling service offerings** through an interactive digital platform.  
The application supports **12 global and regional languages**, providing accessibility for users from diverse linguistic backgrounds.  

It integrates **Razorpay** for secure payments and **Google OAuth** for safe authentication. Upon successful purchase, password-protected eBooks are **automatically delivered via email**, ensuring a smooth and contactless experience for users.  

---

## Live Demo  
The application is deployed on **Render** for public access and testing.  

**Live Application:** [View SR Counselling on Render](https://sr-website-final.onrender.com/)  

---

## Key Features  

-  **Multilingual Interface:**  
  Supports 12 languages — *English, Hindi, Tamil, Bengali, Telugu, Malayalam, Gujarati, Kannada, Marathi, Chinese, French,* and *Spanish*.  

-  **Secure Authentication:**  
  Integrated **Google OAuth** for protected, one-click login using verified Google accounts.  

-  **Online Payment Integration:**  
  Used **Razorpay API** for encrypted, fast, and secure transaction processing.  

-  **Automated eBook Delivery:**  
  Password-protected eBooks are automatically emailed to users immediately after successful purchase.  

-  **Responsive Web Design:**  
  Built with **HTML5, CSS3, and JavaScript**, ensuring full responsiveness across devices.  

-  **User-Friendly Navigation:**  
  Simple and intuitive layout with easy access to services and language selection.  


---

##  Tech Stack  

| Layer | Technologies Used |
|-------|-------------------|
| **Frontend** | HTML5, CSS3, JavaScript |
| **Backend** | Python (Flask Framework) |
| **Database** | SQLite / MySQL |
| **Authentication** | Google OAuth 2.0 |
| **Payment Gateway** | Razorpay API |
| **Email Automation** | Python `smtplib` |
| **Deployment** | Render |
| **Version Control** | Git & GitHub |

---

##  System Architecture  

1. **Frontend (HTML/CSS/JS):**  
   Displays the multilingual interface and user navigation structure.  

2. **Backend (Flask):**  
   Handles user authentication, payment validation, and email automation logic.  

3. **Razorpay Integration:**  
   Manages secure online transactions and sends confirmation back to the Flask server.  

4. **Email Automation:**  
   Sends password-protected eBooks directly to users post successful payment.  

5. **Deployment (Render):**  
   Hosts the frontend for public access, linked with backend endpoints.  

---


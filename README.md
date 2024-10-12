## Getting started
* ##### Prerequisites
  * Python 3.10 or higher
  * Flask

* #### Installation
    To get a local copy up and running follow 
these simple example steps.
  1. Clone the repo

       `git clone https://github.com/singharsh10/GrowthX.git`
  2. Creating virtual environment
      
     `pip install virtualenv`
  
     `python -m venv <myenv>`
  3. Activate virtual environment
  
        * On Windows:
     
          `myenv\Scripts\activate`
        * On macOS/Linux:
     
          `source myenv/bin/activate`

  4. Install requirements
    
     `pip install -r requirements.txt`
  5. Start Flask server
    
     `flask --app app run`

-----------------------
### Usage

register endpoint for users and admins
![img.png](static/user_register.png)

login endpoint for users and admins
![img.png](static/user_login.png)

upload endpoint for users
![img.png](static/upload_assignment.png)

admins endpoint for users
![img.png](static/fetch_admins.png)

assignments endpoint for admins
![img.png](static/fetch_assignments.png)

accept assignment endpoint for admins
![img.png](static/accept_assignment.png)

reject assignment endpoint for admins
![img.png](static/reject_assignment.png)

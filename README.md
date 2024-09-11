![DorkScan Logo](https://raw.githubusercontent.com/balwantyadav1/DorkScan/main/DorkSacnLogo.png)

# [DorkScan](https://balwantyadav1.github.io/DorkScan/index.html)

## Table of Contents

1. [About](#About)
2. [Motivation](#Motivation)
3. [Features](#Features)
4. [Dork List](#Dork-list)
5. [Demo](#Demo)
6. [How It Works](#How-it-works)
7. [Contributing](#Contributing)
8. [License](#License)
9. [Contact](#Contact)


### About

**DorkScan** is an interactive web application designed to efficiently generate Google Dork queries, tailored for both bug bounty hunters and students. The application allows users to customize their searches and view results in a real-time terminal interface, making it an invaluable tool for web reconnaissance and research.
### Motivation
In the world of cybersecurity and academic research, finding relevant information quickly and efficiently is crucial. **DorkScan** was developed to streamline the process of generating Google Dorks, providing a user-friendly interface for both security professionals and students. The tool simplifies the search for vulnerabilities and educational resources, enabling users to focus on their objectives without getting bogged down by manual query creation.
### Features

- **Role-Based Selection**: Choose between "Bug Bounty & Red Team" or "Student" roles to receive tailored Google Dork queries.
- **Predefined Dorks**: Access dorks related to security vulnerabilities or academic resources.
- **Customizable Searches**: Combine predefined dorks with your own search terms for targeted queries.
- **Interactive Terminal**: View and execute generated dorks in real-time with a clickable, terminal-like interface.
- **Responsive Design**: Enjoy a clean and intuitive experience across all devices.
### Dork-list

**DorkScan** supports a variety of Google Dorks, including:

- **For Bug Bounty & Red Team:**

```
Bug bounty & Red Team/
├── PHP & API Vulnerabilities
│   ├── PHP Extension with Parameters
│   │   └── site:target_domain ext:php inurl:?
│   ├── API Endpoints
│   │   ├── site:target_domain inurl:api
│   │   ├── site:target_domain inurl:/rest
│   │   ├── site:target_domain inurl:/v1
│   │   ├── site:target_domain inurl:/v2
│   │   └── site:target_domain inurl:/v3
│
├── Sensitive Data Exposure
│   ├── Juicy Extensions
│   │   ├── site:target_domain ext:log | ext:txt | ext:conf | ext:cnf | ext:ini | ext:env | ext:sh | ext:bak | ext:backup | ext:swp | ext:old | ext:~ | ext:git | ext:svn | ext:htpasswd | ext:htaccess | ext:json
│   │   └── site:target_domain filetype:pdf OR filetype:docx OR filetype:xlsx "confidential" OR "internal use only"
│   ├── Server Errors
│   │   ├── site:target_domain inurl:"error" | intitle:"exception" | intitle:"failure" | intitle:"server at" | inurl:exception | "database error" | "SQL syntax" | "undefined index" | "unhandled exception" | "stack trace"
│   │   └── site:target_domain filetype:log "error" OR "failure" OR "warning"
│
├── Vulnerable Parameters
│   ├── XSS Prone Parameters
│   │   └── site:target_domain inurl:q= | inurl:s= | inurl:search= | inurl:query= | inurl:keyword= | inurl:lang= inurl:&
│   ├── Open Redirect Prone Parameters
│   │   └── site:target_domain inurl:url= | inurl:return= | inurl:next= | inurl:redirect= | inurl:redir= | inurl:ret= | inurl:r2= | inurl:page= inurl:& inurl:http
│   ├── SQL Injection Prone Parameters
│   │   └── site:target_domain inurl:id= | inurl:pid= | inurl:category= | inurl:cat= | inurl:action= | inurl:sid= | inurl:dir= inurl:&
│   ├── SSRF Prone Parameters
│   │   └── site:target_domain inurl:http | inurl:url= | inurl:path= | inurl:dest= | inurl:html= | inurl:data= | inurl:domain= | inurl:page= inurl:&
│   ├── LFI Prone Parameters
│   │   └── site:target_domain inurl:include | inurl:dir | inurl:detail= | inurl:file= | inurl:folder= | inurl:inc= | inurl:locate= | inurl:doc= | inurl:conf= inurl:&
│   └── RCE Prone Parameters
│       └── site:target_domain inurl:cmd | inurl:exec= | inurl:query= | inurl:code= | inurl:do= | inurl:run= | inurl:read= | inurl:ping= inurl:&
│
├── Access Points
│   ├── File Upload Endpoints
│   │   ├── site:target_domain "choose file"
│   │   ├── site:target_domain "upload file"
│   │   ├── site:target_domain "file upload"
│   │   ├── site:target_domain "fileupload"
│   │   ├── site:target_domain intitle:"file upload"
│   │   ├── site:target_domain inurl:/upload
│   │   ├── site:target_domain inurl:/fileupload
│   │   ├── site:target_domain inurl:"/uploads"
│   │   ├── site:target_domain inurl:"/file-upload"
│   │   ├── site:target_domain inurl:"/upload.php"
│   │   ├── site:target_domain inurl:"/upload.aspx"
│   │   ├── site:target_domain inurl:"/upload.html"
│   │   ├── site:target_domain inurl:"/file_upload"
│   │   └── site:target_domain "multipart/form-data"
│   │   └── site:target_domain inurl:"/form"
│   └── Login Pages
│       └── site:target_domain inurl:login OR inurl:signin OR intitle:"login page"
│
├── Development & Test Environments
│   ├── API Documentation
│   │   └── site:target_domain inurl:apidocs | inurl:api-docs | inurl:swagger | inurl:api-explorer
│   └── Test Environments
│       ├── site:target_domain inurl:test | inurl:env | inurl:dev | inurl:staging | inurl:sandbox | inurl:debug | inurl:temp | inurl:internal | inurl:demo
│       └── site:github.com "target_domain" inurl:dev OR inurl:test OR inurl:staging
│
├── Exposed Files & Directories
│   ├── Sensitive Documents
│   │   ├── site:target_domain ext:txt | ext:pdf | ext:xml | ext:xls | ext:xlsx | ext:ppt | ext:pptx | ext:doc | ext:docx intext:"confidential" | intext:"Not for Public Release" | intext:"internal use only"
│   ├── Specific Files
│   │   └── site:target_domain inurl:phpinfo.php | inurl:.htaccess | inurl:.git | inurl:.svn | inurl:.tar.gz
│   ├── Directory Listing Vulnerabilities
│   │   └── site:target_domain intitle:index.of
│   ├── Exposed Configuration Files
│   │   ├── site:target_domain ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini
│   │   └── site:github.com "target_domain" "config" OR "credentials" OR ".env"
│   ├── Exposed Database Files
│   │   └── site:target_domain ext:sql | ext:dbf | ext:mdb
│   ├── Exposed Log Files
│   │   └── site:target_domain ext:log
│   └── Backup and Old Files
│       └── site:target_domain ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup
│
├── Framework & CMS Vulnerabilities
│   ├── WordPress
│   │   └── site:target_domain inurl:wp- | inurl:wp-content | inurl:plugins | inurl:uploads | inurl:themes | inurl:download
│   ├── Apache Struts RCE
│   │   └── site:target_domain ext:action | ext:struts | ext:do
│   └── Adobe Experience Manager (AEM)
│       └── site:target_domain inurl:/content/usergenerated | inurl:/content/dam | inurl:/jcr:content | inurl:/libs/granite | inurl:/etc/clientlibs | inurl:/content/geometrixx | inurl:/bin/wcm | inurl:/crx/de
│
├── Cloud Storage & API Keys
│   ├── Cloud Storage
│   │   ├── site:s3.amazonaws.com "target_domain"
│   │   ├── site:blob.core.windows.net "target_domain"
│   │   ├── site:googleapis.com "target_domain"
│   │   ├── site:drive.google.com "target_domain"
│   │   ├── site:dev.azure.com "target_domain"
│   │   ├── site:onedrive.live.com "target_domain"
│   │   ├── site:digitaloceanspaces.com "target_domain"
│   │   ├── site:sharepoint.com "target_domain"
│   │   ├── site:s3-external-1.amazonaws.com "target_domain"
│   │   ├── site:s3.dualstack.us-east-1.amazonaws.com "target_domain"
│   │   ├── site:dropbox.com/s "target_domain"
│   │   ├── site:box.com/s "target_domain"
│   │   └── site:docs.google.com inurl:"/d/" "target_domain"
│   ├── Firebase
│

   │   └── site:firebase.google.com "target_domain"
│   └── API Keys
│       ├── site:target_domain "API key" OR "apiKey" OR "accessToken" OR "clientSecret" OR "token"
│       ├── site:github.com "target_domain" "apikey" OR "accesskey" OR "secret" OR "token"
│       └── site:github.com "target_domain" "firebase" OR "aws" OR "azure" OR "google" OR "cloud"
│
├── Leaked Credentials & Code
│   ├── Code Leaks
│   │   ├── site:pastebin.com "target_domain"
│   │   ├── site:jsfiddle.net "target_domain"
│   │   ├── site:codebeautify.org "target_domain"
│   │   └── site:codepen.io "target_domain"
│   └── Sensitive Data on GitHub
│       ├── site:github.com "target_domain" "api_key" OR "api-secret" OR "api_token"
│       ├── site:github.com "target_domain" "username" "password"
│       ├── site:github.com "target_domain" "BEGIN RSA PRIVATE KEY" OR "BEGIN OPENSSH PRIVATE KEY"
│       ├── site:github.com "target_domain" "oauth_token" OR "access_token"
│       ├── site:github.com "target_domain" filetype:pdf OR filetype:docx OR filetype:xlsx "confidential"
│       ├── site:github.com "target_domain" ext:log OR ext:txt "error"
│       ├── site:github.com "target_domain" inurl:dev OR inurl:test OR inurl:staging
│       ├── site:github.com "target_domain" "firebase" "apiKey"
│       ├── site:github.com "target_domain" "db.conf" OR "ftp_password"
│       ├── site:github.com "target_domain" "database.yml" OR "config/database.php"
│       ├── site:github.com "target_domain" ".ssh/config"
│       └── site:github.com "target_domain" "DEBUG" OR "stack trace"
│
└── Miscellaneous
    ├── Admin Interfaces
    │   ├── site:target_domain inurl:admin | inurl:admin_login | intitle:"admin login"
    │   ├── site:target_domain inurl:admin | inurl:dashboard | intitle:"admin dashboard"
    │   └── site:target_domain intitle:"admin" inurl:"admin"
    ├── Misconfigurations
    │   └── site:target_domain inurl:/.git/config OR inurl:/.svn/entries OR inurl:/.hg/hgrc
    ├── Application Logs
    │   └── site:target_domain "application.log" OR "app.log" OR "server.log" OR "access.log"
    ├── Directory Traversal
    │   └── site:target_domain inurl:../../../../../etc/passwd OR inurl:../../../../etc/shadow
    ├── Debug Information
    │   └── site:target_domain inurl:"debug" OR inurl:"debug.log" OR inurl:"dump"
    └── Known Vulnerability Databases
        └── site:nvd.nist.gov "target_domain" "CVE" OR "vulnerability"
```

- **For Students:**

```plaintext
student/
├── Download Books & PDFs
│   ├── Book PDF
│   │   └── "Book Title" filetype:pdf
│   └── Free eBooks
│       └── "Free eBook" "Book Title" filetype:pdf
│
├── Search Resumes & CVs
│   ├── Resumes PDF
│   │   ├── "Job Title" resume filetype:pdf
│   │   └── intitle:"resume" OR intitle:"CV" "Job Title"
│   ├── Educational Resumes
│   │   └── site:edu "resume" OR "CV" "Job Title"
│   ├── GitHub Resumes
│   │   └── site:github.com "resume" OR "CV" "Job Title"
│   └── Resume Databases
│       └── site:resume.com "resume" "Job Title"
│
├── Download Free Courses
│   ├── Google Drive
│   │   ├── site:drive.google.com "Course" OR "Tutorial" OR "Resource"
│   │   └── site:drive.google.com "Free Course on Course Name"
│   └── MEGA.nz
│       ├── site:mega.nz "Course" OR "Tutorial" OR "Resource"
│       └── site:mega.nz "Free Course on Course Name"
│
├── Search Topic Educational Resources
│   ├── University Materials
│   │   └── site:edu "Subject Name" "Lecture Notes" OR "Slides" OR "Course"
│   └── YouTube Learning
│       ├── site:youtube.com "Free Course" OR "Tutorial" OR "Resource"
│       └── site:youtube.com "Free Course on Topic Name"
│
├── Research & Papers
│   ├── Research Papers
│   │   └── "Topic Name" "Research Paper" filetype:pdf
│   ├── Academic Papers
│   │   └── "Topic Name" "Academic Paper" filetype:pdf
│   ├── Theses
│   │   └── "Topic Name" "Thesis" filetype:pdf
│   └── Lecture Notes
│       └── "Topic Name" "Lecture Notes" filetype:pdf
│
└── Dissertations
    ├── University Dissertations
    │   └── site:edu "Dissertation" "Topic Name"
    └── PDF Dissertations
        └── site:edu "Dissertation" "Topic Name" filetype:pdf
```
### Demo

Check out the live version of **[DorkScan](https://balwantyadav1.github.io/DorkScan/index.html)** here: [DorkScan Live](https://balwantyadav1.github.io/DorkScan/)
### How-it-works

1. **Role Selection**: Select your role from the dropdown menu.
    - **Bug Bounty & Red Team**: Access queries for security vulnerabilities like XSS and SQL injection.
    - **Student**: Get queries for academic resources such as research papers and free courses.

2. **Dork Selection**: Choose from a list of predefined dork types relevant to your role.

3. **Search Input**: Enter custom search terms to generate specific Google Dork queries.

4. **Real-Time Generation**: View generated dorks in the terminal interface. Clickable links open searches directly in Google.

### Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes.
4. Commit your changes (`git commit -m 'Add new feature'`).
5. Push to your branch (`git push origin feature-branch`).
6. Open a pull request.
### License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

### Contact
For questions or feedback, please reach out:

- **GitHub:** [![GitHub](https://img.shields.io/badge/GitHub-balwantyadav1-black?logo=github&logoColor=white)](https://github.com/balwantyadav1)
- **Website:** [![DorkScan](https://img.shields.io/badge/DorkScan-Website-blue?logo=google&logoColor=white)](https://balwantyadav1.github.io/DorkScan/index.html)
- **LinkedIn:** [![LinkedIn](https://img.shields.io/badge/LinkedIn-Balwant_Yadav-blue?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/balwantyadav7/)
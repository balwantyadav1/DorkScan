    // Handle Role Selection and Populate Dorks
    document.getElementById('role-select').addEventListener('change', function() {
        const role = this.value;
        const dorkSelect = document.getElementById('dork-select');

        // Clear existing options
        dorkSelect.innerHTML = '<option selected disabled>Select the Dork</option>';
        dorkSelect.disabled = false;

        // Define options based on role
        const dorkOptions = {
            'BugBounty': [
                'PHP Extension with Parameters',
                'API Endpoints',
                'Juicy Extensions',
                'Server Errors',
                'XSS Prone Parameters',
                'Open Redirect Prone Parameters',
                'SQL Injection Prone Parameters',
                'SSRF Prone Parameters',
                'LFI & RFI  Parameters',
                'RCE Prone Parameters',
                'File Upload Endpoints',
                'Login Pages',
                'API Documentation',
                'Test Environments',
                'Sensitive Documents',
                'Specific Files',
                'Directory Listing Vulnerabilities',
                'Exposed Configuration Files',
                'Exposed Database Files',
                'Exposed Log Files',
                'Backup and Old Files',
                'WordPress',
                'Apache Struts RCE',
                'Adobe Experience Manager (AEM)',
                'Cloud Storage',
                'Firebase',
                'API Keys',
                'Code Leaks',
                'Sensitive Data on GitHub',
                'Admin Interfaces',
                'Misconfigurations',
                'Application Logs',
                'Directory Traversal',
                'Debug Information',
                'Known Vulnerability Databases'
            ],
            'Student': [
                'Download Books & PDFs',
                'Search Resumes & CVs',
                'Download Free Courses',
                'Search Topic Educational Resources',
                'Research & Papers',
                'Dissertations'
            ]
        };

        // Populate options based on selected role
        if (dorkOptions[role]) {
            dorkOptions[role].forEach(option => {
                const opt = document.createElement('option');
                opt.value = option;
                opt.textContent = option;
                dorkSelect.appendChild(opt);
            });
        }
        updateTerminal(); // Update terminal box initially
    });

    // Handle Dork Search
    document.getElementById('search-btn').addEventListener('click', function() {
        generateAndDisplayDorks();

        // Open the first dork in a new tab if available
        const firstDork = document.getElementById('search-btn').dataset.firstDork;
        if (firstDork) {
            window.open(`https://www.google.com/search?q=${encodeURIComponent(firstDork)}`, '_blank');
        }
    });

    // Handle Input Change (Remove automatic search on input change)
    document.getElementById('search-input').addEventListener('input', function() {
        // Update terminal without automatic search
        updateTerminal();
    });

    // Handle Enter Key Press (Remove automatic search on Enter key press)
    document.getElementById('search-input').addEventListener('keydown', function(event) {
        if (event.key === 'Enter') {
            event.preventDefault(); // Prevent form submission
            generateAndDisplayDorks(); // Trigger search on Enter key press
        }
    });

    function updateTerminal() {
        const role = document.getElementById('role-select').value;
        const dork = document.getElementById('dork-select').value;
        const query = document.getElementById('search-input').value;
        const terminalOutput = document.getElementById('terminal-output');

        // Clear previous terminal content
        terminalOutput.innerHTML = '';

        // Generate and display dorks live
        if (role && dork && query) {
            let dorkStrings = generateDorks(role, dork, query);
            terminalOutput.innerHTML += `<div class="terminal-line">> Generated Google Dorks for: ${query}</div><br>`;
            dorkStrings.forEach((dorkString, index) => {
                terminalOutput.innerHTML += `<div class="terminal-line green-text">[${index + 1}] <a href="#" class="dork-link">${dorkString}</a></div><br>`;
            });

            // Attach click event to each dork link
            document.querySelectorAll('.dork-link').forEach(link => {
                link.addEventListener('click', function() {
                    const searchUrl = `https://www.google.com/search?q=${encodeURIComponent(this.textContent)}`;
                    window.open(searchUrl, '_blank');
                });
            });

            // Store the first dork string to search later
            if (dorkStrings.length > 0) {
                document.getElementById('search-btn').dataset.firstDork = dorkStrings[0];
            }
        } else {
            terminalOutput.innerHTML += `<div class="terminal-line">> Please select a role, dork, and enter a search term.</div>`;
        }
    }

    function generateAndDisplayDorks() {
        updateTerminal();
    }

    function generateDorks(role, dork, query) {
        let dorkStrings = [];
        if (role === 'Student') {
            switch (dork) {
                case 'Download Books & PDFs':
                    dorkStrings = [
                        `"${query}" filetype:pdf`,
                        `"Free eBook" "${query}" filetype:pdf`,
                        `"${query}" "eBook" filetype:pdf`
                    ];
                    break;
                case 'Search Resumes & CVs':
                    dorkStrings = [
                        `"${query}" resume filetype:pdf`,
                        `intitle:"resume" OR intitle:"CV" "${query}"`,
                        `site:edu "resume" OR "CV" "${query}"`,
                        `site:github.com "resume" OR "CV" "${query}"`,
                        `site:resume.com "resume" "${query}"`
                    ];
                    break;
                case 'Download Free Courses':
                    dorkStrings = [
                        `site:drive.google.com "${query}"`,
                        `site:mega.nz "${query}" OR "Tutorial" OR "Resource"`,
                        `site:mega.nz "${query}"`
                    ];
                    break;
                case 'Search Topic Educational Resources':
                    dorkStrings = [
                        `site:edu "${query}" "Lecture Notes" OR "Slides" OR "Course"`,
                        `site:youtube.com "${query}" OR "Tutorial" OR "Resource"`,
                        `site:youtube.com "${query}"`
                    ];
                    break;
                case 'Research & Papers':
                    dorkStrings = [
                        `"${query}" "Research Paper" filetype:pdf`,
                        `"${query}" "Academic Paper" filetype:pdf`,
                        `"${query}" "Thesis" filetype:pdf`,
                        `"${query}" "Lecture Notes" filetype:pdf`
                    ];
                    break;
                case 'Dissertations':
                    dorkStrings = [
                        `site:edu "Dissertation" "${query}"`,
                        `site:edu "Dissertation" "${query}" filetype:pdf`
                    ];
                    break;
                default:
                    dorkStrings = [`"${query}"`];
            }
        } else if (role === 'BugBounty') {
            switch (dork) {
                case 'PHP Extension with Parameters':
                    dorkStrings = [
                        `site:${query} ext:php inurl:?`,
                    ];
                    break;
                case 'API Endpoints':
                    dorkStrings = [
                        `site:${query} inurl:api`,
                        `site:${query} inurl:/rest`,
                        `site:${query} inurl:/v1`,
                        `site:${query} inurl:/v2`,
                        `site:${query} inurl:/v3`
                    ];
                    break;
                case 'Juicy Extensions':
                    dorkStrings = [
                        `site:${query} ext:log | ext:txt | ext:conf | ext:cnf | ext:ini | ext:env | ext:sh | ext:bak | ext:backup | ext:swp | ext:old | ext:~ | ext:git | ext:svn | ext:htpasswd | ext:htaccess | ext:json`,
                        `site:${query} filetype:pdf OR filetype:docx OR filetype:xlsx "confidential" OR "internal use only"`
                    ];
                    break;
                case 'Server Errors':
                    dorkStrings = [
                        `site:${query} inurl:"error" | intitle:"exception" | intitle:"failure" | intitle:"server at" | inurl:exception | "database error" | "SQL syntax" | "undefined index" | "unhandled exception" | "stack trace"`,
                        `site:${query} filetype:log "error" OR "failure" OR "warning"`
                    ];
                    break;
                case 'XSS Prone Parameters':
                    dorkStrings = [
                        `site:${query} inurl:q= | inurl:s= | inurl:search= | inurl:query= | inurl:keyword= | inurl:lang= inurl:&`
                    ];
                    break;
                case 'Open Redirect Prone Parameters':
                    dorkStrings = [
                        `site:${query} inurl:url= | inurl:return= | inurl:next= | inurl:redirect= | inurl:redir= | inurl:ret= | inurl:r2= | inurl:page= inurl:& inurl:http`
                    ];
                    break;
                case 'SQL Injection Prone Parameters':
                    dorkStrings = [
                        `site:${query} inurl:id= | inurl:pid= | inurl:productid= | inurl:category= | inurl:cat= | inurl:action= | inurl:sid= | inurl:dir= inurl:& site:query`,
                        `site:${query} intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"`
                    ];
                    break;
                case 'SSRF Prone Parameters':
                    dorkStrings = [
                        `site:${query} inurl:http | inurl:url= | inurl:path= | inurl:dest= | inurl:html= | inurl:data= | inurl:domain= | inurl:page= inurl:& | inurl:callback= | inurl:proxy= | inurl:target= | inurl:url= | inurl:request= | inurl:destination=`
                    ];
                    break;
                case 'LFI & RFI  Parameters':
                    dorkStrings = [
                        `site:${query} inurl:include | inurl:dir | inurl:detail= | inurl:file= | inurl:folder= | inurl:inc= | inurl:locate= | inurl:doc= | inurl:conf= inurl:& site:query `,
                        `site:${query} inurl:../../../../etc/passwd | inurl:../../../../etc/shadow | inurl:../../../../etc/hosts | inurl:../../../../etc/group | inurl:../../../../etc/issue | inurl:../../../../etc/os-release | inurl:../../../../proc/self/environ`,
                        `inurl:${query}/rte/my_documents/my_files`,
                        `inurl:${query}/my_documents/my_files/`,
                        `inurl:${query}/shoutbox/expanded.php?conf=`,
                        `inurl:${query}/main.php?x=`,
                        `inurl:${query}/myPHPCalendar/admin.php?cal_dir=`,
                        `inurl:${query}/index.php/main.php?x=`,
                        `inurl:${query}/index.php?include=`,
                        `inurl:${query}/index.php?x=`,
                        `inurl:${query}/index.php?open=`,
                        `inurl:${query}/index.php?visualizar=`,
                        `inurl:${query}/template.php?pagina=`,
                        `inurl:${query}/index.php?pagina=`,
                        `inurl:${query}/index.php?inc=`,
                        `inurl:"${query}/index.php?page=contact.php"`,
                        `inurl:"${query}/template.php?goto="`,
                        `inurl:"${query}/video.php?content="`,
                        `inurl:"${query}/pages.php?page="`,
                        `inurl:"${query}/index1.php?choix="`,
                        `inurl:${query}/tinybrowser/upload.php`,
                        `inurl:${query}/examples/uploadbutton.html`,
                        `inurl:${query}/modules/mod_mainmenu.php?mosConfig_absolute_path=`,
                        `inurl:${query}/include/new-visitor.inc.php?lvc_include_dir=`,
                        `inurl:${query}/_functions.php?prefix=`,
                        `inurl:${query}/cpcommerce/_functions.php?prefix=`,
                        `inurl:${query}/modules/coppermine/themes/default/theme.php?THEME_DIR=`,
                        `inurl:${query}/modules/agendax/addevent.inc.php?agendax_path=`,
                        `inurl:${query}/ashnews.php?pathtoashnews=`,
                        `inurl:${query}/eblog/blog.inc.php?xoopsConfig[xoops_url]=`,
                        `inurl:${query}/pm/lib.inc.php?pm_path=`,
                        `inurl:${query}/b2-tools/gm-2-b2.php?b2inc=`,
                        `inurl:${query}/modules/mod_mainmenu.php?mosConfig_absolute_path=`,
                        `inurl:${query}/modules/agendax/addevent.inc.php?agendax_path=`,
                        `inurl:${query}/includes/include_once.php?include_file=`,
                        `inurl:${query}/e107/e107_handlers/secure_img_render.php?p=`,
                        `intitle:"index of?" inurl:${query}/kindeditor`
                    ];
                    break;
                case 'RCE Prone Parameters':
                    dorkStrings = [
                        `site:${query} inurl:cmd= | inurl:exec= | inurl:run= | inurl:command= | inurl:cmdexec= | inurl:execute=`,
                        `site:${query} inurl:query= | inurl:code= | inurl:do= | inurl:run= | inurl:read= | inurl:cmd | inurl:exec= | inurl:query= | inurl:code= | inurl:do= | inurl:run= | inurl:read= | inurl:ping= inurl:& site:query | inurl:ping= inurl:&`
                    ];
                    break;
                case 'File Upload Endpoints':
                    dorkStrings = [
                        `site:${query} inurl:upload | inurl:upload.php | inurl:upload.cgi | inurl:upload_file | inurl:upload_image | inurl:upload_file.php | inurl:upload_file.cgi | inurl:upload_file.asp`
                    ];
                    break;
                case 'Login Pages':
                    dorkStrings = [
                        `site:${query} inurl:login | inurl:signin | inurl:auth | inurl:admin | inurl:admin_login | inurl:login.php | inurl:login.html | inurl:admin.php | inurl:admin.html`
                    ];
                    break;
                case 'API Documentation':
                    dorkStrings = [
                        `site:${query} inurl:api-docs | inurl:swagger | inurl:apidoc | inurl:docs/api | inurl:api/v1 | inurl:api/v2 | inurl:docs | inurl:openapi | inurl:postman | intitle:"Sharing API Info | intitle:"index of" github-api`
                    ];
                    break;
                case 'Test Environments':
                    dorkStrings = [
                        `site:${query} inurl:test | inurl:stage | inurl:staging | inurl:beta | inurl:preprod | inurl:development | inurl:dev`
                    ];
                    break;
                case 'Sensitive Documents':
                    dorkStrings = [
                        `site:${query} filetype:pdf | filetype:docx | filetype:xlsx | filetype:txt | filetype:conf | filetype:env | filetype:ini | filetype:log | ext:ppt | ext:pptx`
                    ];
                    break;
                case 'Specific Files':
                    dorkStrings = [
                        `site:${query} inurl:"/phpinfo.php" | inurl:".htaccess" | inurl:"/.git`,
                        `site:${query} filetype:pdf "confidential" | filetype:docx "confidential" | filetype:xlsx "confidential"`
                    ];
                    break;
                case 'Directory Listing Vulnerabilities':
                    dorkStrings = [
                        `site:${query} intitle:"Index of" | inurl:/cgi-bin/ | inurl:/admin/ | inurl:/backup/ | inurl:/private/ | inurl:/uploads/`
                    ];
                    break;
                case 'Exposed Configuration Files':
                    dorkStrings = [
                        `site:${query} filetype:conf | filetype:ini | filetype:env | filetype:json | filetype:xml | filetype:yaml`
                    ];
                    break;
                case 'Exposed Database Files':
                    dorkStrings = [
                        `site:${query} filetype:sql | filetype:db | filetype:bak | filetype:dump`
                    ];
                    break;
                case 'Exposed Log Files':
                    dorkStrings = [
                        `site:${query} filetype:log | filetype:txt | inurl:logs/ | inurl:log/`
                    ];
                    break;
                case 'Backup and Old Files':
                    dorkStrings = [
                        `site:${query} filetype:bak | filetype:backup | filetype:old | filetype:swp`
                    ];
                    break;
                case 'WordPress':
                    dorkStrings = [
                        `site:${query} inurl:wp-login.php | inurl:wp-admin | inurl:wp-content | inurl:wp-includes | inurl:wp-config.php`
                    ];
                    break;
                case 'Apache Struts RCE':
                    dorkStrings = [
                        `site:${query} ext:action | ext:struts | ext:do | "Apache Struts" "RCE" | "Remote Code Execution" | "CVE-2017-5638" | "CVE-2017-9805" | "CVE-2016-3088"`
                    ];
                    break;
                case 'Adobe Experience Manager (AEM)':
                    dorkStrings = [
                        `site:${query} inurl:/content/usergenerated | inurl:/content/dam | inurl:/jcr:content | inurl:/libs/granite | inurl:/etc/clientlibs | inurl:/content/geometrixx | inurl:/bin/wcm | inurl:/crx/de | "Adobe Experience Manager" | "AEM" | "CVE-2018-15961" | "CVE-2019-7600"`
                    ];
                    break;
                case 'Cloud Storage':
                    dorkStrings = [
                        `site:s3.amazonaws.com "${query}"`,
                        `site:s3-external-1.amazonaws.com "${query}"`,
                        `site:s3.dualstack.us-east-1.amazonaws.com "${query}"`,
                        `site:blob.core.windows.net "${query}"`,
                        `site:googleapis.com "${query}"`,
                        `site:drive.google.com "${query}"`,
                        `site:dev.azure.com "${query}"`,
                        `site:onedrive.live.com "${query}"`,
                        `site:digitaloceanspaces.com "${query}"`,
                        `site:sharepoint.com "${query}"`,
                        `site:dropbox.com/s "${query}"`,
                        `site:box.com/s "${query}"`,
                        `site:docs.google.com inurl:"/d/" "${query}"`,
                        `site:${query} inurl:bucket | inurl:storage | inurl:drive | inurl:cloud | inurl:dropbox`
                    ];
                    break;
                case 'Firebase':
                    dorkStrings = [
                        `site:${query} "Firebase" | "firebaseio.com" | "firebaseapp.com" | "*/security.txt"`
                    ];
                    break;
                case 'API Keys':
                    dorkStrings = [
                        `site:${query} "API Key" | "api_key" | "api_key="`
                    ];
                    break;
                case 'Code Leaks':
                    dorkStrings = [
                        `site:${query} "pastebin.com" | "jsfiddle.net" | "codebeautify.org" | "codepen.io"`,
                        `site:${query} inurl:git | inurl:svn | inurl:repo | inurl:code | filetype:log | filetype:txt`
                    ];
                    break;
                case 'Sensitive Data on GitHub':
                    dorkStrings = [
                        `site:github.com "${query}" | "API Key" | "secret" | "password"`,
                        `https://github.com/search?q=%22*."${query}".com%22&type=host --Use this link in URL... ` 

                    ];
                    break;
                case 'Admin Interfaces':
                    dorkStrings = [
                        `site:${query} inurl:admin | inurl:admin.php | inurl:admin/login.php | inurl:admin/login | inurl:admin/dashboard | inurl:admin/console`
                    ];
                    break;
                case 'Misconfigurations':
                    dorkStrings = [
                        `site:${query} "misconfiguration" | "default configuration" | "setup" | "admin" | "root"`
                    ];
                    break;
                case 'Application Logs':
                    dorkStrings = [
                        `site:${query} filetype:log | inurl:logs/ | inurl:log/ | "error" | "exception" | "warning"`
                    ];
                    break;
                case 'Directory Traversal':
                    dorkStrings = [
                        `site:${query} inurl:../../../../ | inurl:../../../ | inurl:../../ | inurl:../ | inurl:.. | inurl:%2e%2e%2f | inurl:%2e%2e%2c | inurl:%2e%2e%5c | inurl:%2e%2e%2f%2e%2e%2f`
                    ];
                    break;
                case 'Debug Information':
                    dorkStrings = [
                        `site:${query} "debug" | "debugging" | "debug mode" | "error_reporting" | "var_dump"`
                    ];
                    break;
                case 'Known Vulnerability Databases':
                    dorkStrings = [
                        `site:${query} "vulnerability" | "CVE" | "exploit" | "proof of concept"`
                    ];
                    break;
                default:
                    dorkStrings = [`"${query}"`];
            }
        }
        return dorkStrings;
    }

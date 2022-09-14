# python_guidelines.github.io

# Input validation
## Command Injection
### Abstract
Executing commands from an untrusted source or in an untrusted environment can cause an application to execute malicious commands on behalf of an attacker.
Explanation
Command injection vulnerabilities take two forms:

- An attacker can change the command that the program executes: the attacker explicitly controls what the command is.

- An attacker can change the environment in which the command executes: the attacker implicitly controls what the command means.

In this case, we are primarily concerned with the first scenario, the possibility that an attacker may be able to control the command that is executed. Command injection vulnerabilities of this type occur when:

1. Data enters the application from an untrusted source.

2. The data is used as or as part of a string representing a command that is executed by the application.

3. By executing the command, the application gives an attacker a privilege or capability that the attacker would not otherwise have.

Example 1: The following code from a system utility uses the system property APPHOME to determine the directory in which it is installed and then executes an initialization script based on a relative path from the specified directory.



	...
	home = os.getenv('APPHOME')
	cmd = home.join(INITCMD)
	os.system(cmd);
	...


The code in Example 1 allows an attacker to execute arbitrary commands with the elevated privilege of the application by modifying the system property APPHOME to point to a different path containing a malicious version of INITCMD. Because the program does not validate the value read from the environment, if an attacker can control the value of the system property APPHOME, then they can fool the application into running malicious code and take control of the system.

Example 2: The following code is from an administrative web application designed to allow users to kick off a backup of an Oracle database using a batch-file wrapper around the rman utility and then run a cleanup.bat script to delete some temporary files. The script rmanDB.bat accepts a single command line parameter, which specifies the type of backup to perform. Because access to the database is restricted, the application runs the backup as a privileged user.



...
	btype = req.field('backuptype')
	cmd = "cmd.exe /K \"c:\\util\\rmanDB.bat " + btype + "&&c:\\util\\cleanup.bat\""
	os.system(cmd);
...


The problem here is that the program does not do any validation on the backuptype parameter read from the user. Typically the Runtime.exec() function will not execute multiple commands, but in this case the program first runs the cmd.exe shell in order to run multiple commands with a single call to Runtime.exec(). After the shell is invoked, it will allow for the execution of multiple commands separated by two ampersands. If an attacker passes a string of the form "&& del c:\\dbms\\*.*", then the application will execute this command along with the others specified by the program. Because of the nature of the application, it runs with the privileges necessary to interact with the database, which means whatever command the attacker injects will run with those privileges as well.

Example 3: The following code is from a web application that provides an interface through which users can update their password on the system. Part of the process for updating passwords in certain network environments is to run a make command in the /var/yp directory.



	...
	result = os.system("make");
	...


The problem here is that the program does not specify an absolute path for make and fails to clean its environment prior to executing the call to os.system(). If an attacker can modify the $PATH variable to point to a malicious binary called make and cause the program to be executed in their environment, then the malicious binary will be loaded instead of the one intended. Because of the nature of the application, it runs with the privileges necessary to perform system operations, which means the attacker's make will now be run with these privileges, possibly giving the attacker complete control of the system.





## Connection String Parameter Pollution
### Abstract
Concatenating unvalidated input into a database connection may allow an attacker to override the value of a request parameter. An attacker may be able to override existing parameter values, inject a new parameter, or exploit variables that are out of direct reach.
Explanation
Connection String Parameter Pollution (CSPP) attacks consist of injecting connection string parameters into other existing parameters. This vulnerability is similar to vulnerabilities, and perhaps more well known, within HTTP environments where parameter pollution can also occur. However, it also can apply in other places such as database connection strings. If an application does not properly sanitize the user input, a malicious user may compromise the logic of the application to perform attacks from stealing credentials, to retrieving the entire database. By submitting additional parameters to an application, and if these parameters have the same name as an existing parameter, the database connection may react in one of the following ways:

It may only take the data from the first parameter
It may take the data from the last parameter
It may take the data from all parameters and concatenate them together

This may be dependent on the driver used, the database type, or even how APIs are used.

Example 1: The following code uses input from an HTTP request to connect to a database:



username = req.field('username')
password = req.field('password')
...
client = MongoClient('mongodb://%s:%s@aMongoDBInstance.com/?ssl=true' % (username, password))
...


In this example, the programmer has not considered that an attacker could provide a password parameter such as:
"myPassword@aMongoDBInstance.com/?ssl=false&" then the connection string becomes (assuming a username "scott"):

"mongodb://scott:myPassword@aMongoDBInstance.com/?ssl=false&@aMongoDBInstance.com/?ssl=true"

This will cause "@aMongoDBInstance.com/?ssl=true" to be treated as an additional invalid argument, effectively ignoring "ssl=true" and connecting to the database with no encryption.








## Cross-Site Scripting: Content Sniffing
### Abstract
Sending unvalidated data to a web browser may result in certain browsers executing malicious code.
Explanation
Cross-site scripting (XSS) vulnerabilities occur when:

1. Data enters a web application through an untrusted source. In the case of reflected XSS, the untrusted source is typically a web request, while in the case of persisted (also known as stored) XSS it is typically a database or other back-end data store.


2. The data is included in dynamic content that is sent to a web user without validation.

The malicious content sent to the web browser often takes the form of a JavaScript segment, but may also include HTML, Flash or any other type of code that the browser executes. The variety of attacks based on XSS is almost limitless, but they commonly include transmitting private data such as cookies or other session information to the attacker, redirecting the victim to web content controlled by the attacker, or performing other malicious operations on the user's machine under the guise of the vulnerable site.

For the browser to render the response as HTML, or other document that may execute scripts, it has to specify a text/html MIME type. Therefore, XSS is only possible if the response uses this MIME type or any other that also forces the browser to render the response as HTML or other document that may execute scripts such as SVG images (image/svg+xml), XML documents (application/xml), etc.

Most modern browsers will not render HTML, nor execute scripts when provided a response with MIME types such as application/json. However, some browsers such as Internet Explorer perform what is known as Content Sniffing. Content Sniffing involves ignoring the provided MIME type and attempting to infer the correct MIME type by the contents of the response.
It is worth noting however, a MIME type of text/html is only one such MIME type that may lead to XSS vulnerabilities. Other documents that may execute scripts such as SVG images (image/svg+xml), XML documents (application/xml), as well as others may lead to XSS vulnerabilities regardless of whether the browser performs Content Sniffing.

Therefore, a response such as <html><body><script>alert(1)</script></body></html>, could be rendered as HTML even if its content-type header is set to application/json.

Example 1: The following AWS Lambda function reflects user data in an application/json response.



	def mylambda_handler(event, context):
	    name = event['name']
	    response = {
		"statusCode": 200,
		"body": "{'name': name}",
		"headers": {
		    'Content-Type': 'application/json',
		}
	    }
	    return response


If an attacker sends a request with the name parameter set to <html><body><script>alert(1)</script></body></html>, the server will produce the following response:



	HTTP/1.1 200 OK
	Content-Length: 88
	Content-Type: application/json
	Connection: Closed

	{'name': '<html><body><script>alert(1)</script></body></html>'}


Even though, the response clearly states that it should be treated as a JSON document, an old browser may still try to render it as an HTML document, making it vulnerable to a Cross-Site Scripting attack.












## Cross-Site Scripting: Inter-Component Communication (Cloud)
### Abstract
Sending unvalidated data to a web browser can result in the browser executing malicious code.
Explanation
Cross-site scripting (XSS) vulnerabilities occur when:

1. Data enters a cloud-hosted web application through an untrusted source. In the case of Inter-Component Communication Cloud XSS, the untrusted source is data received from other components of the cloud application through communication channels provided by the cloud provider.


2. The data is included in dynamic content that is sent to a web user without validation.

The malicious content sent to the web browser often takes the form of a JavaScript segment, but can also include HTML, Flash or any other type of code that the browser executes. The variety of attacks based on XSS is almost limitless, but they commonly include transmitting private data such as cookies or other session information to the attacker, redirecting the victim to web content controlled by the attacker, or performing other malicious operations on the user's machine under the guise of the vulnerable site.

Example 1: The following Python code segment reads an employee ID, eid, from an HTTP request and displays it to the user.



	req = self.request()  # fetch the request object
        eid = req.field('eid',None) # tainted request message
	...
	self.writeln("Employee ID:" + eid)


The code in this example operates correctly if eid contains only standard alphanumeric text. If eid has a value that includes metacharacters or source code, then the code is executed by the web browser as it displays the HTTP response.

Initially this might not appear to be much of a vulnerability. After all, why would someone enter a URL that causes malicious code to run on their own computer? The real danger is that an attacker will create the malicious URL, then use email or social engineering tricks to lure victims into visiting a link to the URL. When victims click the link, they unwittingly reflect the malicious content through the vulnerable web application back to their own computers. This mechanism of exploiting vulnerable web applications is known as Reflected XSS.

Example 2: The following Python code segment queries a database for an employee with a given ID and prints the corresponding employee's name.




	 cursor.execute("select * from emp where id="+eid)
	 row = cursor.fetchone()
	 self.writeln('Employee name: ' + row["emp"]')



As in Example 1, this code functions correctly when the values of name are well-behaved, but it does nothing to prevent exploits if they are not. Again, this code can appear less dangerous because the value of name is read from a database, whose contents are apparently managed by the application. However, if the value of name originates from user-supplied data, then the database can be a conduit for malicious content. Without proper input validation on all data stored in the database, an attacker may execute malicious commands in the user's web browser. This type of exploit, known as Persistent (or Stored) XSS, is particularly insidious because the indirection caused by the data store makes it difficult to identify the threat and increases the possibility that the attack might affect multiple users. XSS got its start in this form with web sites that offered a "guestbook" to visitors. Attackers would include JavaScript in their guestbook entries, and all subsequent visitors to the guestbook page would execute the malicious code.

As the examples demonstrate, XSS vulnerabilities are caused by code that includes unvalidated data in an HTTP response. There are three vectors by which an XSS attack can reach a victim:

- As in Example 1, data is read directly from the HTTP request and reflected back in the HTTP response. Reflected XSS exploits occur when an attacker causes a user to supply dangerous content to a vulnerable web application, which is then reflected back to the user and executed by the web browser. The most common mechanism for delivering malicious content is to include it as a parameter in a URL that is posted publicly or emailed directly to victims. URLs constructed in this manner constitute the core of many phishing schemes, whereby an attacker convinces victims to visit a URL that refers to a vulnerable site. After the site reflects the attacker's content back to the user, the content is executed and proceeds to transfer private information, such as cookies that might include session information, from the user's machine to the attacker or perform other nefarious activities.

- As in Example 2, the application stores dangerous data in a database or other trusted data store. The dangerous data is subsequently read back into the application and included in dynamic content. Persistent XSS exploits occur when an attacker injects dangerous content into a data store that is later read and included in dynamic content. From an attacker's perspective, the optimal place to inject malicious content is in an area that is displayed to either many users or particularly interesting users. Interesting users typically have elevated privileges in the application or interact with sensitive data that is valuable to the attacker. If one of these users executes malicious content, the attacker may be able to perform privileged operations on behalf of the user or gain access to sensitive data belonging to the user.

- A source outside the application stores dangerous data in a database or other data store, and the dangerous data is subsequently read back into the application as trusted data and included in dynamic content.





## Cross-Site Scripting: Persistent
### Abstract
Sending unvalidated data to a web browser can result in the browser executing malicious code.
Explanation
Cross-site scripting (XSS) vulnerabilities occur when:

1. Data enters a web application through an untrusted source. In the case of persistent (also known as stored) XSS, the untrusted source is typically a database or other back-end data store, while in the case of reflected XSS it is typically a web request.


2. The data is included in dynamic content that is sent to a web user without validation.

The malicious content sent to the web browser often takes the form of a JavaScript segment, but can also include HTML, Flash or any other type of code that the browser executes. The variety of attacks based on XSS is almost limitless, but they commonly include transmitting private data such as cookies or other session information to the attacker, redirecting the victim to web content controlled by the attacker, or performing other malicious operations on the user's machine under the guise of the vulnerable site.

Example 1: The following Python code segment reads an employee ID, eid, from an HTTP request and displays it to the user.



	req = self.request()  # fetch the request object
        eid = req.field('eid',None) # tainted request message
	...
	self.writeln("Employee ID:" + eid)


The code in this example operates correctly if eid contains only standard alphanumeric text. If eid has a value that includes metacharacters or source code, then the code is executed by the web browser as it displays the HTTP response.

Initially this might not appear to be much of a vulnerability. After all, why would someone enter a URL that causes malicious code to run on their own computer? The real danger is that an attacker will create the malicious URL, then use email or social engineering tricks to lure victims into visiting a link to the URL. When victims click the link, they unwittingly reflect the malicious content through the vulnerable web application back to their own computers. This mechanism of exploiting vulnerable web applications is known as Reflected XSS.

Example 2: The following Python code segment queries a database for an employee with a given ID and prints the corresponding employee's name.



	 ...
	 cursor.execute("select * from emp where id="+eid)
	 row = cursor.fetchone()
	 self.writeln('Employee name: ' + row["emp"]')
	 ...


As in Example 1, this code functions correctly when the values of name are well-behaved, but it does nothing to prevent exploits if they are not. Again, this code can appear less dangerous because the value of name is read from a database, whose contents are apparently managed by the application. However, if the value of name originates from user-supplied data, then the database can be a conduit for malicious content. Without proper input validation on all data stored in the database, an attacker may execute malicious commands in the user's web browser. This type of exploit, known as Persistent (or Stored) XSS, is particularly insidious because the indirection caused by the data store makes it difficult to identify the threat and increases the possibility that the attack might affect multiple users. XSS got its start in this form with web sites that offered a "guestbook" to visitors. Attackers would include JavaScript in their guestbook entries, and all subsequent visitors to the guestbook page would execute the malicious code.

As the examples demonstrate, XSS vulnerabilities are caused by code that includes unvalidated data in an HTTP response. There are three vectors by which an XSS attack can reach a victim:

- As in Example 1, data is read directly from the HTTP request and reflected back in the HTTP response. Reflected XSS exploits occur when an attacker causes a user to supply dangerous content to a vulnerable web application, which is then reflected back to the user and executed by the web browser. The most common mechanism for delivering malicious content is to include it as a parameter in a URL that is posted publicly or emailed directly to victims. URLs constructed in this manner constitute the core of many phishing schemes, whereby an attacker convinces victims to visit a URL that refers to a vulnerable site. After the site reflects the attacker's content back to the user, the content is executed and proceeds to transfer private information, such as cookies that might include session information, from the user's machine to the attacker or perform other nefarious activities.

- As in Example 2, the application stores dangerous data in a database or other trusted data store. The dangerous data is subsequently read back into the application and included in dynamic content. Persistent XSS exploits occur when an attacker injects dangerous content into a data store that is later read and included in dynamic content. From an attacker's perspective, the optimal place to inject malicious content is in an area that is displayed to either many users or particularly interesting users. Interesting users typically have elevated privileges in the application or interact with sensitive data that is valuable to the attacker. If one of these users executes malicious content, the attacker may be able to perform privileged operations on behalf of the user or gain access to sensitive data belonging to the user.

- A source outside the application stores dangerous data in a database or other data store, and the dangerous data is subsequently read back into the application as trusted data and included in dynamic content.


## Cross-Site Scripting: Poor Validation
### Abstract
Relying on HTML, XML, and other types of encoding to validate user input can result in the browser executing malicious code.
Explanation
The use of certain encoding functions will prevent some, but not all cross-site scripting attacks. Depending on the context in which the data appear, characters beyond the basic <, >, &, and " that are HTML-encoded and those beyond <, >, &, ", and ' that are XML-encoded may take on meta-meaning. Relying on such encoding functions is equivalent to using a weak deny list to prevent cross-site scripting and might allow an attacker to inject malicious code that will be executed in the browser. Because accurately identifying the context in which the data appear statically is not always possible, the Fortify Secure Coding Rulepacks report cross-site scripting findings even when encoding is applied and presents them as Cross-Site Scripting: Poor Validation issues.

Cross-site scripting (XSS) vulnerabilities occur when:

1. Data enters a web application through an untrusted source. In the case of reflected XSS, the untrusted source is typically a web request, while in the case of persisted (also known as stored) XSS it is typically a database or other back-end data store.


2. The data is included in dynamic content that is sent to a web user without validation.

The malicious content sent to the web browser often takes the form of a JavaScript segment, but can also include HTML, Flash or any other type of code that the browser executes. The variety of attacks based on XSS is almost limitless, but they commonly include transmitting private data such as cookies or other session information to the attacker, redirecting the victim to web content controlled by the attacker, or performing other malicious operations on the user's machine under the guise of the vulnerable site.

Example 1: The following Python code segment reads an employee ID, eid, from an HTTP request, HTML-encodes it, and displays it to the user.



        req = self.request()  # fetch the request object
        eid = req.field('eid',None) # tainted request message
        ...
        self.writeln("Employee ID:" + escape(eid))


The code in this example operates correctly if eid contains only standard alphanumeric text. If eid has a value that includes metacharacters or source code, then the code is executed by the web browser as it displays the HTTP response.

Initially this might not appear to be much of a vulnerability. After all, why would someone enter a URL that causes malicious code to run on their own computer? The real danger is that an attacker will create the malicious URL, then use email or social engineering tricks to lure victims into visiting a link to the URL. When victims click the link, they unwittingly reflect the malicious content through the vulnerable web application back to their own computers. This mechanism of exploiting vulnerable web applications is known as Reflected XSS.

Example 2: The following Python code segment queries a database for an employee with a given ID and prints the corresponding HTML-encoded employee's name.




	 cursor.execute("select * from emp where id="+eid)
	 row = cursor.fetchone()
	 self.writeln('Employee name: ' + escape(row["emp"]))


As in Example 1, this code functions correctly when the values of name are well-behaved, but it does nothing to prevent exploits if they are not. Again, this code can appear less dangerous because the value of name is read from a database, whose contents are apparently managed by the application. However, if the value of name originates from user-supplied data, then the database can be a conduit for malicious content. Without proper input validation on all data stored in the database, an attacker may execute malicious commands in the user's web browser. This type of exploit, known as Persistent (or Stored) XSS, is particularly insidious because the indirection caused by the data store makes it difficult to identify the threat and increases the possibility that the attack might affect multiple users. XSS got its start in this form with web sites that offered a "guestbook" to visitors. Attackers would include JavaScript in their guestbook entries, and all subsequent visitors to the guestbook page would execute the malicious code.

As the examples demonstrate, XSS vulnerabilities are caused by code that includes unvalidated data in an HTTP response. There are three vectors by which an XSS attack can reach a victim:

- As in Example 1, data is read directly from the HTTP request and reflected back in the HTTP response. Reflected XSS exploits occur when an attacker causes a user to supply dangerous content to a vulnerable web application, which is then reflected back to the user and executed by the web browser. The most common mechanism for delivering malicious content is to include it as a parameter in a URL that is posted publicly or emailed directly to victims. URLs constructed in this manner constitute the core of many phishing schemes, whereby an attacker convinces victims to visit a URL that refers to a vulnerable site. After the site reflects the attacker's content back to the user, the content is executed and proceeds to transfer private information, such as cookies that might include session information, from the user's machine to the attacker or perform other nefarious activities.

- As in Example 2, the application stores dangerous data in a database or other trusted data store. The dangerous data is subsequently read back into the application and included in dynamic content. Persistent XSS exploits occur when an attacker injects dangerous content into a data store that is later read and included in dynamic content. From an attacker's perspective, the optimal place to inject malicious content is in an area that is displayed to either many users or particularly interesting users. Interesting users typically have elevated privileges in the application or interact with sensitive data that is valuable to the attacker. If one of these users executes malicious content, the attacker may be able to perform privileged operations on behalf of the user or gain access to sensitive data belonging to the user.

- A source outside the application stores dangerous data in a database or other data store, and the dangerous data is subsequently read back into the application as trusted data and included in dynamic content.





## Cross-Site Scripting: Reflected
### Abstract
Sending unvalidated data to a web browser can result in the browser executing malicious code.
Explanation
Cross-site scripting (XSS) vulnerabilities occur when:

1. Data enters a web application through an untrusted source. In the case of reflected XSS, the untrusted source is typically a web request, while in the case of persisted (also known as stored) XSS it is typically a database or other back-end data store.


2. The data is included in dynamic content that is sent to a web user without validation.

The malicious content sent to the web browser often takes the form of a JavaScript segment, but can also include HTML, Flash or any other type of code that the browser executes. The variety of attacks based on XSS is almost limitless, but they commonly include transmitting private data such as cookies or other session information to the attacker, redirecting the victim to web content controlled by the attacker, or performing other malicious operations on the user's machine under the guise of the vulnerable site.

Example 1: The following Python code segment reads an employee ID, eid, from an HTTP request and displays it to the user.



	req = self.request()  # fetch the request object
        eid = req.field('eid',None) # tainted request message
	...
	self.writeln("Employee ID:" + eid)


The code in this example operates correctly if eid contains only standard alphanumeric text. If eid has a value that includes metacharacters or source code, then the code is executed by the web browser as it displays the HTTP response.

Initially this might not appear to be much of a vulnerability. After all, why would someone enter a URL that causes malicious code to run on their own computer? The real danger is that an attacker will create the malicious URL, then use email or social engineering tricks to lure victims into visiting a link to the URL. When victims click the link, they unwittingly reflect the malicious content through the vulnerable web application back to their own computers. This mechanism of exploiting vulnerable web applications is known as Reflected XSS.

Example 2: The following Python code segment queries a database for an employee with a given ID and prints the corresponding employee's name.



	 ...
	 cursor.execute("select * from emp where id="+eid)
	 row = cursor.fetchone()
	 self.writeln('Employee name: ' + row["emp"]')
	 ...


As in Example 1, this code functions correctly when the values of name are well-behaved, but it does nothing to prevent exploits if they are not. Again, this code can appear less dangerous because the value of name is read from a database, whose contents are apparently managed by the application. However, if the value of name originates from user-supplied data, then the database can be a conduit for malicious content. Without proper input validation on all data stored in the database, an attacker may execute malicious commands in the user's web browser. This type of exploit, known as Persistent (or Stored) XSS, is particularly insidious because the indirection caused by the data store makes it difficult to identify the threat and increases the possibility that the attack might affect multiple users. XSS got its start in this form with web sites that offered a "guestbook" to visitors. Attackers would include JavaScript in their guestbook entries, and all subsequent visitors to the guestbook page would execute the malicious code.

As the examples demonstrate, XSS vulnerabilities are caused by code that includes unvalidated data in an HTTP response. There are three vectors by which an XSS attack can reach a victim:

- As in Example 1, data is read directly from the HTTP request and reflected back in the HTTP response. Reflected XSS exploits occur when an attacker causes a user to supply dangerous content to a vulnerable web application, which is then reflected back to the user and executed by the web browser. The most common mechanism for delivering malicious content is to include it as a parameter in a URL that is posted publicly or emailed directly to victims. URLs constructed in this manner constitute the core of many phishing schemes, whereby an attacker convinces victims to visit a URL that refers to a vulnerable site. After the site reflects the attacker's content back to the user, the content is executed and proceeds to transfer private information, such as cookies that might include session information, from the user's machine to the attacker or perform other nefarious activities.

- As in Example 2, the application stores dangerous data in a database or other trusted data store. The dangerous data is subsequently read back into the application and included in dynamic content. Persistent XSS exploits occur when an attacker injects dangerous content into a data store that is later read and included in dynamic content. From an attacker's perspective, the optimal place to inject malicious content is in an area that is displayed to either many users or particularly interesting users. Interesting users typically have elevated privileges in the application or interact with sensitive data that is valuable to the attacker. If one of these users executes malicious content, the attacker may be able to perform privileged operations on behalf of the user or gain access to sensitive data belonging to the user.

- A source outside the application stores dangerous data in a database or other data store, and the dangerous data is subsequently read back into the application as trusted data and included in dynamic content.
 






## Denial of Service: Regular Expression
### Abstract
Untrusted data is passed to the application and used as a regular expression. This can cause the thread to overconsume CPU resources.
Explanation
There is a vulnerability in implementations of regular expression evaluators and related methods that can cause the thread to hang when evaluating regular expressions that contain a grouping expression that is itself repeated. Additionally, any regular expression that contains alternate subexpressions that overlap one another can also be exploited. This defect can be used to execute a Denial of Service (DoS) attack.
Example:

  (e+)+
  ([a-zA-Z]+)*
  (e|ee)+

There are no known regular expression implementations which are immune to this vulnerability. All platforms and languages are vulnerable to this attack.








## Dynamic Code Evaluation: Code Injection
### Abstract
Interpreting user-controlled instructions at run-time can allow attackers to execute malicious code.
Explanation
Many modern programming languages allow dynamic interpretation of source instructions. This capability allows programmers to perform dynamic instructions based on input received from the user. Code injection vulnerabilities occur when the programmer incorrectly assumes that instructions supplied directly from the user will perform only innocent operations, such as performing simple calculations on active user objects or otherwise modifying the user's state. However, without proper validation, a user might specify operations the programmer does not intend.

Example: In this classic code injection example, the application implements a basic calculator that allows the user to specify commands for execution.



...
userOps = request.GET['operation']
result = eval(userOps)
...


The program behaves correctly when the operation parameter is a benign value, such as "8 + 7 * 2", in which case the result variable is assigned a value of 22. However, if an attacker specifies operations that are both valid and malicious, those operations would be executed with the full privilege of the parent process. Such attacks are even more dangerous when the underlying language provides access to system resources or allows execution of system commands. For example, if an attacker were to specify " os.system('shutdown -h now')" as the value of operation, a shutdown command would be executed on the host system.










## Dynamic Code Evaluation: Unsafe Pickle Deserialization
### Abstract
Deserializing user-controlled data at run-time can allow attackers to execute arbitrary code.
Explanation
Python Official documentation states that:


The pickle module is not intended to be secure against erroneous or maliciously constructed data. Never unpickle data received from an untrusted or unauthenticated source.


Pickle is a powerful serializing library that provides developers with an easy way to transmit objects, serializing them to a custom Pickle representation. Pickle allows arbitrary objects to declare how they should be deserialized by defining a __reduce__ method. This method should return a callable and the arguments for it. Pickle will call the callable with the provided arguments to construct the new object allowing the attacker to execute arbitrary commands.








## Dynamic Code Evaluation: Unsafe YAML Deserialization
### Abstract
Deserializing user-controlled YAML streams might enable attackers to execute arbitrary code on the server, abuse application logic, and/or lead to denial of service.
Explanation
YAML serialization libraries, which convert object graphs into YAML formatted data may include the necessary metadata to reconstruct the objects back from the YAML stream. If attackers can specify the classes of the objects to be reconstructed and are able to force the application to run arbitrary setters with user-controlled data, they may be able to execute arbitrary code during the deserialization of the YAML stream.

Example 1: The following example deserializes an untrusted YAML string using an insecure YAML loader.



import yaml

yamlString = getYamlFromUser()
yaml.load(yamlString)










## Header Manipulation
### Abstract
Including unvalidated data in an HTTP response header can enable cache-poisoning, cross-site scripting, cross-user defacement, page hijacking, cookie manipulation or open redirect.
Explanation
Header Manipulation vulnerabilities occur when:

1. Data enters a web application through an untrusted source, most frequently an HTTP request.

2. The data is included in an HTTP response header sent to a web user without being validated.

As with many software security vulnerabilities, Header Manipulation is a means to an end, not an end in itself. At its root, the vulnerability is straightforward: an attacker passes malicious data to a vulnerable application, and the application includes the data in an HTTP response header.

One of the most common Header Manipulation attacks is HTTP Response Splitting. To mount a successful HTTP Response Splitting exploit, the application must allow input that contains CR (carriage return, also given by %0d or \r) and LF (line feed, also given by %0a or \n)characters into the header. These characters not only give attackers control of the remaining headers and body of the response the application intends to send, but also allows them to create additional responses entirely under their control.

Many of today's modern application servers will prevent the injection of malicious characters into HTTP headers. If your application server prevents setting headers with new line characters, then your application is not vulnerable to HTTP Response Splitting. However, solely filtering for new line characters can leave an application vulnerable to Cookie Manipulation or Open Redirects, so care must still be taken when setting HTTP headers with user input.

Example: The following code segment reads the location from an HTTP request and sets it in a the header its location field of an HTTP response.



    location = req.field('some_location')
    ...
    response.addHeader("location",location)


Assuming a string consisting of standard alphanumeric characters, such as "index.html", is submitted in the request the HTTP response including this cookie might take the following form:



HTTP/1.1 200 OK
...
location: index.html
...


However, because the value of the location is formed of unvalidated user input the response will only maintain this form if the value submitted for some_location does not contain any CR and LF characters. If an attacker submits a malicious string, such as "index.html\r\nHTTP/1.1 200 OK\r\n...", then the HTTP response would be split into two responses of the following form:



HTTP/1.1 200 OK
...
location: index.html

HTTP/1.1 200 OK
...


Clearly, the second response is completely controlled by the attacker and can be constructed with any header and body content desired. The ability of attacker to construct arbitrary HTTP responses permits a variety of resulting attacks, including: cross-user defacement, web and browser cache poisoning, cross-site scripting, and page hijacking.

Cross-User Defacement: An attacker will be able to make a single request to a vulnerable server that will cause the server to create two responses, the second of which may be misinterpreted as a response to a different request, possibly one made by another user sharing the same TCP connection with the server. This can be accomplished by convincing the user to submit the malicious request themselves, or remotely in situations where the attacker and the user share a common TCP connection to the server, such as a shared proxy server. In the best case, an attacker may leverage this ability to convince users that the application has been hacked, causing users to lose confidence in the security of the application. In the worst case, an attacker may provide especially crafted content designed to mimic the behavior of the application but redirect private information, such as account numbers and passwords, back to the attacker.

Cache Poisoning: The impact of a maliciously constructed response can be magnified if it is cached either by a web cache used by multiple users or even the browser cache of a single user. If a response is cached in a shared web cache, such as those commonly found in proxy servers, then all users of that cache will continue receive the malicious content until the cache entry is purged. Similarly, if the response is cached in the browser of an individual user, then that user will continue to receive the malicious content until the cache entry is purged, although only the user of the local browser instance will be affected.

Cross-Site Scripting: Once attackers have control of the responses sent by an application, they have a choice of a variety of malicious content to provide users. Cross-site scripting is common form of attack where malicious JavaScript or other code included in a response is executed in the user's browser. The variety of attacks based on XSS is almost limitless, but they commonly include transmitting private data such as cookies or other session information to the attacker, redirecting the victim to web content controlled by the attacker, or performing other malicious operations on the user's machine under the guise of the vulnerable site. The most common and dangerous attack vector against users of a vulnerable application uses JavaScript to transmit session and authentication information back to the attacker who can then take complete control of the victim's account.

Page Hijacking: In addition to using a vulnerable application to send malicious content to a user, the same root vulnerability can also be leveraged to redirect sensitive content generated by the server and intended for the user to the attacker instead. By submitting a request that results in two responses, the intended response from the server and the response generated by the attacker, an attacker may cause an intermediate node, such as a shared proxy server, to misdirect a response generated by the server for the user to the attacker. Because the request made by the attacker generates two responses, the first is interpreted as a response to the attacker's request, while the second remains in limbo. When the user makes a legitimate request through the same TCP connection, the attacker's request is already waiting and is interpreted as a response to the victim's request. The attacker then sends a second request to the server, to which the proxy server responds with the server generated request intended for the victim, thereby compromising any sensitive information in the headers or body of the response intended for the victim.

Cookie Manipulation: When combined with attacks like Cross-Site Request Forgery, attackers may change, add to, or even overwrite a legitimate user's cookies.

Open Redirect: Allowing unvalidated input to control the URL used in a redirect can aid phishing attacks.









## Header Manipulation: Cookies
### Abstract
Including unvalidated data in an HTTP response header can enable cache-poisoning, cross-site scripting, cross-user defacement, page hijacking, cookie manipulation or open redirect.
Explanation
Header Manipulation vulnerabilities occur when:

1. Data enters a web application through an untrusted source, most frequently an HTTP request.

2. The data is included in an HTTP response header sent to a web user without being validated.

As with many software security vulnerabilities, Header Manipulation is a means to an end, not an end in itself. At its root, the vulnerability is straightforward: an attacker passes malicious data to a vulnerable application, and the application includes the data in an HTTP response header.

One of the most common Header Manipulation attacks is HTTP Response Splitting. To mount a successful HTTP Response Splitting exploit, the application must allow input that contains CR (carriage return, also given by %0d or \r) and LF (line feed, also given by %0a or \n)characters into the header. These characters not only give attackers control of the remaining headers and body of the response the application intends to send, but also allows them to create additional responses entirely under their control.

Many of today's modern application servers will prevent the injection of malicious characters into HTTP headers. If your application server prevents setting headers with new line characters, then your application is not vulnerable to HTTP Response Splitting. However, solely filtering for new line characters can leave an application vulnerable to Cookie Manipulation or Open Redirects, so care must still be taken when setting HTTP headers with user input.

Example: The following code segment reads the location from an HTTP request and sets it in a the header its location field of an HTTP response.



    location = req.field('some_location')
    ...
    response.addHeader("location",location)


Assuming a string consisting of standard alphanumeric characters, such as "index.html", is submitted in the request the HTTP response including this cookie might take the following form:



HTTP/1.1 200 OK
...
location: index.html
...


However, because the value of the location is formed of unvalidated user input the response will only maintain this form if the value submitted for some_location does not contain any CR and LF characters. If an attacker submits a malicious string, such as "index.html\r\nHTTP/1.1 200 OK\r\n...", then the HTTP response would be split into two responses of the following form:



HTTP/1.1 200 OK
...
location: index.html

HTTP/1.1 200 OK
...


Clearly, the second response is completely controlled by the attacker and can be constructed with any header and body content desired. The ability of attacker to construct arbitrary HTTP responses permits a variety of resulting attacks, including: cross-user defacement, web and browser cache poisoning, cross-site scripting, and page hijacking.

Cross-User Defacement: An attacker will be able to make a single request to a vulnerable server that will cause the server to create two responses, the second of which may be misinterpreted as a response to a different request, possibly one made by another user sharing the same TCP connection with the server. This can be accomplished by convincing the user to submit the malicious request themselves, or remotely in situations where the attacker and the user share a common TCP connection to the server, such as a shared proxy server. In the best case, an attacker may leverage this ability to convince users that the application has been hacked, causing users to lose confidence in the security of the application. In the worst case, an attacker may provide especially crafted content designed to mimic the behavior of the application but redirect private information, such as account numbers and passwords, back to the attacker.

Cache Poisoning: The impact of a maliciously constructed response can be magnified if it is cached either by a web cache used by multiple users or even the browser cache of a single user. If a response is cached in a shared web cache, such as those commonly found in proxy servers, then all users of that cache will continue receive the malicious content until the cache entry is purged. Similarly, if the response is cached in the browser of an individual user, then that user will continue to receive the malicious content until the cache entry is purged, although only the user of the local browser instance will be affected.

Cross-Site Scripting: Once attackers have control of the responses sent by an application, they have a choice of a variety of malicious content to provide users. Cross-site scripting is common form of attack where malicious JavaScript or other code included in a response is executed in the user's browser. The variety of attacks based on XSS is almost limitless, but they commonly include transmitting private data such as cookies or other session information to the attacker, redirecting the victim to web content controlled by the attacker, or performing other malicious operations on the user's machine under the guise of the vulnerable site. The most common and dangerous attack vector against users of a vulnerable application uses JavaScript to transmit session and authentication information back to the attacker who can then take complete control of the victim's account.

Page Hijacking: In addition to using a vulnerable application to send malicious content to a user, the same root vulnerability can also be leveraged to redirect sensitive content generated by the server and intended for the user to the attacker instead. By submitting a request that results in two responses, the intended response from the server and the response generated by the attacker, an attacker may cause an intermediate node, such as a shared proxy server, to misdirect a response generated by the server for the user to the attacker. Because the request made by the attacker generates two responses, the first is interpreted as a response to the attacker's request, while the second remains in limbo. When the user makes a legitimate request through the same TCP connection, the attacker's request is already waiting and is interpreted as a response to the victim's request. The attacker then sends a second request to the server, to which the proxy server responds with the server generated request intended for the victim, thereby compromising any sensitive information in the headers or body of the response intended for the victim.

Cookie Manipulation: When combined with attacks like Cross-Site Request Forgery, attackers may change, add to, or even overwrite a legitimate user's cookies.

Open Redirect: Allowing unvalidated input to control the URL used in a redirect can aid phishing attacks.


## Header Manipulation: SMTP
### Abstract
Including unvalidated data in an SMTP header can enable attackers to add arbitrary headers, such as CC or BCC that they can use to leak the mail contents to themselves or use the mail server as a spam bot.
Explanation
SMTP Header Manipulation vulnerabilities occur when:

1. Data enters an application through an untrusted source, most frequently an HTTP request in a web application.

2. The data is included in an SMTP header sent to a mail server without being validated.

As with many software security vulnerabilities, SMTP Header Manipulation is a means to an end, not an end in itself. At its root, the vulnerability is straightforward: an attacker passes malicious data to a vulnerable application, and the application includes the data in an SMTP header.

One of the most common SMTP Header Manipulation attacks is for the use of distributing spam emails. If an application contains a vulnerable "Contact us" form that allows setting the subject and the body of the email, an attacker will be able to set any arbitrary content and inject a CC header with a list of email addresses to spam anonymously since the email will be sent from the victim server.

Example: The following code segment reads the subject and body of a "Contact us" form:



body = request.GET['body']
subject = request.GET['subject']
session = smtplib.SMTP(smtp_server, smtp_tls_port)
session.ehlo()
session.starttls()
session.login(username, password)
headers = "\r\n".join(["from: webform@acme.com",
                       "subject: [Contact us query] " + subject,
                       "to: support@acme.com",
                       "mime-version: 1.0",
                       "content-type: text/html"])
content = headers + "\r\n\r\n" + body
session.sendmail("webform@acme.com", "support@acme.com", content)


Assuming a string consisting of standard alphanumeric characters, such as "Page not working" is submitted in the request, the SMTP headers might take the following form:



...
subject: [Contact us query] Page not working
...


However, because the value of the header is constructed from unvalidated user input the response will only maintain this form if the value submitted for subject does not contain any CR and LF characters. If an attacker submits a malicious string, such as "Congratulations!! You won the lottery!!!\r\ncc:victim1@mail.com,victim2@mail.com ...", then the SMTP headers would be of the following form:



...
subject: [Contact us query] Congratulations!! You won the lottery
cc: victim1@mail.com,victim2@mail.com
...


This will effectively allow an attacker to craft spam messages or to send anonymous emails amongst other attacks.







## HTML5: Cross-Site Scripting Protection
### Abstract
The X-XSS-Protection header is explicitly disabled which may increase the risk of cross-site scripting attacks.
Explanation
X-XSS-Protection refers to a header that is automatically enabled in Internet Explorer 8 upwards and the latest versions of Chrome. When the header value is set to false (0) cross-site scripting protection is disabled.

The header can be set in multiple locations and should be checked for both misconfiguration as well as malicious tampering.






## JSON Injection
### Abstract
The method writes unvalidated input into JSON. This call could allow an attacker to inject arbitrary elements or attributes into the JSON entity.
Explanation
JSON injection occurs when:

1. Data enters a program from an untrusted source.


2. The data is written to a JSON stream.

Applications typically use JSON to store data or send messages. When used to store data, JSON is often treated like cached data and may potentially contain sensitive information. When used to send messages, JSON is often used in conjunction with a RESTful service and can be used to transmit sensitive information such as authentication credentials.

The semantics of JSON documents and messages can be altered if an application constructs JSON from unvalidated input. In a relatively benign case, an attacker may be able to insert extraneous elements that cause an application to throw an exception while parsing a JSON document or request. In a more serious case, such as ones that involves JSON injection, an attacker may be able to insert extraneous elements that allow for the predictable manipulation of business critical values within a JSON document or request. In some cases, JSON injection can lead to cross-site scripting or dynamic code evaluation.

Example : The following python code update a json file with an untrusted value comes from a URL:



import json
import requests
from urllib.parse import urlparse
from urllib.parse import parse_qs

url = 'https://www.example.com/some_path?name=some_value'
parsed_url = urlparse(url)
untrusted_values = parse_qs(parsed_url.query)['name'][0]

with open('data.json', 'r') as json_File:    
    data = json.load(json_File)

    data['name']= untrusted_values
    
with open('data.json', 'w') as json_File:
    json.dump(data, json_File)

...


Here the untrusted data in name will not be validated to escape JSON-related special characters. This allows a user to arbitrarily insert JSON keys, possibly changing the structure of the serialized JSON. In this example, if the non-privileged user mallory were to append ","role":"admin to the name parameter in the URL, the JSON would become:



{
"role":"user",
"username":"mallory",
"role":"admin"
}

The JSON file is now tampered with malicious data and the user has a privileged access of "admin" instead of "user"








## Log Forging
### Abstract
Writing unvalidated user input to log files can allow an attacker to forge log entries or inject malicious content into the logs.
Explanation
Log forging vulnerabilities occur when:

1. Data enters an application from an untrusted source.

2. The data is written to an application or system log file.

Applications typically use log files to store a history of events or transactions for later review, statistics gathering, or debugging. Depending on the nature of the application, the task of reviewing log files may be performed manually on an as-needed basis or automated with a tool that automatically culls logs for important events or trending information.

Interpretation of the log files may be hindered or misdirected if an attacker can supply data to the application that is subsequently logged verbatim. In the most benign case, an attacker may be able to insert false entries into the log file by providing the application with input that includes appropriate characters. If the log file is processed automatically, the attacker may be able to render the file unusable by corrupting the format of the file or injecting unexpected characters. A more subtle attack might involve skewing the log file statistics. Forged or otherwise, corrupted log files can be used to cover an attacker's tracks or even to implicate another party in the commission of a malicious act [1]. In the worst case, an attacker may inject code or other commands into the log file and take advantage of a vulnerability in the log processing utility [2].

Example: The following web application code attempts to read an integer value from a request object. If the value fails to parse as an integer, then the input is logged with an error message indicating what happened.



    name = req.field('name')
    ...
    logout = req.field('logout')

    if (logout):
        ...
    else:
        logger.error("Attempt to log out: name: %s logout: %s" % (name,logout))


If a user submits the string "twenty-one" for logout and he was able to create a user with name "admin", the following entry is logged:



Attempt to log out: name: admin logout: twenty-one


However, if an attacker is able to create a username "admin+logout:+1+++++++++++++++++++++++", the following entry is logged:



Attempt to log out: name: admin logout: 1                       logout: twenty-one







## Log Forging (debug)
### Abstract
Writing unvalidated user input to log files can allow an attacker to forge log entries or inject malicious content into the logs.
Explanation
Log forging vulnerabilities occur when:

1. Data enters an application from an untrusted source.

2. The data is written to an application or system log file.

Applications typically use log files to store a history of events or transactions for later review, statistics gathering, or debugging. Depending on the nature of the application, the task of reviewing log files may be performed manually on an as-needed basis or automated with a tool that automatically culls logs for important events or trending information.

Interpretation of the log files may be hindered or misdirected if an attacker can supply data to the application that is subsequently logged verbatim. In the most benign case, an attacker may be able to insert false entries into the log file by providing the application with input that includes appropriate characters. If the log file is processed automatically, the attacker may be able to render the file unusable by corrupting the format of the file or injecting unexpected characters. A more subtle attack might involve skewing the log file statistics. Forged or otherwise, corrupted log files can be used to cover an attacker's tracks or even to implicate another party in the commission of a malicious act [1]. In the worst case, an attacker may inject code or other commands into the log file and take advantage of a vulnerability in the log processing utility [2].

Example 1: The following web application code attempts to read an integer value from a request object. If the value fails to parse as an integer, then the input is logged with an error message indicating what happened.



...
val = request.GET["val"]
try:
  int_value = int(val)
except:
  logger.debug("Failed to parse val = " + val)
...


If a user submits the string "twenty-one" for val, the following entry is logged:



INFO: Failed to parse val=twenty-one


However, if an attacker submits the string "twenty-one%0a%0aINFO:+User+logged+out%3dbadguy", the following entry is logged:



INFO: Failed to parse val=twenty-one

INFO: User logged out=badguy


Clearly, attackers may use this same mechanism to insert arbitrary log entries.







## Mail Command Injection: SMTP
### Abstract
Executing SMTP commands from an untrusted source can cause the SMTP server to execute malicious commands on behalf of an attacker.
Explanation
SMTP command injection vulnerabilities occur when an attacker may influence the commands sent to an SMTP mail server.

1. Data enters the application from an untrusted source.

2. The data is used as or as part of a string representing a command that is executed by the application.

3. By executing the SMTP command, the attacker is able to instruct the server to carry out malicious actions such as sending spam.

Example 1: The following code uses an HTTP request parameter to craft a VRFY command that is sent to the SMTP server. An attacker may use this parameter to modify the command sent to the server and inject new commands using CRLF characters.



...
user = request.GET['user']
session = smtplib.SMTP(smtp_server, smtp_tls_port)
session.ehlo()
session.starttls()
session.login(username, password)
session.docmd("VRFY", user)
...








## Memcached Injection
### Abstract
Invoking a Memcached operation with input coming from an untrusted source might allow an attacker to introduce new key/value pairs in Memcached cache.
Explanation
Memcached injection errors occur when:

1. Data enters a program from an untrusted source.



2. The data is used to dynamically construct a Memcached key or value.

Example 1: The following code dynamically constructs a Memcached key.



...
def store(request):
    id = request.GET['id']
    result = get_page_from_somewhere()
    response = HttpResponse(result)
    cache_time = 1800
    cache.set("req-" % id, response, cache_time)
    return response
...


The operation that this code intends to execute follows:



set req-1233 0 0 n
<serialized_response_instance>


However, because the operation is constructed dynamically by concatenating a constant key prefix and a user input string, an attacker may send the string ignore 0 0 1\r\n1\r\nset injected 0 3600 10\r\n0123456789\r\nset req-, then the operation becomes the following:



set req-ignore 0 0 1
1
set injected 0 3600 10
0123456789
set req-1233 0 0 n
<serialized_response_instance>


The preceding key will successfully add a new key/value pair in the cache injected=0123456789. Depending on the payload, attackers will be able to poison the cache or execute arbitrary code by injecting a Pickle-serialized payload that will execute arbitrary code upon deserialization.






## NoSQL Injection: MongoDB
### Abstract
Constructing a dynamic MongoDB query with input coming from an untrusted source could allow an attacker to modify the statement's meaning.
Explanation
NoSQL injection in MongoDB errors occur when:

1. Data enters a program from an untrusted source.



2. The data is used to dynamically construct a MongoDB query.

Example 1: The following code dynamically constructs and executes a MongoDB query that searches for an email with a specific ID.



...
    userName = req.field('userName')
    emailId = req.field('emaiId')
    results = db.emails.find({"$where", "this.owner == \"" + userName + "\" && this.emailId == \"" + emailId + "\""});
...


The query intends to execute the following code:



    this.owner == "<userName>" && this.emailId == "<emailId>"


However, because the query is constructed dynamically by concatenating a constant base query string and a user input string, the query only behaves correctly if emailId does not contain a double-quote character. If an attacker with the user name wiley enters the string 123" || "4" != "5 for emailId, then the query becomes the following:



    this.owner == "wiley" && this.emailId == "123" || "4" != "5"


The addition of the || "4" != "5" condition causes the where clause to always evaluate to true, so the query returns all entries stored in the emails collection, regardless of the email owner.







## Open Redirect
### Abstract
Allowing unvalidated input to control the URL used in a redirect can aid phishing attacks.
Explanation
Redirects allow web applications to direct users to different pages within the same application or to external sites. Applications utilize redirects to aid in site navigation and, in some cases, to track how users exit the site. Open redirect vulnerabilities occur when a web application redirects clients to any arbitrary URL that can be controlled by an attacker.

Attackers might utilize open redirects to trick users into visiting a URL to a trusted site, but then redirecting them to a malicious site. By encoding the URL, an attacker can make it difficult for end-users to notice the malicious destination of the redirect, even when it is passed as a URL parameter to the trusted site. Open redirects are often abused as part of phishing scams to harvest sensitive end-user data.

Example 1: The following Python code instructs the user's browser to open a URL parsed from the dest request parameter when a user clicks the link.



        ...
        strDest = request.field("dest")
        redirect(strDest)
        ...


If a victim received an email instructing them to follow a link to "http://trusted.example.com/ecommerce/redirect.asp?dest=www.wilyhacker.com", the user would likely click on the link believing they would be transferred to the trusted site. However, when the victim clicks the link, the code in Example 1 will redirect the browser to "http://www.wilyhacker.com".

Many users have been educated to always inspect URLs they receive in emails to make sure the link specifies a trusted site they know. However, if the attacker Hex encoded the destination url as follows:
"http://trusted.example.com/ecommerce/redirect.asp?dest=%77%69%6C%79%68%61%63%6B%65%72%2E%63%6F%6D"

then even a savvy end-user may be fooled into following the link.





## Path Manipulation
### Abstract
Allowing user input to control paths used in file system operations could enable an attacker to access or modify otherwise protected system resources.
Explanation
Path manipulation errors occur when the following two conditions are met:

1. An attacker can specify a path used in an operation on the file system.

2. By specifying the resource, the attacker gains a capability that would not otherwise be permitted.

For example, the program might give the attacker the ability to overwrite the specified file or run with a configuration controlled by the attacker.
Example 1: The following code uses input from an HTTP request to create a file name. The programmer has not considered the possibility that an attacker could provide a file name such as "../../tomcat/conf/server.xml", which causes the application to delete one of its own configuration files.



rName = req.field('reportName')
rFile = os.open("/usr/local/apfr/reports/" + rName)
...
os.unlink(rFile);
Example 2: The following code uses input from a configuration file to determine which file to open and echo back to the user. If the program runs with adequate privileges and malicious users can change the configuration file, they can use the program to read any file on the system that ends with the extension .txt.



...
filename = CONFIG_TXT['sub'] + ".txt";
handle = os.open(filename)
print handle
...





## Path Manipulation: Zip Entry Overwrite
### Abstract
Allowing user input to control paths used in file system operations could enable an attacker to arbitrarily overwrite files on the system.
Explanation
Path Manipulation: ZIP Entry Overwrite errors occur when a ZIP file is opened and expanded without checking the file path of the ZIP entry.

Example: The following example extracts files from a ZIP file and insecurely writes them to disk.


...
import zipfile
import tarfile

def unzip(archive_name):
    zf = zipfile.ZipFile(archive_name)
    zf.extractall(".")
    zf.close()

def untar(archive_name):
    tf = tarfile.TarFile(archive_name)
    tf.extractall(".")
    tf.close()
...







## Resource Injection
### Abstract
Allowing user input to control resource identifiers could enable an attacker to access or modify otherwise protected system resources.
Explanation
A resource injection issue occurs when the following two conditions are met:

1. An attacker is able to specify the identifier used to access a system resource.

For example, an attacker may be able to specify a port number to be used to connect to a network resource.

2. By specifying the resource, the attacker gains a capability that would not otherwise be permitted.

For example, the program may give the attacker the ability to transmit sensitive information to a third-party server.



Note: Resource injections involving resources stored on the file system are reported in a separate category named path manipulation. See the path manipulation description for further details of this vulnerability.

Example: The following code uses a hostname read from an HTTP request to connect to a database, which determines the price for a ticket.



host=request.GET['host']
dbconn = db.connect(host=host, port=1234, dbname=ticketdb)
c = dbconn.cursor()
...
result = c.execute('SELECT * FROM pricelist')
...


The kind of resource affected by user input indicates the kind of content that may be dangerous. For example, data containing special characters like period, slash, and backslash are risky when used in methods that interact with the file system. Similarly, data that contains URLs and URIs is risky for functions that create remote connections.








## Server-Side Request Forgery
### Abstract
The application initiates a network connection to a third-party system using user-controlled data to craft the resource URI.
Explanation
A Server-Side Request Forgery occurs when an attacker may influence a network connection made by the application server. The network connection will originate from the application server's internal IP address and an attacker will be able to use this connection to bypass network controls and scan or attack internal resources that are not otherwise exposed.

Example: In the following example, an attacker can control the URL to which the server is connecting.



url = request.GET['url']
handle = urllib.urlopen(url)


The attacker's ability to hijack the network connection depends on the specific part of the URI that can be controlled, and on the libraries used to establish the connection. For example, controlling the URI scheme lets the attacker use protocols different from http or https like:

- up://
- ldap://
- jar://
- gopher://
- mailto://
- ssh2://
- telnet://
- expect://

An attacker can leverage this hijacked network connection to perform the following attacks:

- Port Scanning of intranet resources.
- Bypass firewalls.
- Attack vulnerable programs running on the application server or on the intranet.
- Attack internal/external web applications using Injection attacks or CSRF.
- Access local files using file:// scheme.
- On Windows systems, file:// scheme and UNC paths can allow an attacker to scan and access internal shares.
- Perform a DNS cache poisoning attack.








## Server-Side Template Injection
### Abstract
User-controlled data is used as a template engine's template, allowing attackers to access the template context and in some cases inject and run arbitrary code on the application server.
Explanation
Template engines are used to render content using dynamic data. This context data is normally controlled by the user and formatted by the template to generate web pages, emails, and the like. Template engines allow powerful language expressions to be used in templates in order to render dynamic content, by processing the context data with code constructs such as conditionals, loops, etc. If an attacker can control the template to be rendered, they can inject expressions that expose context data or even run arbitrary commands on the server.

Example 1: The following example shows how a template is retrieved from an HTTP request and rendered using the Jinja2 template engine.


from django.http import HttpResponse
from jinja2 import Template as Jinja2_Template
from jinja2 import Environment, DictLoader, escape

def process_request(request):
    # Load the template
    template = request.GET['template']
    t = Jinja2_Template(template)
    name = source(request.GET['name'])
    # Render the template with the context data
    html = t.render(name=escape(name))
    return HttpResponse(html)
Example 1 uses Jinja2 as the template engine. For that engine, an attacker could submit the following template to read arbitrary files from the server:


template={{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}
Example 2: The following example shows how a template is retrieved from an HTTP request and rendered using the Django template engine.


from django.http import HttpResponse
from django.template import Template, Context, Engine

def process_request(request):
    # Load the template
    template = source(request.GET['template'])
    t = Template(template)
    user = {"name": "John", "secret":getToken()}
    ctx = Context(locals())
    html = t.render(ctx)
    return HttpResponse(html)
Example 2 uses Django as the template engine. For that engine, an attacker will not be able to execute arbitrary commands, but they will be able to access all the objects in the template context. In this example, a secret token is available in the context and could be leaked by the attacker.








## Setting Manipulation
### Abstract
Allowing external control of system settings can disrupt service or cause an application to behave in unexpected ways.
Explanation
Setting manipulation vulnerabilities occur when an attacker can control values that govern the behavior of the system, manage specific resources, or in some way affect the functionality of the application.



Because setting manipulation covers a diverse set of functions, any attempt to illustrate it will inevitably be incomplete. Rather than searching for a tight-knit relationship between the functions addressed in the setting manipulation category, take a step back and consider the sorts of system values that an attacker should not be allowed to control.

Example 1: The following code snippet sets an environment variable using user-controlled data.



...
catalog = request.GET['catalog']
path = request.GET['path']
os.putenv(catalog, path)
...


In this example, an attacker could set any arbitrary environment variable and affect how other applications work.

In general, do not allow user-provided or otherwise untrusted data to control sensitive values. The leverage that an attacker gains by controlling these values is not always immediately obvious, but do not underestimate the creativity of your attacker.







## SQL Injection
### Abstract
Constructing a dynamic SQL statement with input that comes from an untrusted source might allow an attacker to modify the statement's meaning or to execute arbitrary SQL commands.
Explanation
SQL injection errors occur when:

1. Data enters a program from an untrusted source.



2. The data is used to dynamically construct a SQL query.

Example 1: The following code dynamically constructs and executes a SQL query that searches for items matching a specified name. The query restricts the items displayed to those where the owner matches the user name of the currently-authenticated user.



	...
	userName = req.field('userName')
	itemName = req.field('itemName')
	query = "SELECT * FROM items WHERE owner = ' " + userName +" ' AND itemname = ' " + itemName +"';"
	cursor.execute(query)
	result = cursor.fetchall()
	...


The query intends to execute the following code:



	SELECT * FROM items
	WHERE owner = <userName>
	AND itemname = <itemName>;


However, because the query is constructed dynamically by concatenating a constant query string and a user input string, the query only behaves correctly if itemName does not contain a single-quote character. If an attacker with the user name wiley enters the string "name' OR 'a'='a" for itemName, then the query becomes the following:



	SELECT * FROM items
	WHERE owner = 'wiley'
	AND itemname = 'name' OR 'a'='a';


The addition of the OR 'a'='a' condition causes the where clause to always evaluate to true, so the query becomes logically equivalent to the much simpler query:



	SELECT * FROM items;


This simplification of the query allows the attacker to bypass the requirement that the query must only return items owned by the authenticated user. The query now returns all entries stored in the items table, regardless of their specified owner.

Example 2: This example examines the effects of a different malicious value passed to the query constructed and executed in Example 1. If an attacker with the user name wiley enters the string "name'; DELETE FROM items; --" for itemName, then the query becomes the following two queries:



	SELECT * FROM items
	WHERE owner = 'wiley'
	AND itemname = 'name';

	DELETE FROM items;

	--'


Many database servers, including Microsoft(R) SQL Server 2000, allow multiple SQL statements separated by semicolons to be executed at once. While this attack string results in an error on Oracle and other database servers that do not allow the batch-execution of statements separated by semicolons, on databases that do allow batch execution, this type of attack allows the attacker to execute arbitrary commands against the database.

Notice the trailing pair of hyphens (--), which specifies to most database servers that the remainder of the statement is to be treated as a comment and not executed [4]. In this case the comment character serves to remove the trailing single-quote left over from the modified query. On a database where comments are not allowed to be used in this way, the general attack could still be made effective using a trick similar to the one shown in Example 1. If an attacker enters the string "name'); DELETE FROM items; SELECT * FROM items WHERE 'a'='a", the following three valid statements will be created:



	SELECT * FROM items
	WHERE owner = 'wiley'
	AND itemname = 'name';

	DELETE FROM items;

	SELECT * FROM items WHERE 'a'='a';


One traditional approach to preventing SQL injection attacks is to handle them as an input validation problem and either accept only characters from an allow list of safe values or identify and escape a list of potentially malicious values (deny list). Checking an allow list can be a very effective means of enforcing strict input validation rules, but parameterized SQL statements require less maintenance and can offer more guarantees with respect to security. As is almost always the case, implementing a deny list is riddled with loopholes that make it ineffective at preventing SQL injection attacks. For example, attackers may:

- Target fields that are not quoted
- Find ways to bypass the need for certain escaped metacharacters
- Use stored procedures to hide the injected metacharacters

Manually escaping characters in input to SQL queries can help, but it will not make your application secure from SQL injection attacks.

Another solution commonly proposed for dealing with SQL injection attacks is to use stored procedures. Although stored procedures prevent some types of SQL injection attacks, they fail to protect against many others. Stored procedures typically help prevent SQL injection attacks by limiting the types of statements that can be passed to their parameters. However, there are many ways around the limitations and many interesting statements that can still be passed to stored procedures. Again, stored procedures can prevent some exploits, but they will not make your application secure against SQL injection attacks.







## Unsafe Reflection
### Abstract
An attacker may be able to create unexpected control flow paths through the application, potentially bypassing security checks.
Explanation
If an attacker can supply values that the application then uses to determine which class to instantiate or which method to invoke, the potential exists for the attacker to create control flow paths through the application that were not intended by the application developers. This attack vector may allow the attacker to bypass authentication or access control checks or otherwise cause the application to behave in an unexpected manner. Even the ability to control the arguments passed to a given method or constructor may give a wily attacker the edge necessary to mount a successful attack.

This situation becomes a doomsday scenario if the attacker may upload files into a location that appears on the application's classpath or add new entries to the application's classpath. Under either of these conditions, the attacker may use reflection to introduce new, presumably malicious, behavior into the application.
References

[1] Standards Mapping - Common Weakness Enumeration 






## XML Entity Expansion Injection
### Abstract
Using XML parsers configured to not prevent nor limit Document Type Definition (DTD) entity resolution can expose the parser to an XML Entity Expansion injection
Explanation
XML Entity Expansion injection also known as XML Bombs are DoS attacks that benefit from valid and well-formed XML blocks that expand exponentially until they exhaust the server allocated resources. XML allows to define custom entities which act as string substitution macros. By nesting recurrent entity resolutions, an attacker may easily crash the server resources.

The following XML document shows an example of an XML Bomb.


<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>


This test could crash the server by expanding the small XML document into more than 3GB in memory.





## XML External Entity Injection
### Abstract
Using XML processors that do not prevent or limit external entities resolution can expose the application to XML External Entities attacks.
Explanation
XML External Entities attacks benefit from an XML feature to dynamically build documents at runtime. An XML entity allows inclusion of data dynamically from a given resource. External entities allow an XML document to include data from an external URI. Unless configured to do otherwise, external entities force the XML parser to access the resource specified by the URI, such as a file on the local machine or on a remote system. This behavior exposes the application to XML External Entity (XXE) attacks, which attackers can use to perform denial of service of the local system, gain unauthorized access to files on the local machine, scan remote machines, and perform denial of service of remote systems.


Example 1: The following XML document shows an example of an XXE attack.


<?xml version="1.0" encoding="ISO-8859-1"?>
 <!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///dev/random" >]><foo>&xxe;</foo>


This example could crash the server (on a UNIX system), if the XML parser attempts to substitute the entity with the contents of the /dev/random file.







## XML Injection
### Abstract
Writing unvalidated data into an XML document can allow an attacker to change the structure and contents of the XML.
Explanation
XML injection occurs when:

1. Data enters a program from an untrusted source.

2. The data is written to an XML document.

Applications typically use XML to store data or send messages. When used to store data, XML documents are often treated like databases and can potentially contain sensitive information. XML messages are often used in web services and can also be used to transmit sensitive information. XML messages can even be used to send authentication credentials.

The semantics of XML documents and messages can be altered if an attacker has the ability to write raw XML. In the most benign case, an attacker may be able to insert extraneous tags and cause an XML parser to throw an exception. In more nefarious cases of XML injection, an attacker may be able to add XML elements that change authentication credentials or modify prices in an XML e-commerce database. In some cases, XML injection can lead to cross-site scripting or dynamic code evaluation.

Example 1:

Assume an attacker is able to control shoes in following XML.


<order>
    <price>100.00</price>
    <item>shoes</item>
</order>


Now suppose this XML is included in a back end web service request to place an order for a pair of shoes. Suppose the attacker modifies his request and replaces shoes with shoes</item><price>1.00</price><item>shoes. The new XML would look like:


<order>
    <price>100.00</price>
    <item>shoes</item><price>1.00</price><item>shoes</item>
</order>


When using SAX parsers, the value from the second <price> overrides the value from the first <price> tag. This allows the attacker to purchase a pair of $100 shoes for $1.







## XPath Injection
### Abstract
Constructing a dynamic XPath query with user input could allow an attacker to modify the statement's meaning.
Explanation
XPath injection occurs when:

1. Data enters a program from an untrusted source.



2. The data is used to dynamically construct an XPath query.

Example 1: The following code dynamically constructs and executes an XPath query that retrieves an email address for a given account ID. The account ID is read from an HTTP request, and is therefore untrusted.



...
tree = etree.parse('articles.xml')
emailAddrs = "/accounts/account[acctID=" + request.GET["test1"] + "]/email/text()"
r = tree.xpath(emailAddrs)
...


Under normal conditions, such as searching for an email address that belongs to the account number 1, the query that this code executes will look like the following:

/accounts/account[acctID='1']/email/text()

However, because the query is constructed dynamically by concatenating a constant query string and a user input string, the query only behaves correctly if acctID does not contain a single-quote character. If an attacker enters the string 1' or '1' = '1 for acctID, then the query becomes the following:

/accounts/account[acctID='1' or '1' = '1']/email/text()

The addition of the 1' or '1' = '1 condition causes the where clause to always evaluate to true, so the query becomes logically equivalent to the much simpler query:

//email/text()

This simplification of the query allows the attacker to bypass the requirement that the query must only return items owned by the authenticated user. The query now returns all email addresses stored in the document, regardless of their specified owner.





## XSLT Injection
### Abstract
Processing an unvalidated XSL stylesheet can allow an attacker to change the structure and contents of the resultant XML, include arbitrary files from the file system, or execute arbitrary code.
Explanation
XSLT injection occurs when:

1. Data enters a program from an untrusted source.

2. The data is written to an XSL stylesheet.


Applications typically use XSL stylesheet to transform XML documents from one format to another. XSL stylesheets include special functions which enhance the transformation process but introduce additional vulnerabilities if used incorrectly.

The semantics of XSL stylesheets and processing can be altered if an attacker has the ability to write XSL elements in a stylesheet. An attacker could alter the output of a stylesheet such that an XSS (cross-site scripting) attack was enabled, expose the contents of local file system resources, or execute arbitrary code.

Example 1: Here is some code that is vulnerable to XSLT Injection:



...
xml = StringIO.StringIO(request.POST['xml'])
xslt = StringIO.StringIO(request.POST['xslt'])

xslt_root = etree.XML(xslt)
transform = etree.XSLT(xslt_root)
result_tree = transform(xml)
return render_to_response(template_name, {'result': etree.tostring(result_tree)})
...


The code in Example 1 results in three different exploits when the attacker passes the identified XSL to the XSTL processor:

1. XSS:




<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <script>alert(123)</script>
  </xsl:template>
</xsl:stylesheet>



When the XSL stylesheet is processed, the <script> tag is rendered to the victim's browser allowing a cross-site scripting attack to be performed.

2. Reading of arbitrary files on the server's file system:




<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="document('/etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>



The preceding XSL stylesheet will return the contents of the /etc/passwd file.



References

[1] A. Klein Divide and Conquer: HTTP Response Splitting, Web Cache Poisoning Attacks, and Related Topics

[2] D. Crab HTTP Response Splitting

[3] Standards Mapping - Common Weakness Enumeration 

[4] Standards Mapping - DISA Control Correlation Identifier Version 2 

[5] Standards Mapping - FIPS200 

[6] Standards Mapping - General Data Protection Regulation (GDPR) 

[7] Standards Mapping - NIST Special Publication 800-53 Revision 4 

[8] Standards Mapping - NIST Special Publication 800-53 Revision 5 

[9] Standards Mapping - OWASP Top 10 2004 

[10] Standards Mapping - OWASP Top 10 2007 

[11] Standards Mapping - OWASP Top 10 2010 

[12] Standards Mapping - OWASP Top 10 2013 

[13] Standards Mapping - OWASP Top 10 2017 

[14] Standards Mapping - OWASP Top 10 2021 

[15] Standards Mapping - OWASP Mobile 2014 

[16] Standards Mapping - Payment Card Industry Data Security Standard Version 1.1 

[17] Standards Mapping - Payment Card Industry Data Security Standard Version 1.2 

[18] Standards Mapping - Payment Card Industry Data Security Standard Version 2.0 

[19] Standards Mapping - Payment Card Industry Data Security Standard Version 3.0 

[20] Standards Mapping - Payment Card Industry Data Security Standard Version 3.1 

[21] Standards Mapping - Payment Card Industry Data Security Standard Version 3.2 

[22] Standards Mapping - Payment Card Industry Data Security Standard Version 3.2.1 

[23] Standards Mapping - Payment Card Industry Software Security Framework 1.0 

[24] Standards Mapping - Payment Card Industry Software Security Framework 1.1 

[25] Standards Mapping - Security Technical Implementation Guide Version 3.1 

[26] Standards Mapping - Security Technical Implementation Guide Version 3.4 

[27] Standards Mapping - Security Technical Implementation Guide Version 3.5 

[28] Standards Mapping - Security Technical Implementation Guide Version 3.6 

[29] Standards Mapping - Security Technical Implementation Guide Version 3.7 

[30] Standards Mapping - Security Technical Implementation Guide Version 3.9 

[31] Standards Mapping - Security Technical Implementation Guide Version 3.10 

[32] Standards Mapping - Security Technical Implementation Guide Version 4.1 

[33] Standards Mapping - Security Technical Implementation Guide Version 4.2 

[34] Standards Mapping - Security Technical Implementation Guide Version 4.3 

[35] Standards Mapping - Security Technical Implementation Guide Version 4.4 

[36] Standards Mapping - Security Technical Implementation Guide Version 4.5 

[37] Standards Mapping - Security Technical Implementation Guide Version 4.6 

[38] Standards Mapping - Security Technical Implementation Guide Version 4.7 

[39] Standards Mapping - Security Technical Implementation Guide Version 4.8 

[40] Standards Mapping - Security Technical Implementation Guide Version 4.9 

[41] Standards Mapping - Security Technical Implementation Guide Version 4.10 

[42] Standards Mapping - Security Technical Implementation Guide Version 4.11 

[43] Standards Mapping - Security Technical Implementation Guide Version 5.1 

[44] Standards Mapping - Web Application Security Consortium 24 + 2 

[45] Standards Mapping - Web Application Security Consortium Version 2.00 

References

[1] Chema Alonso, Manuel Fernandez, Alejandro Martin and Antonio Guzmán Connection String Parameter Pollution Attacks

[2] Standards Mapping - Common Weakness Enumeration 

[3] Standards Mapping - DISA Control Correlation Identifier Version 2 

[4] Standards Mapping - FIPS200 

[5] Standards Mapping - General Data Protection Regulation (GDPR) 

[6] Standards Mapping - NIST Special Publication 800-53 Revision 4 

[7] Standards Mapping - NIST Special Publication 800-53 Revision 5 

[8] Standards Mapping - OWASP Top 10 2004 

[9] Standards Mapping - OWASP Top 10 2007 

[10] Standards Mapping - OWASP Top 10 2010 

[11] Standards Mapping - OWASP Top 10 2013 

[12] Standards Mapping - OWASP Top 10 2017 

[13] Standards Mapping - OWASP Top 10 2021 

[14] Standards Mapping - OWASP Mobile 2014 

[15] Standards Mapping - OWASP Application Security Verification Standard 4.0 

[16] Standards Mapping - Payment Card Industry Data Security Standard Version 1.1 

[17] Standards Mapping - Payment Card Industry Data Security Standard Version 1.2 

[18] Standards Mapping - Payment Card Industry Data Security Standard Version 2.0 

[19] Standards Mapping - Payment Card Industry Data Security Standard Version 3.0 

[20] Standards Mapping - Payment Card Industry Data Security Standard Version 3.1 

[21] Standards Mapping - Payment Card Industry Data Security Standard Version 3.2 

[22] Standards Mapping - Payment Card Industry Data Security Standard Version 3.2.1 

[23] Standards Mapping - Payment Card Industry Software Security Framework 1.0 

[24] Standards Mapping - Payment Card Industry Software Security Framework 1.1 

[25] Standards Mapping - SANS Top 25 2009 

[26] Standards Mapping - SANS Top 25 2010 

[27] Standards Mapping - SANS Top 25 2011 

[28] Standards Mapping - Security Technical Implementation Guide Version 3.1 

[29] Standards Mapping - Security Technical Implementation Guide Version 3.4 

[30] Standards Mapping - Security Technical Implementation Guide Version 3.5 

[31] Standards Mapping - Security Technical Implementation Guide Version 3.6 

[32] Standards Mapping - Security Technical Implementation Guide Version 3.7 

[33] Standards Mapping - Security Technical Implementation Guide Version 3.9 

[34] Standards Mapping - Security Technical Implementation Guide Version 3.10 

[35] Standards Mapping - Security Technical Implementation Guide Version 4.1 

[36] Standards Mapping - Security Technical Implementation Guide Version 4.2 

[37] Standards Mapping - Security Technical Implementation Guide Version 4.3 

[38] Standards Mapping - Security Technical Implementation Guide Version 4.4 

[39] Standards Mapping - Security Technical Implementation Guide Version 4.5 

[40] Standards Mapping - Security Technical Implementation Guide Version 4.6 

[41] Standards Mapping - Security Technical Implementation Guide Version 4.7 

[42] Standards Mapping - Security Technical Implementation Guide Version 4.8 

[43] Standards Mapping - Security Technical Implementation Guide Version 4.9 

[44] Standards Mapping - Security Technical Implementation Guide Version 4.10 

[45] Standards Mapping - Security Technical Implementation Guide Version 4.11 

[46] Standards Mapping - Security Technical Implementation Guide Version 5.1 

[47] Standards Mapping - Web Application Security Consortium Version 2.00 

References

[1] Standards Mapping - Common Weakness Enumeration 

[2] Standards Mapping - Common Weakness Enumeration Top 25 2019 

[3] Standards Mapping - Common Weakness Enumeration Top 25 2020 

[4] Standards Mapping - Common Weakness Enumeration Top 25 2021 

[5] Standards Mapping - DISA Control Correlation Identifier Version 2 

[6] Standards Mapping - FIPS200 

[7] Standards Mapping - General Data Protection Regulation (GDPR) 

[8] Standards Mapping - Motor Industry Software Reliability Association (MISRA) C Guidelines 2012 

[9] Standards Mapping - Motor Industry Software Reliability Association (MISRA) C++ Guidelines 2008 

[10] Standards Mapping - NIST Special Publication 800-53 Revision 4 

[11] Standards Mapping - NIST Special Publication 800-53 Revision 5 

[12] Standards Mapping - OWASP Top 10 2004 

[13] Standards Mapping - OWASP Top 10 2007 

[14] Standards Mapping - OWASP Top 10 2010 

[15] Standards Mapping - OWASP Top 10 2013 

[16] Standards Mapping - OWASP Top 10 2017 

[17] Standards Mapping - OWASP Top 10 2021 

[18] Standards Mapping - OWASP Mobile 2014 

[19] Standards Mapping - OWASP Application Security Verification Standard 4.0 

[20] Standards Mapping - Payment Card Industry Data Security Standard Version 1.1 

[21] Standards Mapping - Payment Card Industry Data Security Standard Version 1.2 

[22] Standards Mapping - Payment Card Industry Data Security Standard Version 2.0 

[23] Standards Mapping - Payment Card Industry Data Security Standard Version 3.0 

[24] Standards Mapping - Payment Card Industry Data Security Standard Version 3.1 

[25] Standards Mapping - Payment Card Industry Data Security Standard Version 3.2 

[26] Standards Mapping - Payment Card Industry Data Security Standard Version 3.2.1 

[27] Standards Mapping - Payment Card Industry Software Security Framework 1.0 

[28] Standards Mapping - Payment Card Industry Software Security Framework 1.1 

[29] Standards Mapping - SANS Top 25 2009 

[30] Standards Mapping - SANS Top 25 2010 

[31] Standards Mapping - SANS Top 25 2011 

[32] Standards Mapping - Security Technical Implementation Guide Version 3.1 

[33] Standards Mapping - Security Technical Implementation Guide Version 3.4 

[34] Standards Mapping - Security Technical Implementation Guide Version 3.5 

[35] Standards Mapping - Security Technical Implementation Guide Version 3.6 

[36] Standards Mapping - Security Technical Implementation Guide Version 3.7 

[37] Standards Mapping - Security Technical Implementation Guide Version 3.9 

[38] Standards Mapping - Security Technical Implementation Guide Version 3.10 

[39] Standards Mapping - Security Technical Implementation Guide Version 4.1 

[40] Standards Mapping - Security Technical Implementation Guide Version 4.2 

[41] Standards Mapping - Security Technical Implementation Guide Version 4.3 

[42] Standards Mapping - Security Technical Implementation Guide Version 4.4 

[43] Standards Mapping - Security Technical Implementation Guide Version 4.5 

[44] Standards Mapping - Security Technical Implementation Guide Version 4.6 

[45] Standards Mapping - Security Technical Implementation Guide Version 4.7 

[46] Standards Mapping - Security Technical Implementation Guide Version 4.8 

[47] Standards Mapping - Security Technical Implementation Guide Version 4.9 

[48] Standards Mapping - Security Technical Implementation Guide Version 4.10 

[49] Standards Mapping - Security Technical Implementation Guide Version 4.11 

[50] Standards Mapping - Security Technical Implementation Guide Version 5.1 

[51] Standards Mapping - Web Application Security Consortium 24 + 2 

[52] Standards Mapping - Web Application Security Consortium Version 2.00 



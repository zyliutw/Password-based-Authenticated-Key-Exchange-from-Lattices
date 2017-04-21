<%@page contentType="text/html" pageEncoding="UTF-8"%>
<html>
    <head>
        <meta http-equiv="Content-Type"
              content="text/html; charset=UTF-8">
        <title>${param.user}</title>
    </head>
    <body>
        <h1>${message}</h1>
        <h1> g : ${g} </h1>
		<h1> pks : <a href="./download/pubKey"> <img border="0" alt="W3Schools" src="./download/file.png" width="32" height="32">
				   </a>
	    </h1>  
	    <h1>ids : ${ids}</h1>
		<h1>ssk : ${ssk}</h1>
    </body>
</html>
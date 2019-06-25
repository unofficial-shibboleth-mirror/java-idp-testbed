<%@page language="java" contentType="text/html; charset=US-ASCII" pageEncoding="US-ASCII"%>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>

<head>
<meta http-equiv="Content-Type" content="text/html; charset=US-ASCII">
<title>CAS Info Page</title>

<style type="text/css">

table {
    border-spacing: 0;
    border-collapse: collapse;
}
td, th {
    padding: 3px;
    text-align: left;
    border: 1px solid black;
}

tr:nth-of-type(odd) { background-color: white; }

tr:nth-of-type(even) { background-color: lightgrey; }

</style>

</head>

<body>

    <h1>CAS Authentication Info</h1>
    
    <p><%= request.getRemoteUser() %></p>

</body>

</html>

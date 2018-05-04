package main

import ()

const WARNING_PAGE = `
<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8">
		<title>Site Blocked by PhisherMan!</title>
		<style>
		 body {
			 background-color: #6d0000;
			 color: white;
		 }
		 body * {
			 text-align: center;
		 }
		 body img {
			 display: block;
			 margin: auto;
		 }
		 body strong {
		 	font-size: 20px;
		 }
		</style>
	</head>
	<body>
		<h1>Site Blocked by PhisherMan!</h1>
		<p><strong>%s</strong> was detected to be a possible phishing site against <strong>%s</strong> and was blocked <strong><em>(Algorithm %s: %v)</em></strong></p>
		<p>If you feel that this is a mistake, click <a href="">here</a> to submit a request to unblock the site to your system administrator.</p>
	</body>
</html>
`

Function New-HTML {
param($InnerHTML)

@"
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>Build Review Results - $(get-date -Format d)</title>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css" integrity="sha384-MCw98/SFnGE8fJT3GXwEOngsV7Zt27NXFoaoApmYm81iuXoPkFOJwJ8ERdknLPMO" crossorigin="anonymous">
</head><body>
<div class="container">
    <h1>Build Review Results</h1>
    <p class="lead">Results were generated on the $(get-date -Format d).</p> 
$InnerHTML
</div>
</body></html>
"@

}
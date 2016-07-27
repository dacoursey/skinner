# skinner
Tool for analyzing your head.

# Overview
This is a small portable tool for quickly evaluating the HTTP response headers on a target website. 

This was designed primarily to be used on networks that do not have access to the internet, but do what you wish. I'm a readme, not a cop.

# Usage

$skinner [-v|-a] -t http://www.yourtargeturl.biz


- t	        Target host	            // For now we only accept full URL's
- r	        Follow redirects        // Not really used yet.
- a	        Print all raw headers
- v	        Increase the number of status messages
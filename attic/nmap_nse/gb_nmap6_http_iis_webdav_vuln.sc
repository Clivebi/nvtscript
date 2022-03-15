if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803555" );
	script_version( "2020-11-26T08:02:59+0000" );
	script_cve_id( "CVE-2009-1122", "CVE-2009-1535" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-11-26 08:02:59 +0000 (Thu, 26 Nov 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 19:00:44 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: http-iis-webdav-vuln" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_xref( name: "URL", value: "http://blog.zoller.lu/2009/05/iis-6-webdac-auth-bypass-and-data.html" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2009/May/att-134/IIS_Advisory_pdf.bin" );
	script_xref( name: "URL", value: "http://www.skullsecurity.org/blog/?p=271" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/787932" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securityadvisories/2009/971492" );
	script_xref( name: "URL", value: "http://nmap.org/r/ms09-020" );
	script_tag( name: "summary", value: "Checks for a vulnerability in IIS 5.1/6.0 that allows arbitrary users to access secured WebDAV
folders by searching for a password-protected folder and attempting to access it. This vulnerability
was patched in Microsoft Security Bulletin MS09-020.

A list of well known folders (almost 900) is used by default. Each one is checked, and if returns an
authentication request (401), another attempt is tried with the malicious encoding. If that attempt
returns a successful result (207), then the folder is marked as vulnerable.

This script is based on the Metasploit
modules/auxiliary/scanner/http/wmap_dir_webdav_unicode_bypass.rb auxiliary module.

For more information on this vulnerability and script see the references.

SYNTAX:

http.pipeline:  If set, it represents the number of HTTP requests that'll be
pipelined (ie, sent in a single request). This can be set low to make
debugging easier, or it can be set high to test how a server reacts (its
chosen max is ignored).

basefolder:  The folder to start in, eg. ''/web'' will try ''/web/xxx''.

folderdb:  The filename of an alternate list of folders.

http-max-cache-size:  The maximum memory size (in bytes) of the cache.

webdavfolder:  Selects a single folder to use, instead of using a built-in list." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );


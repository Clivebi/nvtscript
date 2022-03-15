if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70734" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2012-0448", "CVE-2012-0440" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-02-12 07:27:19 -0500 (Sun, 12 Feb 2012)" );
	script_name( "FreeBSD Ports: bugzilla" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: bugzilla

CVE-2012-0448
Bugzilla 2.x and 3.x before 3.4.14, 3.5.x and 3.6.x before 3.6.8,
3.7.x and 4.0.x before 4.0.4, and 4.1.x and 4.2.x before 4.2rc2 does
not reject non-ASCII characters in e-mail addresses of new user
accounts, which makes it easier for remote authenticated users to
spoof other user accounts by choosing a similar e-mail address.

CVE-2012-0440
Cross-site request forgery (CSRF) vulnerability in jsonrpc.cgi in
Bugzilla 3.5.x and 3.6.x before 3.6.8, 3.7.x and 4.0.x before 4.0.4,
and 4.1.x and 4.2.x before 4.2rc2 allows remote attackers to hijack
the authentication of arbitrary users for requests that use the
JSON-RPC API." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "https://bugzilla.mozilla.org/show_bug.cgi?id=714472" );
	script_xref( name: "URL", value: "https://bugzilla.mozilla.org/show_bug.cgi?id=718319" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/309542b5-50b9-11e1-b0d8-00151735203a.html" );
	script_tag( name: "summary", value: "The remote host is missing an update to the system
  as announced in the referenced advisory." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-bsd.inc.sc");
vuln = FALSE;
txt = "";
bver = portver( pkg: "bugzilla" );
if(!isnull( bver ) && revcomp( a: bver, b: "2.4" ) >= 0 && revcomp( a: bver, b: "3.6.8" ) < 0){
	txt += "Package bugzilla version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "4.0" ) >= 0 && revcomp( a: bver, b: "4.0.4" ) < 0){
	txt += "Package bugzilla version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
if( vuln ){
	security_message( data: txt );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}


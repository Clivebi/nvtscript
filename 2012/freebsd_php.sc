if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71265" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2012-0831", "CVE-2012-1172" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-04-30 07:59:26 -0400 (Mon, 30 Apr 2012)" );
	script_name( "FreeBSD Ports: php" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: php

CVE-2012-0831
PHP before 5.3.10 does not properly perform a temporary change to the
magic_quotes_gpc directive during the importing of environment
variables, which makes it easier for remote attackers to conduct SQL
injection attacks via a crafted request, related to
main/php_variables.c, sapi/cgi/cgi_main.c, and
sapi/fpm/fpm/fpm_main.c." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.php.net/archive/2012.php#id2012-04-26-1" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/2cde1892-913e-11e1-b44c-001fd0af1a4c.html" );
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
bver = portver( pkg: "php" );
if(!isnull( bver ) && revcomp( a: bver, b: "5.3.11" ) < 0){
	txt += "Package php version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "5.4.1" ) < 0){
	txt += "Package php version " + bver + " is installed which is known to be vulnerable.\\n";
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


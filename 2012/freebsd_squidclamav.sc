if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71835" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2012-4667" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-30 11:34:17 -0400 (Thu, 30 Aug 2012)" );
	script_name( "FreeBSD Ports: squidclamav" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: squidclamav

CVE-2012-4667
Multiple cross-site scripting (XSS) vulnerabilities in SquidClamav 5.x
before 5.8 allow remote attackers to inject arbitrary web script or
HTML via the (1) url, (2) virus, (3) source, or (4) user parameter to
(a) clwarn.cgi, (b) clwarn.cgi.de_DE, (c) clwarn.cgi.en_EN, (d)
clwarn.cgi.fr_FR, (e) clwarn.cgi.pt_BR, or (f) clwarn.cgi.ru_RU in
cgi-bin/." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://squidclamav.darold.net/news.html" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/ce680f0a-eea6-11e1-8bd8-0022156e8794.html" );
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
bver = portver( pkg: "squidclamav" );
if(!isnull( bver ) && revcomp( a: bver, b: "5.8" ) < 0){
	txt += "Package squidclamav version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "6.0" ) >= 0 && revcomp( a: bver, b: "6.7" ) < 0){
	txt += "Package squidclamav version " + bver + " is installed which is known to be vulnerable.\\n";
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


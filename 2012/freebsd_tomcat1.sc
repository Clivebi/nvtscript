if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72606" );
	script_version( "2021-08-27T12:28:31+0000" );
	script_cve_id( "CVE-2012-3439", "CVE-2012-2733", "CVE-2012-3546", "CVE-2012-4431", "CVE-2012-4534", "CVE-2012-3544" );
	script_tag( name: "last_modification", value: "2021-08-27 12:28:31 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-11-26 12:47:33 -0500 (Mon, 26 Nov 2012)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "FreeBSD Ports: tomcat" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc." );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: tomcat" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security.html" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-5.html" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-6.html" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-7.html" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/152e4c7e-2a2e-11e2-99c7-00a0d181e71d.html" );
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
bver = portver( pkg: "tomcat" );
if(!isnull( bver ) && revcomp( a: bver, b: "5.5.0" ) > 0 && revcomp( a: bver, b: "5.5.36" ) < 0){
	txt += "Package tomcat version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "6.0.0" ) > 0 && revcomp( a: bver, b: "6.0.36" ) < 0){
	txt += "Package tomcat version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "7.0.0" ) > 0 && revcomp( a: bver, b: "7.0.30" ) < 0){
	txt += "Package tomcat version " + bver + " is installed which is known to be vulnerable.\\n";
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


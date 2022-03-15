if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72607" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2012-2733" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-11-26 12:47:33 -0500 (Mon, 26 Nov 2012)" );
	script_name( "FreeBSD Ports: tomcat" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: tomcat

CVE-2012-2733
java/org/apache/coyote/http11/InternalNioInputBuffer.java in the HTTP
NIO connector in Apache Tomcat 6.x before 6.0.36 and 7.x before 7.0.28
does not properly restrict the request-header size, which allows
remote attackers to cause a denial of service (memory consumption) via
a large amount of header data." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security.html" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-6.html" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-7.html" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/4ca26574-2a2c-11e2-99c7-00a0d181e71d.html" );
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
if(!isnull( bver ) && revcomp( a: bver, b: "6.0.0" ) > 0 && revcomp( a: bver, b: "6.0.36" ) < 0){
	txt += "Package tomcat version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "7.0.0" ) > 0 && revcomp( a: bver, b: "7.0.28" ) < 0){
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


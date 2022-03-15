if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71362" );
	script_cve_id( "CVE-2012-2143" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "$Revision: 14170 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 10:24:12 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-05-31 11:53:50 -0400 (Thu, 31 May 2012)" );
	script_name( "FreeBSD Ports: postgresql-server" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: postgresql-server" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.postgresql.org/about/news/1397/" );
	script_xref( name: "URL", value: "http://git.postgresql.org/gitweb/?p=postgresql.git;a=patch;h=932ded2ed51e8333852e370c7a6dad75d9f236f9" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/a8864f8f-aa9e-11e1-a284-0023ae8e59f0.html" );
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
bver = portver( pkg: "postgresql-server" );
if(!isnull( bver ) && revcomp( a: bver, b: "8.3" ) > 0 && revcomp( a: bver, b: "8.3.18_1" ) < 0){
	txt += "Package postgresql-server version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "8.4" ) > 0 && revcomp( a: bver, b: "8.4.11_1" ) < 0){
	txt += "Package postgresql-server version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "9.0" ) > 0 && revcomp( a: bver, b: "9.0.7_2" ) < 0){
	txt += "Package postgresql-server version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "9.1" ) > 0 && revcomp( a: bver, b: "9.1.3_1" ) < 0){
	txt += "Package postgresql-server version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "9.2" ) > 0 && revcomp( a: bver, b: "9.2.b1_1" ) < 0){
	txt += "Package postgresql-server version " + bver + " is installed which is known to be vulnerable.\\n";
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


if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71168" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2012-1190" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-03-12 11:35:07 -0400 (Mon, 12 Mar 2012)" );
	script_name( "FreeBSD Ports: phpMyAdmin" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: phpMyAdmin" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.phpmyadmin.net/home_page/security/PMASA-2012-1.php" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/fdd1c316-5a3d-11e1-8d3e-e0cb4e266481.html" );
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
bver = portver( pkg: "phpMyAdmin" );
if(!isnull( bver ) && revcomp( a: bver, b: "3.4" ) > 0 && revcomp( a: bver, b: "3.4.10.1" ) < 0){
	txt += "Package phpMyAdmin version " + bver + " is installed which is known to be vulnerable.\\n";
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


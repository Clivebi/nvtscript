if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70597" );
	script_tag( name: "creation_date", value: "2012-02-13 01:48:16 +0100 (Mon, 13 Feb 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $" );
	script_cve_id( "CVE-2011-4634" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "$Revision: 14117 $" );
	script_name( "FreeBSD Ports: phpMyAdmin" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: phpMyAdmin

CVE-2011-4634
Multiple cross-site scripting (XSS) vulnerabilities in phpMyAdmin
3.4.x before 3.4.8 allow remote attackers to inject arbitrary web
script or HTML via (1) a crafted database name, related to the
Database Synchronize panel, (2) a crafted database name, related to
the Database rename panel, (3) a crafted SQL query, related to the
table overview panel, (4) a crafted SQL query, related to the view
creation dialog, (5) a crafted column type, related to the table
search dialog, or (6) a crafted column type, related to the create
index dialog." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.phpmyadmin.net/home_page/security/PMASA-2011-18.php" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/ed536336-1c57-11e1-86f4-e0cb4e266481.html" );
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
if(!isnull( bver ) && revcomp( a: bver, b: "3.4" ) > 0 && revcomp( a: bver, b: "3.4.8.r1" ) < 0){
	txt += "Package phpMyAdmin version " + bver + " is installed which is known to be vulnerable.\n";
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


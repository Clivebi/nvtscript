if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70063" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-08-07 17:37:07 +0200 (Sun, 07 Aug 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-2642", "CVE-2011-2643" );
	script_name( "FreeBSD Ports: phpMyAdmin" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: phpMyAdmin

CVE-2011-2642
Multiple cross-site scripting (XSS) vulnerabilities in the table Print
view implementation in tbl_printview.php in phpMyAdmin before 3.3.10.3
and 3.4.x before 3.4.3.2 allow remote authenticated users to inject
arbitrary web script or HTML via a crafted table name.

CVE-2011-2643
Directory traversal vulnerability in sql.php in phpMyAdmin 3.4.x
before 3.4.3.2, when configuration storage is enabled, allows remote
attackers to include and execute arbitrary local files via directory
traversal sequences in a MIME-type transformation parameter." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.phpmyadmin.net/home_page/security/PMASA-2011-9.php" );
	script_xref( name: "URL", value: "http://www.phpmyadmin.net/home_page/security/PMASA-2011-10.php" );
	script_xref( name: "URL", value: "http://www.phpmyadmin.net/home_page/security/PMASA-2011-11.php" );
	script_xref( name: "URL", value: "http://www.phpmyadmin.net/home_page/security/PMASA-2011-12.php" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/d79fc873-b5f9-11e0-89b4-001ec9578670.html" );
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
if(!isnull( bver ) && revcomp( a: bver, b: "3.4.3.2" ) < 0){
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

